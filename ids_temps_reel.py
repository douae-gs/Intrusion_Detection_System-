
import os
import sys
import time
import threading
import json
import warnings
from collections import defaultdict

import torch
import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP

# Permet d'exécuter ce script depuis n'importe quel sous-dossier (ex. Notebooks/)
# tout en important db.py / llm_alert.py / config.py qui vivent à la racine du
# projet, à côté de app.py. Adapte UNIQUEMENT cette ligne si ton arborescence
# diffère (ex. si tu déplaces ids_temps_reel.py ailleurs que Notebooks/).
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from db import init_db, inserer_alerte
from llm_alert import generer_alerte
from config import LIVE_STATUS_PATH, MODELS_DIR, DATA_DIR

warnings.filterwarnings("ignore", category=UserWarning)
os.makedirs(os.path.join(PROJECT_ROOT, 'results'), exist_ok=True)


FLOW_TIMEOUT = 15.0
CLEANUP_INTERVAL = 1.0
MIN_PAQUETS_EVALUATION = 8
DUREE_MIN_PLANCHER = 0.5

# Fréquence d'écriture de l'état live pour le dashboard (indépendant du
# nettoyage des flux expirés, pour que le monitoring reste fluide même si
# aucun flux n'expire pendant quelques secondes)
LIVE_STATUS_WRITE_INTERVAL = 1.5


class MonModeleHybride(torch.nn.Module):
    def __init__(self, input_size=46, num_classes=7):
        super(MonModeleHybride, self).__init__()
        self.gru = torch.nn.GRU(input_size, 256, batch_first=True, bidirectional=False)
        self.lstm = torch.nn.LSTM(256, 128, batch_first=True, bidirectional=False)
        self.bn = torch.nn.BatchNorm1d(128)
        self.fc = torch.nn.Sequential(
            torch.nn.Linear(128, 64),
            torch.nn.ReLU(),
            torch.nn.Linear(64, num_classes)
        )

    def forward(self, x):
        out, _ = self.gru(x)
        out, _ = self.lstm(out)
        out = out[:, -1, :]
        out = self.bn(out)
        out = self.fc(out)
        return out


print("⏳ Chargement du Scaler et du LabelEncoder...")
scaler = joblib.load(os.path.join(MODELS_DIR, 'scaler.pkl'))
le = joblib.load(os.path.join(MODELS_DIR, 'label_encoder.pkl'))

print("🧠 Chargement des poids du modèle hybride...")
num_features = scaler.n_features_in_
model = MonModeleHybride(input_size=num_features, num_classes=len(le.classes_))
model.load_state_dict(torch.load(os.path.join(MODELS_DIR, 'model_hybride.pth'), map_location=torch.device('cpu')))
model.eval()

# Initialise la base SQLite des alertes (idempotent — peut être déjà créée par le dashboard)
init_db()

print("✅ Système IDS configuré et prêt pour l'analyse réseau.\n")

COLONNES_TRAIN = list(scaler.feature_names_in_) if hasattr(scaler, 'feature_names_in_') else None


flow_buffer = {}
buffer_lock = threading.Lock()
stop_event = threading.Event()

# Buffer circulaire des dernières classifications, pour affichage live
# (dernières 50, le plus récent en premier)
dernieres_predictions = []
predictions_lock = threading.Lock()
compteur_paquets_total = 0
compteur_paquets_intervalle = 0
compteur_lock = threading.Lock()


def cle_flux(packet):
    if IP not in packet:
        return None
    proto = 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'OTHER'
    sport = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0)
    dport = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)
    return (packet[IP].src, packet[IP].dst, sport, dport, proto)


def nouveau_flux(packet):
    now = time.time()
    stats = {
        'first_seen': now, 'last_seen': now, 'last_packet_time': now, 'count': 0,
        'src_ip': packet[IP].src, 'dst_ip': packet[IP].dst, 'proto_type': packet[IP].proto,
        'is_tcp': 0, 'is_udp': 0, 'sum_header_length': 0.0, 'sum_size': 0.0, 'sum_size_sq': 0.0,
        'min_size': None, 'max_size': None, 'sum_iat': 0.0, 'count_iat': 0,
        'fin_count': 0, 'syn_count': 0, 'rst_count': 0, 'psh_count': 0, 'ack_count': 0, 'urg_count': 0,
        'http': 0, 'https': 0, 'dns': 0, 'telnet': 0, 'smtp': 0, 'ssh': 0, 'dhcp': 0,
        'ipv': packet[IP].version,
    }
    return stats


def maj_flux(stats, packet):
    now = time.time()
    if stats['count_iat'] >= 0 and stats['last_packet_time'] is not None:
        stats['sum_iat'] += (now - stats['last_packet_time'])
        stats['count_iat'] += 1
    stats['last_packet_time'] = now
    stats['last_seen'] = now
    stats['count'] += 1

    taille = len(packet)
    stats['sum_size'] += taille
    stats['sum_size_sq'] += taille * taille
    stats['min_size'] = taille if stats['min_size'] is None else min(stats['min_size'], taille)
    stats['max_size'] = taille if stats['max_size'] is None else max(stats['max_size'], taille)

    header_len = len(packet[IP]) - len(packet[IP].payload)

    if packet.haslayer(TCP):
        stats['is_tcp'] = 1
        tcp = packet[TCP]
        header_len += (tcp.dataofs * 4)
        if 'F' in tcp.flags: stats['fin_count'] += 1
        if 'S' in tcp.flags: stats['syn_count'] += 1
        if 'R' in tcp.flags: stats['rst_count'] += 1
        if 'P' in tcp.flags: stats['psh_count'] += 1
        if 'A' in tcp.flags: stats['ack_count'] += 1
        if 'U' in tcp.flags: stats['urg_count'] += 1
        ports = [tcp.sport, tcp.dport]
        if 80 in ports: stats['http'] = 1
        elif 443 in ports: stats['https'] = 1
        elif 22 in ports: stats['ssh'] = 1
        elif 23 in ports: stats['telnet'] = 1
        elif 25 in ports: stats['smtp'] = 1
        elif 1883 in ports or 8883 in ports:
            pass  # MQTT journalisé mais non utilisé par le modèle (cf. limite documentée)
    elif packet.haslayer(UDP):
        stats['is_udp'] = 1
        udp = packet[UDP]
        ports = [udp.sport, udp.dport]
        if 53 in ports: stats['dns'] = 1
        elif 67 in ports or 68 in ports: stats['dhcp'] = 1

    stats['sum_header_length'] += header_len
    return stats


def calculer_features_flux(stats):
    duration_brute = stats['last_seen'] - stats['first_seen']
    duration = max(duration_brute, DUREE_MIN_PLANCHER)
    count = max(stats['count'], 1)

    mean_size = stats['sum_size'] / count
    variance_size = max((stats['sum_size_sq'] / count) - (mean_size ** 2), 0.0)
    std_size = variance_size ** 0.5
    mean_iat = stats['sum_iat'] / stats['count_iat'] if stats['count_iat'] > 0 else 0.0
    rate = count / duration

    feat = {
        'flow_duration': duration_brute, 'Header_Length': stats['sum_header_length'] / count,
        'Protocol Type': stats['proto_type'], 'Duration': duration_brute, 'Rate': rate, 'Srate': rate,
        'Drate': 0.0, 'fin_flag_number': 1 if stats['fin_count'] > 0 else 0,
        'syn_flag_number': 1 if stats['syn_count'] > 0 else 0, 'rst_flag_number': 1 if stats['rst_count'] > 0 else 0,
        'psh_flag_number': 1 if stats['psh_count'] > 0 else 0, 'ack_flag_number': 1 if stats['ack_count'] > 0 else 0,
        'ece_flag_number': 0, 'cwr_flag_number': 0, 'ack_count': stats['ack_count'], 'syn_count': stats['syn_count'],
        'fin_count': stats['fin_count'], 'urg_count': stats['urg_count'], 'rst_count': stats['rst_count'],
        'HTTP': stats['http'], 'HTTPS': stats['https'], 'DNS': stats['dns'], 'Telnet': stats['telnet'],
        'SMTP': stats['smtp'], 'SSH': stats['ssh'], 'IRC': 0, 'TCP': stats['is_tcp'], 'UDP': stats['is_udp'],
        'DHCP': stats['dhcp'], 'ARP': 0, 'ICMP': 0, 'IPv': stats['ipv'], 'LLC': 0, 'Tot sum': stats['sum_size'],
        'Min': stats['min_size'] or 0.0, 'Max': stats['max_size'] or 0.0, 'AVG': mean_size, 'Std': std_size,
        'Tot size': stats['sum_size'], 'IAT': mean_iat, 'Number': count,
        'Magnitue': 0.0, 'Radius': 0.0, 'Covariance': 0.0, 'Variance': 0.0, 'Weight': 0.0,
    }

    if COLONNES_TRAIN:
        liste_ordonnee = [feat.get(col, 0.0) for col in COLONNES_TRAIN]
    else:
        liste_ordonnee = list(feat.values())

    if len(liste_ordonnee) < num_features:
        liste_ordonnee += [0.0] * (num_features - len(liste_ordonnee))
    else:
        liste_ordonnee = liste_ordonnee[:num_features]

    return liste_ordonnee


def evaluer_flux(cle, stats):
    if stats['count'] < MIN_PAQUETS_EVALUATION:
        return

    try:
        features_brutes = calculer_features_flux(stats)

        if COLONNES_TRAIN:
            df_flux = pd.DataFrame([features_brutes], columns=COLONNES_TRAIN)
            features_scaled = scaler.transform(df_flux)
        else:
            features_scaled = scaler.transform([features_brutes])

        features_rnn = features_scaled.reshape(1, 1, -1)
        tensor_input = torch.FloatTensor(features_rnn)

        with torch.no_grad():
            outputs = model(tensor_input)
            probs = torch.softmax(outputs, dim=1)
            prediction_idx = outputs.argmax(1).item()
            confiance = probs[0, prediction_idx].item()

        nom_classe = le.inverse_transform([prediction_idx])[0]
        duree_reelle = stats['last_seen'] - stats['first_seen']

        # Alimente le buffer "dernières prédictions" pour le monitoring live,
        # qu'il s'agisse de trafic bénin ou non (utile pour voir le système vivre)
        with predictions_lock:
            dernieres_predictions.insert(0, {
                "horodatage": time.strftime("%H:%M:%S") + f".{int((time.time()%1)*1000):03d}",
                "prediction": nom_classe,
                "confiance": round(confiance, 4),
                "src_ip": stats['src_ip'],
            })
            del dernieres_predictions[50:]

        if nom_classe != "BenignTraffic":
            print(f"\n🚨 [DETECTION IDS] ----------------------------------")
            print(f"   Type d'attaque : {nom_classe}")
            print(f"   IP Source      : {stats['src_ip']}")
            print(f"   IP Destination : {stats['dst_ip']}")
            print(f"   Paquets agrégés: {stats['count']} sur {duree_reelle:.2f}s")
            print(f"------------------------------------------------------\n")

            details = {
                "ip_source": stats['src_ip'], "ip_destination": stats['dst_ip'],
                "protocole": "TCP" if stats['is_tcp'] else "UDP" if stats['is_udp'] else "AUTRE",
                "nb_paquets": stats['count'], "duree_flux": round(duree_reelle, 2),
            }
            # Enrichissement LLM (ou mode secours automatique si pas de clé API)
            rapport = generer_alerte(nom_classe, confiance, details)

            inserer_alerte(
                type_attaque=nom_classe,
                gravite=rapport.get("gravite", "Élevé"),
                confiance=confiance,
                ip_source=stats['src_ip'],
                ip_destination=stats['dst_ip'],
                protocole=details["protocole"],
                nb_paquets=stats['count'],
                duree_flux=round(duree_reelle, 2),
                rapport_llm=rapport,
            )

    except Exception as e:
        print(f"⚠️  Erreur lors de l'évaluation d'un flux : {e}")


def ecrire_etat_live():
    global compteur_paquets_intervalle
    with buffer_lock:
        flux_actifs = [
            {
                "src_ip": s['src_ip'], "dst_ip": s['dst_ip'],
                "protocole": "TCP" if s['is_tcp'] else "UDP" if s['is_udp'] else "AUTRE",
                "nb_paquets": s['count'],
                "anciennete_s": round(time.time() - s['first_seen'], 1),
            }
            for s in flow_buffer.values()
        ]

    with predictions_lock:
        preds_snapshot = list(dernieres_predictions[:15])

    with compteur_lock:
        debit = compteur_paquets_intervalle / LIVE_STATUS_WRITE_INTERVAL
        compteur_paquets_intervalle = 0
        total = compteur_paquets_total

    status = {
        "derniere_maj": pd.Timestamp.now().isoformat(),
        "statut_capture": "actif",
        "paquets_inspectes_total": total,
        "paquets_par_seconde": round(debit, 1),
        "flux_actifs": flux_actifs,
        "nb_flux_actifs": len(flux_actifs),
        "dernieres_predictions": preds_snapshot,
    }

    try:
        tmp_path = LIVE_STATUS_PATH + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(status, f, ensure_ascii=False)
        os.replace(tmp_path, LIVE_STATUS_PATH)  # écriture atomique pour éviter une lecture partielle par le dashboard
    except OSError as e:
        print(f"⚠️  Impossible d'écrire l'état live : {e}")


def thread_nettoyage():
    dernier_ecriture_live = 0
    while not stop_event.is_set():
        time.sleep(CLEANUP_INTERVAL)
        now = time.time()
        flux_a_evaluer = []

        with buffer_lock:
            cles_expirees = [
                cle for cle, stats in flow_buffer.items()
                if now - stats['last_seen'] > FLOW_TIMEOUT
            ]
            for cle in cles_expirees:
                flux_a_evaluer.append((cle, flow_buffer.pop(cle)))

        for cle, stats in flux_a_evaluer:
            evaluer_flux(cle, stats)

        if now - dernier_ecriture_live >= LIVE_STATUS_WRITE_INTERVAL:
            ecrire_etat_live()
            dernier_ecriture_live = now


def analyser_paquet(packet):
    global compteur_paquets_total, compteur_paquets_intervalle
    try:
        cle = cle_flux(packet)
        if cle is None:
            return

        with buffer_lock:
            if cle not in flow_buffer:
                flow_buffer[cle] = nouveau_flux(packet)
            maj_flux(flow_buffer[cle], packet)

        with compteur_lock:
            compteur_paquets_total += 1
            compteur_paquets_intervalle += 1

    except Exception:
        pass



if __name__ == "__main__":
    print("Démarrage de l'IDS en Temps Réel (avec windowing par flux)...")
    print(f"Fenêtre d'agrégation : flux évalués après {FLOW_TIMEOUT}s d'inactivité")
    print(f"Seuil minimum : {MIN_PAQUETS_EVALUATION} paquets requis avant évaluation")
    print(f"Alertes écrites dans : results/alerts.db")
    print(f"État live écrit dans : {LIVE_STATUS_PATH}")
    print("Analyse de votre carte réseau en cours... (Ctrl+C pour arrêter)\n")

    nettoyeur = threading.Thread(target=thread_nettoyage, daemon=True)
    nettoyeur.start()

    try:
        sniff(filter="ip", prn=analyser_paquet, store=0)
    except KeyboardInterrupt:
        print("\n Arrêt en cours, évaluation des flux restants...")
        stop_event.set()
        with buffer_lock:
            flux_restants = list(flow_buffer.items())
            flow_buffer.clear()
        for cle, stats in flux_restants:
            evaluer_flux(cle, stats)
        # Marque la capture comme arrêtée dans le fichier live, pour que le
        # dashboard affiche "Hors ligne" plutôt qu'une dernière valeur figée
        try:
            with open(LIVE_STATUS_PATH, "r", encoding="utf-8") as f:
                status = json.load(f)
            status["statut_capture"] = "arrêté"
            with open(LIVE_STATUS_PATH, "w", encoding="utf-8") as f:
                json.dump(status, f, ensure_ascii=False)
        except (OSError, json.JSONDecodeError):
            pass
        print("🛑 Arrêt propre du Système de Détection d'Intrusions terminé.")
