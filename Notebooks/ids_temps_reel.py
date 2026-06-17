import os
import time
import torch
import joblib
import warnings
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP

# Masquer les avertissements de Scikit-Learn pour garder la console propre
warnings.filterwarnings("ignore", category=UserWarning)

# Création des dossiers nécessaires s'ils n'existent pas
os.makedirs('../results', exist_ok=True)

# ==========================================
# 1. ARCHITECTURE DU MODÈLE HYBRIDE (EXACTE)
# ==========================================
class MonModeleHybride(torch.nn.Module):
    def __init__(self, input_size=46, num_classes=7):
        super(MonModeleHybride, self).__init__()
        
        # Structure validée par l'alignement des poids du fichier .pth
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
        out = out[:, -1, :] # Extraction du dernier pas temporel
        out = self.bn(out)
        out = self.fc(out)
        return out

# ==========================================
# 2. CHARGEMENT DES COMPOSANTS SAUVEGARDÉS
# ==========================================
print("⏳ Chargement du Scaler et du LabelEncoder...")
scaler = joblib.load('../models/scaler.pkl')
le = joblib.load('../models/label_encoder.pkl')

print("🧠 Chargement des poids du modèle hybride...")
num_features = scaler.n_features_in_ # Doit être égal à 46
model = MonModeleHybride(input_size=num_features, num_classes=len(le.classes_))
model.load_state_dict(torch.load('../models/model_hybride.pth', map_location=torch.device('cpu')))
model.eval()

print("✅ Système IDS configuré et prêt pour l'analyse réseau.\n")

# Extraire le nom des colonnes attendues par le StandardScaler
COLONNES_TRAIN = list(scaler.feature_names_in_) if hasattr(scaler, 'feature_names_in_') else None

# ==========================================
# 3. EXTRACTION DES CARACTÉRISTIQUES (SCAPY)
# ==========================================
def extraire_caracteristiques(packet):
    """
    Transforme un paquet Scapy en un dictionnaire aligné 
    avec les variables de cache_filtre.csv
    """
    # Initialisation à 0 (valeurs par défaut pour un paquet isolé)
    feat = {
        'flow_duration': 0.0, 'Header_Length': 0, 'Protocol Type': 0, 'Duration': 0.0,
        'Rate': 1.0, 'Srate': 0.0, 'Drate': 0.0, 'fin_flag_number': 0, 'syn_flag_number': 0,
        'rst_flag_number': 0, 'psh_flag_number': 0, 'ack_flag_number': 0, 'ece_flag_number': 0,
        'cwr_flag_number': 0, 'ack_count': 0, 'syn_count': 0, 'fin_count': 0, 'urg_count': 0,
        'rst_count': 0, 'HTTP': 0, 'HTTPS': 0, 'DNS': 0, 'Telnet': 0, 'SMTP': 0, 'SSH': 0,
        'IRC': 0, 'TCP': 0, 'UDP': 0, 'DHCP': 0, 'ARP': 0, 'ICMP': 0, 'IPv': 0, 'LLC': 0
    }
    
    if IP in packet:
        feat['IPv'] = packet[IP].version
        feat['Protocol Type'] = packet[IP].proto
        feat['Header_Length'] = len(packet[IP]) - len(packet[IP].payload)
        
        if packet.haslayer(TCP):
            feat['TCP'] = 1
            tcp = packet[TCP]
            feat['Header_Length'] += (tcp.dataofs * 4)
            
            # Drapeaux (Flags) TCP
            feat['fin_flag_number'] = 1 if 'F' in tcp.flags else 0
            feat['syn_flag_number'] = 1 if 'S' in tcp.flags else 0
            feat['rst_flag_number'] = 1 if 'R' in tcp.flags else 0
            feat['psh_flag_number'] = 1 if 'P' in tcp.flags else 0
            feat['ack_flag_number'] = 1 if 'A' in tcp.flags else 0
            
            # Protocoles Applicatifs via les ports de destination/source
            ports = [tcp.sport, tcp.dport]
            if 80 in ports: feat['HTTP'] = 1
            elif 443 in ports: feat['HTTPS'] = 1
            elif 22 in ports: feat['SSH'] = 1
            elif 23 in ports: feat['Telnet'] = 1
            elif 25 in ports: feat['SMTP'] = 1
            
        elif packet.haslayer(UDP):
            feat['UDP'] = 1
            udp = packet[UDP]
            ports = [udp.sport, udp.dport]
            if 53 in ports: feat['DNS'] = 1
            elif 67 in ports or 68 in ports: feat['DHCP'] = 1

    elif packet.haslayer('ARP'):
        feat['ARP'] = 1
    elif packet.haslayer('ICMP'):
        feat['ICMP'] = 1

    # Construire la liste ordonnée en suivant rigoureusement l'ordre défini par COLONNES_TRAIN
    if COLONNES_TRAIN:
        liste_ordonnee = [feat.get(col, 0.0) for col in COLONNES_TRAIN]
    else:
        liste_ordonnee = [feat.get(k, 0.0) for k in feat.keys()]
        
    # Ajustement de sécurité sur la taille (Padding / Troncature)
    if len(liste_ordonnee) < num_features:
        liste_ordonnee += [0.0] * (num_features - len(liste_ordonnee))
    else:
        liste_ordonnee = liste_ordonnee[:num_features]
        
    return liste_ordonnee

# ==========================================
# 4. PRÉDICTION & LOGIC D'ALERTE
# ==========================================
def analyser_paquet(packet):
    try:
        # 1. Extraction du vecteur de caractéristiques
        features_brutes = extraire_caracteristiques(packet)
        
        # 2. Conversion en DataFrame Pandas pour éviter le UserWarning du Scaler
        if COLONNES_TRAIN:
            df_paquet = pd.DataFrame([features_brutes], columns=COLONNES_TRAIN)
            features_scaled = scaler.transform(df_paquet)
        else:
            features_scaled = scaler.transform([features_brutes])
        
        # 3. Reshape pour le format attendu par GRU/LSTM : (Batch=1, Time_Steps=1, Features=46)
        features_rnn = features_scaled.reshape(1, 1, -1)
        tensor_input = torch.FloatTensor(features_rnn)
        
        # 4. Classification par l'Intelligence Artificielle
        with torch.no_grad():
            outputs = model(tensor_input)
            prediction_idx = outputs.argmax(1).item()
            
        # 5. Traduction de l'index en nom de classe lisible
        nom_classe = le.inverse_transform([prediction_idx])[0]
        
        # 6. Levée et sauvegarde de l'alerte (si non bénin)
        if nom_classe != "BenignTraffic" and IP in packet:
            # Affichage structuré et lisible à l'écran
            print(f"\n🚨 [DETECTION IDAM] ----------------------------------")
            print(f"   Type d'attaque : {nom_classe}")
            print(f"   IP Source      : {packet[IP].src}")
            print(f"   IP Destination : {packet[IP].dst}")
            print(f"------------------------------------------------------\n")
            
            # Enregistrement persistant dans un fichier d'historique
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            with open("../results/historique_alertes.txt", "a", encoding="utf-8") as log_file:
                log_file.write(f"[{timestamp}] Attaque: {nom_classe} | Source: {packet[IP].src} -> Dest: {packet[IP].dst}\n")
            
            # Petite pause pour stabiliser le défilement de la console VS Code
            time.sleep(0.5)
            
    except Exception as e:
        # Ignorer les paquets corrompus sans bloquer la capture réseau
        pass

# ==========================================
# 5. CODE PRINCIPAL (LANCEMENT)
# ==========================================
if __name__ == "__main__":
    print("🚀 Démarrage de l'IDS en Temps Réel...")
    print("📢 Analyse de votre carte réseau en cours... (Ctrl+C pour arrêter)\n")
    
    try:
        # filter="ip" : Analyse uniquement le trafic IP
        # store=0 : Ne garde pas les paquets passés en mémoire vive pour éviter les fuites de RAM
        sniff(filter="ip", prn=analyser_paquet, store=0)
    except KeyboardInterrupt:
        print("\n🛑 Arrêt propre du Système de Détection d'Intrusions demandé par l'utilisateur.")