import json
import random
import sqlite3
from datetime import datetime, timedelta

from config import ATTACK_FAMILIES, LIVE_STATUS_PATH, RESULTS_DIR, TRAINING_HISTORY_PATH
from db import init_db, inserer_alerte, get_connection
from llm_alert import alerte_secours

random.seed(42)

IPS_INTERNES = [f"192.168.1.{i}" for i in (12, 23, 45, 67, 88, 101, 114)]
IPS_EXTERNES = [
    "203.0.113.41", "198.51.100.7", "212.85.10.4", "45.142.120.33",
    "185.220.101.5", "91.219.236.18",
]
PORTS_PAR_ATTAQUE = {
    "DDoS": [80, 443, 53],
    "DoS": [80, 8080],
    "Mirai": [23, 2323],
    "Recon": [22, 80, 443, 3389],
    "Spoofing": [53, 67],
}


def reset_db():
    conn = get_connection()
    conn.execute("DROP TABLE IF EXISTS alertes")
    conn.commit()
    conn.close()
    init_db()


def generer_alertes(nb_jours=2, alertes_par_jour=35):
    reset_db()
    conn = get_connection()
    maintenant = datetime.now()

    for jour in range(nb_jours, -1, -1):
        for _ in range(random.randint(alertes_par_jour - 10, alertes_par_jour + 10)):
            famille = random.choices(
                ATTACK_FAMILIES,
                weights=[30, 20, 15, 25, 10],  # DDoS/Recon plus fréquents
            )[0]
            ts = maintenant - timedelta(
                days=jour,
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59),
                seconds=random.randint(0, 59),
            )
            confiance = round(random.uniform(0.72, 0.998), 4)
            src = random.choice(IPS_INTERNES + IPS_EXTERNES)
            dst = random.choice(IPS_INTERNES)
            port = random.choice(PORTS_PAR_ATTAQUE.get(famille, [80]))
            rapport = alerte_secours(famille, confiance)

            conn.execute("""
                INSERT INTO alertes (
                    timestamp, type_attaque, gravite, confiance, ip_source,
                    ip_destination, port_destination, protocole, nb_paquets,
                    duree_flux, titre_llm, description_llm, recommandations_llm
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                ts.isoformat(), famille, rapport["gravite"], confiance, src, dst,
                port, random.choice(["TCP", "UDP"]), random.randint(8, 450),
                round(random.uniform(0.5, 15.0), 2),
                rapport["titre"], rapport["description"],
                json.dumps(rapport["recommandations"], ensure_ascii=False),
            ))

    conn.commit()
    conn.close()
    print("Base d'alertes peuplée.")


def generer_live_status():
    """Simule un instantané de l'état du moteur IDS, au même format que ce
    qu'écrirait ids_temps_reel.py modifié (voir integration_ids.py)."""
    flux_actifs = []
    for _ in range(random.randint(4, 12)):
        flux_actifs.append({
            "src_ip": random.choice(IPS_INTERNES),
            "dst_ip": random.choice(IPS_INTERNES + IPS_EXTERNES),
            "protocole": random.choice(["TCP", "UDP"]),
            "nb_paquets": random.randint(1, 7),
            "anciennete_s": round(random.uniform(0, 14), 1),
        })

    dernieres_predictions = []
    maintenant = datetime.now()
    for i in range(15):
        famille = random.choices(
            ["BenignTraffic"] + ATTACK_FAMILIES,
            weights=[55, 15, 8, 7, 10, 5],
        )[0]
        dernieres_predictions.append({
            "horodatage": (maintenant - timedelta(seconds=i * 3)).strftime("%H:%M:%S.%f")[:-3],
            "prediction": famille,
            "confiance": round(random.uniform(0.7, 0.999), 4),
            "src_ip": random.choice(IPS_INTERNES),
        })

    status = {
        "derniere_maj": maintenant.isoformat(),
        "statut_capture": "actif",
        "paquets_inspectes_total": random.randint(120000, 480000),
        "paquets_par_seconde": round(random.uniform(40, 320), 1),
        "flux_actifs": flux_actifs,
        "nb_flux_actifs": len(flux_actifs),
        "dernieres_predictions": dernieres_predictions,
    }
    with open(LIVE_STATUS_PATH, "w", encoding="utf-8") as f:
        json.dump(status, f, indent=2, ensure_ascii=False)
    print(f"live_status.json généré : {LIVE_STATUS_PATH}")


def generer_training_history():
    """Reprend les VRAIES métriques finales issues de Training_hybride.ipynb
    après suppression de la classe Injection (6 classes au lieu de 7) :
    accuracy 88.65%, loss 0.2590 après 50 epochs. Valeurs epoch par epoch
    recopiées directement depuis la sortie du notebook fourni."""
    epochs_loss_acc = [
        (1, 0.4822, 77.59), (2, 0.4124, 80.26), (3, 0.3922, 81.35),
        (4, 0.3819, 81.86), (5, 0.3750, 82.27), (6, 0.3687, 82.63),
        (7, 0.3632, 82.93), (8, 0.3588, 83.06), (9, 0.3544, 83.25),
        (10, 0.3518, 83.30), (11, 0.3473, 83.50), (12, 0.3452, 83.52),
        (13, 0.3443, 83.62), (14, 0.3412, 83.74), (15, 0.3382, 83.89),
        (16, 0.3377, 83.94), (17, 0.3342, 84.12), (18, 0.3329, 84.23),
        (19, 0.3284, 84.54), (20, 0.3248, 84.80), (21, 0.3218, 85.02),
        (22, 0.3166, 85.49), (23, 0.3074, 86.09), (24, 0.3010, 86.59),
        (25, 0.2982, 86.82), (26, 0.2829, 87.67), (27, 0.2904, 87.40),
        (28, 0.2718, 88.23), (29, 0.2689, 88.41), (30, 0.2673, 88.52),
        (31, 0.2695, 88.41), (32, 0.2639, 88.62), (33, 0.2608, 88.77),
        (34, 0.2668, 88.57), (35, 0.2470, 89.48), (36, 0.2603, 88.83),
        (37, 0.2690, 88.27), (38, 0.2651, 88.55), (39, 0.2616, 88.67),
        (40, 0.2504, 89.25), (41, 0.2432, 89.63), (42, 0.2481, 89.29),
        (43, 0.2554, 89.03), (44, 0.2718, 88.24), (45, 0.2439, 89.59),
        (46, 0.2624, 88.63), (47, 0.2768, 87.96), (48, 0.2547, 89.09),
        (49, 0.2508, 89.26), (50, 0.2590, 88.65),
    ]

    precision_par_famille = {
        "BenignTraffic": 83.9,
        "DDoS": 92.5,
        "DoS": 99.8,
        "Mirai": 85.4,
        "Recon": 87.4,
        "Spoofing": 72.8,
    }

    matrice_confusion = {
        "classes": ["BenignTraffic", "DDoS", "DoS", "Mirai", "Recon", "Spoofing"],
        "valeurs": [
            [84.6, 0.0, 0.0, 0.0, 5.0, 5.0],
            [0.0, 93.3, 6.6, 0.1, 0.0, 0.0],
            [0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            [0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            [8.1, 0.0, 0.0, 0.0, 68.3, 5.1],
            [9.6, 0.0, 0.0, 0.0, 6.0, 72.8],
        ],
    }

    history = {
        "epochs": epochs_loss_acc,
        "accuracy_finale": 88.65,
        "loss_finale": 0.2590,
        "learning_rate": 0.001,
        "nb_epochs": 50,
        "precision_par_famille": precision_par_famille,
        "matrice_confusion": matrice_confusion,
        "auteurs": [ "Nassira Amhaoui","Douae Gasmi"],
    }
    with open(TRAINING_HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)
    print(f"training_history.json généré : {TRAINING_HISTORY_PATH}")


if __name__ == "__main__":
    generer_alertes()
    generer_live_status()
    generer_training_history()
    print("\nDonnées de démonstration prêtes.")
