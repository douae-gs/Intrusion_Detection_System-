# IoT Guard — Système Intelligent de Détection d'Intrusions IoT
---

## Description

**IoT Guard** est un système de détection d'intrusions (IDS) en temps réel destiné aux environnements IoT. Il combine un modèle de Deep Learning hybride **GRU+LSTM** pour la classification du trafic réseau et un **LLM (LLaMA 3.3 via API Groq)** pour la génération automatique d'alertes de sécurité en langage naturel. L'ensemble est intégré dans un tableau de bord interactif développé avec **Dash**.

---

## Fonctionnalités

- Capture du trafic réseau en temps réel via **Scapy**
- Classification automatique du trafic en 6 catégories : `DDoS`, `DoS`, `Mirai`, `Recon`, `Spoofing`, `Benign`
- Génération d'alertes contextualisées en français via **LLaMA 3.3**
- Mode secours local en cas d'indisponibilité de l'API Groq
- Tableau de bord interactif avec supervision en temps réel
- Analyse de fichiers CSV de captures réseau en mode différé
- Authentification sécurisée

---

## Technologies utilisées

| Composant | Technologie |
|---|---|
| Deep Learning | PyTorch, scikit-learn, imbalanced-learn |
| Capture réseau | Scapy |
| Communication IoT | MQTT |
| LLM | LLaMA 3.3 70B via API Groq |
| Dashboard | Python Dash, Bootstrap |
| Données | pandas, numpy |
| Visualisation | matplotlib, seaborn |
| Dataset | CICIoT2023 (Canadian Institute for Cybersecurity) |

---

## Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/votre-repo/Intrusion_Detection_System-.git
cd Intrusion_Detection_System-
```

### . Installer les dépendances

```bash
pip install -r requirements.txt
```

### . Configurer la clé API Groq

Créer un fichier `.env` à la racine du projet :

```
GROQ_API_KEY=votre_clé_groq_ici
```

---

## Lancement

### Démarrer le tableau de bord

```bash
python app.py
```

Accéder à l'interface sur : [http://localhost:8050](http://localhost:8050)

### Lancer le moteur de détection en temps réel

> Nécessite des privilèges administrateur (requis par Scapy)

```bash
# Windows (PowerShell en mode administrateur)
python ids_temps_reel.py

# Linux / macOS
sudo python ids_temps_reel.py
```

---




## Performances du modèle

| Métrique | Valeur |
|---|---|
| Précision finale | **88,65 %** |
| Perte finale | **0,259** |
| Époques | 50 |
| Taux d'apprentissage | 0,001 |
| Dataset | CICIoT2023 — 900 000 flux (6 classes équilibrées) |

---

## Dataset

Le modèle est entraîné sur le **CICIoT2023** du Canadian Institute for Cybersecurity (Université du Nouveau-Brunswick), composé de 105 dispositifs IoT réels et couvrant 33 types d'attaques regroupées en 7 familles.

Lien officiel : [https://www.unb.ca/cic/datasets/iotdataset-2023.html](https://www.unb.ca/cic/datasets/iotdataset-2023.html)

