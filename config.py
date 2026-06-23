
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

LIVE_STATUS_PATH = os.path.join(RESULTS_DIR, "live_status.json")
ALERTS_DB_PATH = os.path.join(RESULTS_DIR, "alerts.db")
TRAINING_HISTORY_PATH = os.path.join(RESULTS_DIR, "training_history.json")

os.makedirs(RESULTS_DIR, exist_ok=True)

VALID_USERS = {
    "admin": {"password": "admin123", "role": "Administrateur Sécurité SOC"},
}

ATTACK_FAMILIES = ["DDoS", "DoS", "Mirai", "Recon", "Spoofing"]
BENIGN_LABEL = "BenignTraffic"
ALL_CLASSES = [BENIGN_LABEL] + ATTACK_FAMILIES

SEVERITY_MAP = {
    "DDoS": "Critique",
    "DoS": "Critique",
    "Mirai": "Critique",
    "Recon": "Élevé",
    "Spoofing": "Élevé",
    "BenignTraffic": "Faible",
}
COLORS = {
    "bg_primary": "#0B1120",
    "bg_secondary": "#111A2E",
    "bg_card": "#15213A",
    "bg_card_hover": "#1A2740",
    "border": "#22304D",
    "text_primary": "#E7ECF7",
    "text_secondary": "#8C9AB8",
    "text_muted": "#5A6A8A",
    "accent_cyan": "#33D6E0",
    "accent_blue": "#3B82F6",
    "accent_indigo": "#6366F1",
    "critical": "#F0445C",
    "high": "#F2A93B",
    "medium": "#E0C341",
    "low": "#33C97A",
    "benign": "#33C97A",
}

SEVERITY_COLORS = {
    "Critique": COLORS["critical"],
    "Élevé": COLORS["high"],
    "Moyen": COLORS["medium"],
    "Faible": COLORS["low"],
}

FAMILY_COLORS = {
    "BenignTraffic": COLORS["benign"],
    "DDoS": COLORS["critical"],
    "DoS": "#D9534F",
    "Mirai": "#B83280",
    "Recon": COLORS["accent_blue"],
    "Spoofing": COLORS["high"],
}

COLORS_LIGHT = {
    "bg_card": "#FFFFFF",
    "border": "#CBD5E1",
    "text_primary": "#0F172A",
    "text_secondary": "#334155",
    "text_muted": "#64748B",
    "accent_cyan": "#0891B2",
    "critical": "#DC2626",
    "high": "#D97706",
    "medium": "#B45309",
    "low": "#15803D",
}

REFRESH_INTERVAL_MS = 2000  # fréquence de rafraîchissement du monitoring live
