
import sqlite3
import json
import os
import hashlib
import secrets
from datetime import datetime, timedelta

from config import ALERTS_DB_PATH

try:
    from config import VALID_USERS
except ImportError:
    VALID_USERS = {}


def get_connection():
    conn = sqlite3.connect(ALERTS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _hash_password(password, salt=None):
    """PBKDF2-HMAC-SHA256, salé. Retourne (hash_hex, salt_hex)."""
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), 100_000)
    return digest.hex(), salt


def init_db():
    """Crée les tables si elles n'existent pas encore.
    Appelée au démarrage du dashboard ET au démarrage de ids_temps_reel.py
    (idempotent grâce à IF NOT EXISTS) pour que l'un ou l'autre puisse
    démarrer en premier sans erreur.
    """
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alertes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            type_attaque TEXT NOT NULL,
            gravite TEXT NOT NULL,
            confiance REAL NOT NULL,
            ip_source TEXT,
            ip_destination TEXT,
            port_destination INTEGER,
            protocole TEXT,
            nb_paquets INTEGER,
            duree_flux REAL,
            titre_llm TEXT,
            description_llm TEXT,
            recommandations_llm TEXT,
            statut TEXT DEFAULT 'Nouvelle'
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_alertes_timestamp ON alertes(timestamp)
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS utilisateurs (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            password_salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'Analyste SOC',
            nom_complet TEXT,
            email TEXT,
            date_creation TEXT NOT NULL,
            derniere_connexion TEXT
        )
    """)
    conn.commit()

  
    existing = conn.execute("SELECT COUNT(*) AS c FROM utilisateurs").fetchone()["c"]
    if existing == 0 and VALID_USERS:
        now = datetime.now().isoformat()
        for uname, info in VALID_USERS.items():
            pwd_hash, salt = _hash_password(info.get("password", ""))
            conn.execute("""
                INSERT OR IGNORE INTO utilisateurs (
                    username, password_hash, password_salt, role, nom_complet, date_creation
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (uname, pwd_hash, salt, info.get("role", "Analyste SOC"), uname.capitalize(), now))
        conn.commit()

    conn.close()


def verifier_identifiants(username, password):
   
    conn = get_connection()
    row = conn.execute("SELECT * FROM utilisateurs WHERE username = ?", (username,)).fetchone()
    if row is None:
        conn.close()
        return None

    computed_hash, _ = _hash_password(password, row["password_salt"])
    if computed_hash != row["password_hash"]:
        conn.close()
        return None

    conn.execute(
        "UPDATE utilisateurs SET derniere_connexion = ? WHERE username = ?",
        (datetime.now().isoformat(), username),
    )
    conn.commit()
    conn.close()
    return dict(row)


def get_utilisateur(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM utilisateurs WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_profil(username, nom_complet=None, email=None, role=None):
    """Met à jour les champs de profil fournis (les autres restent inchangés)."""
    champs, valeurs = [], []
    if nom_complet is not None:
        champs.append("nom_complet = ?")
        valeurs.append(nom_complet)
    if email is not None:
        champs.append("email = ?")
        valeurs.append(email)
    if role is not None:
        champs.append("role = ?")
        valeurs.append(role)
    if not champs:
        return False

    valeurs.append(username)
    conn = get_connection()
    conn.execute(f"UPDATE utilisateurs SET {', '.join(champs)} WHERE username = ?", valeurs)
    conn.commit()
    conn.close()
    return True


def changer_mot_de_passe(username, ancien_mdp, nouveau_mdp):
    """Change le mot de passe après vérification de l'ancien.
    Retourne (succès: bool, message: str)."""
    user = verifier_identifiants(username, ancien_mdp)
    if user is None:
        return False, "Mot de passe actuel incorrect."
    if not nouveau_mdp or len(nouveau_mdp) < 6:
        return False, "Le nouveau mot de passe doit contenir au moins 6 caractères."

    pwd_hash, salt = _hash_password(nouveau_mdp)
    conn = get_connection()
    conn.execute(
        "UPDATE utilisateurs SET password_hash = ?, password_salt = ? WHERE username = ?",
        (pwd_hash, salt, username),
    )
    conn.commit()
    conn.close()
    return True, "Mot de passe mis à jour avec succès."


def get_stats_utilisateur(username, depuis_jours=30):
  
    conn = get_connection()
    seuil = (datetime.now() - timedelta(days=depuis_jours)).isoformat()

    total = conn.execute(
        "SELECT COUNT(*) AS c FROM alertes WHERE timestamp >= ?", (seuil,)
    ).fetchone()["c"]

    critiques = conn.execute(
        "SELECT COUNT(*) AS c FROM alertes WHERE timestamp >= ? AND gravite = 'Critique'", (seuil,)
    ).fetchone()["c"]

    conn.close()
    return {"total_alertes_periode": total, "alertes_critiques_periode": critiques}


def inserer_alerte(type_attaque, gravite, confiance, ip_source=None,
                    ip_destination=None, port_destination=None, protocole=None,
                    nb_paquets=None, duree_flux=None, rapport_llm=None):
    """Insère une nouvelle alerte. rapport_llm est le dict retourné par
    generer_alerte() (titre / gravite / description / recommandations)."""
    conn = get_connection()
    recommandations_json = None
    titre = None
    description = None
    if rapport_llm:
        titre = rapport_llm.get("titre")
        description = rapport_llm.get("description")
        recommandations_json = json.dumps(
            rapport_llm.get("recommandations", []), ensure_ascii=False
        )
        gravite = rapport_llm.get("gravite", gravite)

    conn.execute("""
        INSERT INTO alertes (
            timestamp, type_attaque, gravite, confiance, ip_source,
            ip_destination, port_destination, protocole, nb_paquets,
            duree_flux, titre_llm, description_llm, recommandations_llm
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().isoformat(), type_attaque, gravite, confiance, ip_source,
        ip_destination, port_destination, protocole, nb_paquets,
        duree_flux, titre, description, recommandations_json
    ))
    conn.commit()
    conn.close()


def get_alertes(limit=200, depuis_heures=None, famille=None, gravite=None):
    """Récupère les alertes avec filtres optionnels, triées des plus récentes
    aux plus anciennes."""
    conn = get_connection()
    query = "SELECT * FROM alertes WHERE 1=1"
    params = []

    if depuis_heures is not None:
        seuil = (datetime.now() - timedelta(hours=depuis_heures)).isoformat()
        query += " AND timestamp >= ?"
        params.append(seuil)
    if famille:
        query += " AND type_attaque = ?"
        params.append(famille)
    if gravite:
        query += " AND gravite = ?"
        params.append(gravite)

    query += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alerte_by_id(alerte_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM alertes WHERE id = ?", (alerte_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def get_stats_resume(depuis_heures=24):
    """Statistiques agrégées pour les KPIs de la page Overview."""
    conn = get_connection()
    seuil = (datetime.now() - timedelta(hours=depuis_heures)).isoformat()

    total = conn.execute(
        "SELECT COUNT(*) as c FROM alertes WHERE timestamp >= ?", (seuil,)
    ).fetchone()["c"]

    par_famille = conn.execute("""
        SELECT type_attaque, COUNT(*) as c FROM alertes
        WHERE timestamp >= ? GROUP BY type_attaque ORDER BY c DESC
    """, (seuil,)).fetchall()

    par_gravite = conn.execute("""
        SELECT gravite, COUNT(*) as c FROM alertes
        WHERE timestamp >= ? GROUP BY gravite
    """, (seuil,)).fetchall()

    top_ips = conn.execute("""
        SELECT ip_source, COUNT(*) as c FROM alertes
        WHERE timestamp >= ? AND ip_source IS NOT NULL
        GROUP BY ip_source ORDER BY c DESC LIMIT 5
    """, (seuil,)).fetchall()

    conn.close()
    return {
        "total": total,
        "par_famille": {r["type_attaque"]: r["c"] for r in par_famille},
        "par_gravite": {r["gravite"]: r["c"] for r in par_gravite},
        "top_ips": [(r["ip_source"], r["c"]) for r in top_ips],
    }


def get_timeline(depuis_heures=24, intervalle_minutes=30):
    """Renvoie le nombre d'alertes groupées par tranche de temps, pour le
    graphe de timeline de la page Overview."""
    conn = get_connection()
    seuil = (datetime.now() - timedelta(hours=depuis_heures)).isoformat()
    rows = conn.execute("""
        SELECT timestamp, type_attaque FROM alertes WHERE timestamp >= ?
        ORDER BY timestamp ASC
    """, (seuil,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
