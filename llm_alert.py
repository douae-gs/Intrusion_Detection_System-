import os
import json
from dotenv import load_dotenv

# Chargement du fichier .env
load_dotenv()

# Récupération de la clé API
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

_client = None
_mode_secours = True

# --- BLOC DE DIAGNOSTIC DE LA CONSOLE ---
print("\n" + "="*40)
print("=== DIAGNOSTIC INITIALISATION GROQ ===")
print("="*40)

if GROQ_API_KEY:
    # On affiche les 12 premiers caractères pour des raisons de sécurité
    print(f"[DEBUG] Clé trouvée dans le .env ! Début de la clé : {GROQ_API_KEY[:12]}...")
    if GROQ_API_KEY.startswith("gsk_"):
        try:
            from groq import Groq
            _client = Groq(api_key=GROQ_API_KEY)
            _mode_secours = False
            print("[OK] Client Groq initialisé avec succès. Mode LLM ACTIF.")
        except ImportError:
            _mode_secours = True
            print("[ERREUR] Impossible d'importer 'groq'. Lancez : pip install groq")
    else:
        print("[ERREUR] La clé dans le .env ne commence pas par 'gsk_'. Format invalide.")
else:
    print("[ERREUR] Aucune clé GROQ_API_KEY trouvée par os.getenv().")
    print("[CONSEIL] Vérifiez que le fichier s'appelle exactement '.env' (sans .txt à la fin).")

print("="*40 + "\n")
# --- FIN DU BLOC DE DIAGNOSTIC ---


def mode_actuel():
    """Retourne le mode actif pour l'affichage des badges sur le Dashboard."""
    return "secours" if _mode_secours else "llm"


def alerte_secours(type_attaque, confiance):
    """Garantit un dictionnaire de repli propre avec des clés standardisées si l'API échoue."""
    gravite = "Critique" if type_attaque in ["DDoS", "DoS", "Mirai"] else "Élevé" if type_attaque != "BenignTraffic" else "Faible"
    recommandations_par_type = {
        "DDoS": [
            "Isoler immédiatement l'équipement IoT cible ou le segment réseau affecté.",
            "Activer le rate-limiting / scrubbing sur le pare-feu ou le load balancer.",
            "Vérifier la disponibilité des services critiques en aval.",
        ],
        "DoS": [
            "Isoler la source identifiée si elle est interne au réseau.",
            "Appliquer une règle de limitation de débit (rate-limit) sur le port ciblé.",
        ],
        "Mirai": [
            "Isoler immédiatement l'équipement IoT cible du réseau.",
            "Changer les identifiants par défaut (Telnet/SSH) de l'appareil concerné.",
            "Inspecter la capture PCAP avec Wireshark pour confirmer le pattern Mirai."
        ],
        "Spoofing": [
            "Vérifier la cohérence des tables ARP / DNS sur le segment concerné.",
            "Isoler l'hôte source suspecté.",
        ],
    }
    return {
        "titre": f"Alerte Système : Détection de {type_attaque} (Secours)",
        "gravite": gravite,
        "description": f"Le modèle hybride (GRU+LSTM) a détecté un comportement correspondant à {type_attaque} avec une confiance de {confiance:.1%}.",
        "recommandations": recommandations_par_type.get(type_attaque, ["Isoler l'équipement concerné.", "Inspecter le trafic réseau."])
    }


def generer_alerte(type_attaque, confiance, details=None):
    """Envoie l'incident à Llama-3.3 si la clé est valide, sinon utilise la fonction de secours."""
    details = details or {}

    if _mode_secours or _client is None:
        return alerte_secours(type_attaque, confiance)

    prompt = f"""Tu es un expert cyber pour un SOC. Analyse cet incident détecté par notre IDS hybride.
Incident :
- Menace : {type_attaque}
- Confiance : {confiance:.1%}
- Caractéristiques : {json.dumps(details, ensure_ascii=False)}

Génère une réponse STRICTEMENT au format JSON suivant, sans texte d'introduction ni de conclusion, et sans balises markdown de code.
Chaque recommandation doit être une chaîne de caractères simple (une phrase).

Structure JSON attendue :
{{
  "titre": "Alerte de Sécurité : Détection d'une attaque {type_attaque}",
  "gravite": "Critique",
  "description": "Description détaillée de la menace.",
  "recommandations": [
    "Action immediate 1",
    "Action immediate 2",
    "Action immediate 3"
  ]
}}"""

    try:
        response = _client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": "Tu es un analyste SOC expert. Tu réponds exclusivement en JSON pur, sans markdown, sans dictionnaire imbriqué dans la liste des recommandations."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=600,
            temperature=0.2,
        )
        texte = response.choices[0].message.content.strip()

        # Nettoyage des balises markdown si le modèle en ajoute malgré tout
        if "```json" in texte:
            texte = texte.split("```json")[1].split("```")[0]
        elif "```" in texte:
            texte = texte.split("```")[1].split("```")[0]

        data = json.loads(texte.strip())
        
        return {
            "titre": data.get("titre") or f"Alerte de Sécurité : {type_attaque}",
            "gravite": data.get("gravite") or "Élevé",
            "description": data.get("description") or "Description indisponible.",
            "recommandations": data.get("recommandations") or []
        }

    except Exception as e:
        print(f"[Erreur Groq] Incident durant la requête live, repli secours : {e}")
        return alerte_secours(type_attaque, confiance)
