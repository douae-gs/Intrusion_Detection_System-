from dash import html

from components import sidebar, page_header, card
from config import COLORS


def layout(username="admin", role="Administrateur Sécurité SOC"):
    return html.Div(
        [
            sidebar("/apropos", username, role),
            html.Div(
                [
                    page_header("À propos du projet", "Détection d'intrusions IoT en temps réel via LLMs et Deep Learning"),
                    html.Div(
                        [
                            card(
                                "Contexte",
                                html.P(
                                    "Ce projet de fin d'année (PFA) développe un système capable d'analyser "
                                    "les flux de données de dispositifs IoT d'un réseau domestique ou industriel "
                                    "et de détecter automatiquement les comportements suspects ou les attaques "
                                    "(malwares, botnets, spoofing). Le système combine un modèle de Deep Learning "
                                    "hybride (GRU + LSTM) pour l'analyse séquentielle du trafic réseau, et un LLM "
                                    "pour générer des alertes compréhensibles et des recommandations de sécurité "
                                    "exploitables par un opérateur SOC.",
                                    style={"fontSize": "13.5px", "lineHeight": "1.7"},
                                    className="text-secondary",
                                ),
                            ),
                            card(
                                "Équipe",
                                html.Div(
                                    [
                                        html.Div("Nassira Amhaoui", style={"fontSize": "14px", "fontWeight": "600"}, className="text-primary"),
                                        html.Div("Douae Gasmi", style={"fontSize": "14px", "fontWeight": "600", "marginTop": "6px"}, className="text-primary"),
                                    ]
                                ),
                            ),
                        ],
                        className="grid-2",
                    ),
                    html.Div(
                        card(
                            "Pipeline du projet",
                            html.Div(
                                [
                                    _etape("1", "Prétraitement", "Filtrage et équilibrage du dataset CICIoT2023 par famille d'attaque (Preprocessing.ipynb)"),
                                    _etape("2", "Stabilisation & SMOTE", "Encodage des labels, standardisation et sur-échantillonnage des classes minoritaires (Stabilizing_and_SMOTE.ipynb)"),
                                    _etape("3", "Entraînement hybride", "Modèle GRU + LSTM entraîné sur 50 epochs, 88.65% d'accuracy finale (Training_hybride.ipynb)"),
                                    _etape("4", "Capture temps réel", "Capture Scapy avec agrégation par flux (5-tuple) et fenêtrage temporel (ids_temps_reel.py)"),
                                    _etape("5", "Enrichissement LLM", "Génération d'alertes contextualisées via Groq/Llama-3.3, avec mode secours local (llm_alert.py)"),
                                    _etape("6", "Dashboard", "Visualisation SOC temps réel et investigation des incidents (ce dashboard)"),
                                ],
                                style={"display": "flex", "flexDirection": "column", "gap": "2px"},
                            ),
                        ),
                        className="mt-24",
                    ),
                    html.Div(
                        card(
                            "Technologies utilisées",
                            html.Div(
                                [_tech_badge(t) for t in [
                                    "Python", "PyTorch", "Scapy", "Dash / Plotly", "SQLite",
                                    "Groq API (Llama-3.3)", "scikit-learn", "imbalanced-learn (SMOTE)",
                                ]],
                                style={"display": "flex", "flexWrap": "wrap", "gap": "8px"},
                            ),
                        ),
                        className="mt-24",
                    ),
                    html.Div(
                        card(
                            "Limites connues",
                            html.Ul(
                                [
                                    html.Li(
                                        "La classe Injection a été retirée du périmètre d'étude : trop minoritaire "
                                        "dans le dataset source (~7 300 échantillons après filtrage) pour permettre "
                                        "une généralisation fiable. Le modèle classe désormais sur 6 familles "
                                        "(BenignTraffic, DDoS, DoS, Mirai, Recon, Spoofing).",
                                        style={"marginBottom": "8px"},
                                    ),
                                    html.Li(
                                        "Les features dérivées Magnitude, Radius, Covariance, Variance et Weight, "
                                        "spécifiques à la construction originale du dataset CICIoT2023, ne peuvent pas "
                                        "être recalculées à l'identique en capture live faute du script de génération "
                                        "original ; elles sont fixées à 0 dans ids_temps_reel.py.",
                                        style={"marginBottom": "8px"},
                                    ),
                                    html.Li(
                                        "Le trafic MQTT (ports 1883/8883) est détecté mais non utilisé par le modèle, "
                                        "ce protocole n'étant pas isolé comme feature dédiée dans CICIoT2023.",
                                    ),
                                ],
                                style={"fontSize": "13px", "lineHeight": "1.6", "paddingLeft": "18px"},
                                className="text-secondary",
                            ),
                        ),
                        className="mt-24",
                    ),
                ],
                className="main-content",
            ),
        ],
        className="app-shell",
    )


def _etape(num, titre, desc):
    return html.Div(
        [
            html.Div(
                num,
                style={
                    "width": "26px", "height": "26px", "borderRadius": "8px",
                    "backgroundColor": "rgba(51, 214, 224, 0.12)", "color": COLORS["accent_cyan"],
                    "display": "flex", "alignItems": "center", "justifyContent": "center",
                    "fontSize": "12px", "fontWeight": "700", "flexShrink": "0",
                },
            ),
            html.Div(
                [
                    html.Div(titre, style={"fontSize": "13.5px", "fontWeight": "600"}, className="text-primary"),
                    html.Div(desc, style={"fontSize": "12.5px", "marginTop": "2px"}, className="text-secondary"),
                ]
            ),
        ],
        style={"display": "flex", "gap": "12px", "padding": "10px 0", "borderBottom": f"1px solid {COLORS['border']}"},
    )


def _tech_badge(label):
    return html.Span(
        label,
        style={
            "fontSize": "12px", "padding": "5px 12px", "borderRadius": "16px",
            "backgroundColor": "var(--bg-secondary)", "border": f"1px solid {COLORS['border']}",
        },
        className="text-secondary",
    )