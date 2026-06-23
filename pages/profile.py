from datetime import datetime

from dash import html, dcc

from components import sidebar, page_header, card, kpi_card, empty_state
from config import COLORS
import db


def layout(username="admin", role="Administrateur Sécurité SOC"):
    user = db.get_utilisateur(username) or {}
    stats = db.get_stats_utilisateur(username, depuis_jours=30)

    return html.Div(
        [
            sidebar("/profil", username, role),
            html.Div(
                [
                    page_header(
                        "Mon profil",
                        "Informations de compte, sécurité et activité opérateur",
                    ),
                    html.Div(id="profil-feedback-zone"),
                    html.Div(
                        [
                            html.Div(_carte_identite(user, username, role), style={"flex": "1"}),
                            html.Div(_carte_stats(stats), style={"flex": "1"}),
                        ],
                        className="grid-2",
                    ),
                    html.Div(_carte_infos_compte(user, username), className="mt-24"),
                    html.Div(_carte_securite(), className="mt-24"),
                ],
                className="main-content",
            ),
        ],
        className="app-shell",
    )


def _format_date(iso_str, fallback="Jamais"):
    if not iso_str:
        return fallback
    try:
        return datetime.fromisoformat(iso_str).strftime("%d/%m/%Y à %H:%M")
    except (ValueError, TypeError):
        return iso_str


def _carte_identite(user, username, role):
    initials = username[:2].upper() if username else "??"
    nom_complet = user.get("nom_complet") or username.capitalize()
    membre_depuis = _format_date(user.get("date_creation"), fallback="—")

    return card(
        None,
        html.Div(
            [
                html.Div(
                    initials,
                    style={
                        "width": "72px", "height": "72px", "borderRadius": "50%",
                        "background": f"linear-gradient(135deg, {COLORS['accent_cyan']}, {COLORS['accent_blue']})",
                        "color": "#06121F", "display": "flex", "alignItems": "center",
                        "justifyContent": "center", "fontSize": "26px", "fontWeight": "700",
                        "marginBottom": "16px",
                    },
                ),
                html.Div(nom_complet, style={"fontSize": "18px", "fontWeight": "700"}, className="text-primary"),
                html.Div(f"@{username}", style={"fontSize": "13px", "fontFamily": "JetBrains Mono, monospace", "marginTop": "2px"}, className="text-muted"),
                html.Div(
                    user.get("role") or role,
                    style={
                        "fontSize": "11.5px", "fontWeight": "600", "color": COLORS["accent_cyan"],
                        "backgroundColor": "rgba(51, 214, 224, 0.1)", "padding": "4px 12px",
                        "borderRadius": "16px", "marginTop": "12px", "display": "inline-block",
                    },
                ),
                html.Div(
                    [
                        html.Div(
                            [html.Span("Membre depuis : ", className="text-muted"), membre_depuis],
                            style={"fontSize": "12.5px", "marginTop": "16px"},
                        ),
                        html.Div(
                            [html.Span("Dernière connexion : ", className="text-muted"), _format_date(user.get("derniere_connexion"))],
                            style={"fontSize": "12.5px", "marginTop": "6px"},
                        ),
                    ],
                    className="text-secondary",
                ),
            ],
            style={"display": "flex", "flexDirection": "column", "alignItems": "center", "textAlign": "center", "padding": "10px 0"},
        ),
    )


def _carte_stats(stats):
    return html.Div(
        [
            html.Div("Activité (30 derniers jours)", className="card-title"),
            html.Div(
                [
                    kpi_card(
                        "Alertes système (période)",
                        str(stats.get("total_alertes_periode", 0)),
                        icon="⚠", accent_color=COLORS["accent_cyan"],
                    ),
                    kpi_card(
                        "Dont critiques",
                        str(stats.get("alertes_critiques_periode", 0)),
                        icon="◉", accent_color=COLORS["critical"],
                    ),
                ],
                style={"display": "grid", "gridTemplateColumns": "1fr 1fr", "gap": "14px"},
            ),
            html.P(
                "Statistiques globales du moteur IDS sur la période. Le suivi nominatif "
                "par opérateur (alertes traitées individuellement) n'est pas encore "
                "tracé en base et pourra être ajouté ultérieurement.",
                style={"fontSize": "11.5px", "marginTop": "14px", "fontStyle": "italic", "lineHeight": "1.5"},
                className="text-muted",
            ),
        ],
        className="card-base",
    )


def _carte_infos_compte(user, username):
    return card(
        "Informations du compte",
        html.Div(
            [
                html.Div(
                    [
                        html.Label("Nom complet", className="form-label"),
                        dcc.Input(
                            id="profil-input-nom",
                            type="text",
                            value=user.get("nom_complet") or "",
                            placeholder="Votre nom complet",
                            className="form-input",
                        ),
                    ]
                ),
                html.Div(
                    [
                        html.Label("Adresse e-mail", className="form-label"),
                        dcc.Input(
                            id="profil-input-email",
                            type="email",
                            value=user.get("email") or "",
                            placeholder="vous@exemple.com",
                            className="form-input",
                        ),
                    ]
                ),
                html.Div(
                    [
                        html.Label("Identifiant", className="form-label"),
                        dcc.Input(
                            value=username, disabled=True,
                            className="form-input",
                            style={"opacity": "0.55", "cursor": "not-allowed"},
                        ),
                    ]
                ),
                html.Button(
                    "Enregistrer les modifications",
                    id="btn-save-profil",
                    n_clicks=0,
                    className="btn-primary",
                    style={"width": "auto", "padding": "10px 22px", "marginTop": "4px"},
                ),
            ],
            style={"display": "flex", "flexDirection": "column", "gap": "2px", "maxWidth": "420px"},
        ),
    )


def _carte_securite():
    return card(
        "Sécurité — changer le mot de passe",
        html.Div(
            [
                html.Div(
                    [
                        html.Label("Mot de passe actuel", className="form-label"),
                        dcc.Input(id="profil-mdp-actuel", type="password", className="form-input"),
                    ]
                ),
                html.Div(
                    [
                        html.Label("Nouveau mot de passe", className="form-label"),
                        dcc.Input(id="profil-mdp-nouveau", type="password", className="form-input"),
                    ]
                ),
                html.Div(
                    [
                        html.Label("Confirmer le nouveau mot de passe", className="form-label"),
                        dcc.Input(id="profil-mdp-confirmation", type="password", className="form-input"),
                    ]
                ),
                html.Button(
                    "Mettre à jour le mot de passe",
                    id="btn-save-mdp",
                    n_clicks=0,
                    className="btn-secondary",
                    style={"width": "auto", "padding": "10px 22px", "marginTop": "4px"},
                ),
            ],
            style={"display": "flex", "flexDirection": "column", "gap": "2px", "maxWidth": "420px"},
        ),
    )


def feedback_banner(message, success=True):
    return html.Div(
        message,
        style={
            "backgroundColor": "rgba(51, 201, 122, 0.1)" if success else "rgba(240, 68, 92, 0.1)",
            "border": f"1px solid {'rgba(51, 201, 122, 0.3)' if success else 'rgba(240, 68, 92, 0.3)'}",
            "color": COLORS["low"] if success else COLORS["critical"],
            "borderRadius": "8px", "padding": "10px 14px", "fontSize": "13px",
            "marginBottom": "18px",
        },
    )