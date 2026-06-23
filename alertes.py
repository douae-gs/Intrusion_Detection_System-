import json
from datetime import datetime

from dash import html, dcc

from components import sidebar, page_header, card, severity_badge, empty_state
from config import ATTACK_FAMILIES, COLORS, FAMILY_COLORS
import db
import llm_alert as alert  


def layout(username="admin", role="Administrateur Sécurité SOC"):
    return html.Div(
        [
            sidebar("/alertes", username, role),
            html.Div(
                [
                    page_header(
                        "Alertes & investigation",
                        "Historique des alertes générées par le moteur IDS, enrichies par le module LLM",
                    ),
                    html.Div(
                        [
                            dcc.Dropdown(
                                id="filtre-famille",
                                options=[{"label": "Toutes les familles", "value": "all"}]
                                + [{"label": f, "value": f} for f in ATTACK_FAMILIES],
                                value="all",
                                clearable=False,
                                className="dropdown-dark",
                                style={"width": "220px"},
                            ),
                            dcc.Dropdown(
                                id="filtre-gravite",
                                options=[{"label": "Toutes les gravités", "value": "all"}]
                                + [{"label": g, "value": g} for g in ["Critique", "Élevé", "Moyen", "Faible"]],
                                value="all",
                                clearable=False,
                                className="dropdown-dark",
                                style={"width": "200px"},
                            ),
                        ],
                        style={"display": "flex", "gap": "12px", "marginBottom": "20px"},
                    ),
                    html.Div(
                        [
                            html.Div(id="alertes-liste-container", style={"flex": "1.3", "minWidth": "0"}),
                            html.Div(id="alerte-detail-container", style={"flex": "1"}),
                        ],
                        style={"display": "flex", "gap": "20px", "alignItems": "flex-start"},
                    ),
                    dcc.Store(id="alerte-selectionnee-id"),
                ],
                className="main-content",
            ),
        ],
        className="app-shell",
    )


def render_alertes_liste(famille=None, gravite=None, selected_id=None):
    famille = None if famille == "all" else famille
    gravite = None if gravite == "all" else gravite
    alertes = db.get_alertes(limit=100, famille=famille, gravite=gravite)

    if not alertes:
        return card("Alertes récentes", empty_state("Aucune alerte ne correspond aux filtres sélectionnés."))

    rows = []
    for a in alertes:
        try:
            ts = datetime.fromisoformat(a["timestamp"]).strftime("%d/%m %H:%M:%S")
        except (ValueError, TypeError):
            ts = a["timestamp"]
        is_selected = selected_id == a["id"]
        rows.append(
            html.Tr(
                [
                    html.Td(ts),
                    html.Td(
                        html.Span(
                            a["type_attaque"],
                            style={"color": FAMILY_COLORS.get(a["type_attaque"], COLORS["text_secondary"]), "fontWeight": "600"},
                        )
                    ),
                    html.Td(severity_badge(a["gravite"])),
                    html.Td(f"{a['confiance']:.1%}"),
                    html.Td(a.get("ip_source") or "—"),
                ],
                id={"type": "alerte-row", "index": a["id"]},
                style={"backgroundColor": "rgba(51, 214, 224, 0.07)"} if is_selected else {},
                n_clicks=0,
            )
        )

    table = html.Div(
        html.Table(
            [
                html.Thead(
                    html.Tr(
                        [html.Th("Horodatage"), html.Th("Type"), html.Th("Gravité"), html.Th("Confiance"), html.Th("IP source")]
                    )
                ),
                html.Tbody(rows),
            ],
            className="soc-table",
        ),
        className="soc-table-wrapper",
    )

    return card(f"Alertes récentes ({len(alertes)})", table)


def render_alerte_detail(alerte_id):
    if alerte_id is None:
        return card(None, empty_state("Sélectionnez une alerte dans la liste pour voir le rapport détaillé."))

    a = db.get_alerte_by_id(alerte_id)
    if a is None:
        return card(None, empty_state("Alerte introuvable."))

    # --- ENRICHISSEMENT DIRECT ET DYNAMIQUE PAR LE LLM ---
    details_techniques = {
        "ip_source": a.get("ip_source") or "—",
        "ip_destination": a.get("ip_destination") or "—",
        "port_destination": str(a.get("port_destination") or "—"),
        "protocole": a.get("protocole") or "—",
        "nb_paquets": str(a.get("nb_paquets") or "—"),
        "duree_flux": f"{a.get('duree_flux') or 0:.2f}s"
    }

    analyse_dynamique = alert.generer_alerte(
        type_attaque=a["type_attaque"],
        confiance=a["confiance"],
        details=details_techniques
    )

    titre_affiche = analyse_dynamique.get("titre") or f"Détection de {a['type_attaque']}"
    gravite_affiche = analyse_dynamique.get("gravite") or a["gravite"]
    description_affiche = analyse_dynamique.get("description") or "Aucune description enrichie disponible."
    recommandations_brutes = analyse_dynamique.get("recommandations", [])
    
   
    recommandations_nettoyees = []
    for item in recommandations_brutes:
        if isinstance(item, dict):
            # Extrait 'description' si présent, sinon prend la clé 'texte', ou la première valeur
            texte_rec = item.get("description") or item.get("text") or list(item.values())[0]
            recommandations_nettoyees.append(str(texte_rec))
        else:
            recommandations_nettoyees.append(str(item))

    mode_tag_cls = "llm" if alert.mode_actuel() == "llm" else "secours"

    reco_items = [
        html.Div(
            [html.Div(str(i + 1), className="recommandation-num"), html.Div(r)],
            className="recommandation-item",
        )
        for i, r in enumerate(recommandations_nettoyees) # Utilisation de la liste nettoyée
    ]

    detail_content = html.Div(
        [
            html.Div(
                [
                    severity_badge(gravite_affiche),
                    html.Span(
                        "Mode secours (local)" if mode_tag_cls == "secours" else "Analyse LLM",
                        className=f"mode-tag {mode_tag_cls}",
                        style={"marginLeft": "10px"},
                    ),
                ],
                style={"marginBottom": "12px"},
            ),
            html.H3(
                titre_affiche,
                style={"fontSize": "16px", "marginBottom": "14px"},
                className="text-primary",
            ),
            html.P(
                description_affiche,
                style={"fontSize": "13px", "lineHeight": "1.6", "marginBottom": "18px"},
                className="text-secondary",
            ),
            html.Div(
                [
                    html.Div("Détails techniques", style={"fontSize": "12px", "fontWeight": "600", "marginBottom": "10px", "textTransform": "uppercase", "letterSpacing": "0.05em"}, className="text-muted"),
                    html.Div(
                        [
                            html.Div([html.Span("IP source : ", className="text-muted"), a.get("ip_source") or "—"]),
                            html.Div([html.Span("IP destination : ", className="text-muted"), a.get("ip_destination") or "—"]),
                            html.Div([html.Span("Port destination : ", className="text-muted"), str(a.get("port_destination") or "—")]),
                            html.Div([html.Span("Protocole : ", className="text-muted"), a.get("protocole") or "—"]),
                            html.Div([html.Span("Paquets agrégés : ", className="text-muted"), str(a.get("nb_paquets") or "—")]),
                            html.Div([html.Span("Durée du flux : ", className="text-muted"), f"{a.get('duree_flux') or 0:.2f}s"]),
                        ],
                        style={"fontSize": "12.5px", "fontFamily": "JetBrains Mono, monospace", "display": "flex", "flexDirection": "column", "gap": "6px"},
                        className="text-secondary",
                    ),
                ],
                style={"marginBottom": "18px", "paddingBottom": "18px", "borderBottom": f"1px solid {COLORS['border']}"},
            ),
            html.Div(
                [
                    html.Div("Recommandations", style={"fontSize": "12px", "fontWeight": "600", "marginBottom": "4px", "textTransform": "uppercase", "letterSpacing": "0.05em"}, className="text-muted"),
                    html.Div(reco_items) if reco_items else empty_state("Aucune recommandation disponible."),
                ]
            ),
        ]
    )

    return card("Rapport d'incident", detail_content)
