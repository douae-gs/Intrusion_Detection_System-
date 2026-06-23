import json
import os
from datetime import datetime

from dash import html, dcc

from components import sidebar, page_header, kpi_card, card, empty_state
from config import COLORS, FAMILY_COLORS, LIVE_STATUS_PATH, REFRESH_INTERVAL_MS
import capture_control


def layout(username="admin", role="Administrateur Sécurité SOC"):
    return html.Div(
        [
            dcc.Interval(id="monitoring-interval", interval=REFRESH_INTERVAL_MS, n_intervals=0),
            dcc.Interval(id="capture-status-fast-interval", interval=2000, n_intervals=0),
            sidebar("/monitoring", username, role),
            html.Div(
                [
                    page_header(
                        "Monitoring réseau et flux en temps réel",
                        "Lecture en direct de l'état du moteur IDS (ids_temps_reel.py)",
                    ),
                    html.Div(
                        [
                            html.Div(id="capture-status-pill"),
                            html.Button(
                                "Démarrer la capture", id="btn-toggle-capture", n_clicks=0,
                                className="btn-primary", style={"width": "auto", "padding": "9px 20px"},
                            ),
                        ],
                        style={"display": "flex", "alignItems": "center", "gap": "14px"},
                    ),
                    html.Div(id="capture-action-feedback", style={"marginTop": "10px"}),
                    html.Div(id="capture-note"),
                    html.Div(id="monitoring-content"),
                ],
                className="main-content card-base mt-24",
            ),
        ],
        className="app-shell",
    )


def render_status_pill():
    status, pid = capture_control.get_status()
    is_running = status == "running"
    return html.Div(
        [
            html.Span(className=f"live-dot{'' if is_running else ' offline'}"),
            html.Span(f"Capture active (PID {pid})" if is_running else "Capture arrêtée"),
        ],
        className="live-indicator",
    )


def render_capture_note():
    status, _ = capture_control.get_status()
    if status == "running":
        return None
    return html.P(
        "Le démarrage ouvrira une invite Windows demandant les droits administrateur "
        "(requis par Scapy pour capturer les paquets réseau).",
        style={"fontSize": "11.5px", "marginTop": "8px", "marginBottom": "0"},
        className="text-muted",
    )


def _read_live_status():
    if not os.path.exists(LIVE_STATUS_PATH):
        return None
    try:
        with open(LIVE_STATUS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _anciennete_label(timestamp_iso):
    try:
        dt = datetime.fromisoformat(timestamp_iso)
        delta = (datetime.now() - dt).total_seconds()
        if delta < 5:
            return "à l'instant"
        return f"il y a {int(delta)}s"
    except (ValueError, TypeError):
        return ""


def render_monitoring_content():
    status = _read_live_status()

    if status is None:
        return html.Div(
            [
                card(
                    None,
                    empty_state(
                        "Aucune donnée live disponible. Lancez ids_temps_reel.py "
                        "sur la machine de capture pour alimenter cette page "
                        "(fichier results/live_status.json introuvable ou invalide)."
                    ),
                )
            ]
        )

    derniere_maj = status.get("derniere_maj", "")
    statut_capture = status.get("statut_capture", "inactif")
    is_offline = (statut_capture != "actif") or (not derniere_maj) or (
        (datetime.now() - datetime.fromisoformat(derniere_maj)).total_seconds() > 30
        if derniere_maj else True
    )

    kpis = html.Div(
        [
            kpi_card(
                "Paquets inspectés (total)",
                f"{status.get('paquets_inspectes_total', 0):,}".replace(",", " "),
                icon="▤", accent_color=COLORS["accent_cyan"],
            ),
            kpi_card(
                "Débit instantané", f"{status.get('paquets_par_seconde', 0):.1f} pkt/s",
                icon="◉", accent_color=COLORS["accent_blue"],
            ),
            kpi_card(
                "Flux actifs (en agrégation)", str(status.get("nb_flux_actifs", 0)),
                icon="◈", accent_color=COLORS["high"],
            ),
            kpi_card(
                "Statut capture",
                "Hors ligne" if is_offline else "Actif",
                icon="●",
                accent_color=COLORS["text_muted"] if is_offline else COLORS["low"],
            ),
        ],
        className="grid-4",
    )

    flux_actifs = status.get("flux_actifs", [])
    flux_rows = []
    for f in flux_actifs:
        flux_rows.append(
            html.Tr(
                [
                    html.Td(f.get("src_ip", "—")),
                    html.Td(f.get("dst_ip", "—")),
                    html.Td(f.get("protocole", "—")),
                    html.Td(str(f.get("nb_paquets", 0))),
                    html.Td(f"{f.get('anciennete_s', 0):.1f}s"),
                ]
            )
        )

    flux_table = html.Div(
        html.Table(
            [
                html.Thead(
                    html.Tr(
                        [
                            html.Th("IP source"), html.Th("IP destination"), html.Th("Protocole"),
                            html.Th("Paquets agrégés"), html.Th("Ancienneté"),
                        ]
                    )
                ),
                html.Tbody(flux_rows) if flux_rows else html.Tbody(
                    html.Tr(html.Td(empty_state("Aucun flux actif."), colSpan=5))
                ),
            ],
            className="soc-table",
        ),
        className="soc-table-wrapper",
    )

    predictions = status.get("dernieres_predictions", [])
    pred_rows = []
    for p in predictions:
        famille = p.get("prediction", "BenignTraffic")
        couleur = FAMILY_COLORS.get(famille, COLORS["text_muted"])
        is_attack = famille != "BenignTraffic"
        pred_rows.append(
            html.Tr(
                [
                    html.Td(p.get("horodatage", "—")),
                    html.Td(
                        html.Span(
                            famille,
                            style={
                                "color": couleur, "fontWeight": "600" if is_attack else "400",
                            },
                        )
                    ),
                    html.Td(f"{p.get('confiance', 0):.1%}"),
                    html.Td(p.get("src_ip", "—")),
                ],
                className="row-new" if predictions.index(p) == 0 else "",
            )
        )

    pred_table = html.Div(
        html.Table(
            [
                html.Thead(
                    html.Tr(
                        [html.Th("Horodatage"), html.Th("Prédiction"), html.Th("Confiance"), html.Th("IP source")]
                    )
                ),
                html.Tbody(pred_rows) if pred_rows else html.Tbody(
                    html.Tr(html.Td(empty_state("Aucune classification récente."), colSpan=4))
                ),
            ],
            className="soc-table",
        ),
        className="soc-table-wrapper",
    )

    return html.Div(
        [
            kpis,
            html.Div(
                [
                    card("Flux en cours d'agrégation", flux_table),
                    card("Dernières classifications du modèle hybride", pred_table),
                ],
                className="grid-2 mt-24",
            ),
        ]
    )