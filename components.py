from dash import html, dcc
from config import SEVERITY_COLORS

NAV_ITEMS = [
    {"path": "/overview", "label": "Vue d'ensemble", "icon": "◈"},
    {"path": "/monitoring", "label": "Monitoring temps réel", "icon": "◉"},
    {"path": "/alertes", "label": "Alertes & investigation", "icon": "⚠"},
    {"path": "/analyse-csv", "label": "Analyse de fichier", "icon": "▤"},
    {"path": "/performance", "label": "Performance du modèle", "icon": "◬"},
    {"path": "/apropos", "label": "À propos du projet", "icon": "ⓘ"},
]

PROFILE_PATH = "/profil"


def sidebar(current_path, username="admin", role="Administrateur Sécurité SOC", nb_alertes_recentes=0):
    nav_links = []
    for item in NAV_ITEMS:
        is_active = current_path == item["path"]
        badge = None
        if item["path"] == "/alertes" and nb_alertes_recentes > 0:
            badge = html.Span(str(nb_alertes_recentes), className="nav-badge")
        nav_links.append(
            dcc.Link(
                [
                    html.Span(item["icon"], className="icon"),
                    html.Span(item["label"]),
                    badge,
                ],
                href=item["path"],
                className=f"nav-link{' active' if is_active else ''}",
            )
        )

    initials = username[:2].upper() if username else "??"

    return html.Div(
        [
            html.Div(
                [
                    html.Div("◆", className="brand-icon"),
                    html.Span("IoT Guard", className="brand-text"),
                ],
                className="brand",
            ),
            html.Div("Système de Détection d'Intrusions IoT", className="brand-subtitle"),
            html.Div("Navigation", className="nav-section-label"),
            *nav_links,
            html.Div(
                [
                    dcc.Link(
                        html.Div(
                            [
                                html.Div(initials, className="user-avatar"),
                                html.Div(
                                    [
                                        html.Div(username, className="user-name"),
                                        html.Div(role, className="user-role"),
                                    ]
                                ),
                            ],
                            className="user-row",
                        ),
                        href=PROFILE_PATH,
                        style={"textDecoration": "none", "color": "inherit"},
                    ),
                    html.Button("Se déconnecter", id="btn-logout", className="logout-btn", n_clicks=0),
                ],
                className="sidebar-footer",
            ),
        ],
        className="sidebar",
    )


def page_header(title, subtitle=None, live=False):
    children_right = []
    if live:
        children_right.append(
            html.Div(
                [
                    html.Span(className="live-dot"),
                    html.Span("Capture active"),
                ],
                className="live-indicator",
            )
        )
    return html.Div(
        [
            html.Div(
                [
                    html.H1(title, className="page-title"),
                    html.P(subtitle, className="page-subtitle") if subtitle else None,
                ]
            ),
            html.Div(children_right) if children_right else None,
        ],
        className="page-header",
    )


def kpi_card(label, value, icon=None, accent_color="#33D6E0", delta=None, delta_direction="neutral"):
    children = [
        html.Div(className="kpi-accent-bar", style={"backgroundColor": accent_color}),
        html.Div(
            [html.Span(icon, style={"fontSize": "13px"}) if icon else None, html.Span(label)],
            className="kpi-label",
        ),
        html.Div(value, className="kpi-value"),
    ]
    if delta:
        children.append(html.Div(delta, className=f"kpi-delta {delta_direction}"))
    return html.Div(children, className="kpi-card")


def severity_badge(gravite):
    cls_map = {
        "Critique": "badge-critique",
        "Élevé": "badge-eleve",
        "Moyen": "badge-moyen",
        "Faible": "badge-faible",
    }
    cls = cls_map.get(gravite, "badge-faible")
    return html.Span(gravite, className=f"badge-pill {cls}")


def card(title, children, extra_class=""):
    content = []
    if title:
        content.append(html.Div(title, className="card-title"))
    content.append(children if isinstance(children, list) else children)
    return html.Div(content, className=f"card-base {extra_class}")


def empty_state(message):
    return html.Div(message, className="empty-state")
