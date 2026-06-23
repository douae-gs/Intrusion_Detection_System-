
import dash
from dash import html, dcc, Input, Output, State, ALL, ctx, clientside_callback
import dash_bootstrap_components as dbc

from config import REFRESH_INTERVAL_MS, COLORS, COLORS_LIGHT
import db as db_module
import capture_control

from pages import login, overview, monitoring, alertes, analyse_csv, performance, apropos, profile

db_module.init_db()

app = dash.Dash(
    __name__,
    suppress_callback_exceptions=True,
    title="IoT Guard — Détection d'Intrusions IoT",
    update_title=None,
)
server = app.server

app.layout = html.Div(
    [
        dcc.Location(id="url", refresh=False),
        dcc.Store(id="session-store", storage_type="session"),
        dcc.Store(id="capture-refresh-trigger", data=0),
        dcc.Store(
            id="theme-colors-store",
            data={
                "dark": {
                    "bg_card": COLORS["bg_card"],
                    "border": COLORS["border"],
                    "text_primary": COLORS["text_primary"],
                    "text_secondary": COLORS["text_secondary"],
                    "text_muted": COLORS["text_muted"],
                    "accent_cyan": COLORS["accent_cyan"],
                    "critical": COLORS["critical"],
                    "high": COLORS["high"],
                    "medium": COLORS["medium"],
                    "low": COLORS["low"],
                },
                "light": COLORS_LIGHT,
            },
        ),
        dcc.Store(id="chart-repaint-ack"),
        # Repeint périodiquement les graphes Plotly nouvellement injectés dans
        # le DOM (changement de page, rafraîchissement overview/monitoring) avec
        # les couleurs du thème actif — nécessaire car Plotly génère du SVG
        # statique côté serveur dans les couleurs du thème sombre par défaut.
        dcc.Interval(id="chart-repaint-watcher", interval=600, n_intervals=0),
        
        # COMMUTATEUR FIXE DE CHANGEMENT DE THÈME (Haut à Droite)
        html.Button(
            [
                html.Span(
                    [
                        # Icône lune (visible en thème sombre, à gauche du curseur)
                        html.Img(
                            src="data:image/svg+xml;utf8,"
                                "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' "
                                "width='13' height='13' fill='none' stroke='%2333D6E0' "
                                "stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'%3E"
                                "%3Cpath d='M20.354 15.354A9 9 0 0 1 8.646 3.646 9.003 9.003 0 1 0 20.354 15.354Z'/%3E"
                                "%3C/svg%3E",
                            className="theme-toggle-icon theme-toggle-icon--moon",
                            alt="",
                        ),
                        # Icône soleil (visible en thème clair, à droite du curseur)
                        html.Img(
                            src="data:image/svg+xml;utf8,"
                                "%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' "
                                "width='13' height='13' fill='none' stroke='%235A6A8A' "
                                "stroke-width='1.8' stroke-linecap='round'%3E"
                                "%3Ccircle cx='12' cy='12' r='4.2'/%3E"
                                "%3Cpath d='M12 2.5v2.2M12 19.3v2.2M4.93 4.93l1.56 1.56M17.51 17.51l1.56 1.56"
                                "M2.5 12h2.2M19.3 12h2.2M4.93 19.07l1.56-1.56M17.51 6.49l1.56-1.56'/%3E"
                                "%3C/svg%3E",
                            className="theme-toggle-icon theme-toggle-icon--sun",
                            alt="",
                        ),
                        html.Span(className="theme-toggle-knob"),
                    ],
                    className="theme-toggle-track",
                ),
                html.Span("Mode sombre", id="theme-toggle-label", className="theme-toggle-label"),
            ],
            id="theme-toggle",
            className="theme-toggle-btn",
            n_clicks=0,
            **{"data-theme-state": "dark"}  # Requis pour forcer l'état initial côté DOM
        ),
        
        html.Div(id="page-content"),
    ]
)

clientside_callback(
    """
    function(n_clicks, colorsStore) {
        if (!window.repaintPlotlyCharts) {
            window.repaintPlotlyCharts = function(themeKey) {
                const colors = (colorsStore && colorsStore[themeKey]) || {};
                if (!colors.text_secondary || !window.Plotly) return;

                document.querySelectorAll('.js-plotly-plot').forEach(function(gd) {
                    try {
                        Plotly.relayout(gd, {
                            'font.color': colors.text_secondary,
                            'xaxis.gridcolor': colors.border,
                            'xaxis.tickfont.color': colors.text_secondary,
                            'xaxis.title.font.color': colors.text_secondary,
                            'yaxis.gridcolor': colors.border,
                            'yaxis.tickfont.color': colors.text_secondary,
                            'yaxis.title.font.color': colors.text_secondary,
                            'yaxis2.tickfont.color': colors.text_secondary,
                            'yaxis2.title.font.color': colors.text_secondary,
                            'legend.font.color': colors.text_secondary,
                        }).catch(function() {});
                        const data = gd.data || [];
                        if (data.length && data[0].type === 'pie') {
                            Plotly.restyle(gd, { 'marker.line.color': colors.bg_card }).catch(function() {});
                        }
                      
                        if (data.length && data[0].type === 'heatmap') {
                            const scale = (data[0].colorscale || []).map(function(stop) {
                                return stop[0] === 0 ? [0, colors.bg_card] : stop;
                            });
                            Plotly.restyle(gd, { colorscale: [scale] }).catch(function() {});
                        }

                       
                        const traceColorByName = {
                            "Précision (%)": colors.accent_cyan,
                            "Perte (loss)": colors.critical,
                        };
                        data.forEach(function(trace, idx) {
                            const newColor = traceColorByName[trace.name];
                            if (newColor && trace.line) {
                                Plotly.restyle(gd, { 'line.color': newColor }, [idx]).catch(function() {});
                            }
                        });

                        // Annotation centrale du donut (ex. "4673 alertes") et
                        // texte de la heatmap de confusion : pas couverts par
                        // relayout ci-dessus, mis à jour séparément.
                        const fig = gd._fullLayout;
                        if (fig && fig.annotations && fig.annotations.length) {
                            const updated = gd.layout.annotations.map(function(a) {
                                return Object.assign({}, a, {
                                    font: Object.assign({}, a.font, { color: colors.text_primary })
                                });
                            });
                            Plotly.relayout(gd, { annotations: updated }).catch(function() {});
                        }
                    } catch (e) { /* graphe pas encore prêt, ignoré */ }
                });
            };
        }

        if (n_clicks === 0) {
            window.__iotguardTheme = 'dark';
            return ["Mode sombre", "dark"];
        }

        
        const isLight = document.body.classList.toggle('light-theme');
        const themeKey = isLight ? 'light' : 'dark';
        window.__iotguardTheme = themeKey;
        window.repaintPlotlyCharts(themeKey);

        return [isLight ? "Mode clair" : "Mode sombre", themeKey];
    }
    """,
    [Output("theme-toggle-label", "children"), Output("theme-toggle", "data-theme-state")],
    [Input("theme-toggle", "n_clicks")],
    [State("theme-colors-store", "data")],
)
clientside_callback(
    """
    function(n_intervals, colorsStore) {
        const theme = window.__iotguardTheme || 'dark';
        if (theme === 'dark') return window.dash_clientside.no_update;
        if (window.repaintPlotlyCharts) {
            window.repaintPlotlyCharts(theme);
        }
        return n_intervals;
    }
    """,
    Output("chart-repaint-ack", "data"),
    Input("chart-repaint-watcher", "n_intervals"),
    State("theme-colors-store", "data"),
    prevent_initial_call=True,
)
PROTECTED_ROUTES = {
    "/overview": overview,
    "/monitoring": monitoring,
    "/alertes": alertes,
    "/analyse-csv": analyse_csv,
    "/performance": performance,
    "/apropos": apropos,
    "/profil": profile,
}


@app.callback(
    Output("page-content", "children"),
    Input("url", "pathname"),
    State("session-store", "data"),
)
def route(pathname, session_data):
    is_authenticated = bool(session_data and session_data.get("username"))

    if not is_authenticated:
        return login.layout()

    username = session_data.get("username", "admin")
    role = session_data.get("role", "Administrateur Sécurité SOC")

    if pathname in (None, "/", ""):
        return dcc.Location(id="redirect-overview", pathname="/overview")

    page_module = PROTECTED_ROUTES.get(pathname)
    if page_module is None:
        return html.Div(
            "Page introuvable.",
            style={"color": "#E7ECF7", "padding": "40px", "fontFamily": "Inter, sans-serif"},
        )
    return page_module.layout(username=username, role=role)


@app.callback(
    Output("session-store", "data"),
    Output("login-error-zone", "children"),
    Output("url", "pathname"),
    Input("btn-login", "n_clicks"),
    Input("login-password", "n_submit"),
    State("login-username", "value"),
    State("login-password", "value"),
    prevent_initial_call=True,
)
def handle_login(n_clicks, n_submit, username, password):
    if not username or not password:
        return dash.no_update, html.Div("Veuillez renseigner l'identifiant et le mot de passe.", className="login-error"), dash.no_update

    user = db_module.verifier_identifiants(username, password)
    if user is None:
        return dash.no_update, html.Div("Identifiant ou mot de passe incorrect.", className="login-error"), dash.no_update

    return {"username": username, "role": user["role"]}, None, "/overview"


@app.callback(
    Output("session-store", "data", allow_duplicate=True),
    Output("url", "pathname", allow_duplicate=True),
    Input("btn-logout", "n_clicks"),
    prevent_initial_call=True,
)
def handle_logout(n_clicks):
    if n_clicks:
        return None, "/"
    return dash.no_update, dash.no_update


# ---------------------------------------------------------------------------
# Rafraîchissement — Overview
# ---------------------------------------------------------------------------
@app.callback(
    Output("overview-content", "children"),
    Input("overview-interval", "n_intervals"),
    Input("url", "pathname"),
)
def refresh_overview(n_intervals, pathname):
    if pathname != "/overview":
        return dash.no_update
    return overview.render_overview_content()


@app.callback(
    Output("monitoring-content", "children"),
    Input("monitoring-interval", "n_intervals"),
    Input("url", "pathname"),
)
def refresh_monitoring(n_intervals, pathname):
    if pathname != "/monitoring":
        return dash.no_update
    return monitoring.render_monitoring_content()


@app.callback(
    Output("capture-status-pill", "children"),
    Output("capture-note", "children"),
    Output("btn-toggle-capture", "children"),
    Output("btn-toggle-capture", "className"),
    Output("btn-toggle-capture", "style"),
    Output("capture-action-feedback", "children", allow_duplicate=True),
    Input("monitoring-interval", "n_intervals"),
    Input("capture-status-fast-interval", "n_intervals"),
    Input("url", "pathname"),
    Input("capture-refresh-trigger", "data"),
    prevent_initial_call=True,
)
def refresh_capture_status(n_intervals, n_intervals_fast, pathname, _trigger):
    if pathname != "/monitoring":
        return (dash.no_update,) * 6

    status, _ = capture_control.get_status()
    is_running = status == "running"

    if is_running:
        btn_style = {"borderColor": "var(--critical)", "color": "var(--critical)", "width": "auto", "padding": "9px 20px"}
        btn_class = "btn-secondary"
        btn_text = "Arrêter la capture"
        feedback_clear = None
    else:
        btn_style = {"width": "auto", "padding": "9px 20px"}
        btn_class = "btn-primary"
        btn_text = "Démarrer la capture"
        feedback_clear = dash.no_update

    return (
        monitoring.render_status_pill(),
        monitoring.render_capture_note(),
        btn_text,
        btn_class,
        btn_style,
        feedback_clear,
    )


@app.callback(
    Output("capture-action-feedback", "children", allow_duplicate=True),
    Output("capture-refresh-trigger", "data"),
    Input("btn-toggle-capture", "n_clicks"),
    State("capture-refresh-trigger", "data"),
    prevent_initial_call=True,
)
def handle_toggle_capture(n_clicks, trigger_count):
    if not n_clicks:
        return dash.no_update, dash.no_update

    status, _ = capture_control.get_status()
    if status == "running":
        success, message = capture_control.stop_capture()
    else:
        success, message = capture_control.start_capture()

    if success:
        color = "var(--low)"
    elif "Aucun processus" in message and "détecté après" in message:
        color = "var(--high)"
    else:
        color = "var(--critical)"

    feedback = html.Div(
        message,
        style={
            "fontSize": "12.5px", "color": color, "padding": "8px 12px",
            "backgroundColor": "var(--bg-secondary)", "border": "1px solid var(--border)", "borderRadius": "6px",
        },
    )
    return feedback, (trigger_count or 0) + 1

@app.callback(
    Output("alertes-liste-container", "children"),
    Input("filtre-famille", "value"),
    Input("filtre-gravite", "value"),
    Input("alerte-selectionnee-id", "data"),
)
def refresh_alertes_liste(famille, gravite, selected_id):
    return alertes.render_alertes_liste(famille, gravite, selected_id)


@app.callback(
    Output("alerte-selectionnee-id", "data"),
    Input({"type": "alerte-row", "index": ALL}, "n_clicks"),
    prevent_initial_call=True,
)
def select_alerte(n_clicks_list):
    triggered = ctx.triggered_id
    if triggered is None or not isinstance(triggered, dict):
        return dash.no_update
    if not any(n_clicks_list):
        return dash.no_update
    return triggered["index"]


@app.callback(
    Output("alerte-detail-container", "children"),
    Input("alerte-selectionnee-id", "data"),
)
def refresh_alerte_detail(selected_id):
    return alertes.render_alerte_detail(selected_id)
@app.callback(
    Output("csv-analyse-resultat", "children"),
    Input("upload-csv", "contents"),
    State("upload-csv", "filename"),
    prevent_initial_call=True,
)
def handle_csv_upload(contents, filename):
    if contents is None:
        return dash.no_update

    df, error = analyse_csv.parse_csv_contents(contents, filename)
    if error:
        return html.Div(
            error,
            style={
                "backgroundColor": "rgba(240, 68, 92, 0.1)", "border": "1px solid rgba(240, 68, 92, 0.3)",
                "color": "#F0445C", "borderRadius": "8px", "padding": "10px 14px", "fontSize": "13px",
            },
        )
    return analyse_csv.render_resultat(df, filename)



@app.callback(
    Output("profil-feedback-zone", "children", allow_duplicate=True),
    Output("session-store", "data", allow_duplicate=True),
    Input("btn-save-profil", "n_clicks"),
    State("profil-input-nom", "value"),
    State("profil-input-email", "value"),
    State("session-store", "data"),
    prevent_initial_call=True,
)
def handle_save_profil(n_clicks, nom_complet, email, session_data):
    if not n_clicks:
        return dash.no_update, dash.no_update

    username = (session_data or {}).get("username")
    if not username:
        return profile.feedback_banner("Session expirée, veuillez vous reconnecter.", success=False), dash.no_update

    db_module.update_profil(username, nom_complet=nom_complet, email=email)
    return profile.feedback_banner("Profil mis à jour avec succès."), dash.no_update


@app.callback(
    Output("profil-feedback-zone", "children", allow_duplicate=True),
    Output("profil-mdp-actuel", "value"),
    Output("profil-mdp-nouveau", "value"),
    Output("profil-mdp-confirmation", "value"),
    Input("btn-save-mdp", "n_clicks"),
    State("profil-mdp-actuel", "value"),
    State("profil-mdp-nouveau", "value"),
    State("profil-mdp-confirmation", "value"),
    State("session-store", "data"),
    prevent_initial_call=True,
)
def handle_change_password(n_clicks, ancien, nouveau, confirmation, session_data):
    if not n_clicks:
        return dash.no_update, dash.no_update, dash.no_update, dash.no_update

    username = (session_data or {}).get("username")
    if not username:
        return profile.feedback_banner("Session expirée, veuillez vous reconnecter.", success=False), "", "", ""

    if not ancien or not nouveau or not confirmation:
        return profile.feedback_banner("Veuillez remplir les trois champs.", success=False), ancien, nouveau, confirmation

    if nouveau != confirmation:
        return profile.feedback_banner("Les deux mots de passe ne correspondent pas.", success=False), ancien, "", ""

    success, message = db_module.changer_mot_de_passe(username, ancien, nouveau)
    return profile.feedback_banner(message, success=success), "", "", ""


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8050)
