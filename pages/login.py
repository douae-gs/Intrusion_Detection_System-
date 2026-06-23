from dash import html, dcc


def layout():
    return html.Div(
        html.Div(
            [
                html.Div(
                    [
                        html.Div("◆", className="brand-icon"),
                        html.Div("IoT Guard", className="login-title"),
                        html.Div(
                            "Système de Détection d'Intrusions IoT " \
                            " GRU/LSTM + LLM",
                            className="login-subtitle",
                        ),
                    ],
                    className="login-logo",
                ),
                html.Div(id="login-error-zone"),
                html.Label("Identifiant", className="form-label"),
                dcc.Input(
                    id="login-username",
                    type="text",
                    placeholder="admin",
                    className="form-input",
                    n_submit=0,
                ),
                html.Label("Mot de passe", className="form-label"),
                dcc.Input(
                    id="login-password",
                    type="password",
                    placeholder="Entrez votre mot de passe",
                    className="form-input",
                    n_submit=0,
                ),
                html.Button("Se connecter", id="btn-login", className="btn-primary", n_clicks=0),
            ],
            className="login-card",
        ),
        className="login-wrapper",
    )
