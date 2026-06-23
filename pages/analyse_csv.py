import base64
import io

import pandas as pd
import plotly.graph_objects as go
from dash import html, dcc

from components import sidebar, page_header, card, empty_state
from config import COLORS, FAMILY_COLORS, ALL_CLASSES


def layout(username="admin", role="Administrateur Sécurité SOC"):
    return html.Div(
        [
            sidebar("/analyse-csv", username, role),
            html.Div(
                [
                    page_header(
                        "Analyse de fichier de capture (CSV)",
                        "Classification batch d'un export de flux réseau par le modèle hybride GRU+LSTM",
                    ),
                    card(
                        None,
                        html.Div(
                            [
                                dcc.Upload(
                                    id="upload-csv",
                                    children=html.Div(
                                        [
                                            html.Div("▤", style={"fontSize": "26px", "marginBottom": "8px", "color": COLORS["accent_cyan"]}),
                                            html.Div("Glissez un fichier CSV ici ou cliquez pour parcourir"),
                                            html.Div("200 Mo max · format .csv (colonnes alignées sur le scaler entraîné)", className="text-muted", style={"fontSize": "11.5px", "marginTop": "4px"}),
                                        ]
                                    ),
                                    className="upload-zone",
                                    multiple=False,
                                ),
                            ]
                        ),
                    ),
                    html.Div(id="csv-analyse-resultat", className="mt-24"),
                ],
                className="main-content",
            ),
        ],
        className="app-shell",
    )


def parse_csv_contents(contents, filename):
    content_type, content_string = contents.split(",")
    decoded = base64.b64decode(content_string)
    try:
        if filename.endswith(".csv"):
            df = pd.read_csv(io.StringIO(decoded.decode("utf-8")))
            return df, None
        return None, "Format non supporté. Veuillez importer un fichier .csv."
    except Exception as e:
        return None, f"Erreur lors de la lecture du fichier : {e}"


def _repartition_figure(counts_dict):
    classes = [c for c in ALL_CLASSES if c in counts_dict]
    values = [counts_dict[c] for c in classes]
    colors = [FAMILY_COLORS.get(c, COLORS["text_muted"]) for c in classes]

    fig = go.Figure(
        data=[
            go.Bar(
                x=classes, y=values, marker_color=colors,
                text=values, textposition="outside",
                hovertemplate="%{x} : %{y}<extra></extra>",
            )
        ]
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color=COLORS["text_secondary"], size=12),
        margin=dict(l=10, r=10, t=20, b=10),
        height=320,
        xaxis=dict(title="Type d'attaque", gridcolor=COLORS["border"], showgrid=False),
        yaxis=dict(title="Occurrences", gridcolor=COLORS["border"], zeroline=False),
        showlegend=False,
    )
    return fig


def render_resultat(df, filename, predictions_col=None):
    """predictions_col : si le modèle a déjà tourné, colonne des prédictions.
    À défaut, on suppose une colonne 'label' déjà présente dans le CSV
    (cas d'un fichier de test déjà labellisé, comme dans tes captures)."""
    nb_lignes = len(df)

    label_col = predictions_col
    if label_col is None:
        for candidate in ["prediction", "label", "Label"]:
            if candidate in df.columns:
                label_col = candidate
                break

    success_banner = html.Div(
        f"Fichier importé avec succès. Lignes trouvées : {nb_lignes}",
        style={
            "backgroundColor": "rgba(51, 201, 122, 0.1)", "border": f"1px solid rgba(51, 201, 122, 0.3)",
            "color": COLORS["low"], "borderRadius": "8px", "padding": "10px 14px", "fontSize": "13px",
            "marginBottom": "18px",
        },
    )

    if label_col is None or label_col not in df.columns:
        return html.Div(
            [
                success_banner,
                card(
                    None,
                    empty_state(
                        "Aucune colonne de label/prédiction détectée dans ce fichier. "
                        "Branchez ici l'appel au modèle hybride (scaler + model_hybride.pth) "
                        "pour classer chaque ligne avant affichage."
                    ),
                ),
            ]
        )

    counts = df[label_col].value_counts().to_dict()
    total_attaques = sum(v for k, v in counts.items() if k != "BenignTraffic")
    famille_dominante = max(counts, key=counts.get) if counts else "—"

    kpis = html.Div(
        [
            card(
                None,
                html.Div(
                    [
                        html.Div("Lignes analysées", className="kpi-label"),
                        html.Div(str(nb_lignes), className="kpi-value"),
                    ]
                ),
            ),
            card(
                None,
                html.Div(
                    [
                        html.Div("Attaques détectées", className="kpi-label"),
                        html.Div(str(total_attaques), className="kpi-value", style={"color": COLORS["critical"]}),
                    ]
                ),
            ),
            card(
                None,
                html.Div(
                    [
                        html.Div("Famille dominante", className="kpi-label"),
                        html.Div(famille_dominante, className="kpi-value", style={"fontSize": "20px"}),
                    ]
                ),
            ),
        ],
        className="grid-3",
    )

    contexte = "Aucune anomalie significative détectée — trafic majoritairement bénin."
    if total_attaques > 0 and famille_dominante != "BenignTraffic":
        contexte = (
            f"Le fichier analysé montre une activité notable de type {famille_dominante} "
            f"({counts.get(famille_dominante, 0)} occurrences sur {nb_lignes} lignes). "
            f"Il est recommandé d'isoler les hôtes impliqués et de vérifier les règles de pare-feu associées."
        )

    return html.Div(
        [
            success_banner,
            kpis,
            html.Div(
                card("Analyse contextuelle", html.P(contexte, style={"fontSize": "13px", "color": COLORS["text_secondary"], "lineHeight": "1.6"})),
                className="mt-24",
            ),
            html.Div(
                card(f"Visualisation des attaques trouvées — {filename}", dcc.Graph(figure=_repartition_figure(counts), config={"displayModeBar": False})),
                className="mt-24",
            ),
        ]
    )
