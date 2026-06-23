import json
import os

import plotly.graph_objects as go
from dash import html, dcc

from components import sidebar, page_header, kpi_card, card, empty_state
from config import COLORS, FAMILY_COLORS, TRAINING_HISTORY_PATH


def layout(username="admin", role="Administrateur Sécurité SOC"):
    history = _load_history()
    return html.Div(
        [
            sidebar("/performance", username, role),
            html.Div(
                [
                    page_header(
                        "Performance du modèle hybride",
                        "Résultats réels de l'entraînement GRU+LSTM (Training_hybride.ipynb)",
                    ),
                    render_performance_content(history),
                ],
                className="main-content",
            ),
        ],
        className="app-shell",
    )


def _load_history():
    if not os.path.exists(TRAINING_HISTORY_PATH):
        return None
    try:
        with open(TRAINING_HISTORY_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _courbes_figure(epochs_data):
    epochs = [e[0] for e in epochs_data]
    losses = [e[1] for e in epochs_data]
    accs = [e[2] for e in epochs_data]

    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=epochs, y=accs, name="Précision (%)", yaxis="y1",
            line=dict(color=COLORS["accent_cyan"], width=2.2),
            hovertemplate="Epoch %{x} — Acc : %{y:.2f}%<extra></extra>",
        )
    )
    fig.add_trace(
        go.Scatter(
            x=epochs, y=losses, name="Perte (loss)", yaxis="y2",
            line=dict(color=COLORS["critical"], width=2.2, dash="dot"),
            hovertemplate="Epoch %{x} — Loss : %{y:.4f}<extra></extra>",
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color=COLORS["text_secondary"], size=12),
        margin=dict(l=10, r=10, t=20, b=10),
        height=300,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
        xaxis=dict(title="Epoch", gridcolor=COLORS["border"], showgrid=False),
        yaxis=dict(title="Précision (%)", gridcolor=COLORS["border"], zeroline=False, side="left"),
        yaxis2=dict(title="Loss", overlaying="y", side="right", showgrid=False),
    )
    return fig


def _precision_par_famille_figure(precision_dict):
    classes = list(precision_dict.keys())
    values = list(precision_dict.values())
    colors = [FAMILY_COLORS.get(c, COLORS["text_muted"]) for c in classes]

    fig = go.Figure(
        data=[
            go.Bar(
                x=classes, y=values, marker_color=colors,
                text=[f"{v:.1f}%" for v in values], textposition="outside",
                hovertemplate="%{x} : %{y:.1f}%<extra></extra>",
            )
        ]
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color=COLORS["text_secondary"], size=12),
        margin=dict(l=10, r=10, t=30, b=10),
        height=340,
        yaxis=dict(title="Précision (%)", range=[0, 110], gridcolor=COLORS["border"], zeroline=False),
        xaxis=dict(gridcolor=COLORS["border"], showgrid=False),
        showlegend=False,
    )
    return fig


def _matrice_confusion_figure(matrice):
    classes = matrice["classes"]
    valeurs = matrice["valeurs"]

    fig = go.Figure(
        data=go.Heatmap(
            z=valeurs, x=classes, y=classes,
            colorscale=[[0, COLORS["bg_card"]], [0.5, "#1F4F8F"], [1, COLORS["accent_cyan"]]],
            text=[[f"{v:.1f}" for v in row] for row in valeurs],
            texttemplate="%{text}",
            textfont=dict(size=10.5),
            hovertemplate="Réel : %{y}<br>Prédit : %{x}<br>%{z:.1f}%<extra></extra>",
            showscale=True,
            colorbar=dict(thickness=12, len=0.8),
        )
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color=COLORS["text_secondary"], size=11),
        margin=dict(l=10, r=10, t=20, b=10),
        height=380,
        xaxis=dict(title="Famille prédite", side="bottom"),
        yaxis=dict(title="Famille réelle", autorange="reversed"),
    )
    return fig


def render_performance_content(history):
    if history is None:
        return card(
            None,
            empty_state(
                "Aucun historique d'entraînement disponible (results/training_history.json introuvable). "
                "Exportez les métriques depuis Training_hybride.ipynb pour peupler cette page."
            ),
        )

    avertissement_donnees_provisoires = html.Div(
        "Les courbes d'apprentissage (précision/perte par epoch) reflètent le dernier entraînement réel "
        "à 6 classes. La précision par famille et la matrice de confusion ci-dessous sont en revanche des "
        "valeurs provisoires de l'entraînement précédent (7 classes, avant retrait d'Injection) — à régénérer "
        "depuis classification_report() dans Training_hybride.ipynb avant la soutenance.",
        style={
            "backgroundColor": "rgba(242, 169, 59, 0.1)", "border": "1px solid rgba(242, 169, 59, 0.3)",
            "color": COLORS["high"], "borderRadius": "8px", "padding": "10px 14px", "fontSize": "12.5px",
            "marginBottom": "20px", "lineHeight": "1.5",
        },
    )

    kpis = html.Div(
        [
            kpi_card("Précision finale (accuracy)", f"{history['accuracy_finale']:.2f}%", icon="◬", accent_color=COLORS["low"]),
            kpi_card("Perte finale (loss)", f"{history['loss_finale']:.4f}", icon="▼", accent_color=COLORS["accent_blue"]),
            kpi_card("Taux d'apprentissage (LR)", f"{history['learning_rate']}", icon="◈", accent_color=COLORS["accent_cyan"]),
            kpi_card("Epochs d'entraînement", str(history["nb_epochs"]), icon="◉", accent_color=COLORS["high"]),
        ],
        className="grid-4",
    )

    courbes = card(
        "Courbes d'apprentissage (précision / perte)",
        dcc.Graph(figure=_courbes_figure(history["epochs"]), config={"displayModeBar": False}),
    )

    precision_fam = card(
        "Précision par famille d'attaque",
        dcc.Graph(figure=_precision_par_famille_figure(history["precision_par_famille"]), config={"displayModeBar": False}),
    )

    matrice = card(
        "Matrice de confusion (en %)",
        dcc.Graph(figure=_matrice_confusion_figure(history["matrice_confusion"]), config={"displayModeBar": False}),
    )

    note_matrice = None
    mc = history["matrice_confusion"]
    lignes_vides = [
        mc["classes"][i] for i, row in enumerate(mc["valeurs"]) if sum(row) == 0
    ]
    if lignes_vides:
        note_matrice = html.P(
            f"Note : données de classification non disponibles pour {', '.join(lignes_vides)} "
            f"dans cet export — à régénérer depuis le notebook d'entraînement pour une matrice complète.",
            style={"fontSize": "11.5px", "color": COLORS["text_muted"], "marginTop": "10px", "fontStyle": "italic"},
        )

    return html.Div(
        [
            avertissement_donnees_provisoires,
            kpis,
            html.Div(courbes, className="mt-24"),
            html.Div(precision_fam, className="mt-24"),
            html.Div([matrice, note_matrice], className="mt-24"),
        ]
    )