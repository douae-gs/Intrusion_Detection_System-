from datetime import datetime, timedelta
from collections import Counter

import plotly.graph_objects as go
from dash import html, dcc

from components import sidebar, page_header, kpi_card, card, empty_state
from config import COLORS, FAMILY_COLORS, SEVERITY_COLORS, REFRESH_INTERVAL_MS
import db


PLOTLY_LAYOUT_BASE = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter, sans-serif", color=COLORS["text_secondary"], size=12),
    margin=dict(l=10, r=10, t=10, b=10),
)


def _donut_par_famille(par_famille):
    if not par_famille:
        return go.Figure()
    labels = list(par_famille.keys())
    values = list(par_famille.values())
    colors = [FAMILY_COLORS.get(l, COLORS["text_muted"]) for l in labels]

    fig = go.Figure(
        data=[
            go.Pie(
                labels=labels,
                values=values,
                hole=0.62,
                marker=dict(colors=colors, line=dict(color=COLORS["bg_card"], width=2)),
                textinfo="none",
                hovertemplate="%{label} : %{value} (%{percent})<extra></extra>",
            )
        ]
    )
    total = sum(values)
    fig.update_layout(
        **PLOTLY_LAYOUT_BASE,
        showlegend=True,
        legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=1.02, font=dict(size=11)),
        annotations=[
            dict(
                text=f"<b>{total}</b><br><span style='font-size:11px'>alertes</span>",
                x=0.5, y=0.5, font=dict(size=20, color=COLORS["text_primary"]), showarrow=False,
            )
        ],
        height=240,
    )
    return fig


def _timeline_figure(timeline_rows):
    if not timeline_rows:
        return go.Figure()

    buckets = {}
    for row in timeline_rows:
        ts = datetime.fromisoformat(row["timestamp"])
        bucket_ts = ts.replace(minute=(ts.minute // 30) * 30, second=0, microsecond=0)
        buckets.setdefault(bucket_ts, Counter())[row["type_attaque"]] += 1

    if not buckets:
        return go.Figure()

    sorted_buckets = sorted(buckets.keys())
    familles = sorted({fam for c in buckets.values() for fam in c})

    fig = go.Figure()
    for fam in familles:
        fig.add_trace(
            go.Bar(
                x=sorted_buckets,
                y=[buckets[b].get(fam, 0) for b in sorted_buckets],
                name=fam,
                marker_color=FAMILY_COLORS.get(fam, COLORS["text_muted"]),
                hovertemplate=f"{fam} : %{{y}}<extra></extra>",
            )
        )

    fig.update_layout(
        **PLOTLY_LAYOUT_BASE,
        barmode="stack",
        height=260,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, font=dict(size=10.5)),
        xaxis=dict(gridcolor=COLORS["border"], showgrid=False, tickfont=dict(size=10.5)),
        yaxis=dict(gridcolor=COLORS["border"], zeroline=False, tickfont=dict(size=10.5)),
    )
    return fig


def _top_ips_bar(top_ips):
    if not top_ips:
        return go.Figure()
    ips = [ip for ip, _ in reversed(top_ips)]
    counts = [c for _, c in reversed(top_ips)]
    fig = go.Figure(
        data=[
            go.Bar(
                x=counts,
                y=ips,
                orientation="h",
                marker_color=COLORS["accent_cyan"],
                hovertemplate="%{y} : %{x} alertes<extra></extra>",
            )
        ]
    )
    fig.update_layout(
        **PLOTLY_LAYOUT_BASE,
        height=200,
        xaxis=dict(gridcolor=COLORS["border"], zeroline=False, tickfont=dict(size=10.5)),
        yaxis=dict(tickfont=dict(size=11, family="JetBrains Mono")),
    )
    return fig


def layout(username="admin", role="Administrateur Sécurité SOC"):
    return html.Div(
        [
            dcc.Interval(id="overview-interval", interval=REFRESH_INTERVAL_MS * 3, n_intervals=0),
            sidebar("/overview", username, role),
            html.Div(
                [
                    page_header(
                        "Vue d'ensemble",
                        "Synthèse de l'activité de détection sur les dernières 24 heures",
                    ),
                    html.Div(id="overview-content"),
                ],
                className="main-content",
            ),
        ],
        className="app-shell",
    )


def render_overview_content():
    stats = db.get_stats_resume(depuis_heures=24)
    timeline_rows = db.get_timeline(depuis_heures=24)

    total = stats["total"]
    nb_critiques = stats["par_gravite"].get("Critique", 0)
    familles_actives = len(stats["par_famille"])
    famille_dominante = (
        max(stats["par_famille"], key=stats["par_famille"].get) if stats["par_famille"] else "—"
    )

    kpis = html.Div(
        [
            kpi_card("Alertes (24h)", str(total), icon="⚠", accent_color=COLORS["accent_cyan"]),
            kpi_card(
                "Alertes critiques", str(nb_critiques), icon="◉", accent_color=COLORS["critical"],
                delta=f"{round(100*nb_critiques/total) if total else 0}% du total", delta_direction="up" if nb_critiques else "neutral",
            ),
            kpi_card("Familles actives", f"{familles_actives} / 6", icon="◈", accent_color=COLORS["high"]),
            kpi_card("Famille dominante", famille_dominante, icon="▲", accent_color=COLORS["accent_blue"]),
        ],
        className="grid-4",
    )

    charts_row = html.Div(
        [
            card(
                "Répartition par famille d'attaque",
                dcc.Graph(figure=_donut_par_famille(stats["par_famille"]), config={"displayModeBar": False})
                if stats["par_famille"] else empty_state("Aucune alerte enregistrée sur cette période."),
            ),
            card(
                "Top 5 — IP sources les plus actives",
                dcc.Graph(figure=_top_ips_bar(stats["top_ips"]), config={"displayModeBar": False})
                if stats["top_ips"] else empty_state("Aucune IP source identifiée sur cette période."),
            ),
        ],
        className="grid-2 mt-24",
    )

    timeline_card = html.Div(
        card(
            "Chronologie des alertes (tranches de 30 min)",
            dcc.Graph(figure=_timeline_figure(timeline_rows), config={"displayModeBar": False})
            if timeline_rows else empty_state("Aucune donnée à afficher sur cette période."),
        ),
        className="mt-24",
    )

    return html.Div([kpis, charts_row, timeline_card])
