"""
dashboard/app.py
----------------
Botnet & Vulnerability Detection - Dashboard

Pure Flask application — pre-renders all charts and templates at startup.
No Dash dependency; tab switching via vanilla JavaScript.
"""

import base64
import io
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash

import networkx as nx
import pandas as pd
import plotly.graph_objects as go
from matplotlib import pyplot as plt

from config import (
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    TOP_N_RISKY_NODES,
    COLOR_HIGH_RISK,
    COLOR_SUSPICIOUS,
    COLOR_NORMAL,
)
from data_generator import generate_synthetic_flows
from graph_builder import load_graph_from_csv
from centrality_metrics import compute_phase1_centralities, flag_centrality_anomalies
from centrality_phase2 import compute_phase2_centralities
from community_detection import compute_community_summary_report
from ml_classification import run_ml_detection_pipeline

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR.parent / "data"
SAMPLE_DATASET_PATH = DATA_DIR / "sample_network_flows.csv"

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)


def _bar_html(df, x_col, y_col, title, color):
    rows = df.head(TOP_N_RISKY_NODES)
    fig = go.Figure(go.Bar(
        x=rows[x_col], y=rows[y_col], marker_color=color, marker_line_width=0,
        text=[f"{v:.4f}" for v in rows[y_col]], textposition="outside", cliponaxis=False,
    ))
    fig.update_layout(
        title={"text": title, "font": {"size": 14, "weight": 600}},
        xaxis_title="", yaxis_title="",
        margin=dict(l=40, r=20, t=50, b=80), xaxis_tickangle=-45,
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)", height=350,
    )
    return fig.to_html(full_html=False, include_plotlyjs=False)


# ---------------------------------------------------------------------------
# Data loading + pre-rendering
# ---------------------------------------------------------------------------

def build_context(csv_path: Path | None = None):
    if csv_path is None:
        if not SAMPLE_DATASET_PATH.exists():
            generate_synthetic_flows(output_path=SAMPLE_DATASET_PATH)
        csv_path = SAMPLE_DATASET_PATH
    else:
        csv_path = Path(csv_path)

    G, ingestion_stats = load_graph_from_csv(csv_path)
    df_p1 = compute_phase1_centralities(G)
    df_flagged, thresholds, summary = flag_centrality_anomalies(df_p1, k_sigma=2.0)

    df_p2 = compute_phase2_centralities(G)
    df_p2_flagged, _, phase2_summary = flag_centrality_anomalies(df_p2, k_sigma=2.0)

    for col in ("flag_count", "risk_level"):
        if col not in df_p2_flagged.columns:
            src = df_flagged.get(col) if col in df_flagged.columns else None
            df_p2_flagged[col] = src if src is not None else 0

    df_communities = compute_community_summary_report(G)
    df_ml, _ = run_ml_detection_pipeline(df_p2_flagged)

    # Graph image
    img_bytes = io.BytesIO()
    fig, ax = plt.subplots(figsize=(14, 10), dpi=150)
    pos = nx.spring_layout(G, k=1.5 / (G.number_of_nodes() ** 0.5), iterations=50, seed=42)
    node_colors = []
    for node in G.nodes():
        if node in df_flagged.index:
            risk = df_flagged.loc[node, "risk_level"]
            node_colors.append(
                COLOR_HIGH_RISK if risk == "High Risk"
                else COLOR_SUSPICIOUS if risk == "Suspicious"
                else COLOR_NORMAL
            )
        else:
            node_colors.append(COLOR_NORMAL)
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#cbd5e1", alpha=0.25, arrows=False, width=0.5)
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors, node_size=100, alpha=0.85)
    ax.axis("off")
    plt.tight_layout()
    fig.savefig(img_bytes, format="png", bbox_inches="tight", dpi=150)
    img_bytes.seek(0)
    graph_image_b64 = base64.b64encode(img_bytes.read()).decode()
    plt.close()

    # Pre-sort all data
    def _reset(rows_df):
        """Reset index and ensure the id column is named 'ip'."""
        out = rows_df.reset_index()
        if "_id" in out.columns and "ip" not in out.columns:
            out = out.rename(columns={"_id": "ip"})
        return out

    flagged_sorted = _reset(df_flagged).sort_values("degree_centrality", ascending=False).to_dict(orient="records")
    phase2_sorted = _reset(df_p2_flagged).sort_values("composite_risk_score", ascending=False).to_dict(orient="records")
    phase2_by_btwn = _reset(df_p2_flagged).sort_values("betweenness_centrality", ascending=False).to_dict(orient="records")
    phase2_by_evec = _reset(df_p2_flagged).sort_values("eigenvector_centrality", ascending=False).to_dict(orient="records")
    phase2_by_pr = _reset(df_p2_flagged).sort_values("pagerank", ascending=False).to_dict(orient="records")
    communities_sorted = df_communities.reset_index().to_dict(orient="records")
    ml_sorted = _reset(df_ml).sort_values("ml_probability", ascending=False).to_dict(orient="records")
    ml_top = ml_sorted[:TOP_N_RISKY_NODES]
    risky_sorted = _reset(df_flagged).sort_values("flag_count", ascending=False).to_dict(orient="records")

    def _chart(df, x_col, y_col, title, color):
        return _bar_html(df, x_col, y_col, title, color)

    charts = {
        "deg": _chart(pd.DataFrame(flagged_sorted), "ip", "degree_centrality", "Degree Centrality", "#1d4ed8"),
        "close": _chart(pd.DataFrame(flagged_sorted), "ip", "closeness_centrality", "Closeness Centrality", "#059669"),
        "cluster": _chart(pd.DataFrame(flagged_sorted), "ip", "clustering_coefficient", "Clustering Coefficient", "#7c3aed"),
        "comp": _chart(pd.DataFrame(phase2_sorted), "ip", "composite_risk_score", "Composite Risk Score", "#1d4ed8"),
        "btwn": _chart(pd.DataFrame(phase2_by_btwn), "ip", "betweenness_centrality", "Betweenness Centrality", "#059669"),
        "evec": _chart(pd.DataFrame(phase2_by_evec), "ip", "eigenvector_centrality", "Eigenvector Centrality", "#7c3aed"),
        "pr": _chart(pd.DataFrame(phase2_by_pr), "ip", "pagerank", "PageRank", "#dc2626"),
        "ml": _chart(pd.DataFrame(ml_sorted), "ip", "ml_probability", "ML Anomaly Probability", "#1d4ed8"),
    }

    anomalous_count = sum(1 for c in communities_sorted if c.get("is_anomalous"))

    return {
        "summary": summary,
        "phase2_summary": phase2_summary,
        "ingestion": ingestion_stats,
        "thresholds": thresholds,
        "flagged": flagged_sorted,
        "phase2": phase2_sorted,
        "communities": communities_sorted,
        "anomalous_count": anomalous_count,
        "ml": ml_sorted,
        "ml_top": ml_top,
        "risky": risky_sorted,
        "graph_image": graph_image_b64,
        "n_nodes": len(G.nodes()),
        "n_edges": len(G.edges()),
        **charts,
    }


def build_context_from(csv_path: Path):
    """Public entry point used by the /upload route."""
    return build_context(csv_path)


print("Loading dashboard data...")
_CONTEXT = build_context()
print(f"Data loaded: {_CONTEXT['n_nodes']} nodes, {_CONTEXT['n_edges']} edges")


# Track which CSV file is currently in use (default: generated/sample)
_current_source = str(SAMPLE_DATASET_PATH)


def _is_uploaded(path: str) -> bool:
    return path != str(SAMPLE_DATASET_PATH)


@app.route("/")
def index():
    ctx = dict(_CONTEXT)
    if _current_source != str(SAMPLE_DATASET_PATH):
        ctx["source_label"] = f"Loaded from: {Path(_current_source).name}"
    return render_template("index.html", **ctx)


UPLOAD_DIR = DATA_DIR / "uploads"
ALLOWED_EXTENSIONS = {".csv"}


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() == "csv"


@app.route("/upload", methods=["GET", "POST"])
def upload():
    global _CONTEXT, _current_source
    error = None
    success_msg = None

    if request.method == "POST":
        if "csvfile" not in request.files:
            error = "No file selected."
        else:
            f = request.files["csvfile"]
            if f.filename == "":
                error = "No file selected."
            elif not _allowed_file(f.filename):
                error = "Only .csv files are accepted."
            else:
                UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                dest = UPLOAD_DIR / f.filename.replace(" ", "_")
                counter = 1
                while dest.exists():
                    stem = dest.stem
                    ext = dest.suffix
                    dest = UPLOAD_DIR / f"{stem}_{counter}{ext}"
                    counter += 1
                f.save(str(dest))
                try:
                    # Validate columns before computing
                    df = pd.read_csv(dest)
                    required = {"src_ip", "dst_ip", "bytes_sent", "bytes_recv", "duration_s"}
                    missing = required - set(df.columns)
                    if missing:
                        raise ValueError(f"Missing columns: {', '.join(sorted(missing))}")
                    _CONTEXT = build_context_from(dest)
                    _current_source = str(dest)
                    success_msg = f"{len(df)} rows from '{f.filename}'"
                except Exception as e:
                    error = str(e)

    ctx = dict(_CONTEXT)
    ctx["error"] = error
    ctx["success_msg"] = success_msg
    if _current_source != str(SAMPLE_DATASET_PATH):
        ctx["source_label"] = f"Loaded from: {Path(_current_source).name}"
    return render_template("index.html", **ctx)


if __name__ == "__main__":
    app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False)
