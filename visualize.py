"""
visualize.py
------------
Phase 1 Deliverable:
Visualizes the network communication graph:
- Color-coded nodes by risk level:
    * Green: Normal (0 flags)
    * Yellow/Orange: Suspicious (1 flag)
    * Red: High Risk (2+ flags, e.g., C2 servers, scanners)
- Node size proportional to Degree Centrality (scaling high-degree hubs visibly)
- High-risk / suspicious nodes clearly labeled with their IP addresses
- Saves publication-quality static plot to outputs/ directory.
"""

from pathlib import Path
from typing import Optional, Union

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx
import numpy as np
import pandas as pd

from config import (
    COLOR_HIGH_RISK,
    COLOR_NORMAL,
    COLOR_SUSPICIOUS,
    MAX_NODE_SIZE,
    MIN_NODE_SIZE,
    VIZ_FIGURE_SIZE,
    VISUALIZATION_PNG_PATH,
)


def plot_network_risk_graph(
    G: Union[nx.DiGraph, nx.Graph],
    df_flagged: pd.DataFrame,
    output_path: Optional[Union[str, Path]] = VISUALIZATION_PNG_PATH,
    top_label_count: int = 10,
    title: str = "Network Communication Graph — Botnet & Anomaly Risk Detection",
    show_plot: bool = False,
) -> Path:
    """
    Renders and saves a network visualization with color-coded risk levels
    and degree-proportional node scaling.
    """
    if output_path is None:
        output_path = VISUALIZATION_PNG_PATH
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=VIZ_FIGURE_SIZE, dpi=300)

    # Graph layout: spring layout with reproducible seed
    # Use k-distance parameter proportional to graph size for optimal spacing
    n_nodes = G.number_of_nodes()
    k_dist = 1.8 / np.sqrt(max(1, n_nodes))
    pos = nx.spring_layout(G, k=k_dist, iterations=50, seed=42)

    # Prepare node colors and sizes
    node_colors = []
    node_sizes = []
    labels_to_draw = {}

    # Extract degree centralities for sizing
    deg_series = df_flagged.get("degree_centrality", pd.Series(0.0, index=df_flagged.index))
    max_deg = deg_series.max() if not deg_series.empty and deg_series.max() > 0 else 1.0
    min_deg = deg_series.min() if not deg_series.empty else 0.0

    # Identify top nodes to label
    flagged_nodes = df_flagged[df_flagged["flag_count"] > 0].index.tolist()
    top_labeled_ips = set(flagged_nodes[:top_label_count])

    for node in G.nodes():
        if node in df_flagged.index:
            risk = df_flagged.loc[node, "risk_level"]
            deg_val = float(df_flagged.loc[node, "degree_centrality"])
        else:
            risk = "Normal"
            deg_val = 0.0

        # Assign Color based on risk level
        if risk == "High Risk":
            node_colors.append(COLOR_HIGH_RISK)
        elif risk == "Suspicious":
            node_colors.append(COLOR_SUSPICIOUS)
        else:
            node_colors.append(COLOR_NORMAL)

        # Scale node size linearly between MIN_NODE_SIZE and MAX_NODE_SIZE
        norm_deg = (deg_val - min_deg) / (max_deg - min_deg + 1e-9)
        size = MIN_NODE_SIZE + norm_deg * (MAX_NODE_SIZE - MIN_NODE_SIZE)
        node_sizes.append(size)

        # Assign labels to key suspicious/high-risk nodes
        if node in top_labeled_ips:
            labels_to_draw[node] = node

    # Draw Graph Components
    # 1. Edges (faint gray lines with low alpha for clarity)
    nx.draw_networkx_edges(
        G,
        pos,
        ax=ax,
        edge_color="#bdc3c7",
        alpha=0.35,
        arrows=False,  # Undirected aesthetic reduces clutter
        width=0.8,
    )

    # 2. Nodes
    nx.draw_networkx_nodes(
        G,
        pos,
        ax=ax,
        node_color=node_colors,
        node_size=node_sizes,
        alpha=0.88,
        edgecolors="#2c3e50",
        linewidths=0.7,
    )

    # 3. Node Labels (only for flagged/hub nodes)
    nx.draw_networkx_labels(
        G,
        pos,
        labels=labels_to_draw,
        ax=ax,
        font_size=8,
        font_weight="bold",
        font_color="#1a252f",
        bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="#7f8c8d", alpha=0.85, lw=0.5),
    )

    # 4. Legend & Metadata
    legend_elements = [
        mpatches.Patch(color=COLOR_NORMAL, label="Normal (0 flags)"),
        mpatches.Patch(color=COLOR_SUSPICIOUS, label="Suspicious (1 flag)"),
        mpatches.Patch(color=COLOR_HIGH_RISK, label="High Risk (>=2 flags - C2 / Scanners)"),
        plt.Line2D([0], [0], marker="o", color="w", label="Node size proportional to Degree",
                   markerfacecolor="#7f8c8d", markersize=10),
    ]

    ax.legend(
        handles=legend_elements,
        loc="upper right",
        frameon=True,
        framealpha=0.92,
        facecolor="#f8f9fa",
        edgecolor="#bdc3c7",
        fontsize=10,
        title="Risk Classification Legend",
        title_fontsize=11,
    )

    # Title & Subtitle formatting
    total_nodes = G.number_of_nodes()
    total_edges = G.number_of_edges()
    high_risk_count = (df_flagged["risk_level"] == "High Risk").sum() if "risk_level" in df_flagged else 0
    suspicious_count = (df_flagged["risk_level"] == "Suspicious").sum() if "risk_level" in df_flagged else 0

    ax.set_title(
        f"{title}\n"
        f"Network Topology: {total_nodes} nodes, {total_edges} edges | "
        f"Detected: {high_risk_count} High Risk, {suspicious_count} Suspicious",
        fontsize=13,
        fontweight="bold",
        pad=15,
        color="#2c3e50",
    )
    ax.axis("off")
    plt.tight_layout()

    # Save to disk
    plt.savefig(output_path, dpi=300, bbox_inches="tight")
    print(f"[visualize] Network graph visualization saved to: {output_path}")

    if show_plot:
        plt.show()

    plt.close(fig)
    return output_path


if __name__ == "__main__":
    from data_generator import generate_synthetic_flows
    from graph_builder import load_graph_from_csv
    from centrality_metrics import compute_phase1_centralities
    from anomaly_flagging import flag_centrality_anomalies

    test_csv = generate_synthetic_flows()
    G, _ = load_graph_from_csv(test_csv)
    df_metrics = compute_phase1_centralities(G)
    df_flagged, _, _ = flag_centrality_anomalies(df_metrics)
    plot_network_risk_graph(G, df_flagged)
