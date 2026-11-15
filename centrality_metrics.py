"""
centrality_metrics.py
Phase 1: Compute degree centrality, closeness centrality, clustering coefficient.
Flag anomalies using z-scores (mean + k*std).
"""

import numpy as np
import pandas as pd
import networkx as nx


def compute_phase1_centralities(G: nx.Graph) -> pd.DataFrame:
    """
    Compute Phase 1 centrality metrics for each node.

    Returns DataFrame indexed by node ID with columns:
      - degree_centrality
      - closeness_centrality
      - clustering_coefficient
      - raw_degree
    """
    records = []
    for node in G.nodes():
        degree = G.degree(node)
        records.append({
            "_id": node,
            "degree_centrality": nx.degree_centrality(G)[node],
            "closeness_centrality": nx.closeness_centrality(G, u=node) if G.number_of_nodes() > 1 else 0.0,
            "clustering_coefficient": nx.clustering(G, node),
            "raw_degree": degree,
        })
    return pd.DataFrame(records).set_index("_id")


def flag_centrality_anomalies(df: pd.DataFrame, k_sigma: float = 2.0) -> tuple[pd.DataFrame, dict, dict]:
    """
    Flag nodes whose metrics exceed mean + k * std.

    Returns:
        flagged_df: original df plus flags + risk_level
        thresholds: dict of {metric_name: {mean, std, threshold}}
        summary: counts of high_risk / suspicious / normal
    """
    metrics = ["degree_centrality", "closeness_centrality", "clustering_coefficient"]
    thresholds: dict = {}
    flags: dict[str, list[str]] = {row: [] for row in df.index}
    explanations: dict[str, str] = {row: "" for row in df.index}

    for m in metrics:
        mean = df[m].mean()
        std = df[m].std()
        thresh = mean + k_sigma * std if std > 0 else mean + k_sigma
        thresholds[m] = {"mean": round(mean, 6), "std": round(std, 6), "threshold": round(thresh, 6)}

        above = df[m] > thresh
        for idx in df.index[above]:
            flags[idx].append(m)
            existing = explanations[idx]
            explanations[idx] = f"{existing}; {m}={df.loc[idx, m]:.4f}>{thresh:.4f}" if existing else f"{m}={df.loc[idx, m]:.4f}>{thresh:.4f}"

    df = df.copy()
    df["flag_count"] = df.index.map(lambda i: len(flags[i]))
    df["anomaly_explanation"] = df.index.map(lambda i: explanations[i])

    def risk_level(fc):
        if fc >= 2:
            return "High Risk"
        elif fc == 1:
            return "Suspicious"
        return "Normal"

    df["risk_level"] = df["flag_count"].map(risk_level)

    summary = {
        "high_risk_count": int((df["risk_level"] == "High Risk").sum()),
        "suspicious_count": int((df["risk_level"] == "Suspicious").sum()),
        "normal_count": int((df["risk_level"] == "Normal").sum()),
        "total_nodes": len(df),
        "k_sigma": k_sigma,
    }
    return df, thresholds, summary


if __name__ == "__main__":
    from graph_builder import load_graph_from_csv
    from pathlib import Path
    csv_path = Path(__file__).parent / "data" / "sample_network_flows.csv"
    G, _ = load_graph_from_csv(csv_path)
    df = compute_phase1_centralities(G)
    df_flagged, thresholds, summary = flag_centrality_anomalies(df)
    print(f"Nodes analyzed: {len(df)}")
    print(f"High risk: {summary['high_risk_count']}, Suspicious: {summary['suspicious_count']}")
    print("\nThresholds:")
    for m, t in thresholds.items():
        print(f"  {m}: mean={t['mean']}, std={t['std']}, threshold={t['threshold']}")
    print("\nTop flagged:")
    print(df_flagged.sort_values("flag_count", ascending=False).head(10))
