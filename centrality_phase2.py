"""
centrality_phase2.py
Phase 2: Betweenness, eigenvector centrality, PageRank + composite risk score.
"""

import numpy as np
import pandas as pd
import networkx as nx


def compute_phase2_centralities(G: nx.Graph) -> pd.DataFrame:
    """
    Compute Phase 2 centrality metrics.

    Returns DataFrame indexed by node ID with columns:
      - degree_centrality
      - closeness_centrality
      - betweenness_centrality
      - eigenvector_centrality
      - pagerank
      - clustering_coefficient
      - composite_risk_score
    """
    records = []
    dc = nx.degree_centrality(G)
    cc = nx.closeness_centrality(G)
    clust = nx.clustering(G)

    try:
        btwn = nx.betweenness_centrality(G, normalized=True)
    except Exception:
        btwn = {n: 0.0 for n in G.nodes()}

    try:
        evec = nx.eigenvector_centrality(G, max_iter=1000, tol=1e-6)
    except nx.PowerIterationFailedConvergence:
        evec = nx.eigenvector_centrality(G, max_iter=10000, tol=1e-6) if nx.is_connected(G.to_undirected()) else {n: 0.0 for n in G.nodes()}

    pr = nx.pagerank(G, alpha=0.85)

    # Composite risk: weighted average of z-scores (higher = more suspicious)
    all_keys = set(dc) | set(cc) | set(btwn) | set(evec) | set(pr)
    scores = {k: [dc.get(k, 0), cc.get(k, 0), btwn.get(k, 0), evec.get(k, 0), pr.get(k, 0)] for k in all_keys}
    means = np.mean([scores[k] for k in scores], axis=0)
    stds = np.std([scores[k] for k in scores], axis=0) + 1e-10
    composites = {}
    for node in all_keys:
        vals = scores[node]
        z_scores = [(v - m) / s for v, m, s in zip(vals, means, stds)]
        composites[node] = float(np.mean(z_scores))

    for node in G.nodes():
        records.append({
            "_id": node,
            "degree_centrality": dc.get(node, 0.0),
            "closeness_centrality": cc.get(node, 0.0),
            "betweenness_centrality": btwn.get(node, 0.0),
            "eigenvector_centrality": evec.get(node, 0.0),
            "pagerank": pr.get(node, 0.0),
            "clustering_coefficient": clust.get(node, 0.0),
            "composite_risk_score": composites.get(node, 0.0),
        })
    return pd.DataFrame(records).set_index("_id")


if __name__ == "__main__":
    from graph_builder import load_graph_from_csv
    from pathlib import Path
    csv_path = Path(__file__).parent / "data" / "sample_network_flows.csv"
    G, _ = load_graph_from_csv(csv_path)
    df = compute_phase2_centralities(G)
    print(f"Nodes analyzed: {len(df)}")
    print(df.sort_values("composite_risk_score", ascending=False).head(10))
