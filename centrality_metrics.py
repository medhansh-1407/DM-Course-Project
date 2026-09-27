"""
centrality_metrics.py
---------------------
Phase 1 Deliverable:
Computes foundational graph centrality metrics:
1. Degree Centrality (with both custom hand-coded formula and NetworkX implementation)
2. Closeness Centrality
3. Clustering Coefficient

These metrics form the mathematical backbone for detecting abnormally connected
Command-and-Control (C2) servers, scanners, and tightly-knit bot clusters.
"""

from typing import Dict, Optional, Tuple, Union

import networkx as nx
import numpy as np
import pandas as pd


def compute_degree_centrality_manual(
    G: Union[nx.DiGraph, nx.Graph],
) -> Dict[str, float]:
    """
    Hand-coded computation of degree centrality based on first principles:
        C_D(v) = deg(v) / (n - 1)
    where n is the total number of nodes in the graph, and deg(v) is the number
    of incident edges (total in + out degree for directed graphs).
    
    Used to validate mathematical correctness against NetworkX library implementation.
    """
    n = G.number_of_nodes()
    if n <= 1:
        return {node: 0.0 for node in G.nodes()}

    scale = 1.0 / (n - 1)
    manual_degree = {}
    for node in G.nodes():
        # In directed graphs, degree is in_degree + out_degree
        deg = G.degree(node)
        manual_degree[node] = deg * scale

    return manual_degree


def compute_phase1_centralities(
    G: Union[nx.DiGraph, nx.Graph],
    validate_against_nx: bool = True,
) -> pd.DataFrame:
    """
    Computes Degree Centrality, Closeness Centrality, and Clustering Coefficient
    across all nodes in the network graph.

    Returns:
    --------
    pd.DataFrame:
        Table indexed by IP address containing all computed centrality scores.
    """
    n = G.number_of_nodes()
    if n == 0:
        return pd.DataFrame()

    nodes = list(G.nodes())

    # 1. Degree Centralities
    # Hand-coded degree centrality
    manual_deg_dict = compute_degree_centrality_manual(G)

    # NetworkX Degree Centrality (total)
    nx_deg_dict = nx.degree_centrality(G)

    if validate_against_nx:
        # Validate that custom hand-coded degree matches NetworkX output within floating tolerance
        diffs = [abs(manual_deg_dict[node] - nx_deg_dict[node]) for node in nodes]
        max_diff = max(diffs) if diffs else 0.0
        assert max_diff < 1e-7, f"Degree centrality validation failed! Max diff: {max_diff}"

    # In-Degree & Out-Degree Centralities for directed graphs
    if G.is_directed():
        in_deg_dict = nx.in_degree_centrality(G)
        out_deg_dict = nx.out_degree_centrality(G)
    else:
        in_deg_dict = nx_deg_dict
        out_deg_dict = nx_deg_dict

    # 2. Closeness Centrality: C_C(v) = (n - 1) / sum_u d(v, u)
    # networkx handles disconnected graphs via Wasserman & Faust formula (wf_improved=True)
    closeness_dict = nx.closeness_centrality(G)

    # 3. Clustering Coefficient: C(v) = 2 * e_v / (k_v * (k_v - 1))
    # Note: clustering on directed graph is supported by NetworkX (Fagiolo's directed clustering),
    # and we also compute undirected clustering for standard neighbor triangle density.
    if G.is_directed():
        # nx.clustering on DiGraph computes directed clustering
        clustering_dict = nx.clustering(G)
    else:
        clustering_dict = nx.clustering(G)

    # Build structured DataFrame
    data = []
    for node in nodes:
        raw_degree = G.degree(node)
        data.append({
            "ip": node,
            "raw_degree": raw_degree,
            "degree_centrality": nx_deg_dict.get(node, 0.0),
            "in_degree_centrality": in_deg_dict.get(node, 0.0),
            "out_degree_centrality": out_deg_dict.get(node, 0.0),
            "closeness_centrality": closeness_dict.get(node, 0.0),
            "clustering_coefficient": clustering_dict.get(node, 0.0),
            "degree_manual": manual_deg_dict.get(node, 0.0),
        })

    df_centralities = pd.DataFrame(data).set_index("ip")
    return df_centralities


def get_top_k_centrality_nodes(
    df_centralities: pd.DataFrame,
    metric: str = "degree_centrality",
    top_k: int = 10,
) -> pd.DataFrame:
    """
    Returns the top-K nodes ranked descending by a specific centrality metric.
    """
    if metric not in df_centralities.columns:
        raise ValueError(f"Unknown metric '{metric}'. Available: {list(df_centralities.columns)}")
    return df_centralities.sort_values(by=metric, ascending=False).head(top_k)


if __name__ == "__main__":
    from data_generator import generate_synthetic_flows
    from graph_builder import load_graph_from_csv

    test_csv = generate_synthetic_flows()
    G, stats = load_graph_from_csv(test_csv)
    df_metrics = compute_phase1_centralities(G)

    print(f"\n[centrality_metrics] Computed metrics for {len(df_metrics)} nodes.")
    print("\n--- Top 5 Nodes by Degree Centrality ---")
    print(df_metrics[["degree_centrality", "in_degree_centrality", "out_degree_centrality"]].head(5))

    print("\n--- Top 5 Nodes by Closeness Centrality ---")
    print(df_metrics.sort_values(by="closeness_centrality", ascending=False)[["closeness_centrality"]].head(5))

    print("\n--- Top 5 Nodes by Clustering Coefficient ---")
    print(df_metrics.sort_values(by="clustering_coefficient", ascending=False)[["clustering_coefficient"]].head(5))
