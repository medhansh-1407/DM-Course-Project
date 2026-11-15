"""
community_detection.py
Louvain-based community detection with anomalous community scoring.
Botnet nodes often form tightly-knit clusters with high internal density
and disproportionate external connections to command nodes.
"""

import numpy as np
import pandas as pd
import networkx as nx


def identify_anomalous_communities(G: nx.Graph, density_ratio_threshold: float = 1.5):
    """
    Detect communities using greedy modularity optimization and flag anomalous ones.

    An anomalous community is one where:
      - Internal density >> External density (density_ratio > threshold)
      - Small community size but high connectivity (bots working together)

    Returns:
        community_stats: list of dicts per community
        node_community_map: dict mapping node_id -> community_id
    """
    # Use greedy modularity (CommunityDetector)
    try:
        from networkx.algorithms.community import greedy_modularity_communities
        raw_comms = list(greedy_modularity_communities(G))
    except Exception:
        raw_comms = _label_propagation_communities(G)

    # Build node-to-community map
    node_community = {}
    for cid, members in enumerate(raw_comms):
        for node in members:
            node_community[node] = cid

    stats = []
    total_edges = G.number_of_edges()

    for cid, members in enumerate(raw_comms):
        sub = G.subgraph(members)
        n_nodes = len(members)
        n_internal = sub.number_of_edges()
        n_external = sum(1 for u in members for v in G.neighbors(u) if v not in members)

        max_possible_internal = n_nodes * (n_nodes - 1)
        internal_density = n_internal / max_possible_internal if max_possible_internal > 0 else 0
        # Normalise external per internal member
        external_density = n_external / n_nodes if n_nodes > 0 else 0
        density_ratio = internal_density / (external_density + 1e-10)

        is_anomalous = density_ratio > density_ratio_threshold and n_nodes <= 50

        stats.append({
            "community_id": cid,
            "size": n_nodes,
            "internal_edges": n_internal,
            "external_connections": n_external,
            "internal_density": round(internal_density, 4),
            "external_density": round(external_density, 4),
            "density_ratio": round(density_ratio, 4),
            "avg_internal_degree": round(2 * n_internal / n_nodes, 2) if n_nodes else 0,
            "is_anomalous": is_anomalous,
            "risk_level": "High Risk" if is_anomalous else "Normal",
        })

    return stats, node_community


def _label_propagation_communities(G: nx.Graph):
    """Fallback community detection via label propagation."""
    try:
        from networkx.algorithms.community import label_combinatorial_communities
        return list(label_combinatorial_communities(G))
    except Exception:
        return [{n} for n in G.nodes()]


def compute_community_summary_report(G: nx.Graph) -> pd.DataFrame:
    """Return a DataFrame of community statistics for dashboard display."""
    stats, _ = identify_anomalous_communities(G)
    return pd.DataFrame(stats)


if __name__ == "__main__":
    from graph_builder import load_graph_from_csv
    from pathlib import Path
    csv_path = Path(__file__).parent / "data" / "sample_network_flows.csv"
    G, _ = load_graph_from_csv(csv_path)
    stats, cmap = identify_anomalous_communities(G)
    anomalous = [s for s in stats if s["is_anomalous"]]
    print(f"Communities found: {len(stats)}, Anomalous: {len(anomalous)}")
    for s in sorted(stats, key=lambda x: -x["density_ratio"])[:5]:
        print(f"  #{s['community_id']}: size={s['size']}, density_ratio={s['density_ratio']}, anomalous={s['is_anomalous']}")
