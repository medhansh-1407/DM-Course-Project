"""
graph_builder.py
Build a NetworkX graph from network flow CSV data.
"""

import pandas as pd
import networkx as nx
from pathlib import Path


def load_graph_from_csv(csv_path: Path) -> tuple[nx.DiGraph, dict]:
    """
    Load network flows from CSV and build a directed graph.

    Each edge stores:
      - 'weight': total bytes transferred (bytes_sent + bytes_recv)
      - 'flow_count': number of individual flows on this edge
      - 'src_label', 'dst_label': node labels if known

    Returns:
        G: NetworkX DiGraph
        stats: ingestion statistics
    """
    df = pd.read_csv(csv_path)

    G = nx.DiGraph()

    # Add nodes (preserve order to keep first seen IP)
    all_ips = set(df["src_ip"].unique()) | set(df["dst_ip"].unique())
    for ip in all_ips:
        G.add_node(ip)

    # Aggregate edges
    edge_stats: dict[tuple[str, str], dict] = {}
    for _, row in df.iterrows():
        src, dst = str(row["src_ip"]), str(row["dst_ip"])
        key = (src, dst)
        if key not in edge_stats:
            edge_stats[key] = {"weight": 0, "flow_count": 0}
        edge_stats[key]["weight"] += int(row["bytes_sent"]) + int(row["bytes_recv"])
        edge_stats[key]["flow_count"] += 1
        # Remember label
        if "label" in row and pd.notna(row["label"]):
            edge_stats[key]["label"] = str(row["label"])

    for (src, dst), stats in edge_stats.items():
        G.add_edge(src, dst, weight=stats["weight"], flow_count=stats["flow_count"])
        if "label" in stats:
            G.nodes[src]["label"] = stats["label"]
            G.nodes[dst]["label"] = stats["label"]

    stats = {
        "total_flows": len(df),
        "total_nodes": len(G.nodes()),
        "total_edges": len(G.edges()),
        "valid_flows": len(df[df["label"].isin(["normal", "botnet"])]),
        "dropped_flows": len(df) - len(df[df["label"].isin(["normal", "botnet"])]),
        "initial_flows": len(df),
    }
    return G, stats


if __name__ == "__main__":
    DATA_DIR = Path(__file__).parent / "data"
    csv_path = DATA_DIR / "sample_network_flows.csv"
    if not csv_path.exists():
        print(f"No data file at {csv_path}. Run data_generator.py first.")
        exit(1)
    G, stats = load_graph_from_csv(csv_path)
    print(f"Graph: {stats['total_nodes']} nodes, {stats['total_edges']} edges")
    print(f"Flows ingested: {stats['total_flows']}")
