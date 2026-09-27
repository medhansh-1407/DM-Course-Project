"""
graph_builder.py
----------------
Phase 1 Deliverable:
1. Data Ingestion: Loads network flow CSV / binetflow dataset.
2. Data Cleaning & Filtering: Validates IP addresses, strips broadcast,
   multicast, loopback, and malformed entries.
3. Graph Construction: Builds directed or undirected weighted graphs using NetworkX.
   - Nodes = unique IP addresses
   - Edges = communications between IP pairs
   - Edge Weights = number of flows or aggregate bytes transferred
"""

import ipaddress
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

import networkx as nx
import pandas as pd

from config import (
    DEFAULT_DIRECTED,
    EDGE_WEIGHT_METRIC,
    FILTER_BROADCAST,
    FILTER_LOOPBACK,
    FILTER_MULTICAST,
    IGNORED_IPS,
    SAMPLE_DATASET_PATH,
)


def is_valid_ip(ip_str: str) -> bool:
    """
    Validates whether an IP address is syntactically valid and filters out
    broadcast, loopback, multicast, or unspecified addresses based on config.
    """
    if not isinstance(ip_str, str):
        return False

    ip_str = ip_str.strip()
    if not ip_str or ip_str in IGNORED_IPS:
        return False

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if FILTER_LOOPBACK and ip_obj.is_loopback:
        return False
    if FILTER_MULTICAST and ip_obj.is_multicast:
        return False
    if FILTER_BROADCAST and (ip_str == "255.255.255.255" or ip_obj.is_reserved):
        return False
    if ip_obj.is_unspecified:
        return False

    return True


def load_and_clean_flows(
    csv_path: Union[str, Path] = SAMPLE_DATASET_PATH,
) -> Tuple[pd.DataFrame, Dict[str, int]]:
    """
    Loads network flow CSV into a pandas DataFrame, sanitizes fields,
    and filters out malformed or unwanted IP records.
    Returns cleaned DataFrame and cleaning audit statistics.
    """
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"Flow dataset not found at: {csv_path}")

    df = pd.read_csv(csv_path)

    # Standardize column names (supports both custom format and CTU-13 / CICIDS2017 naming)
    column_mapping = {
        "SrcAddr": "src_ip",
        "DstAddr": "dst_ip",
        "Source IP": "src_ip",
        "Destination IP": "dst_ip",
        "TotBytes": "bytes",
        "Total Length of Fwd Packets": "bytes",
        "Proto": "protocol",
        "Protocol": "protocol",
        "Dport": "port",
        "Destination Port": "port",
        "StartTime": "timestamp",
        "Timestamp": "timestamp",
        "Label": "label",
    }
    df = df.rename(columns={k: v for k, v in column_mapping.items() if k in df.columns})

    # Required core columns
    required_cols = ["src_ip", "dst_ip"]
    for col in required_cols:
        if col not in df.columns:
            raise ValueError(f"Missing required column '{col}' in flow dataset: {csv_path}")

    # Optional defaults for missing columns
    if "bytes" not in df.columns:
        df["bytes"] = 1
    else:
        df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce").fillna(1).astype(int)

    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    initial_row_count = len(df)

    # Apply IP validation filters
    valid_src = df["src_ip"].astype(str).apply(is_valid_ip)
    valid_dst = df["dst_ip"].astype(str).apply(is_valid_ip)
    clean_mask = valid_src & valid_dst & (df["src_ip"] != df["dst_ip"])

    cleaned_df = df[clean_mask].copy()
    dropped_count = initial_row_count - len(cleaned_df)

    stats = {
        "initial_flows": initial_row_count,
        "valid_flows": len(cleaned_df),
        "dropped_flows": dropped_count,
        "unique_src_ips": cleaned_df["src_ip"].nunique(),
        "unique_dst_ips": cleaned_df["dst_ip"].nunique(),
    }

    return cleaned_df, stats


def build_network_graph(
    df: pd.DataFrame,
    directed: bool = DEFAULT_DIRECTED,
    weight_metric: str = EDGE_WEIGHT_METRIC,
) -> Union[nx.DiGraph, nx.Graph]:
    """
    Constructs a weighted NetworkX graph from cleaned flow DataFrame.

    Parameters:
    -----------
    df : pd.DataFrame
        Cleaned network flow records with src_ip, dst_ip, and bytes.
    directed : bool
        If True, creates a DiGraph (preserves communication directionality).
        If False, creates an undirected Graph.
    weight_metric : str
        'num_flows' (frequency of connection events) or 'total_bytes'.

    Returns:
    --------
    G : nx.DiGraph or nx.Graph
        The constructed NetworkX graph with node and edge attributes.
    """
    G = nx.DiGraph() if directed else nx.Graph()

    # Aggregate edges to determine weights
    agg_dict = {"bytes": ["count", "sum"]}
    if "label" in df.columns:
        # Collect distinct flow labels observed on the edge
        agg_dict["label"] = lambda s: list(set(s.dropna()))

    grouped = df.groupby(["src_ip", "dst_ip"]).agg(agg_dict).reset_index()
    # Flatten multi-level column names
    grouped.columns = [
        col[0] if col[1] == "" else f"{col[0]}_{col[1]}"
        for col in grouped.columns
    ]

    for _, row in grouped.iterrows():
        u = str(row["src_ip"])
        v = str(row["dst_ip"])
        flow_count = int(row["bytes_count"])
        total_bytes = int(row["bytes_sum"])
        labels = row.get("label_<lambda>", [])

        weight = total_bytes if weight_metric == "total_bytes" else flow_count

        if G.has_edge(u, v):
            G[u][v]["weight"] += weight
            G[u][v]["flow_count"] += flow_count
            G[u][v]["total_bytes"] += total_bytes
        else:
            G.add_edge(
                u,
                v,
                weight=weight,
                flow_count=flow_count,
                total_bytes=total_bytes,
                labels=labels,
            )

    # Annotate node-level volume and activity statistics
    for node in G.nodes():
        if G.is_directed():
            in_edges = G.in_edges(node, data=True)
            out_edges = G.out_edges(node, data=True)
            G.nodes[node]["in_flows"] = sum(d.get("flow_count", 1) for _, _, d in in_edges)
            G.nodes[node]["out_flows"] = sum(d.get("flow_count", 1) for _, _, d in out_edges)
            G.nodes[node]["in_bytes"] = sum(d.get("total_bytes", 0) for _, _, d in in_edges)
            G.nodes[node]["out_bytes"] = sum(d.get("total_bytes", 0) for _, _, d in out_edges)
        else:
            edges = G.edges(node, data=True)
            G.nodes[node]["total_flows"] = sum(d.get("flow_count", 1) for _, _, d in edges)
            G.nodes[node]["total_bytes"] = sum(d.get("total_bytes", 0) for _, _, d in edges)

    return G


def load_graph_from_csv(
    csv_path: Union[str, Path] = SAMPLE_DATASET_PATH,
    directed: bool = DEFAULT_DIRECTED,
    weight_metric: str = EDGE_WEIGHT_METRIC,
) -> Tuple[Union[nx.DiGraph, nx.Graph], Dict[str, int]]:
    """
    Convenience pipeline function: loads CSV, cleans data, and returns the graph.
    """
    df, stats = load_and_clean_flows(csv_path)
    G = build_network_graph(df, directed=directed, weight_metric=weight_metric)
    stats["num_nodes"] = G.number_of_nodes()
    stats["num_edges"] = G.number_of_edges()
    return G, stats


if __name__ == "__main__":
    from data_generator import generate_synthetic_flows

    test_csv = generate_synthetic_flows()
    G, stats = load_graph_from_csv(test_csv)
    print(f"[graph_builder] Ingestion Stats: {stats}")
    print(f"[graph_builder] Graph successfully constructed: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges.")
