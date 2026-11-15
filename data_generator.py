"""
data_generator.py
Generate synthetic botnet network flow data for testing.
Creates a CSV with nodes, edges, traffic volumes, and botnet labels.
"""

import random
import csv
from pathlib import Path


def generate_synthetic_flows(output_path: Path, n_nodes: int = 400, n_botnet: int = 30, seed: int = 42):
    """
    Generate a synthetic network flow dataset as CSV.

    Nodes are split into normal (92.5%) and botnet (7.5%).
    Botnet nodes have:
      - Higher degree centrality (more connections)
      - Higher clustering coefficient (tight-knit groups)
      - More outbound connections to command-and-control IPs
      - More internal commmunication within the botnet community
    """
    rng = random.Random(seed)

    # --- Node definition -------------------------------------------------
    node_ids = [f"10.0.{rng.randint(0, 254)}.{rng.randint(1, 254)}" for _ in range(n_nodes)]
    node_ids = list(dict.fromkeys(node_ids))  # deduplicate while preserving order
    while len(node_ids) < n_nodes:
        node_ids.append(f"10.0.{rng.randint(0, 254)}.{rng.randint(1, 254)}")
    node_ids = node_ids[:n_nodes]

    is_botnet = set()
    botnet_pool = rng.sample(range(n_nodes), k=n_botnet)
    for idx in botnet_pool:
        is_botnet.add(node_ids[idx])

    # Pick a few of the botnet nodes as "commanders" that other bots contact
    commanders = list(rng.sample(botnet_pool, k=max(3, n_botnet // 5)))

    rows = []

    # --- Intra-botnet edges (clique-like) -------------------------------
    # Every bot contacts at least 2 other bots
    for i, idx in enumerate(botnet_pool):
        peers = [j for j in botnet_pool if j != idx][:rng.randint(2, min(8, n_botnet - 1))]
        for peer_idx in peers:
            src, dst = node_ids[idx], node_ids[peer_idx]
            tstamp = f"2025-01-{rng.randint(1,28):02d}T{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}"
            rows.append({
                "src_ip": src,
                "dst_ip": dst,
                "proto": rng.choice(["TCP", "UDP"]),
                "bytes_sent": rng.randint(500, 50000),
                "bytes_recv": rng.randint(100, 10000),
                "duration_s": round(rng.uniform(0.1, 30.0), 2),
                "label": "botnet",
            })

    # --- Commander → bot C2 beacons ------------------------------------
    for cmd_idx in commanders:
        for bot_idx in botnet_pool:
            if bot_idx == cmd_idx:
                continue
            if rng.random() < 0.6:
                src, dst = node_ids[cmd_idx], node_ids[bot_idx]
                tstamp = f"2025-01-{rng.randint(1,28):02d}T{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}"
                rows.append({
                    "src_ip": src,
                    "dst_ip": dst,
                    "proto": "TCP",
                    "bytes_sent": rng.randint(50, 500),     # small beacon
                    "bytes_recv": rng.randint(200, 2000),
                    "duration_s": round(rng.uniform(0.05, 2.0), 2),
                    "label": "botnet",
                })

    # --- Normal inter-node edges ----------------------------------------
    for i, src in enumerate(node_ids):
        if src in is_botnet:
            continue
        n_edges = rng.randint(1, 6)
        candidates = [n for n in node_ids if n != src and n not in is_botnet]
        for dst in rng.sample(candidates, k=min(n_edges, len(candidates))):
            tstamp = f"2025-01-{rng.randint(1,28):02d}T{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}"
            rows.append({
                "src_ip": src,
                "dst_ip": dst,
                "proto": rng.choice(["TCP", "UDP", "ICMP"]),
                "bytes_sent": rng.randint(100, 5000),
                "bytes_recv": rng.randint(100, 5000),
                "duration_s": round(rng.uniform(0.1, 60.0), 2),
                "label": "normal",
            })

    # --- Some cross-over edges (bots talking to normal hosts) ------------
    for idx in rng.sample(list(botnet_pool), k=min(len(botnet_pool), 10)):
        src = node_ids[idx]
        candidates = [n for n in node_ids if n not in is_botnet]
        for dst in rng.sample(candidates, k=rng.randint(1, 3)):
            tstamp = f"2025-01-{rng.randint(1,28):02d}T{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}"
            rows.append({
                "src_ip": src,
                "dst_ip": dst,
                "proto": "TCP",
                "bytes_sent": rng.randint(200, 8000),
                "bytes_recv": rng.randint(100, 4000),
                "duration_s": round(rng.uniform(0.5, 15.0), 2),
                "label": "botnet",
            })

    # Write CSV
    fieldnames = ["src_ip", "dst_ip", "proto", "bytes_sent", "bytes_recv", "duration_s", "label"]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    return {
        "total_flows": len(rows),
        "nodes": len(node_ids),
        "botnet_nodes": len(is_botnet),
        "normal_nodes": len(node_ids) - len(is_botnet),
    }


if __name__ == "__main__":
    from pathlib import Path
    DATA_DIR = Path(__file__).parent / "data"
    result = generate_synthetic_flows(DATA_DIR / "sample_network_flows.csv")
    print(f"Generated {result['total_flows']} flows across {result['nodes']} nodes")
    print(f"  Botnet: {result['botnet_nodes']}, Normal: {result['normal_nodes']}")
