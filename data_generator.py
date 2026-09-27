"""
data_generator.py
-----------------
Generates realistic network flow datasets (CSV format) for testing the
Botnet & Vulnerability Detection pipeline.

Includes:
- Benign background traffic (workstations -> DNS, web, email, internal servers)
- Star C2 Botnet (central C2 server controlling infected worker bots)
- P2P Botnet mesh (inter-communicating bot cluster with high clustering)
- Horizontal port scanner (reconnaissance node probing many destinations)
- Edge case dirty records (broadcast, multicast, loopback, malformed) to verify data cleaning.
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from config import DATA_DIR, SAMPLE_DATASET_PATH


def generate_synthetic_flows(
    output_path: Optional[Path] = None,
    num_normal_hosts: int = 150,
    num_bot_nodes: int = 35,
    num_p2p_bots: int = 15,
    num_scanners: int = 2,
    base_time: Optional[datetime] = None,
    seed: int = 42,
) -> Path:
    """
    Generates a realistic flow log CSV with 100-300 unique nodes, containing both
    legitimate enterprise traffic and known botnet/scanner topological anomalies.
    """
    random.seed(seed)
    if output_path is None:
        output_path = SAMPLE_DATASET_PATH
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if base_time is None:
        base_time = datetime(2026, 9, 13, 9, 0, 0)

    records = []

    # 1. IP Pools Definition
    # Enterprise internal subnet: 192.168.1.0/24
    internal_dns = "192.168.1.2"
    internal_web = "192.168.1.5"
    internal_file = "192.168.1.10"
    
    benign_workstations = [f"192.168.1.{i}" for i in range(20, 20 + num_normal_hosts)]
    
    # Diverse external web services (CDN, web, public APIs) so normal traffic is properly dispersed
    external_servers = [
        f"198.51.{i // 256}.{i % 256 + 1}" for i in range(max(80, num_normal_hosts))
    ]

    # Botnet Infrastructure
    c2_server = "203.0.113.195"  # Primary C2 hub
    backup_c2 = "198.51.100.88"   # Secondary C2 bridge
    bot_workers = [f"192.168.1.{i}" for i in range(180, 180 + num_bot_nodes)]
    p2p_bots = [f"192.168.1.{i}" for i in range(100, 100 + num_p2p_bots)]
    scanners = [f"192.168.1.{240 + i}" for i in range(num_scanners)]

    current_time = base_time

    # 2. Benign Background Traffic Generation
    for ws in benign_workstations:
        # Every host does DNS lookups (subset of lookups)
        num_dns_queries = random.randint(2, 5)
        for _ in range(num_dns_queries):
            ts = current_time + timedelta(seconds=random.randint(0, 3600))
            records.append({
                "src_ip": ws,
                "dst_ip": internal_dns,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "bytes": random.randint(64, 512),
                "protocol": "UDP",
                "port": 53,
                "label": "benign"
            })

        # Internal file/web server access
        if random.random() < 0.35:
            for _ in range(random.randint(1, 3)):
                ts = current_time + timedelta(seconds=random.randint(0, 3600))
                records.append({
                    "src_ip": ws,
                    "dst_ip": random.choice([internal_web, internal_file]),
                    "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                    "bytes": random.randint(500, 15000),
                    "protocol": "TCP",
                    "port": 80 if random.random() < 0.5 else 445,
                    "label": "benign"
                })

        # External web browsing (dispersed across distinct destinations)
        sampled_destinations = random.sample(external_servers, k=min(random.randint(2, 4), len(external_servers)))
        for dst in sampled_destinations:
            ts = current_time + timedelta(seconds=random.randint(0, 3600))
            records.append({
                "src_ip": ws,
                "dst_ip": dst,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "bytes": random.randint(1024, 65535),
                "protocol": "TCP",
                "port": 443 if random.random() < 0.85 else 80,
                "label": "benign"
            })

    # 3. Star C2 Botnet Traffic (Hub & Spoke Pattern)
    # The C2 server (203.0.113.195) maintains command sessions with 35 internal bot workers.
    # Each bot beacons regularly, and the C2 issues commands.
    # This creates a massive star hub signature in degree and betweenness centrality!
    for bot in bot_workers:
        # Periodic beaconing to primary C2
        for t_offset in range(0, 3600, 300):  # Every 5 minutes
            jitter = random.randint(-15, 15)
            ts = current_time + timedelta(seconds=max(0, t_offset + jitter))
            # Outgoing beacon
            records.append({
                "src_ip": bot,
                "dst_ip": c2_server,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "bytes": random.randint(120, 350),
                "protocol": "TCP",
                "port": 8443,
                "label": "botnet_beacon"
            })
            # Incoming command response from C2
            records.append({
                "src_ip": c2_server,
                "dst_ip": bot,
                "timestamp": (ts + timedelta(milliseconds=random.randint(50, 200))).strftime("%Y-%m-%d %H:%M:%S"),
                "bytes": random.randint(256, 4096),
                "protocol": "TCP",
                "port": 8443,
                "label": "botnet_c2"
            })

        # Subset of bots also contact the backup C2 relay bridge
        if random.random() < 0.4:
            ts = current_time + timedelta(seconds=random.randint(600, 3000))
            records.append({
                "src_ip": bot,
                "dst_ip": backup_c2,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "bytes": random.randint(150, 400),
                "protocol": "TCP",
                "port": 4444,
                "label": "botnet_c2_bridge"
            })
            records.append({
                "src_ip": backup_c2,
                "dst_ip": c2_server,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "bytes": random.randint(150, 400),
                "protocol": "TCP",
                "port": 4444,
                "label": "botnet_c2_relay"
            })

    # 4. P2P Botnet Traffic (High Clustering / Mesh Topology)
    # P2P botnet members exchange heartbeat & command payloads amongst each other.
    for i, bot_a in enumerate(p2p_bots):
        # Connect to 3-5 peer bots in the cluster
        peers = [b for j, b in enumerate(p2p_bots) if j != i and abs(i - j) <= 3]
        for peer in peers:
            ts = current_time + timedelta(seconds=random.randint(100, 3500))
            records.append({
                "src_ip": bot_a,
                "dst_ip": peer,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "bytes": random.randint(200, 800),
                "protocol": "UDP",
                "port": 6881,
                "label": "p2p_botnet"
            })

    # 5. Horizontal Port Scanner (High Out-Degree Reconnaissance)
    # The scanner rapidly contacts many distinct target IPs on SMB (445), SSH (22), and HTTP (80)
    for scanner in scanners:
        target_sample = random.sample(benign_workstations, min(40, len(benign_workstations)))
        for target in target_sample:
            ts = current_time + timedelta(seconds=random.randint(1800, 2400))  # Burst scan
            records.append({
                "src_ip": scanner,
                "dst_ip": target,
                "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "bytes": 60,
                "protocol": "TCP",
                "port": random.choice([22, 445, 80, 8080]),
                "label": "port_scan"
            })

    # 6. Dirty / Edge-Case Records (to test data cleaning and filtering)
    dirty_records = [
        # Broadcast
        {"src_ip": "192.168.1.55", "dst_ip": "255.255.255.255", "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"), "bytes": 64, "protocol": "UDP", "port": 67, "label": "broadcast"},
        # Multicast
        {"src_ip": "192.168.1.42", "dst_ip": "224.0.0.1", "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"), "bytes": 48, "protocol": "IGMP", "port": 0, "label": "multicast"},
        {"src_ip": "192.168.1.77", "dst_ip": "239.255.255.250", "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"), "bytes": 128, "protocol": "UDP", "port": 1900, "label": "multicast_ssdp"},
        # Loopback
        {"src_ip": "127.0.0.1", "dst_ip": "127.0.0.1", "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"), "bytes": 512, "protocol": "TCP", "port": 3306, "label": "loopback"},
        # Zero / Unspecified
        {"src_ip": "0.0.0.0", "dst_ip": "192.168.1.1", "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"), "bytes": 32, "protocol": "UDP", "port": 68, "label": "unspecified"},
        # Malformed IP strings
        {"src_ip": "invalid_ip_text", "dst_ip": "192.168.1.10", "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"), "bytes": 64, "protocol": "TCP", "port": 80, "label": "malformed"},
        {"src_ip": "192.168.1.33", "dst_ip": "999.999.999.999", "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"), "bytes": 64, "protocol": "TCP", "port": 80, "label": "malformed"},
    ]
    records.extend(dirty_records)

    # Sort records chronologically
    records.sort(key=lambda r: r["timestamp"])

    # Write CSV
    fieldnames = ["src_ip", "dst_ip", "timestamp", "bytes", "protocol", "port", "label"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    print(f"[data_generator] Successfully generated {len(records)} flow records written to {output_path}")
    return output_path


if __name__ == "__main__":
    generate_synthetic_flows()
