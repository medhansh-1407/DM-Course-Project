"""
config.py
---------
Central configuration module for Botnet & Vulnerability Detection via Graph Centrality Metrics.
Maintains all tunable hyperparameters, threshold values, and file paths in one place.
"""

from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
OUTPUTS_DIR = BASE_DIR / "outputs"

# Ensure runtime directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

# Default File Paths
SAMPLE_DATASET_PATH = DATA_DIR / "sample_network_flows.csv"
REPORT_CSV_PATH = OUTPUTS_DIR / "report.csv"
VISUALIZATION_PNG_PATH = OUTPUTS_DIR / "phase1_network_graph.png"

# Data Cleaning & Ingestion
IGNORED_IPS = {
    "0.0.0.0",
    "255.255.255.255",
    "127.0.0.1",
    "::1",
    "fe80::1",
}

# Multicast IP prefix (IPv4 class D: 224.0.0.0 - 239.255.255.255)
FILTER_MULTICAST = True
FILTER_BROADCAST = True
FILTER_LOOPBACK = True

# Graph Construction Parameters
DEFAULT_DIRECTED = True
EDGE_WEIGHT_METRIC = "num_flows"  # Options: "num_flows", "total_bytes"

# Phase 1: Anomaly Flagging Parameters
# Metric is flagged if metric_value > mean + (k_sigma * std_dev)
K_SIGMA = 2.0  # Tunable: 2.0 to 3.0

# Multi-metric threshold for risk levels:
# 0 flags -> Normal
# 1 flag -> Suspicious
# >= HIGH_RISK_THRESHOLD flags -> High Risk
HIGH_RISK_THRESHOLD = 2

# Reporting
TOP_N_REPORT = 15

# Visualization Parameters
VIZ_FIGURE_SIZE = (14, 10)
COLOR_NORMAL = "#2ecc71"      # Green
COLOR_SUSPICIOUS = "#f39c12"  # Yellow/Orange (1 flag)
COLOR_HIGH_RISK = "#e74c3c"   # Red (2+ flags)
MIN_NODE_SIZE = 50
MAX_NODE_SIZE = 800
