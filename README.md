# Botnet & Vulnerability Detection via Graph Centrality Metrics

A modular graph-theoretic security analytics system designed to identify:
1. **Botnet Command-and-Control (C2) Nodes**: Hubs and bridges controlling infected bot armies.
2. **Critical / Vulnerable Infrastructure Nodes**: Single-points-of-failure whose compromise would maximally disrupt communications.
3. **Reconnaissance Port Scanners**: Nodes with anomalous connection degrees.
4. **P2P Botnet Clusters**: Tightly knit bot clusters exhibiting abnormal clustering coefficients.

---

## Phase 1: Foundational Detection Pipeline

### Architecture & Deliverables

| File | Purpose |
| :--- | :--- |
| `config.py` | Central configuration containing tunable thresholds ($k \cdot \sigma$), file paths, and filtering rules. |
| `data_generator.py` | Realistic synthetic NetFlow generator (100–500 nodes) simulating enterprise traffic with injected C2 star botnets, P2P meshes, scanners, and dirty records. |
| `graph_builder.py` | Loads CSV flow logs, filters/cleans invalid/broadcast/multicast/loopback IPs, and builds weighted NetworkX graphs (`nx.DiGraph` / `nx.Graph`). |
| `centrality_metrics.py` | Computes **Degree Centrality** (both hand-coded from first principles and NetworkX), **Closeness Centrality**, and **Clustering Coefficient**. |
| `anomaly_flagging.py` | Computes $\mu$ and $\sigma$ per metric, applies $\mu + k\sigma$ thresholding, aggregates multi-metric flags (Normal = 0, Suspicious = 1, High Risk $\ge 2$), and generates human-readable explanations. |
| `visualize.py` | Generates publication-ready network graph visual with color-coded risk levels and node sizes proportional to degree centrality. |
| `run_phase1.py` | End-to-end execution runner that processes flow logs, computes metrics, flags anomalies, outputs `outputs/report.csv`, and renders `outputs/phase1_network_graph.png`. |
| `tests/test_phase1.py` | Comprehensive test suite verifying mathematical correctness, data cleaning, flagging logic, and end-to-end execution. |

---

## Quick Start

### 1. Run All Tests
Verify that all mathematical computations, graph operations, and validation checks pass:
```bash
python -m unittest tests/test_phase1.py -v
```

### 2. Execute Phase 1 Pipeline
Run the foundational detection pipeline:
```bash
python run_phase1.py
```

### 3. Customize Thresholds
Tune the $k$-sigma anomaly threshold via command-line arguments:
```bash
python run_phase1.py --k-sigma 2.5 --output-csv outputs/report.csv
```

---

## Phase 1 Mathematical Formulas

1. **Degree Centrality**:
   $$C_D(v) = \frac{\text{deg}(v)}{n - 1}$$
   Detects nodes with abnormally high connection volume (C2 hubs, reconnaissance scanners).

2. **Closeness Centrality**:
   $$C_C(v) = \frac{n - 1}{\sum_{u} d(v, u)}$$
   Measures the reciprocal of the sum of shortest path distances, identifying nodes capable of rapidly spreading commands or malware.

3. **Clustering Coefficient**:
   $$C(v) = \frac{2 e_v}{k_v (k_v - 1)}$$
   Quantifies neighbor inter-connectivity, distinguishing tightly-knit P2P botnet clusters from sparse normal communications.

4. **Statistical Anomaly Threshold**:
   $$\text{Threshold}(M) = \mu_M + k \cdot \sigma_M$$
   Where $k$ is tunable (default $k=2.0$). Nodes exceeding the threshold on $\ge 2$ metrics are classified as **High Risk**.

---

## Outputs

- **Ranked Shortlist**: `outputs/report.csv` contains top suspicious nodes ranked by risk and flag count with detailed z-score explanations.
- **Graph Plot**: `outputs/phase1_network_graph.png` visualizes the entire communication graph with color-coded risk and degree-scaled nodes.
