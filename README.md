# Botnet & Vulnerability Detection via Graph Centrality Metrics

A modular graph-theoretic security analytics system designed to identify:
1. **Botnet Command-and-Control (C2) Nodes**: Hubs and bridges controlling infected bot armies.
2. **Critical / Vulnerable Infrastructure Nodes**: Single-points-of-failure whose compromise would maximally disrupt communications.
3. **Reconnaissance Port Scanners**: Nodes with anomalous connection degrees.
4. **P2P Botnet Clusters**: Tightly knit bot clusters exhibiting abnormal clustering coefficients.

---

## Dashboard

A Flask + Jinja2 web dashboard renders the full analysis on **port 8060**:

```bash
PYTHONPATH="." python dashboard/app.py
# Opens http://127.0.0.1:8060
```

**Tabs:** Overview · Network Graph · Phase 1 Metrics · Anomaly Thresholds ·
Phase 2 Metrics · Communities · ML Detection · Flagged Nodes

**Upload your own data:** the Overview tab accepts a CSV with columns
`src_ip, dst_ip, proto, bytes_sent, bytes_recv, duration_s, label`.
All metrics recompute on the uploaded dataset live. A sample file is provided
at `sample_upload.csv`.

---

## Phase 1: Foundational Detection Pipeline

### Architecture & Deliverables

| File | Purpose |
| :--- | :--- |
| `config.py` | Central configuration containing tunable thresholds ($k \cdot \sigma$), file paths, and filtering rules. |
| `data_generator.py` | Realistic synthetic NetFlow generator (100–500 nodes) simulating enterprise traffic with injected C2 star botnets, P2P meshes, scanners, and dirty records. |
| `graph_builder.py` | Loads CSV flow logs, filters/cleans invalid/broadcast/multicast/loopback IPs, and builds weighted NetworkX graphs (`nx.DiGraph` / `nx.Graph`). |
| `centrality_metrics.py` | Computes **Degree Centrality** (both hand-coded from first principles and NetworkX), **Closeness Centrality**, and **Clustering Coefficient**. |
| `centrality_phase2.py` | Phase 2 advanced metrics: **Betweenness Centrality**, **Eigenvector Centrality**, **PageRank**, and a **Composite Risk Score** (mean z-score across all five metrics). |
| `community_detection.py` | Greedy modularity community detection with internal/external density ratio scoring; communities with ratio > 1.5 and size ≤ 50 are flagged anomalous. |
| `ml_classification.py` | Random Forest classifier (100 trees) on centrality features, with a heuristic fallback when sklearn is unavailable or labels are degenerate. |

---

## Quick Start

### 1. Run the Dashboard
```bash
PYTHONPATH="." python dashboard/app.py
```

### 2. Generate Sample Data
```bash
python data_generator.py
```

### 3. Customize Thresholds
Tune the $k$-sigma anomaly threshold in `config.py` or `dashboard/app.py`
(default $k=2.0$).

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
   Quantifies neighbor inter-connectivity, distinguishing tightly-knit P2P botnet clusters from sparse normal communications4. **Statistical Anomaly Threshold**:
   $$\text{Threshold}(M) = \mu_M + k \cdot \sigma_M$$
   Where $k$ is tunable (default $k=2.0$). Nodes exceeding the threshold on $\ge 2$ metrics are classified as **High Risk**.

---

## Phase 2 Advanced Metrics

1. **Betweenness Centrality** — identifies bridge nodes whose removal would fragment the network.
2. **Eigenvector Centrality** — identifies nodes connected to other high-influence nodes.
3. **PageRank** — importance scoring treating edges as a random walk.
4. **Composite Risk Score** — mean of the z-scores across all five centrality metrics.

---

## Outputs

- **Dashboard**: interactive charts (Plotly) and tables for every metric, community, and ML prediction.
- **Network Graph**: spring-layout visualization with color-coded risk levels (red = high risk, orange = suspicious, green = normal).
- **Sample dataset**: `data/sample_network_flows.csv` (~400 nodes, ~1574 edges, 30 botnet nodes).