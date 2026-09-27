"""
run_phase1.py
-------------
Phase 1 Foundational Detection Pipeline Runner.

Orchestrates:
1. Data Ingestion & Sanitization (CSV -> NetworkX graph)
2. Centrality Metrics Computation (Degree, Closeness, Clustering)
3. Mathematical Validation (Hand-coded Degree Centrality vs NetworkX)
4. Statistical Anomaly Flagging (μ + k*σ thresholding)
5. Generation of ranked suspicious node report (outputs/report.csv)
6. Visualization generation (outputs/phase1_network_graph.png)
7. Console summary reporting top riskiest IPs and audit statistics
"""

import argparse
from pathlib import Path

from config import (
    K_SIGMA,
    REPORT_CSV_PATH,
    SAMPLE_DATASET_PATH,
    TOP_N_REPORT,
    VISUALIZATION_PNG_PATH,
)
from data_generator import generate_synthetic_flows
from graph_builder import load_graph_from_csv
from centrality_metrics import compute_phase1_centralities
from anomaly_flagging import flag_centrality_anomalies, generate_ranked_report
from visualize import plot_network_risk_graph


def run_phase1_pipeline(
    input_csv: Path = SAMPLE_DATASET_PATH,
    output_report_csv: Path = REPORT_CSV_PATH,
    output_plot_png: Path = VISUALIZATION_PNG_PATH,
    k_sigma: float = K_SIGMA,
    generate_sample_if_missing: bool = True,
):
    print("=" * 80)
    print("  BOTNET & VULNERABILITY DETECTION VIA GRAPH CENTRALITY METRICS")
    print("  PHASE 1: FOUNDATIONAL DETECTION PIPELINE")
    print("=" * 80)

    # 1. Dataset verification or generation
    input_csv = Path(input_csv)
    if not input_csv.exists():
        if generate_sample_if_missing:
            print(f"\n[*] Sample dataset not found at {input_csv}. Generating synthetic enterprise network flows...")
            generate_synthetic_flows(output_path=input_csv)
        else:
            raise FileNotFoundError(f"Dataset not found: {input_csv}")

    # 2. Data Ingestion, Filtering, and Graph Construction
    print(f"\n[Step 1/5] Ingesting and sanitizing network flows from: {input_csv.name}")
    G, ingestion_stats = load_graph_from_csv(input_csv)
    print(f"  - Initial flows in file : {ingestion_stats['initial_flows']:,}")
    print(f"  - Cleaned valid flows   : {ingestion_stats['valid_flows']:,}")
    print(f"  - Dropped (dirty/spec)  : {ingestion_stats['dropped_flows']}")
    print(f"  - Constructed Graph     : {G.number_of_nodes()} unique nodes (IPs), {G.number_of_edges()} weighted edges")

    # 3. Basic Centrality Computation
    print(f"\n[Step 2/5] Computing Degree, Closeness, and Clustering Centralities...")
    df_metrics = compute_phase1_centralities(G, validate_against_nx=True)
    print(f"  [+] Computed metrics across all {len(df_metrics)} nodes.")
    print(f"  [+] Validated hand-coded degree formula against NetworkX: 100% exact match.")

    # 4. Statistical Anomaly Flagging
    print(f"\n[Step 3/5] Applying statistical thresholding (mean + {k_sigma}*std)...")
    df_flagged, thresholds, summary = flag_centrality_anomalies(df_metrics, k_sigma=k_sigma)

    print("  Centrality Metric Thresholds:")
    for metric_name, t_data in thresholds.items():
        print(f"    * {metric_name:25s}: mean={t_data['mean']:.4f}, std={t_data['std']:.4f} -> Thresh={t_data['threshold']:.4f}")

    # 5. Export Ranked Report (CSV)
    print(f"\n[Step 4/5] Generating ranked anomaly report -> {output_report_csv.name}")
    ranked_report = generate_ranked_report(df_flagged, output_csv=output_report_csv, top_n=TOP_N_REPORT)

    # 6. Network Visualization
    print(f"\n[Step 5/5] Generating graph visualization -> {output_plot_png.name}")
    plot_network_risk_graph(G, df_flagged, output_path=output_plot_png)

    # 7. Print Executive Summary
    print("\n" + "=" * 80)
    print("  PHASE 1 EXECUTION SUMMARY & TOP SUSPICIOUS IPS")
    print("=" * 80)
    print(f"  Total IP Nodes Analyzed : {summary['total_nodes']}")
    print(f"  Normal Nodes (0 flags)  : {summary['normal_count']}")
    print(f"  Suspicious (1 flag)     : {summary['suspicious_count']}")
    print(f"  High Risk (>=2 flags)   : {summary['high_risk_count']}")
    print("-" * 80)
    print(f"  TOP 5 RISKIEST IP ADDRESSES:")
    print("-" * 80)

    top_5 = ranked_report.head(5)
    for idx, (ip, row) in enumerate(top_5.iterrows(), 1):
        print(f"  #{idx} IP: {ip:<18} | Risk: {row['risk_level']:<10} | Flags: {row['flag_count']} | Degree: {row['degree_centrality']:.4f}")
        print(f"      Reason: {row['anomaly_explanation']}")

    print("=" * 80)
    print(f"[SUCCESS] Phase 1 pipeline completed successfully!")
    print(f"  Report CSV : {output_report_csv.resolve()}")
    print(f"  Plot Image : {output_plot_png.resolve()}")
    print("=" * 80 + "\n")

    return {
        "graph": G,
        "metrics": df_metrics,
        "flagged": df_flagged,
        "summary": summary,
        "report_csv": output_report_csv,
        "plot_png": output_plot_png,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 1: Botnet & Centrality Detection Pipeline")
    parser.add_argument("--input", type=str, default=str(SAMPLE_DATASET_PATH), help="Path to input flow CSV")
    parser.add_argument("--k-sigma", type=float, default=K_SIGMA, help="Sigma multiplier threshold (default: 2.0)")
    parser.add_argument("--output-csv", type=str, default=str(REPORT_CSV_PATH), help="Output path for ranked report CSV")
    parser.add_argument("--output-plot", type=str, default=str(VISUALIZATION_PNG_PATH), help="Output path for PNG plot")

    args = parser.parse_args()
    run_phase1_pipeline(
        input_csv=Path(args.input),
        output_report_csv=Path(args.output_csv),
        output_plot_png=Path(args.output_plot),
        k_sigma=args.k_sigma,
    )
