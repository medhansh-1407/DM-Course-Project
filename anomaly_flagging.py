"""
anomaly_flagging.py
-------------------
Phase 1 Deliverable:
Statistical Threshold-Based Anomaly Flagging.

Mathematical Logic:
1. Compute the sample mean (μ) and sample standard deviation (σ) for each centrality metric:
       threshold = μ + (k * σ)
   where k is a tunable parameter (typically 2.0 to 3.0, defined in config.py).
2. Any node with metric score exceeding its threshold is flagged for that metric.
3. Combine multi-metric flags:
   - 0 flags: "Normal" (low risk)
   - 1 flag: "Suspicious" (moderate risk)
   - >= 2 flags: "High Risk" (high-confidence anomaly, e.g. C2 hub or scanner)
"""

from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from config import HIGH_RISK_THRESHOLD, K_SIGMA


def compute_metric_thresholds(
    df_metrics: pd.DataFrame,
    metrics: Optional[List[str]] = None,
    k_sigma: float = K_SIGMA,
) -> Dict[str, Dict[str, float]]:
    """
    Calculates the mean (μ), standard deviation (σ), and threshold (μ + k*σ)
    for each designated centrality metric across all network nodes.
    """
    if metrics is None:
        metrics = [
            "degree_centrality",
            "in_degree_centrality",
            "out_degree_centrality",
            "closeness_centrality",
            "clustering_coefficient",
        ]

    thresholds = {}
    for metric in metrics:
        if metric in df_metrics.columns:
            series = df_metrics[metric].astype(float)
            mu = float(series.mean())
            sigma = float(series.std(ddof=1)) if len(series) > 1 else 0.0
            thresh = mu + (k_sigma * sigma)
            thresholds[metric] = {
                "mean": mu,
                "std": sigma,
                "threshold": thresh,
                "k_sigma": k_sigma,
            }

    return thresholds


def flag_centrality_anomalies(
    df_metrics: pd.DataFrame,
    k_sigma: float = K_SIGMA,
    high_risk_threshold: int = HIGH_RISK_THRESHOLD,
    evaluation_metrics: Optional[List[str]] = None,
) -> Tuple[pd.DataFrame, Dict[str, Dict[str, float]], Dict[str, int]]:
    """
    Applies the μ + k*σ statistical thresholding logic to detect anomalies.

    Parameters:
    -----------
    df_metrics : pd.DataFrame
        DataFrame of centrality metrics indexed by IP address.
    k_sigma : float
        Multiplier for standard deviation above the mean.
    high_risk_threshold : int
        Number of flags required to classify a node as "High Risk" (default >= 2).
    evaluation_metrics : List[str], optional
        Specific metrics to use for flag counting. Defaults to Phase 1 metrics.

    Returns:
    --------
    result_df : pd.DataFrame
        Enriched DataFrame with flag columns, total flag count, risk level, and explanations.
    thresholds : Dict
        Dictionary of computed μ, σ, and threshold values per metric.
    summary : Dict
        Summary counts of Normal, Suspicious, and High Risk nodes.
    """
    if df_metrics.empty:
        return df_metrics, {}, {}

    if evaluation_metrics is None:
        # Core Phase 1 centrality metrics evaluated for anomalous spikes
        evaluation_metrics = [
            "degree_centrality",
            "closeness_centrality",
            "clustering_coefficient",
        ]

    thresholds = compute_metric_thresholds(
        df_metrics, metrics=evaluation_metrics, k_sigma=k_sigma
    )

    df_out = df_metrics.copy()
    flag_columns = []

    # Flag individual metrics
    for metric in evaluation_metrics:
        if metric not in thresholds:
            continue

        thresh_val = thresholds[metric]["threshold"]
        flag_col = f"flag_{metric}"
        flag_columns.append(flag_col)

        # Boolean flag: 1 if score > threshold, else 0
        df_out[flag_col] = (df_out[metric] > thresh_val).astype(int)

    # Multi-metric flag aggregation
    df_out["flag_count"] = df_out[flag_columns].sum(axis=1)

    # Assign categorical risk levels
    def categorize_risk(count: int) -> str:
        if count >= high_risk_threshold:
            return "High Risk"
        elif count == 1:
            return "Suspicious"
        else:
            return "Normal"

    df_out["risk_level"] = df_out["flag_count"].apply(categorize_risk)

    # Generate explanatory strings for security analysts
    explanations = []
    for _, row in df_out.iterrows():
        reasons = []
        for metric in evaluation_metrics:
            if metric in thresholds and row.get(f"flag_{metric}", 0) == 1:
                val = row[metric]
                thresh = thresholds[metric]["threshold"]
                std = thresholds[metric]["std"]
                mu = thresholds[metric]["mean"]
                z = (val - mu) / std if std > 0 else 0.0
                reasons.append(f"{metric}={val:.4f} (z={z:.1f} > thresh {thresh:.4f})")

        if reasons:
            explanations.append("; ".join(reasons))
        else:
            explanations.append("Within normal baseline")

    df_out["anomaly_explanation"] = explanations

    # Sort descending by flag count, then degree centrality
    sort_cols = ["flag_count", "degree_centrality"]
    ascending = [False, False]
    df_out = df_out.sort_values(by=sort_cols, ascending=ascending)

    # Summary statistics
    counts = df_out["risk_level"].value_counts().to_dict()
    summary = {
        "total_nodes": len(df_out),
        "normal_count": counts.get("Normal", 0),
        "suspicious_count": counts.get("Suspicious", 0),
        "high_risk_count": counts.get("High Risk", 0),
        "k_sigma_used": k_sigma,
    }

    return df_out, thresholds, summary


def generate_ranked_report(
    df_flagged: pd.DataFrame,
    output_csv: Optional[str] = None,
    top_n: int = 15,
) -> pd.DataFrame:
    """
    Extracts and ranks the top-N most suspicious/risky nodes for reporting.
    """
    # Select prioritized columns for human-readable report
    report_cols = [
        "raw_degree",
        "degree_centrality",
        "closeness_centrality",
        "clustering_coefficient",
        "flag_count",
        "risk_level",
        "anomaly_explanation",
    ]
    # Filter only available columns
    available_cols = [c for c in report_cols if c in df_flagged.columns]
    report_df = df_flagged[available_cols].head(top_n).copy()

    if output_csv:
        report_df.to_csv(output_csv, index=True)

    return report_df


if __name__ == "__main__":
    from data_generator import generate_synthetic_flows
    from graph_builder import load_graph_from_csv
    from centrality_metrics import compute_phase1_centralities

    test_csv = generate_synthetic_flows()
    G, _ = load_graph_from_csv(test_csv)
    metrics_df = compute_phase1_centralities(G)
    flagged_df, thresholds, summary = flag_centrality_anomalies(metrics_df, k_sigma=2.0)

    print("\n--- Centrality Thresholds (mean + 2*std) ---")
    for m, vals in thresholds.items():
        print(f"  {m:25s}: mean={vals['mean']:.4f}, std={vals['std']:.4f} -> Thresh={vals['threshold']:.4f}")

    print("\n--- Detection Summary ---")
    for k, v in summary.items():
        print(f"  {k:20s}: {v}")

    print("\n--- Top 5 Flagged Nodes ---")
    top_report = generate_ranked_report(flagged_df, top_n=5)
    print(top_report[["degree_centrality", "flag_count", "risk_level", "anomaly_explanation"]])
