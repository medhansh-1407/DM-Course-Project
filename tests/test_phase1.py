"""
test_phase1.py
--------------
Unit and integration test suite for Phase 1 of Botnet & Vulnerability Detection.

Tests:
1. IP Validation and Data Cleaning
2. Graph Construction and Attribute Correctness
3. Hand-Coded Degree Centrality vs. NetworkX Reference
4. Closeness Centrality & Clustering Coefficient Computation
5. Statistical Anomaly Flagging (μ + k*σ) Logic
6. End-to-End Pipeline Execution & Deliverables (report.csv, graph plot)
"""

import sys
import unittest
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import networkx as nx
import pandas as pd

from anomaly_flagging import compute_metric_thresholds, flag_centrality_anomalies
from centrality_metrics import (
    compute_degree_centrality_manual,
    compute_phase1_centralities,
)
from config import REPORT_CSV_PATH, VISUALIZATION_PNG_PATH
from data_generator import generate_synthetic_flows
from graph_builder import build_network_graph, is_valid_ip, load_and_clean_flows
from run_phase1 import run_phase1_pipeline


class TestPhase1Pipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_data_dir = Path(__file__).resolve().parent / "test_data"
        cls.test_data_dir.mkdir(parents=True, exist_ok=True)
        cls.test_csv = cls.test_data_dir / "test_flows.csv"
        # Generate smaller synthetic dataset for speedy unit testing
        generate_synthetic_flows(
            output_path=cls.test_csv,
            num_normal_hosts=50,
            num_bot_nodes=10,
            num_p2p_bots=6,
            num_scanners=1,
            seed=123,
        )

    def test_ip_validation(self):
        """Verify that malformed, broadcast, loopback, and multicast IPs are correctly rejected."""
        self.assertTrue(is_valid_ip("192.168.1.100"))
        self.assertTrue(is_valid_ip("8.8.8.8"))
        self.assertTrue(is_valid_ip("203.0.113.195"))

        # Invalid or dirty
        self.assertFalse(is_valid_ip("255.255.255.255"))  # Broadcast
        self.assertFalse(is_valid_ip("0.0.0.0"))          # Unspecified
        self.assertFalse(is_valid_ip("127.0.0.1"))        # Loopback
        self.assertFalse(is_valid_ip("224.0.0.1"))        # Multicast
        self.assertFalse(is_valid_ip("not_an_ip"))        # Malformed
        self.assertFalse(is_valid_ip("999.999.999.999"))  # Out of range

    def test_data_cleaning_and_graph_construction(self):
        """Verify that flow CSV is properly ingested, cleaned, and converts to a valid graph."""
        cleaned_df, stats = load_and_clean_flows(self.test_csv)
        self.assertGreater(stats["valid_flows"], 0)
        self.assertGreater(stats["dropped_flows"], 0)  # Should catch injected dirty rows

        G = build_network_graph(cleaned_df, directed=True)
        self.assertGreater(G.number_of_nodes(), 40)
        self.assertGreater(G.number_of_edges(), 50)

        # Check edge weights and node attributes
        sample_u, sample_v = list(G.edges())[0]
        self.assertIn("weight", G[sample_u][sample_v])
        self.assertIn("flow_count", G[sample_u][sample_v])
        self.assertIn("in_flows", G.nodes[sample_u])

    def test_hand_coded_vs_networkx_degree_centrality(self):
        """
        Critical Success Criterion:
        Validate that custom hand-coded degree centrality matches NetworkX library values exactly.
        """
        cleaned_df, _ = load_and_clean_flows(self.test_csv)
        G = build_network_graph(cleaned_df, directed=True)

        manual_deg = compute_degree_centrality_manual(G)
        nx_deg = nx.degree_centrality(G)

        self.assertEqual(len(manual_deg), len(nx_deg))
        for node in G.nodes():
            self.assertAlmostEqual(
                manual_deg[node],
                nx_deg[node],
                places=7,
                msg=f"Discrepancy in degree centrality for node {node}",
            )

    def test_centrality_metrics_dataframe(self):
        """Verify computation of all Phase 1 metrics (Degree, Closeness, Clustering)."""
        cleaned_df, _ = load_and_clean_flows(self.test_csv)
        G = build_network_graph(cleaned_df, directed=True)

        df_metrics = compute_phase1_centralities(G)
        self.assertEqual(len(df_metrics), G.number_of_nodes())

        expected_cols = [
            "raw_degree",
            "degree_centrality",
            "in_degree_centrality",
            "out_degree_centrality",
            "closeness_centrality",
            "clustering_coefficient",
        ]
        for col in expected_cols:
            self.assertIn(col, df_metrics.columns)
            # Scores should be non-negative
            self.assertTrue((df_metrics[col] >= 0.0).all())

    def test_statistical_anomaly_flagging(self):
        """Verify mu + k*sigma thresholding logic and risk categorization."""
        cleaned_df, _ = load_and_clean_flows(self.test_csv)
        G = build_network_graph(cleaned_df, directed=True)
        df_metrics = compute_phase1_centralities(G)

        k = 2.0
        df_flagged, thresholds, summary = flag_centrality_anomalies(df_metrics, k_sigma=k)

        # Ensure thresholds were calculated
        self.assertIn("degree_centrality", thresholds)
        t_deg = thresholds["degree_centrality"]
        self.assertAlmostEqual(t_deg["threshold"], t_deg["mean"] + k * t_deg["std"], places=5)

        # Check risk categories
        self.assertIn("risk_level", df_flagged.columns)
        self.assertIn("flag_count", df_flagged.columns)
        valid_risk_levels = {"Normal", "Suspicious", "High Risk"}
        self.assertTrue(set(df_flagged["risk_level"].unique()).issubset(valid_risk_levels))

        # Check known malicious C2 hub (203.0.113.195) is flagged
        if "203.0.113.195" in df_flagged.index:
            c2_row = df_flagged.loc["203.0.113.195"]
            self.assertGreaterEqual(c2_row["flag_count"], 1)

    def test_end_to_end_phase1_runner(self):
        """Verify complete pipeline execution and deliverable artifact generation."""
        out_report = self.test_data_dir / "test_report.csv"
        out_plot = self.test_data_dir / "test_graph.png"

        results = run_phase1_pipeline(
            input_csv=self.test_csv,
            output_report_csv=out_report,
            output_plot_png=out_plot,
            k_sigma=2.0,
        )

        self.assertTrue(out_report.exists())
        self.assertTrue(out_plot.exists())
        self.assertGreater(out_report.stat().st_size, 100)
        self.assertGreater(out_plot.stat().st_size, 1000)

        # Verify CSV contents
        report_df = pd.read_csv(out_report)
        self.assertGreater(len(report_df), 0)
        self.assertIn("degree_centrality", report_df.columns)
        self.assertIn("risk_level", report_df.columns)


if __name__ == "__main__":
    unittest.main()
