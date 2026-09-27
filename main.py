"""
main.py
-------
Main entry point for running the Botnet & Vulnerability Detection project.

Usage:
    python main.py              # Runs Phase 1 with default sample dataset
    python main.py --test       # Runs the automated test suite
    python main.py --generate   # Generates a fresh synthetic NetFlow dataset
    python main.py --input file.csv --k-sigma 2.5  # Custom flow dataset and threshold
"""

import argparse
import sys
import unittest
from pathlib import Path

from config import (
    K_SIGMA,
    REPORT_CSV_PATH,
    SAMPLE_DATASET_PATH,
    VISUALIZATION_PNG_PATH,
)
from data_generator import generate_synthetic_flows
from run_phase1 import run_phase1_pipeline


def main():
    parser = argparse.ArgumentParser(
        description="Botnet & Vulnerability Detection via Graph Centrality Metrics"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run unit and mathematical validation tests",
    )
    parser.add_argument(
        "--generate",
        action="store_true",
        help="Generate a new synthetic network flow dataset",
    )
    parser.add_argument(
        "--input",
        type=str,
        default=str(SAMPLE_DATASET_PATH),
        help="Path to input network flow CSV (default: data/sample_network_flows.csv)",
    )
    parser.add_argument(
        "--k-sigma",
        type=float,
        default=K_SIGMA,
        help="Anomaly threshold multiplier k (default: 2.0)",
    )
    parser.add_argument(
        "--output-csv",
        type=str,
        default=str(REPORT_CSV_PATH),
        help="Path for generated report CSV (default: outputs/report.csv)",
    )
    parser.add_argument(
        "--output-plot",
        type=str,
        default=str(VISUALIZATION_PNG_PATH),
        help="Path for output graph image (default: outputs/phase1_network_graph.png)",
    )

    args = parser.parse_args()

    # Option 1: Run tests
    if args.test:
        print("[*] Running automated test suite...")
        loader = unittest.TestLoader()
        suite = loader.discover("tests")
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)

    # Option 2: Generate dataset
    if args.generate:
        print("[*] Generating fresh synthetic network flow dataset...")
        path = generate_synthetic_flows(output_path=Path(args.input))
        print(f"[+] Dataset saved to: {path.resolve()}")
        sys.exit(0)

    # Option 3: Run Phase 1 Detection Pipeline
    run_phase1_pipeline(
        input_csv=Path(args.input),
        output_report_csv=Path(args.output_csv),
        output_plot_png=Path(args.output_plot),
        k_sigma=args.k_sigma,
    )


if __name__ == "__main__":
    main()
