#!/usr/bin/env python3
"""Benchmark regression detection for CI.

Compares current benchmark results against a baseline and fails if performance
regresses beyond configured thresholds.

Usage:
    python scripts/benchmark_regression.py --current results.json --baseline baseline.json
    python scripts/benchmark_regression.py --current results.json --baseline baseline.json --threshold 0.15
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load_json(filepath: Path) -> dict[str, Any]:
    """Load JSON file."""
    with open(filepath) as f:
        return json.load(f)


def compare_metrics(
    current: dict[str, Any],
    baseline: dict[str, Any],
    threshold: float = 0.15,  # 15% regression allowed
) -> tuple[bool, list[str]]:
    """
    Compare current metrics against baseline.

    Returns (passed, failures_list).
    """
    failures = []

    # Compare overall metrics
    current_overall = current.get("overall", {})
    baseline_overall = baseline.get("overall", {})

    metrics_to_check = [
        ("avg_duration", "Average Duration"),
        ("p95_duration", "P95 Duration"),
        ("p99_duration", "P99 Duration"),
        ("error_rate", "Error Rate"),
    ]

    for metric_key, metric_name in metrics_to_check:
        current_val = current_overall.get(metric_key, 0)
        baseline_val = baseline_overall.get(metric_key, 0)

        if baseline_val > 0:
            regression = (current_val - baseline_val) / baseline_val
            if regression > threshold:
                failures.append(
                    f"{metric_name}: {current_val:.2f} vs baseline {baseline_val:.2f} "
                    f"({regression*100:.1f}% regression, threshold: {threshold*100:.1f}%)"
                )

    # Compare per-scenario metrics
    current_scenarios = current.get("scenarios", {})
    baseline_scenarios = baseline.get("scenarios", {})

    for scenario_name in current_scenarios:
        if scenario_name not in baseline_scenarios:
            continue  # New scenario, no baseline

        current_scenario = current_scenarios[scenario_name]
        baseline_scenario = baseline_scenarios[scenario_name]

        # Skip if either has error
        if "error" in current_scenario or "error" in baseline_scenario:
            continue

        for metric_key, metric_name in metrics_to_check:
            current_val = current_scenario.get(metric_key, 0)
            baseline_val = baseline_scenario.get(metric_key, 0)

            if baseline_val > 0:
                regression = (current_val - baseline_val) / baseline_val
                if regression > threshold:
                    failures.append(
                        f"[{scenario_name}] {metric_name}: {current_val:.2f} vs baseline {baseline_val:.2f} "
                        f"({regression*100:.1f}% regression, threshold: {threshold*100:.1f}%)"
                    )

    # Check for success rate regression
    for scenario_name in current_scenarios:
        if scenario_name not in baseline_scenarios:
            continue

        current_scenario = current_scenarios[scenario_name]
        baseline_scenario = baseline_scenarios[scenario_name]

        if "error" in current_scenario or "error" in baseline_scenario:
            continue

        # Calculate success rate from error rate
        current_success = 1.0 - current_scenario.get("error_rate", 0)
        baseline_success = 1.0 - baseline_scenario.get("error_rate", 0)

        if baseline_success > 0:
            regression = (baseline_success - current_success) / baseline_success
            if regression > threshold:
                failures.append(
                    f"[{scenario_name}] Success Rate: {current_success*100:.1f}% "
                    f"vs baseline {baseline_success*100:.1f}% "
                    f"({regression*100:.1f}% regression, threshold: {threshold*100:.1f}%)"
                )

    return len(failures) == 0, failures


def compare_k6_results(
    current_file: Path,
    baseline_file: Path,
    threshold: float = 0.15,
) -> int:
    """Compare k6 benchmark results against baseline."""

    if not current_file.exists():
        print(f"ERROR: Current results file not found: {current_file}")
        return 2

    if not baseline_file.exists():
        print(f"ERROR: Baseline file not found: {baseline_file}")
        print("Run with --create-baseline to create initial baseline")
        return 2

    current = load_json(current_file)
    baseline = load_json(baseline_file)

    print(f"Comparing {current_file} against baseline {baseline_file}")
    print(f"Regression threshold: {threshold*100:.1f}%")
    print()

    passed, failures = compare_metrics(current, baseline, threshold)

    if failures:
        print("❌ REGRESSION DETECTED:")
        for failure in failures:
            print(f"  - {failure}")
        print()
        return 1

    print("✅ NO REGRESSION: All metrics within threshold")
    return 0


def create_baseline(current_file: Path, baseline_file: Path) -> int:
    """Create baseline from current results."""
    if not current_file.exists():
        print(f"ERROR: Current results file not found: {current_file}")
        return 2

    current = load_json(current_file)
    baseline_file.parent.mkdir(parents=True, exist_ok=True)
    baseline_file.write_text(json.dumps(current, indent=2))
    print(f"✅ Baseline created at {baseline_file}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark regression detection for CI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compare current results against baseline
  python scripts/benchmark_regression.py \\
    --current benchmark-results.json --baseline baseline.json

  # Create initial baseline
  python scripts/benchmark_regression.py \\
    --current benchmark-results.json --baseline baseline.json --create-baseline

  # Custom threshold (20% regression allowed)
  python scripts/benchmark_regression.py \\
    --current benchmark-results.json --baseline baseline.json --threshold 0.20
        """,
    )

    parser.add_argument(
        "--current",
        type=Path,
        required=True,
        help="Current benchmark results JSON file",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        required=True,
        help="Baseline benchmark results JSON file",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.15,
        help="Regression threshold as fraction (default: 0.15 = 15%%)",
    )
    parser.add_argument(
        "--create-baseline",
        action="store_true",
        help="Create baseline from current results instead of comparing",
    )

    args = parser.parse_args()

    if args.create_baseline:
        return create_baseline(args.current, args.baseline)

    return compare_k6_results(args.current, args.baseline, args.threshold)


if __name__ == "__main__":
    sys.exit(main())
