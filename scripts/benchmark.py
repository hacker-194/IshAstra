#!/usr/bin/env python3
"""Benchmark runner for Strix load/stress testing.

This script wraps k6 to run load tests and generates JSON output for CI integration.

Usage:
    python scripts/benchmark.py --scenario smoke
    python scripts/benchmark.py --scenario load --base-url http://localhost:8000 --api-key $KEY
    python scripts/benchmark.py --all --output results.json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SCENARIOS = {
    "smoke": "Quick validation (1 VU, 30s)",
    "load": "Sustained load (50 VU, 5m with ramp)",
    "stress": "Find breaking point (200 VU, 10m)",
    "soak": "Long-running stability (100 VU, 1h)",
    "spike": "Sudden burst (500 VU, 50s)",
}


def check_k6_available() -> bool:
    """Check if k6 is installed and available."""
    return shutil.which("k6") is not None


def install_k6() -> bool:
    """Attempt to install k6 on Linux."""
    print("k6 not found. Attempting to install...")
    try:
        # Try apt-get (Debian/Ubuntu)
        subprocess.run(["sudo", "apt-get", "update"], check=False, capture_output=True)
        subprocess.run(["sudo", "apt-get", "install", "-y", "k6"], check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    try:
        # Try snap
        subprocess.run(["sudo", "snap", "install", "k6"], check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return False


def run_k6_scenario(
    scenario: str,
    base_url: str,
    api_key: str,
    tenant_id: str,
    output_file: Path,
    k6_script: Path,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Run a single k6 scenario and return parsed results."""

    test_env = os.environ.copy()
    test_env.update(
        {
            "BASE_URL": base_url,
            "STRIX_API_KEY": api_key,
            "TENANT_ID": tenant_id,
            "K6_SCENARIO": scenario,
        }
    )
    if env:
        test_env.update(env)

    # Build k6 command
    cmd = [
        "k6",
        "run",
        "--scenario",
        scenario,
        "--out",
        f"json={output_file}",
        "--summary-export",
        str(output_file.with_suffix(".summary.json")),
        str(k6_script),
    ]

    print(f"Running {scenario} scenario...")
    print(f"  Command: {' '.join(cmd)}")
    print(f"  Base URL: {base_url}")

    try:
        result = subprocess.run(
            cmd,
            env=test_env,
            capture_output=True,
            text=True,
            timeout=7200,  # 2 hours max (for soak test)
        )

        stdout = result.stdout
        stderr = result.stderr

        if result.returncode != 0:
            print(f"k6 exited with code {result.returncode}")
            print(f"STDOUT:\n{stdout}")
            print(f"STDERR:\n{stderr}")

        # Try to read the JSON output
        if output_file.exists():
            with open(output_file) as f:
                # k6 outputs JSON lines, we need the last complete object
                lines = f.readlines()
                for line in reversed(lines):
                    line = line.strip()
                    if line:
                        try:
                            return json.loads(line)
                        except json.JSONDecodeError:
                            continue

        # Fallback: parse from summary export
        summary_file = output_file.with_suffix(".summary.json")
        if summary_file.exists():
            with open(summary_file) as f:
                return json.load(f)

        return {
            "scenario": scenario,
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "error": "No output file generated",
        }

    except subprocess.TimeoutExpired:
        return {
            "scenario": scenario,
            "error": "Timeout (exceeded 2 hours)",
        }
    except Exception as e:
        return {
            "scenario": scenario,
            "error": str(e),
        }


def parse_k6_summary(summary_file: Path) -> dict[str, Any]:
    """Parse k6 summary JSON export."""
    try:
        with open(summary_file) as f:
            return json.load(f)
    except Exception:
        return {}


def generate_report(results: dict[str, Any], output_file: Path) -> None:
    """Generate a human-readable report from results."""
    report_lines = [
        "# Strix Benchmark Results",
        f"Generated: {results.get('timestamp', 'N/A')}",
        f"Base URL: {results.get('base_url', 'N/A')}",
        "",
        "## Scenario Results",
        "",
    ]

    for scenario, data in results.get("scenarios", {}).items():
        report_lines.append(f"### {scenario.upper()}")
        report_lines.append(f"- **Description**: {SCENARIOS.get(scenario, 'N/A')}")

        if "error" in data:
            report_lines.append(f"- **Status**: FAILED - {data['error']}")
        else:
            report_lines.append(f"- **Status**: {'PASSED' if data.get('exit_code', 1) == 0 else 'FAILED'}")
            report_lines.append(f"- **VUs (max)**: {data.get('vus', 'N/A')}")
            report_lines.append(f"- **Iterations**: {data.get('iterations', 'N/A')}")
            report_lines.append(f"- **Avg Duration**: {data.get('avg_duration', 0):.2f} ms")
            report_lines.append(f"- **P95 Duration**: {data.get('p95_duration', 0):.2f} ms")
            report_lines.append(f"- **P99 Duration**: {data.get('p99_duration', 0):.2f} ms")
            report_lines.append(f"- **Error Rate**: {data.get('error_rate', 0) * 100:.2f}%")

        report_lines.append("")

    # Overall summary
    overall = results.get("overall", {})
    report_lines.extend(
        [
            "## Overall Summary",
            "",
            f"- **Total Requests**: {overall.get('total_requests', 0)}",
            f"- **Failed Requests**: {overall.get('failed_requests', 0)}",
            f"- **Avg Duration**: {overall.get('avg_duration', 0):.2f} ms",
            f"- **P95 Duration**: {overall.get('p95_duration', 0):.2f} ms",
            f"- **P99 Duration**: {overall.get('p99_duration', 0):.2f} ms",
            "",
        ]
    )

    # Threshold assessment
    report_lines.append("## Threshold Assessment")
    report_lines.append("")

    thresholds = {
        "smoke": {"p95": 500, "p99": 1000, "error_rate": 0.01, "success_rate": 0.99},
        "load": {"p95": 2000, "p99": 5000, "error_rate": 0.01, "success_rate": 0.95},
        "stress": {"p95": 5000, "p99": 10000, "error_rate": 0.01, "success_rate": 0.90},
        "soak": {"p95": 2000, "p99": 5000, "error_rate": 0.01, "success_rate": 0.95},
        "spike": {"p95": 10000, "p99": 15000, "error_rate": 0.01, "success_rate": 0.85},
    }

    for scenario, data in results.get("scenarios", {}).items():
        if "error" in data:
            report_lines.append(f"- **{scenario}**: SKIPPED ({data['error']})")
            continue

        t = thresholds.get(scenario, {})
        p95 = data.get("p95_duration", float("inf"))
        p99 = data.get("p99_duration", float("inf"))
        error_rate = data.get("error_rate", 1.0)

        passed = (
            p95 <= t.get("p95", float("inf"))
            and p99 <= t.get("p99", float("inf"))
            and error_rate <= t.get("error_rate", 0.0)
        )

        status = "✅ PASS" if passed else "❌ FAIL"
        report_lines.append(f"- **{scenario}**: {status}")
        report_lines.append(f"  - P95: {p95:.0f}ms (thresh: {t.get('p95', 'N/A')}ms)")
        report_lines.append(f"  - P99: {p99:.0f}ms (thresh: {t.get('p99', 'N/A')}ms)")
        err_thresh = t.get("error_rate", 0) * 100
        report_lines.append(f"  - Error Rate: {error_rate * 100:.2f}% (thresh: {err_thresh:.2f}%)")

    report_content = "\n".join(report_lines)

    # Write markdown report
    report_file = output_file.with_suffix(".md")
    report_file.write_text(report_content)
    print(f"\nReport written to: {report_file}")

    # Also print to stdout
    print("\n" + "=" * 60)
    print(report_content)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Strix load/stress benchmarks using k6",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Scenarios:
  smoke   - {SCENARIOS["smoke"]}
  load    - {SCENARIOS["load"]}
  stress  - {SCENARIOS["stress"]}
  soak    - {SCENARIOS["soak"]}
  spike   - {SCENARIOS["spike"]}

Environment variables:
  BASE_URL       - Target API URL (default: http://localhost:8000)
  STRIX_API_KEY  - API key for authenticated endpoints
  TENANT_ID      - Tenant ID for multi-tenant testing

Examples:
  python scripts/benchmark.py --scenario smoke
  python scripts/benchmark.py --scenario load --base-url https://strix.example.com
  python scripts/benchmark.py --all --output benchmark-results.json
        """,
    )

    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()) + ["all"],
        default="smoke",
        help="Benchmark scenario to run (default: smoke)",
    )
    parser.add_argument(
        "--base-url",
        default=os.environ.get("BASE_URL", "http://localhost:8000"),
        help="Base URL of the Strix API",
    )
    parser.add_argument(
        "--api-key",
        default=os.environ.get("STRIX_API_KEY", "test-admin-key-123456"),
        help="API key for authenticated requests",
    )
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("TENANT_ID", "test-tenant"),
        help="Tenant ID for multi-tenant testing",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmark-results.json"),
        help="Output JSON file for results",
    )
    parser.add_argument(
        "--k6-script",
        type=Path,
        default=Path(__file__).parent / "benchmark.js",
        help="Path to k6 script",
    )
    parser.add_argument(
        "--install-k6",
        action="store_true",
        help="Attempt to install k6 if not found",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Skip generating markdown report",
    )

    args = parser.parse_args()

    # Check k6 availability
    if not check_k6_available():
        if args.install_k6:
            if not install_k6():
                print("ERROR: Failed to install k6. Please install manually:")
                print("  https://k6.io/docs/getting-started/installation/")
                return 1
        else:
            print("ERROR: k6 not found. Install it first:")
            print("  https://k6.io/docs/getting-started/installation/")
            print("Or run with --install-k6 to attempt automatic installation")
            return 1

    # Verify k6 script exists
    k6_script = args.k6_script.resolve()
    if not k6_script.exists():
        print(f"ERROR: k6 script not found: {k6_script}")
        return 1

    # Determine scenarios to run
    scenarios = list(SCENARIOS.keys()) if args.scenario == "all" else [args.scenario]

    # Run scenarios
    all_results = {
        "timestamp": __import__("datetime").datetime.now().isoformat(),
        "base_url": args.base_url,
        "scenarios": {},
        "overall": {
            "total_requests": 0,
            "failed_requests": 0,
            "avg_duration": 0,
            "p95_duration": 0,
            "p99_duration": 0,
        },
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        for scenario in scenarios:
            output_file = tmpdir_path / f"{scenario}-results.json"
            result = run_k6_scenario(
                scenario=scenario,
                base_url=args.base_url,
                api_key=args.api_key,
                tenant_id=args.tenant_id,
                output_file=output_file,
                k6_script=k6_script,
            )

            all_results["scenarios"][scenario] = result

            # Aggregate overall metrics
            if "error" not in result:
                all_results["overall"]["total_requests"] += result.get("iterations", 0)

        # Save combined results
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)

        print(f"\nResults saved to: {args.output}")

        # Generate report
        if not args.no_report:
            generate_report(all_results, args.output)

    # Determine exit code
    failed = any("error" in r or r.get("exit_code", 1) != 0 for r in all_results["scenarios"].values())

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
