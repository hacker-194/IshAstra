"""Detection benchmark for Ishastra: deterministic, reproducible evaluation against
the loopback lab target.

This script runs the oracle-based detection evaluation (python -m ishastra.lab)
and outputs structured JSON results that can be compared across runs.

It measures detection rates for common vulnerability classes:
- XSS (reflection indicator)
- Open Redirect
- SQLi (error indicator)
- Git config exposure
- Missing CSP
- Open TCP port

Usage:
    python scripts/detection_benchmark.py [--output results.json] [--min-precision 1.0] [--min-recall 1.0]
    python scripts/detection_benchmark.py --workflow web,network --output results.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ishastra.lab.evaluate import EvaluationRun, run_evaluation

VULNERABILITY_CLASSES = [
    "xss",
    "open_redirect",
    "sqli_error_indicator",
    "git-config",
    "git_config_exposed",
    "missing_csp",
    "open_tcp_port",
]


def build_class_breakdown(run: EvaluationRun, oracle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build per-vulnerability-class breakdown from evaluation results."""
    cases = oracle.get("cases", [])
    class_map: dict[str, dict[str, Any]] = {}

    for vuln_class in VULNERABILITY_CLASSES:
        class_map[vuln_class] = {
            "positives_expected": 0,
            "positives_measured": 0,
            "true_positives": 0,
            "false_negatives": 0,
            "false_positives": 0,
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
            "cases": [],
        }

    for case in cases:
        category = case.get("category", "")
        categories = category if isinstance(category, list) else [category]

        for cat in categories:
            if cat not in class_map:
                class_map[cat] = {
                    "positives_expected": 0,
                    "positives_measured": 0,
                    "true_positives": 0,
                    "false_negatives": 0,
                    "false_positives": 0,
                    "precision": 1.0,
                    "recall": 1.0,
                    "f1": 1.0,
                    "cases": [],
                }

            expect = case.get("expect", False)
            case_id = case["id"]
            assigned = run.assigned.get(case_id, [])

            unmeasured_case_ids = run.metrics.get("unmeasured_cases", [])
            is_measured = case_id not in unmeasured_case_ids

            class_map[cat]["cases"].append(
                {
                    "case_id": case_id,
                    "expect": expect,
                    "measured": is_measured if expect else True,
                    "findings_count": len(assigned),
                    "verification_levels": [f.verification for f in assigned],
                }
            )

            if expect:
                class_map[cat]["positives_expected"] += 1
                if is_measured:
                    class_map[cat]["positives_measured"] += 1
                    if assigned:
                        class_map[cat]["true_positives"] += 1
                    else:
                        class_map[cat]["false_negatives"] += 1
            else:
                if assigned and is_measured:
                    class_map[cat]["false_positives"] += 1

    for _cat, data in class_map.items():
        tp = data["true_positives"]
        fp = data["false_positives"]
        fn = data["false_negatives"]
        measured_positives = data["positives_measured"]

        precision = (tp / (tp + fp)) if (tp + fp) else (1.0 if fn == 0 else 0.0)
        recall = (tp / measured_positives) if measured_positives else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

        data["precision"] = round(precision, 4)
        data["recall"] = round(recall, 4)
        data["f1"] = round(f1, 4)

    return class_map


def build_detector_breakdown(run: EvaluationRun, oracle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Build per-detector breakdown from evaluation results."""
    detector_map: dict[str, dict[str, Any]] = {}

    for case_id, findings in run.assigned.items():
        for finding in findings:
            detector = finding.detector
            if detector not in detector_map:
                detector_map[detector] = {
                    "findings": 0,
                    "true_positives": 0,
                    "false_positives": 0,
                    "categories": set(),
                    "verification_levels": set(),
                }

            detector_map[detector]["findings"] += 1
            detector_map[detector]["categories"].add(finding.category)
            detector_map[detector]["verification_levels"].add(finding.verification)

            case = next((c for c in oracle.get("cases", []) if c["id"] == case_id), None)
            if case and case.get("expect") is True:
                detector_map[detector]["true_positives"] += 1
            elif case and case.get("expect") is False:
                detector_map[detector]["false_positives"] += 1

    for _detector, data in detector_map.items():
        data["categories"] = sorted(data["categories"])
        data["verification_levels"] = sorted(data["verification_levels"])

    return detector_map


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="python scripts/detection_benchmark.py",
        description="Run deterministic detection benchmark against the Ishastra loopback lab.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/detection_benchmark.py --output results.json

  python scripts/detection_benchmark.py --workflow web,network --output results.json

  python scripts/detection_benchmark.py --include-nuclei --include-nmap --output results.json

  python scripts/detection_benchmark.py --allow-unmeasured --output results.json
        """,
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path("detection-benchmark-results.json"),
        help="Output JSON file for results (default: detection-benchmark-results.json)",
    )
    parser.add_argument(
        "--min-precision",
        type=float,
        default=1.0,
        help="Minimum precision threshold (default: 1.0)",
    )
    parser.add_argument(
        "--min-recall",
        type=float,
        default=1.0,
        help="Minimum recall threshold (default: 1.0)",
    )
    parser.add_argument(
        "--no-nuclei",
        action="store_true",
        help="Skip the nuclei adapter (offline runs)",
    )
    parser.add_argument(
        "--include-nuclei",
        action="store_true",
        help="Include the nuclei adapter (default: false)",
    )
    parser.add_argument(
        "--no-nmap",
        action="store_true",
        help="Skip the nmap adapter",
    )
    parser.add_argument(
        "--include-nmap",
        action="store_true",
        help="Include the nmap adapter (default: false)",
    )
    parser.add_argument(
        "--nuclei-subset",
        default="http/exposures/configs",
        help="Comma-separated template subset for nuclei (default: http/exposures/configs)",
    )
    parser.add_argument(
        "--workflow",
        default="",
        help="Comma-separated profiles to run as production jobs (e.g., web,network)",
    )
    parser.add_argument(
        "--allow-unmeasured",
        action="store_true",
        help="Exit 0 even when some oracle cases could not be measured",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print benchmark version and exit",
    )

    args = parser.parse_args()

    if args.version:
        print("Ishastra Detection Benchmark v1.1.0 (oracle 1.1.0)")
        return 0

    include_nuclei = args.include_nuclei and not args.no_nuclei
    include_nmap = args.include_nmap and not args.no_nmap

    subset = tuple(s.strip() for s in args.nuclei_subset.split(",") if s.strip())
    workflows = tuple(s.strip() for s in args.workflow.split(",") if s.strip())

    print("Starting detection benchmark...")
    print(f"  Include nuclei: {include_nuclei}")
    print(f"  Include nmap: {include_nmap}")
    print(f"  Nuclei subset: {subset}")
    print(f"  Workflow profiles: {workflows}")
    print(f"  Min precision: {args.min_precision}")
    print(f"  Min recall: {args.min_recall}")
    print(f"  Allow unmeasured: {args.allow_unmeasured}")

    try:
        run: EvaluationRun = run_evaluation(
            include_nuclei=include_nuclei,
            include_nmap=include_nmap,
            nuclei_subset=subset,
            workflow_profiles=workflows,
        )
    except Exception as exc:
        print(f"ERROR: Evaluation failed: {exc}", file=sys.stderr)
        return 2

    from ishastra.lab.evaluate import load_oracle

    oracle = load_oracle()

    class_breakdown = build_class_breakdown(run, oracle)
    detector_breakdown = build_detector_breakdown(run, oracle)

    result = {
        "benchmark_version": "1.1.0",
        "oracle_version": run.oracle_version,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "duration_s": round(run.duration_s, 2),
        "tools": run.tools,
        "detectors_run": run.detectors_run,
        "detectors_unavailable": run.detectors_unavailable,
        "workflows": run.workflows,
        "overall_metrics": run.metrics,
        "vulnerability_class_breakdown": class_breakdown,
        "detector_breakdown": detector_breakdown,
        "cases": [
            {
                "case_id": case_id,
                "findings": [f.to_dict() for f in findings],
            }
            for case_id, findings in run.assigned.items()
        ],
        "unmatched_findings": [f.to_dict() for f in run.unmatched],
        "notes": run.notes,
    }

    metrics = run.metrics
    threshold_passed = True
    threshold_failures = []

    if metrics.get("precision", 0) < args.min_precision:
        threshold_passed = False
        threshold_failures.append(f"precision {metrics['precision']} < {args.min_precision}")
    if metrics.get("recall", 0) < args.min_recall:
        threshold_passed = False
        threshold_failures.append(f"recall {metrics['recall']} < {args.min_recall}")
    if metrics.get("verification_violations"):
        threshold_passed = False
        threshold_failures.append(
            f"{len(metrics['verification_violations'])} verification level violation(s)"
        )
    if not metrics.get("coverage_complete", True) and not args.allow_unmeasured:
        threshold_passed = False
        threshold_failures.append(f"coverage incomplete: {metrics.get('unmeasured_cases', [])}")

    result["threshold_assessment"] = {
        "passed": threshold_passed,
        "failures": threshold_failures,
        "min_precision": args.min_precision,
        "min_recall": args.min_recall,
        "allow_unmeasured": args.allow_unmeasured,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"\nResults written to: {args.output}")

    print("\n" + "=" * 60)
    print("DETECTION BENCHMARK SUMMARY")
    print("=" * 60)
    print(f"Oracle version: {run.oracle_version}")
    print(f"Duration: {run.duration_s:.1f}s")
    print(f"Tools: {', '.join(f'{k} {v}' for k, v in run.tools.items()) or 'none'}")
    print(
        f"Precision: {metrics.get('precision')} | "
        f"Recall: {metrics.get('recall')} | "
        f"F1: {metrics.get('f1')} | "
        f"FP rate: {metrics.get('false_positive_rate')}"
    )
    print(
        f"TP: {metrics.get('true_positives')}/{metrics.get('total_positives')}, "
        f"FP: {metrics.get('false_positives')}, "
        f"FN: {metrics.get('false_negatives')}"
    )

    unmeasured = metrics.get("unmeasured_cases") or []
    if unmeasured:
        print(f"COVERAGE INCOMPLETE — not measured: {', '.join(unmeasured)}")

    unavailable = run.detectors_unavailable
    if unavailable:
        for name, reason in sorted(unavailable.items()):
            print(f"Detector unavailable: {name} ({reason})")

    if run.workflows:
        print("Workflow scans: " + ", ".join(f"{item['profile']}={item['state']}" for item in run.workflows))

    print("\nPer-class breakdown:")
    for cat, data in sorted(class_breakdown.items()):
        if data["positives_expected"] > 0 or data["false_positives"] > 0:
            print(
                f"  {cat}: TP={data['true_positives']}, FP={data['false_positives']}, "
                f"FN={data['false_negatives']}, P={data['precision']}, R={data['recall']}, F1={data['f1']}"
            )

    print("\nThreshold assessment:")
    if threshold_passed:
        print("  PASSED: All thresholds satisfied.")
        return 0
    print(f"  FAILED: {'; '.join(threshold_failures)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
