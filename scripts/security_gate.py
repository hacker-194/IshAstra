"""Fail-closed evaluation of downloaded security scanner reports.

Used by the `security-gate` CI job. A missing, empty, unreadable or malformed
report is a FAILURE, never "zero findings". A scanner may only be absent when
it is explicitly listed as optional, and any exception must name an owner, a
justification, a tracking issue and an expiry date.

Usage:
    python scripts/security_gate.py [--exceptions exceptions.json] [--json]

Exit codes: 0 = pass (or pass-with-exception / optional skipped), 1 = fail.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import date
from pathlib import Path
from typing import Any

DEFAULT_REPORTS = {
    "bandit": "security-reports/bandit-results.json",
    "pip-audit": "security-reports/pip-audit-results.json",
    "grype": "grype-results/grype-results.json",
}

EXCEPTION_FIELDS = ("scanner", "owner", "justification", "tracking", "expires")


@dataclass(frozen=True)
class GateResult:
    """Outcome for one scanner report."""

    scanner: str
    status: str  # pass | pass_with_exception | fail | skipped
    reason: str
    blocking_count: int = 0

    def ok(self) -> bool:
        return self.status in ("pass", "pass_with_exception", "skipped")


def _bandit_blocking(data: dict[str, Any]) -> int:
    results = data["results"]
    return sum(1 for item in results if item.get("issue_severity") == "HIGH")


def _pip_audit_blocking(data: dict[str, Any]) -> int:
    """pip-audit JSON has no severity, so every reported vulnerability blocks."""
    if "vulnerabilities" in data:
        return len(data["vulnerabilities"] or [])
    dependencies = data["dependencies"]
    return sum(len(dep.get("vulns") or []) for dep in dependencies if isinstance(dep, dict))


def _grype_blocking(data: dict[str, Any]) -> int:
    matches = data["matches"]
    return sum(
        1 for match in matches if str(match.get("vulnerability", {}).get("severity", "")).upper() == "HIGH"
    )


def _trivy_blocking(data: dict[str, Any]) -> int:
    results = data["Results"]
    return sum(
        1
        for result in results
        for vuln in result.get("Vulnerabilities") or []
        if str(vuln.get("Severity", "")).upper() == "HIGH"
    )


BLOCKING_COUNTERS: dict[str, Callable[[dict[str, Any]], int]] = {
    "bandit": _bandit_blocking,
    "pip-audit": _pip_audit_blocking,
    "grype": _grype_blocking,
    "trivy": _trivy_blocking,
}


def evaluate_report(scanner: str, path: Path, *, required: bool = True) -> GateResult:
    """Evaluate one report. Any problem other than zero findings is a failure."""
    if scanner not in BLOCKING_COUNTERS:
        return GateResult(scanner, "fail", f"unknown scanner: {scanner}")
    if not path.exists():
        if not required:
            return GateResult(scanner, "skipped", "optional scan not enabled")
        return GateResult(scanner, "fail", f"required report not found: {path}")

    try:
        text = path.read_text()
    except OSError as exc:
        return GateResult(scanner, "fail", f"report unreadable: {exc}")
    if not text.strip():
        return GateResult(scanner, "fail", "report is empty")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return GateResult(scanner, "fail", f"invalid JSON: {exc.msg}")
    if not isinstance(data, dict):
        return GateResult(scanner, "fail", "report is not a JSON object")

    try:
        blocking = BLOCKING_COUNTERS[scanner](data)
    except (KeyError, TypeError, AttributeError) as exc:
        return GateResult(scanner, "fail", f"unexpected report shape: {exc!r}")
    if blocking > 0:
        return GateResult(scanner, "fail", f"{blocking} HIGH/blocking finding(s)", blocking)
    return GateResult(scanner, "pass", "no HIGH findings", 0)


def load_exceptions(path: Path) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Load scanner exceptions; invalid entries are returned as errors."""
    if not path.exists():
        return {}, [f"exceptions file not found: {path}"]
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return {}, [f"exceptions file unreadable: {exc}"]

    items = payload.get("exceptions") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        return {}, ["exceptions file must contain an 'exceptions' list"]

    exceptions: dict[str, dict[str, str]] = {}
    errors: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"exception #{index} is not an object")
            continue
        missing = [field for field in EXCEPTION_FIELDS if not str(item.get(field, "")).strip()]
        if missing:
            errors.append(f"exception #{index} missing: {', '.join(missing)}")
            continue
        try:
            expires = date.fromisoformat(str(item["expires"]))
        except ValueError:
            errors.append(f"exception #{index} has an invalid expiry date: {item['expires']}")
            continue
        if expires < date.today():
            errors.append(f"exception #{index} expired on {expires.isoformat()}")
            continue
        exceptions[str(item["scanner"])] = {key: str(item[key]) for key in EXCEPTION_FIELDS}
    return exceptions, errors


def apply_exceptions(results: list[GateResult], exceptions: dict[str, dict[str, str]]) -> list[GateResult]:
    """Turn a failure into pass_with_exception only for a valid, unexpired entry."""
    resolved: list[GateResult] = []
    for result in results:
        exception = exceptions.get(result.scanner)
        if result.status != "fail" or exception is None:
            resolved.append(result)
            continue
        resolved.append(
            GateResult(
                result.scanner,
                "pass_with_exception",
                (
                    f"exception {exception['tracking']} owned by {exception['owner']} "
                    f"until {exception['expires']}: {exception['justification']}"
                ),
                result.blocking_count,
            )
        )
    return resolved


def evaluate(
    reports: dict[str, Path],
    *,
    optional: set[str] | None = None,
    exceptions: dict[str, dict[str, str]] | None = None,
) -> tuple[list[GateResult], list[str]]:
    optional = optional or set()
    results = [evaluate_report(name, path, required=name not in optional) for name, path in reports.items()]
    if exceptions:
        results = apply_exceptions(results, exceptions)
    errors = [r.reason for r in results if r.status == "fail"]
    return results, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed security report gate")
    for scanner, default in DEFAULT_REPORTS.items():
        parser.add_argument(f"--{scanner}", default=default, help=f"{scanner} report path")
    parser.add_argument(
        "--optional",
        nargs="*",
        default=[],
        help="scanners allowed to be absent because they are intentionally disabled",
    )
    parser.add_argument("--exceptions", default="", help="JSON file of approved exceptions")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    exceptions: dict[str, dict[str, str]] = {}
    errors: list[str] = []
    if args.exceptions:
        exceptions, errors = load_exceptions(Path(args.exceptions))

    reports = {scanner: Path(getattr(args, scanner.replace("-", "_"))) for scanner in DEFAULT_REPORTS}
    results, _ = evaluate(
        reports,
        optional=set(args.optional),
        exceptions=exceptions,
    )
    errors.extend(result.reason for result in results if result.status == "fail")

    if args.json:
        print(
            json.dumps(
                {
                    "passed": not errors,
                    "results": [asdict(result) for result in results],
                    "errors": errors,
                },
                indent=2,
            )
        )
    else:
        for result in results:
            print(f"{result.status.upper():18} {result.scanner}: {result.reason}")
        for error in errors:
            print(f"::error::{error}" if not args.json else error)

    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
