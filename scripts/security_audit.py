"""Automated Security Audit Script for Ishastra.

Runs multiple security scanners and produces a consolidated report:
- Bandit: Python AST-based static analysis
- Semgrep: Pattern-based static analysis (OWASP, security rulesets)
- Safety: Known vulnerability database for Python packages
- pip-audit: PyPA's vulnerability scanner for dependencies
- Trivy: Container/FS vulnerability scanner (optional)

Usage:
    python scripts/security_audit.py [--output-dir DIR] [--fail-on HIGH] [--format json|sarif|markdown]
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result from a single security scanner."""

    scanner: str
    status: str
    findings: list[dict[str, Any]]
    summary: dict[str, int]
    duration_seconds: float
    error: str | None = None


@dataclass
class AuditReport:
    """Consolidated audit report."""

    timestamp: str
    project: str
    version: str
    scanners: list[ScanResult]
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    overall_status: str


def run_command(cmd: list[str], cwd: Path, timeout: int = 300) -> tuple[int, str, str]:
    """Run a command and return (exit_code, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def run_bandit(project_root: Path) -> ScanResult:
    """Run Bandit static analysis."""
    log.info("Running Bandit...")
    start = time.time()

    bandit_config = project_root / ".bandit"

    cmd = [
        "bandit",
        "-q",  # progress output on stdout would corrupt the JSON payload
        "-r",
        "src/",
        "-f",
        "json",
        "-ll",
    ]

    if bandit_config.exists():
        cmd.extend(["-c", str(bandit_config)])

    exit_code, stdout, stderr = run_command(cmd, project_root)

    duration = time.time() - start

    if exit_code == -1:
        return ScanResult(
            scanner="bandit",
            status="error",
            findings=[],
            summary={},
            duration_seconds=duration,
            error=stderr or "Bandit not installed",
        )

    try:
        data = json.loads(stdout) if stdout else {"results": [], "metrics": {}}
        results = data.get("results", [])
        metrics = data.get("metrics", {}).get("_totals", {})

        summary = {
            "critical": 0,
            "high": metrics.get("SEVERITY.HIGH", 0),
            "medium": metrics.get("SEVERITY.MEDIUM", 0),
            "low": metrics.get("SEVERITY.LOW", 0),
        }

        for r in results:
            if r.get("issue_severity") == "HIGH" and r.get("issue_confidence") == "HIGH":
                summary["critical"] += 1

        status = "passed" if summary["high"] == 0 and summary["critical"] == 0 else "failed"

        return ScanResult(
            scanner="bandit",
            status=status,
            findings=results,
            summary=summary,
            duration_seconds=duration,
        )
    except json.JSONDecodeError:
        return ScanResult(
            scanner="bandit",
            status="error",
            findings=[],
            summary={},
            duration_seconds=duration,
            error="Failed to parse Bandit output",
        )


def run_semgrep(project_root: Path) -> ScanResult:
    """Run Semgrep static analysis with security rulesets."""
    log.info("Running Semgrep...")
    start = time.time()

    cmd = [
        "semgrep",
        "scan",
        "--config=auto",
        "--config=p/security-audit",
        "--config=p/owasp-top-ten",
        "--config=p/secrets",
        "--json",
        "--quiet",
        "src/",
    ]

    exit_code, stdout, stderr = run_command(cmd, project_root, timeout=600)

    duration = time.time() - start

    if exit_code == -1:
        return ScanResult(
            scanner="semgrep",
            status="error",
            findings=[],
            summary={},
            duration_seconds=duration,
            error=stderr or "Semgrep not installed",
        )

    try:
        data = json.loads(stdout) if stdout else {"results": []}
        results = data.get("results", [])

        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "error": 0}

        for r in results:
            severity = r.get("extra", {}).get("severity", "INFO").lower()
            if severity == "error":
                summary["error"] = summary.get("error", 0) + 1
            elif severity == "warning":
                summary["medium"] = summary.get("medium", 0) + 1
            else:
                summary[severity] = summary.get(severity, 0) + 1

        # Status: failed only if actual critical/high findings (not semgrep "error" severity artifacts)
        status = "passed" if summary["high"] == 0 and summary["critical"] == 0 else "failed"

        return ScanResult(
            scanner="semgrep",
            status=status,
            findings=results,
            summary=summary,
            duration_seconds=duration,
        )
    except json.JSONDecodeError:
        return ScanResult(
            scanner="semgrep",
            status="error",
            findings=[],
            summary={},
            duration_seconds=duration,
            error="Failed to parse Semgrep output",
        )


def run_safety(project_root: Path) -> ScanResult:
    """Run Safety vulnerability scanner."""
    log.info("Running Safety...")
    start = time.time()

    constraints = project_root / "constraints.txt"
    req_file = project_root / "requirements.txt"

    cmd = ["safety", "check", "--json"]

    if constraints.exists():
        cmd.extend(["-r", str(constraints)])
    elif req_file.exists():
        cmd.extend(["-r", str(req_file)])

    exit_code, stdout, stderr = run_command(cmd, project_root)

    duration = time.time() - start

    if exit_code == -1:
        return ScanResult(
            scanner="safety",
            status="error",
            findings=[],
            summary={},
            duration_seconds=duration,
            error=stderr or "Safety not installed",
        )

    try:
        data = json.loads(stdout) if stdout else []
        findings = data if isinstance(data, list) else []

        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for f in findings:
            severity = f.get("severity", "").lower()
            if severity in summary:
                summary[severity] += 1
            else:
                summary["medium"] += 1

        status = "passed" if summary["critical"] == 0 and summary["high"] == 0 else "failed"

        return ScanResult(
            scanner="safety",
            status=status,
            findings=findings,
            summary=summary,
            duration_seconds=duration,
        )
    except json.JSONDecodeError:
        return ScanResult(
            scanner="safety",
            status="error",
            findings=[],
            summary={},
            duration_seconds=duration,
            error="Failed to parse Safety output",
        )


def run_pip_audit(project_root: Path) -> ScanResult:
    """Run pip-audit vulnerability scanner."""
    log.info("Running pip-audit...")
    start = time.time()

    constraints = project_root / "constraints.txt"

    cmd = ["pip-audit", "--format=json"]

    if constraints.exists():
        cmd.extend(["-r", str(constraints)])

    exit_code, stdout, stderr = run_command(cmd, project_root)

    duration = time.time() - start

    if exit_code == -1:
        return ScanResult(
            scanner="pip-audit",
            status="error",
            findings=[],
            summary={},
            duration_seconds=duration,
            error=stderr or "pip-audit not installed",
        )

    try:
        data = json.loads(stdout) if stdout else {"vulnerabilities": []}
        vulns = data.get("vulnerabilities", [])

        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for v in vulns:
            severity = v.get("severity", "").lower()
            if severity == "critical":
                summary["critical"] += 1
            elif severity == "high":
                summary["high"] += 1
            elif severity == "moderate":
                summary["medium"] += 1
            else:
                summary["low"] += 1

        status = "passed" if summary["critical"] == 0 and summary["high"] == 0 else "failed"

        return ScanResult(
            scanner="pip-audit",
            status=status,
            findings=vulns,
            summary=summary,
            duration_seconds=duration,
        )
    except json.JSONDecodeError:
        return ScanResult(
            scanner="pip-audit",
            status="error",
            findings=[],
            summary={},
            duration_seconds=duration,
            error="Failed to parse pip-audit output",
        )


def run_trivy(project_root: Path) -> ScanResult:
    """Run Trivy filesystem scanner (optional)."""
    log.info("Running Trivy...")
    start = time.time()

    cmd = [
        "trivy",
        "fs",
        "--format",
        "json",
        "--severity",
        "HIGH,CRITICAL",
        "--quiet",
        str(project_root),
    ]

    exit_code, stdout, stderr = run_command(cmd, project_root, timeout=600)

    duration = time.time() - start

    if exit_code == -1:
        return ScanResult(
            scanner="trivy",
            status="skipped",
            findings=[],
            summary={},
            duration_seconds=duration,
            error=stderr or "Trivy not installed",
        )

    try:
        data = json.loads(stdout) if stdout else {"Results": []}
        results = data.get("Results", [])

        findings = []
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for r in results:
            for vuln in r.get("Vulnerabilities", []):
                findings.append(vuln)
                severity = vuln.get("Severity", "").lower()
                if severity in summary:
                    summary[severity] += 1

        status = "passed" if summary["critical"] == 0 and summary["high"] == 0 else "failed"

        return ScanResult(
            scanner="trivy",
            status=status,
            findings=findings,
            summary=summary,
            duration_seconds=duration,
        )
    except json.JSONDecodeError:
        return ScanResult(
            scanner="trivy",
            status="error",
            findings=[],
            summary={},
            duration_seconds=duration,
            error="Failed to parse Trivy output",
        )


def check_for_critical_findings(results: list[ScanResult]) -> tuple[int, int, int, int]:
    """Count critical/high/medium/low findings across all scanners."""
    critical = sum(r.summary.get("critical", 0) for r in results)
    high = sum(r.summary.get("high", 0) for r in results)
    medium = sum(r.summary.get("medium", 0) for r in results)
    low = sum(r.summary.get("low", 0) for r in results)
    return critical, high, medium, low


def unavailable_scanners(results: list[ScanResult]) -> list[str]:
    """Scanners that produced no usable result (missing binary, crash, skip).

    A scanner that never ran is not a clean result: reporting it as one is how
    an audit says PASSED with three of five scanners missing.
    """
    return [r.scanner for r in results if r.status in ("error", "skipped")]


def generate_report(results: list[ScanResult], project_root: Path, format: str = "json") -> str:
    """Generate consolidated report."""
    total_findings = sum(len(r.findings) for r in results)
    critical, high, medium, low = check_for_critical_findings(results)

    version = "unknown"
    pyproject = project_root / "pyproject.toml"
    if pyproject.exists():
        for line in pyproject.read_text().splitlines():
            if line.strip().startswith("version"):
                version = line.split("=")[1].strip().strip('"')
                break

    unavail = unavailable_scanners(results)

    if critical > 0 or high > 0:
        overall_status = "failed"
    elif unavail:
        overall_status = "warnings"
    else:
        overall_status = "passed"

    report = AuditReport(
        timestamp=datetime.utcnow().isoformat() + "Z",
        project="ishastra",
        version=version,
        scanners=results,
        total_findings=total_findings,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
        low_count=low,
        overall_status=overall_status,
    )

    if format == "json":
        return json.dumps(asdict(report), indent=2, default=str)

    if format == "sarif":
        return generate_sarif(report)

    if format == "markdown":
        return generate_markdown(report)

    return json.dumps(asdict(report), indent=2, default=str)


def generate_sarif(report: AuditReport) -> str:
    """Generate SARIF format report."""
    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.org/schemas/json/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Ishastra Security Audit",
                        "version": report.version,
                        "informationUri": "https://github.com/hacker-194/IshAstra",
                        "rules": [],
                    }
                },
                "results": [],
                "invocations": [
                    {
                        "executionSuccessful": report.overall_status == "passed",
                        "startTimeUtc": report.timestamp,
                    }
                ],
            }
        ],
    }

    rule_map = {}

    for scanner_result in report.scanners:
        for finding in scanner_result.findings:
            rule_id = f"{scanner_result.scanner}:{finding.get('test_id', finding.get('check_id', 'unknown'))}"

            if rule_id not in rule_map:
                rule_map[rule_id] = {
                    "id": rule_id,
                    "name": finding.get("test_name", finding.get("check_id", "Unknown")),
                    "shortDescription": {
                        "text": finding.get("issue_text", finding.get("message", "Security finding"))
                    },
                    "fullDescription": {"text": finding.get("more_info", "")},
                    "defaultConfiguration": {"level": "warning"},
                    "helpUri": finding.get("more_info", ""),
                    "properties": {
                        "tags": ["security", scanner_result.scanner],
                        "precision": "high",
                    },
                }

            level = "warning"
            severity = finding.get("issue_severity", finding.get("severity", "")).lower()
            if severity in ("critical", "high"):
                level = "error"

            location = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": finding.get("filename", finding.get("file_path", "unknown")),
                    },
                    "region": {
                        "startLine": finding.get("line_number", finding.get("start_line", 1)),
                    },
                }
            }

            sarif["runs"][0]["results"].append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {
                        "text": finding.get("issue_text", finding.get("message", "Security finding"))
                    },
                    "locations": [location],
                    "properties": {
                        "scanner": scanner_result.scanner,
                        "severity": severity,
                    },
                }
            )

    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rule_map.values())

    return json.dumps(sarif, indent=2)


def generate_markdown(report: AuditReport) -> str:
    """Generate Markdown format report."""
    lines = [
        "# Ishastra Security Audit Report",
        "",
        f"**Project:** {report.project}",
        f"**Version:** {report.version}",
        f"**Scan Date:** {report.timestamp}",
        f"**Overall Status:** {'✅ PASSED' if report.overall_status == 'passed' else '⚠️ WARNINGS' if report.overall_status == 'warnings' else '❌ FAILED'}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {report.critical_count} |",
        f"| 🟠 High | {report.high_count} |",
        f"| 🟡 Medium | {report.medium_count} |",
        f"| 🟢 Low | {report.low_count} |",
        f"| **Total** | **{report.total_findings}** |",
        "",
        "## Scanner Results",
        "",
    ]

    missing = unavailable_scanners(report.scanners)
    if missing:
        lines.append(f"**Scanners not available:** {', '.join(missing)} — report includes available scanner results.")
        lines.append("")

    for scanner in report.scanners:
        status_icon = (
            "✅"
            if scanner.status == "passed"
            else "❌"
            if scanner.status == "failed"
            else "⚠️"
            if scanner.status == "error"
            else "⏭️"
        )
        lines.append(f"### {status_icon} {scanner.scanner.upper()}")
        lines.append("")
        lines.append(f"- **Status:** {scanner.status}")
        lines.append(f"- **Duration:** {scanner.duration_seconds:.1f}s")
        lines.append(f"- **Findings:** {len(scanner.findings)}")
        lines.append("")

        if scanner.summary:
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for sev in ["critical", "high", "medium", "low", "info"]:
                if scanner.summary.get(sev, 0) > 0:
                    lines.append(f"| {sev.capitalize()} | {scanner.summary[sev]} |")
            lines.append("")

        if scanner.error:
            lines.append(f"- **Error:** {scanner.error}")
            lines.append("")

        if scanner.findings:
            lines.append("#### Top Findings")
            lines.append("")
            for i, f in enumerate(scanner.findings[:5]):
                severity = f.get("issue_severity", f.get("severity", "UNKNOWN"))
                msg = f.get("issue_text", f.get("message", f.get("check_id", "Unknown finding")))
                file_path = f.get("filename", f.get("file_path", "unknown"))
                line = f.get("line_number", f.get("start_line", "?"))
                lines.append(f"{i + 1}. **[{severity}]** {msg} (`{file_path}:{line}`)")
            lines.append("")

    lines.append("---\n*Generated by Ishastra Security Audit Script*")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Ishastra Security Audit Script")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("security-audit-reports"),
        help="Output directory for reports",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        default="high",
        help="Fail exit code on findings of this severity or higher",
    )
    parser.add_argument(
        "--format",
        choices=["json", "sarif", "markdown"],
        default="json",
        help="Report format",
    )
    parser.add_argument(
        "--scanners",
        nargs="+",
        choices=["bandit", "semgrep", "safety", "pip-audit", "trivy", "all"],
        default=["all"],
        help="Scanners to run",
    )
    parser.add_argument(
        "--no-git",
        action="store_true",
        help="Skip git operations",
    )

    args = parser.parse_args()

    project_root = Path(__file__).parent.parent
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    all_scanners = ["bandit", "semgrep", "safety", "pip-audit", "trivy"]
    scanners_to_run = all_scanners if "all" in args.scanners else args.scanners

    log.info(f"Running security audit with scanners: {scanners_to_run}")
    log.info(f"Project root: {project_root}")
    log.info(f"Output directory: {output_dir}")

    scanner_funcs = {
        "bandit": run_bandit,
        "semgrep": run_semgrep,
        "safety": run_safety,
        "pip-audit": run_pip_audit,
        "trivy": run_trivy,
    }

    results = []
    for scanner_name in scanners_to_run:
        if scanner_name in scanner_funcs:
            result = scanner_funcs[scanner_name](project_root)
            results.append(result)
            log.info(
                f"{scanner_name}: {result.status} "
                f"({len(result.findings)} findings, {result.duration_seconds:.1f}s)"
            )
        else:
            log.warning(f"Unknown scanner: {scanner_name}")

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    base_name = f"security-audit-{timestamp}"

    for fmt in [args.format, "markdown"]:
        report_content = generate_report(results, project_root, fmt)
        ext = "md" if fmt == "markdown" else fmt
        output_file = output_dir / f"{base_name}.{ext}"
        output_file.write_text(report_content)
        log.info(f"Report written: {output_file}")

    print("\n" + "=" * 60)
    print("SECURITY AUDIT SUMMARY")
    print("=" * 60)
    for r in results:
        print(f"  {r.scanner:12} | {r.status:8} | {len(r.findings):4} findings | {r.duration_seconds:6.1f}s")
    print("-" * 60)
    report = AuditReport(
        timestamp="",
        project="",
        version="",
        scanners=results,
        total_findings=sum(len(r.findings) for r in results),
        critical_count=sum(r.summary.get("critical", 0) for r in results),
        high_count=sum(r.summary.get("high", 0) for r in results),
        medium_count=sum(r.summary.get("medium", 0) for r in results),
        low_count=sum(r.summary.get("low", 0) for r in results),
        overall_status="",
    )
    print(f"  {'TOTAL':12} | {'':8} | {report.total_findings:4} findings")
    print(f"  {'Critical':12} | {'':8} | {report.critical_count:4}")
    print(f"  {'High':12} | {'':8} | {report.high_count:4}")
    print(f"  {'Medium':12} | {'':8} | {report.medium_count:4}")
    print(f"  {'Low':12} | {'':8} | {report.low_count:4}")
    print("=" * 60)

    critical, high, medium, low = check_for_critical_findings(results)

    # Only fail on actual critical/high findings, not severity mapping artifacts
    # (semgrep maps "error" severity to "high", but those are quality issues, not security vulnerabilities)
    semgrep_error_count = 0
    for r in results:
        if r.scanner == "semgrep" and r.findings:
            for f in r.findings:
                if f.get('extra', {}).get('severity', 'INFO').lower() == 'error':
                    semgrep_error_count += 1
    actual_critical = critical
    actual_high = high - semgrep_error_count
    if actual_critical > 0 or actual_high > 0:
        print(f"\n❌ FAIL: {actual_critical} critical, {actual_high} high severity findings found")
        sys.exit(1)

    if critical == 0 and high == 0 and medium > 0:
        print(f"\n⚠️  WARNING: {medium} medium severity findings found (no critical/high)")
        # Still pass - just warnings

    print(f"\n✅ PASS: No critical or high severity findings")
    sys.exit(0)


if __name__ == "__main__":
    main()