"""Export a stored job's findings in the formats consumers ask for.

The web UI, the CLI and CI all want the same job in different clothes.
Conversion lives here once so every entry point agrees on severity
mapping, CSV columns and the DefectDojo payload.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any

from ishastra.core.findings import Finding, to_sarif

FORMATS = ("sarif", "json", "csv", "html", "pdf", "defectdojo")

DEFECTDOJO_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}

_CSV_FIELDS = (
    "fingerprint",
    "severity",
    "confidence",
    "verification",
    "status",
    "title",
    "category",
    "cwe",
    "cvss_score",
    "asset",
    "location",
    "detector",
    "detector_version",
    "evidence",
    "remediation",
    "description",
)


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def report_document(job: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
    """The report dict shared by the HTML and PDF renderers."""
    scope = job.get("scope") or {}
    return {
        "target": job.get("target", ""),
        "job_id": job.get("id", ""),
        "state": job.get("state", ""),
        "verdict": job.get("verdict", ""),
        "program": job.get("program") or scope.get("program", ""),
        "authorized_by": job.get("authorized_by") or scope.get("authorized_by", ""),
        "authorization_ref": job.get("authorization_ref") or scope.get("authorization_ref", ""),
        "scope_include": job.get("scope_include") or scope.get("include", []),
        "findings": [
            {
                "severity": finding.severity,
                "confidence": finding.confidence,
                "title": finding.title,
                "category": finding.category,
                "cwe": finding.cwe or "no CWE",
                "asset": finding.asset,
                "location": finding.location or finding.asset,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
                "description": finding.description,
                "detector": finding.detector,
                "detector_version": finding.detector_version,
            }
            for finding in findings
        ],
        "coverage": job.get("coverage") or {},
        "severity_counts": _severity_counts(findings),
        "integrity": job.get("integrity") or {"chain_valid": True, "chain_hash": ""},
    }


def to_csv(findings: list[Finding]) -> str:
    """One row per finding, quoted by the csv module (evidence holds anything)."""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_CSV_FIELDS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for finding in findings:
        row = {field: getattr(finding, field, "") for field in _CSV_FIELDS}
        row["fingerprint"] = finding.fingerprint
        writer.writerow(row)
    return buffer.getvalue()


def _finding_date(job: dict[str, Any]) -> str:
    finished = job.get("finished_at")
    if isinstance(finished, (int, float)):
        return datetime.fromtimestamp(finished, UTC).date().isoformat()
    return datetime.now(UTC).date().isoformat()


def _cwe_number(cwe: str) -> int | None:
    digits = cwe.rsplit("-", 1)[-1] if "-" in cwe else cwe
    return int(digits) if digits.isdigit() else None


def to_defectdojo(job: dict[str, Any], findings: list[Finding]) -> str:
    """DefectDojo ``import-scan`` payload (Generic Findings Import)."""
    date = _finding_date(job)
    payload: list[dict[str, Any]] = []
    for finding in findings:
        entry: dict[str, Any] = {
            "title": finding.title,
            "severity": DEFECTDOJO_SEVERITY[finding.severity],
            "description": finding.description or finding.evidence,
            "date": date,
            "cwe": _cwe_number(finding.cwe),
            "endpoints": [finding.location or finding.asset],
            "unique_id_from_tool": finding.fingerprint,
            "vuln_id_from_tool": finding.category,
            "mitigation": finding.remediation,
            "active": True,
            "verified": finding.verification == "observed",
            "dynamic_finding": True,
        }
        try:
            score = float(finding.cvss_score)
        except (TypeError, ValueError):
            score = 0.0
        if score > 0:
            entry["cvssv3_score"] = score
        payload.append(entry)
    return json.dumps({"findings": payload}, indent=2)


def build_export(job: dict[str, Any], findings: list[Finding], fmt: str) -> str | bytes:
    """Render ``job`` in ``fmt``. PDF returns bytes, everything else text."""
    fmt = fmt.lower()
    if fmt == "sarif":
        return json.dumps(to_sarif(findings, tool_version="ishastra-export"), indent=2)
    if fmt == "json":
        return json.dumps(
            {"job": job, "findings": [finding.to_dict() for finding in findings]},
            indent=2,
            default=str,
        )
    if fmt == "csv":
        return to_csv(findings)
    if fmt == "defectdojo":
        return to_defectdojo(job, findings)
    if fmt not in ("html", "pdf"):
        raise ValueError(f"unsupported export format: {fmt}")

    from ishastra.report_html import render_html_report

    document = report_document(job, findings)
    if fmt == "html":
        return render_html_report(document)

    from ishastra.report_pdf import render_pdf_report

    return render_pdf_report(document)
