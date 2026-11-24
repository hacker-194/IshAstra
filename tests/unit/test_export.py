"""Tests for exporting a stored job's findings."""

from __future__ import annotations

import csv
import io
import json

import pytest

from ishastra.core.exports import build_export, report_document, to_csv, to_defectdojo
from ishastra.core.findings import Finding

JOB = {
    "id": "job-1",
    "target": "https://example.com",
    "state": "completed",
    "verdict": "findings",
    "finished_at": 1764000000,
    "scope": {"program": "Demo", "authorized_by": "Owner", "authorization_ref": "REF-1"},
}

FINDINGS = [
    Finding(
        asset="https://example.com/login",
        category="sql-injection",
        title="SQL injection",
        severity="critical",
        confidence="high",
        detector="probe",
        detector_version="1.0",
        evidence="' OR 1=1--",
        location="https://example.com/login?user=",
        description="Unsanitized query parameter",
        remediation="Use parameterized queries",
        cwe="CWE-89",
        cvss_score="9.8",
    ),
    Finding(
        asset="https://example.com",
        category="server-version",
        title="Server version disclosed",
        severity="info",
        confidence="low",
        detector="probe",
        detector_version="1.0",
        evidence="Server: nginx/1.2",
    ),
]


def test_sarif_export_has_every_finding():
    sarif = json.loads(build_export(JOB, FINDINGS, "sarif"))
    assert len(sarif["runs"][0]["results"]) == 2


def test_json_export_keeps_job_metadata():
    data = json.loads(build_export(JOB, FINDINGS, "json"))
    assert data["job"]["id"] == "job-1"
    assert len(data["findings"]) == 2


def test_csv_export_one_row_per_finding():
    rows = list(csv.DictReader(io.StringIO(to_csv(FINDINGS))))
    assert len(rows) == 2
    assert rows[0]["severity"] == "critical"
    assert rows[0]["cwe"] == "CWE-89"


def test_defectdojo_payload_mapping():
    data = json.loads(to_defectdojo(JOB, FINDINGS))
    first, second = data["findings"]
    assert first["severity"] == "Critical"
    assert first["cwe"] == 89
    assert first["cvssv3_score"] == 9.8
    assert first["endpoints"] == ["https://example.com/login?user="]
    assert first["verified"] is True
    assert first["date"] == "2025-11-24"
    assert second["severity"] == "Info"
    assert "cvssv3_score" not in second


def test_report_document_pulls_scope_fields():
    document = report_document(JOB, FINDINGS)
    assert document["program"] == "Demo"
    assert document["severity_counts"]["critical"] == 1
    assert document["findings"][0]["cwe"] == "CWE-89"


def test_html_export_contains_target_and_finding():
    html = build_export(JOB, FINDINGS, "html")
    assert isinstance(html, str)
    assert "SQL injection" in html
    assert "https://example.com" in html


def test_unknown_format_is_rejected():
    with pytest.raises(ValueError, match="unsupported export format"):
        build_export(JOB, FINDINGS, "docx")


def test_cli_export_writes_file(monkeypatch, tmp_path):
    """The `export` subcommand loads the job and writes the requested format."""
    import sys

    from ishastra.cli import main
    from ishastra.core import store

    async def fake_get_database():
        return None

    async def fake_get_job(job_id, tenant=None):
        return JOB if job_id == "job-1" else None

    async def fake_get_findings(job_id, tenant=None):
        return FINDINGS

    monkeypatch.setattr(store, "configure", lambda path: None)
    monkeypatch.setattr(store, "get_database", fake_get_database)
    monkeypatch.setattr(store, "get_job", fake_get_job)
    monkeypatch.setattr(store, "get_findings", fake_get_findings)

    output = tmp_path / "findings.csv"
    monkeypatch.setattr(
        sys, "argv", ["ishastra", "export", "--job", "job-1", "--format", "csv", "-o", str(output)]
    )
    try:
        main()
    except SystemExit as exc:
        assert exc.code == 0

    rows = list(csv.DictReader(io.StringIO(output.read_text())))
    assert len(rows) == 2
    assert rows[0]["title"] == "SQL injection"


def test_cli_export_missing_job_exits_nonzero(monkeypatch):
    import sys

    from ishastra.cli import main
    from ishastra.core import store

    async def fake_get_database():
        return None

    async def fake_get_job(job_id, tenant=None):
        return None

    async def fake_get_findings(job_id, tenant=None):
        return []

    monkeypatch.setattr(store, "configure", lambda path: None)
    monkeypatch.setattr(store, "get_database", fake_get_database)
    monkeypatch.setattr(store, "get_job", fake_get_job)
    monkeypatch.setattr(store, "get_findings", fake_get_findings)
    monkeypatch.setattr(sys, "argv", ["ishastra", "export", "--job", "missing"])

    try:
        main()
    except SystemExit as exc:
        assert exc.code == 3
