"""Regression coverage for evidence-based dynamic, API, SAST and SCA detection."""
from __future__ import annotations

import json
import threading
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import pytest

from strix.code_scan import scan_codebase
from strix.core import adapters as adapter_module
from strix.core.adapters import DynamicValidationAdapter, OpenAPIAdapter
from strix.core.probe import EndpointProbe


def test_reflection_context_is_reported_without_claiming_execution(local_target):
    probe = EndpointProbe(timeout=2)
    hits = probe.reflections(f"{local_target.url}/?q=hello", deadline=None)
    assert hits
    assert "html_text" in hits[0]["contexts"]
    assert "execution context was not tested" in hits[0]["evidence"]


def test_redirect_probe_uses_reserved_canary_and_never_follows(monkeypatch):
    probe = EndpointProbe(timeout=1)
    calls = []

    def fake_fetch(url, *, timeout=None, deadline=None):
        calls.append(url)
        query = dict(parse_qsl(urlparse(url).query))
        return {"status": 302, "headers": {"location": query["next"]}, "body": ""}

    monkeypatch.setattr(probe, "_fetch", fake_fetch)
    results = probe.redirect_tests("http://example.com/?next=/home")
    assert len(results) == 1
    assert urlparse(results[0]["canary"]).hostname.endswith(".invalid")
    assert results[0]["parameter"] == "next"
    assert len(calls) == 1  # only the original scoped endpoint was requested


def test_database_error_probe_is_only_an_indicator(monkeypatch):
    probe = EndpointProbe(timeout=1)

    def fake_fetch(url, *, timeout=None, deadline=None):
        value = dict(parse_qsl(urlparse(url).query))["id"]
        body = "You have an error in your SQL syntax" if value == "'" else "ok"
        return {"status": 500 if value == "'" else 200, "headers": {}, "body": body}

    monkeypatch.setattr(probe, "_fetch", fake_fetch)
    hits = probe.database_error_tests("http://example.com/?id=1")
    assert len(hits) == 1
    assert "possible" not in hits[0]["evidence"].lower()  # raw evidence, not a verdict
    assert "SQL syntax" in hits[0]["evidence"]


def test_dynamic_validation_confirms_canary_redirect_but_not_sqli(monkeypatch):
    adapter = DynamicValidationAdapter()
    fake_dest = adapter_module.scope.Destination(
        scheme="http", host="example.com", port=80, ip="93.184.216.34")
    monkeypatch.setattr(adapter_module.scope, "destination",
                        lambda target: ("", "", fake_dest))

    class StubProbe:
        def __init__(self, timeout):
            pass

        def redirect_tests(self, target, *, cancel, deadline):
            return [{"parameter": "next", "request_url": target,
                     "evidence": "Location redirected to unique .invalid canary"}]

        def database_error_tests(self, target, *, cancel, deadline):
            return [{"parameter": "id", "request_url": target,
                     "evidence": "SQL error signature observed"}]

    monkeypatch.setattr(adapter_module, "EndpointProbe", StubProbe)
    result = adapter.assess("http://example.com/?next=/", timeout=5,
                             cancel=threading.Event())
    by_category = {finding.category: finding for finding in result.findings}
    assert by_category["open_redirect"].verification == "observed"
    assert by_category["sqli_error_indicator"].verification == "inferred"


def test_openapi_adapter_flags_only_documented_protected_success(local_target, monkeypatch):
    spec = {
        "openapi": "3.0.3",
        "security": [{"bearerAuth": []}],
        "paths": {
            "/private": {"get": {"responses": {"200": {"description": "ok"}}}},
            "/public": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
        },
    }

    def fake_fetch(self, url, *, timeout=None, deadline=None):
        path = urlparse(url).path
        if path.endswith("/openapi.json"):
            return {"status": 200, "headers": {"content-type": "application/json"},
                    "body": json.dumps(spec)}
        if path == "/private":
            return {"status": 200, "headers": {}, "body": "private response not retained"}
        return {"status": 200, "headers": {}, "body": ""}

    monkeypatch.setattr(EndpointProbe, "_fetch", fake_fetch)
    result = OpenAPIAdapter().assess(local_target.url, timeout=5, cancel=threading.Event())
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.category == "api_documented_auth_mismatch"
    assert finding.verification == "unverified"
    assert finding.location.endswith("/private")


def test_code_scan_normalizes_bandit_semgrep_and_trivy(tmp_path, monkeypatch):
    from strix import code_scan

    repo = tmp_path / "sample-repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import subprocess\nsubprocess.run(user_input, shell=True)\n", encoding="utf-8")
    (repo / "requirements.txt").write_text("demo-package==1.0\n", encoding="utf-8")

    monkeypatch.setattr(code_scan.shutil, "which", lambda name: f"/fake/{name}"
                        if name in {"semgrep", "bandit", "trivy"} else None)

    def fake_run(argv, *, timeout, cancel):
        tool = Path(argv[0]).name
        snapshot = Path(argv[-1])
        if tool == "bandit":
            payload = {"results": [{
                "filename": str(snapshot / "app.py"), "line_number": 2,
                "test_id": "B602", "issue_text": "subprocess call with shell=True",
                "issue_severity": "HIGH", "issue_confidence": "HIGH",
                "issue_cwe": {"id": 78}, "code": "subprocess.run(user_input, shell=True)",
            }]}
        elif tool == "semgrep":
            payload = {"results": [{
                "path": str(snapshot / "app.py"), "start": {"line": 2},
                "check_id": "strix.python.subprocess-shell-true",
                "extra": {"message": "shell=True can cause command injection", "severity": "WARNING",
                          "metadata": {"cwe": "CWE-78", "confidence": "MEDIUM"}},
            }]}
        else:
            payload = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2026-12345", "PkgName": "demo-package",
                "InstalledVersion": "1.0", "FixedVersion": "1.2", "Severity": "HIGH",
                "Title": "Example dependency advisory", "PrimaryURL": "https://example.invalid/advisory",
            }], "Secrets": [{
                "RuleID": "generic-api-key", "Title": "Potential API key", "Severity": "HIGH",
                "StartLine": 1, "Match": "AKIAEXAMPLESECRETNOLEAK",
            }]}]}
        return 0, json.dumps(payload), ""

    monkeypatch.setattr(code_scan, "_run_tool", fake_run)
    report = scan_codebase(repo)
    assert report.state == "completed"
    assert set(report.tools_run) == {"semgrep", "bandit", "trivy-fs"}
    assert len(report.findings) == 4
    assert any(f.location == "app.py:2" and f.cwe == "CWE-78" for f in report.findings)
    assert any(f.category.startswith("sca_CVE-2026-12345") for f in report.findings)
    rendered = json.dumps([finding.to_dict() for finding in report.findings])
    assert "AKIAEXAMPLESECRETNOLEAK" not in rendered


def test_code_scan_without_tools_is_not_clean(tmp_path, monkeypatch):
    from strix import code_scan

    repo = tmp_path / "empty-scannable"
    repo.mkdir()
    (repo / "app.py").write_text("print('hello')\n", encoding="utf-8")
    monkeypatch.setattr(code_scan.shutil, "which", lambda _name: None)
    report = scan_codebase(repo)
    assert report.state == "failed"
    assert report.clean is False
    assert any("no requested scanner tools" in note for note in report.notes)


def test_code_scan_rejects_symlinked_repository_root(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    link = tmp_path / "source-link"
    link.symlink_to(source, target_is_directory=True)
    with pytest.raises(ValueError, match="must not be a symlink"):
        scan_codebase(link)


def test_dynamic_validation_without_parameters_is_inconclusive():
    from strix.core.adapters import AdapterError

    adapter = DynamicValidationAdapter()
    with pytest.raises(AdapterError, match="inconclusive"):
        adapter.assess("http://example.com/", timeout=2, cancel=threading.Event())


def test_openapi_without_spec_is_inconclusive(local_target, monkeypatch):
    from strix.core.adapters import AdapterError

    def missing_spec(self, url, *, timeout=None, deadline=None):
        return {"status": 404, "headers": {"content-type": "text/html"}, "body": "not found"}

    monkeypatch.setattr(EndpointProbe, "_fetch", missing_spec)
    with pytest.raises(AdapterError, match="coverage is inconclusive"):
        OpenAPIAdapter().assess(local_target.url, timeout=5, cancel=threading.Event())
