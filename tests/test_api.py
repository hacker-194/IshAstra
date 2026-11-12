"""Endpoint behavior: health, overview, scope, adapters, assessments, reports."""
from fastapi.testclient import TestClient

from strix.api.app import app
from strix.api.security import api_keys

client = TestClient(app)


def _auth_headers():
    key = api_keys.register("test-tenant", "enterprise")
    return {"Authorization": f"Bearer {key}"}


def _admin_headers():
    key = api_keys.register("test-admin", "enterprise", admin=True)
    return {"Authorization": f"Bearer {key}"}


def test_health_endpoint():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["service"] == "strix"
    assert data["uptime_seconds"] >= 0


def test_overview_endpoint():
    res = client.get("/api/overview", headers=_auth_headers())
    assert res.status_code == 200
    data = res.json()
    assert data["tenant_id"] == "test-tenant"
    assert {"total_jobs", "total_findings", "targets", "audit_events"} <= set(data)


def test_probe_endpoint():
    res = client.post(
        "/api/probe",
        json={"url": "http://127.0.0.1:59999/", "timeout": 0.5},
        headers=_auth_headers(),
    )
    assert res.status_code == 200
    data = res.json()
    assert data["security_grade"] == "N/A"  # a closed port is not a scorable response
    assert data["security_score"] is None
    assert "latency_ms" in data


def test_audit_trail():
    res = client.get("/api/audit", headers=_auth_headers())
    assert res.status_code == 200
    data = res.json()
    assert "total_records" in data
    assert "audit_logs" in data


def test_scope_endpoint_reports_authorization_record():
    res = client.get("/api/scope", headers=_auth_headers())
    assert res.status_code == 200
    data = res.json()
    assert data["configured"] is True
    assert data["program"] == "strix test suite"
    assert data["authorization_ref"] == "local-tests"
    assert "evil.com" in data["include"]


def test_report_bundles_evidence_and_authorization(local_target):
    target = f"{local_target.url}/?q=1"
    job = client.post("/api/assess", json={"target": target, "wait": True},
                      headers=_auth_headers())
    assert job.status_code == 200

    res = client.post("/api/report", json={"target": target}, headers=_auth_headers())
    assert res.status_code == 200
    data = res.json()
    # A bounty submission is useless without who authorized it and for what
    assert data["program"] == "strix test suite"
    assert data["authorization_ref"] == "local-tests"
    assert data["target"] == target
    assert data["job_id"] == job.json()["id"]
    assert "xss" in {item["category"] for item in data["findings"]}
    assert all(item["evidence"] for item in data["findings"])
    assert data["severity_counts"]
    assert data["integrity"]["chain_valid"] is True
    assert len(data["integrity"]["chain_hash"]) == 64


def test_report_requires_a_prior_assessment():
    res = client.post(
        "/api/report",
        json={"target": "http://example.com/never-scanned"},
        headers=_auth_headers(),
    )
    assert res.status_code == 404


def test_report_refuses_out_of_scope_target():
    res = client.post(
        "/api/report",
        json={"target": "http://victim.example.net/"},
        headers=_auth_headers(),
    )
    assert res.status_code == 403


def test_adapters_endpoint_reports_real_availability():
    res = client.get("/api/adapters", headers=_auth_headers())
    assert res.status_code == 200
    data = res.json()
    by_id = {adapter["id"]: adapter for adapter in data["adapters"]}
    assert by_id["strix-http"]["available"] is True
    assert "detail" in by_id["nmap"]        # availability is stated, never assumed
    # Every profile names registered adapters, and the default web profile
    # keeps the built-in exposure check that works without external tools.
    for names in data["profiles"].values():
        assert set(names) <= set(by_id)
    assert "strix-http" in data["profiles"]["web"]
    assert "strix-git-exposure" in data["profiles"]["web"]
    assert by_id["strix-git-exposure"]["available"] is True


def test_assess_returns_findings_and_coverage(local_target):
    res = client.post(
        "/api/assess",
        json={"target": f"{local_target.url}/?q=1", "profile": "web", "wait": True},
        headers=_auth_headers(),
    )
    assert res.status_code == 200
    data = res.json()
    assert data["state"] in ("completed", "partial")
    assert data["policy"]["authorization_ref"] == "local-tests"
    assert data["coverage"]["total"] == len(data["coverage"]["adapters"])
    assert data["coverage"]["total"] >= 1
    assert data["verdict"]
    assert "xss" in {finding["category"] for finding in data["findings"]}
    assert data["sarif_url"].endswith("/sarif")
    assert len(data["audit_chain_hash"]) == 64


def test_assess_out_of_scope_is_forbidden():
    res = client.post(
        "/api/assess",
        json={"target": "http://victim.example.net/"},
        headers=_auth_headers(),
    )
    assert res.status_code == 403
    assert "not in the authorized scope" in res.json()["detail"]


def test_assess_rejects_unknown_profile(local_target):
    res = client.post(
        "/api/assess",
        json={"target": f"{local_target.url}/", "profile": "everything"},
        headers=_auth_headers(),
    )
    assert res.status_code == 400


def test_sarif_document_is_served_and_well_formed(local_target):
    job = client.post(
        "/api/assess",
        json={"target": f"{local_target.url}/?q=1", "profile": "web", "wait": True},
        headers=_auth_headers(),
    ).json()

    res = client.get(job["sarif_url"], headers=_auth_headers())
    assert res.status_code == 200
    document = res.json()
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["tool"]["driver"]["name"] == "strix"
    assert document["runs"][0]["results"]


def test_unknown_job_is_404():
    assert client.get("/api/assess/job_missing", headers=_auth_headers()).status_code == 404


def test_static_index():
    res = client.get("/")
    assert res.status_code == 200
    assert "STRIX" in res.text
    assert "Autonomous Cyber Defense" in res.text
    # Scope panel and evidence bundle must actually be served
    assert 'data-tab="evidence"' in res.text
    assert 'id="scope-panel"' in res.text
    assert 'id="report-output-container"' in res.text
    # Assessment runner is wired into the same view
    assert 'id="btn-run-assess"' in res.text
    assert 'id="assess-output-container"' in res.text
    assert 'id="assess-history"' in res.text
