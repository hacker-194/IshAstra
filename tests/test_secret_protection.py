"""Secret protection: credentials inserted at every input must not survive in
any output. These tests inspect the *actual* persisted records and generated
outputs — database rows, API responses, audit entries, chain entries, SARIF,
HTML reports — not just the redaction functions.
"""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from strix.api.app import app
from strix.api.security import api_keys
from strix.core import adapters as adapter_module
from strix.core import scope, store
from strix.core.adapters import Adapter, AdapterError, AdapterResult
from strix.core.findings import Finding
from strix.core.redaction import redact_cookie_value, redact_text, sanitize_target

client = TestClient(app)

SECRET = "s3cr3t_T0ken_Value"
TARGET = f"http://example.com/dashboard?token={SECRET}&q=page&view=grid"


def auth(key):
    return {"Authorization": f"Bearer {key}"}


class Noop(Adapter):
    id = "noop"
    asset_types = ("web",)

    def assess(self, target, *, timeout, cancel, context=None):
        return AdapterResult(findings=[], notes=["noop"])


class Broken(Adapter):
    id = "broken"
    asset_types = ("web",)

    def assess(self, target, *, timeout, cancel, context=None):
        raise AdapterError(f"connect failed for ?token={SECRET} session={SECRET}")


@pytest.fixture
def noop(monkeypatch):
    monkeypatch.setattr(adapter_module, "select", lambda profile: [Noop()])


@pytest.fixture
def broken(monkeypatch):
    monkeypatch.setattr(adapter_module, "select", lambda profile: [Broken()])


# ---------------------------------------------------------------------------
# Unit behavior of the redaction layers
# ---------------------------------------------------------------------------
def test_sanitize_target_removes_sensitive_values_and_keeps_the_asset():
    out = sanitize_target(TARGET)
    assert SECRET not in out
    assert "example.com/dashboard" in out
    assert "q=page" in out and "view=grid" in out          # useful context kept
    assert "token=%5BREDACTED%5D" in out or "token=[REDACTED]" in out


@pytest.mark.parametrize("raw, marker", [
    ("api_key=abc123", "api_key="),
    ("sessionid=0123abc", "sessionid="),
    ("client_secret=xyz", "client_secret="),
    ("access_token=zzz", "access_token="),
    ('{"access_token":"very_secret_access_value"}', "access_token"),
    ('{"refresh_token":"very_secret_refresh_value"}', "refresh_token"),
    ('{"id_token":"very_secret_id_value"}', "id_token"),
    ('{"oauth_token":"very_secret_oauth_value"}', "oauth_token"),
    ("pwd=hunter2", "pwd="),
    ("X-Amz-Credential=AKIAEXAMPLE/20261026/region/s3/aws4_request", "X-Amz-Credential="),
])
def test_sensitive_query_parameters_are_redacted_by_name(raw, marker):
    out = sanitize_target(f"http://example.com/?{raw}&ok=1")
    assert SECRET not in out and "abc123" not in out and "0123abc" not in out
    assert marker in out and "ok=1" in out


def test_redact_text_covers_modern_credential_shapes():
    jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
           "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")
    # Deliberate credential-shaped fixtures: the point of this test is that
    # redaction removes them. Allowlisted for scripts/check_secrets.py.
    aws_key = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret
    pem_bait = ("-----BEGIN RSA PRIVATE KEY-----"  # pragma: allowlist secret
                "MIIEpAIBAAKCAQ"
                "-----END RSA PRIVATE KEY-----")
    text = (f"Authorization: Bearer {jwt}; aws key {aws_key}; "
            f"password=hunter2; connect user:secretpw@host; {pem_bait}")
    out = redact_text(text)
    assert "hunter2" not in out and aws_key not in out
    assert jwt not in out and "secretpw" not in out and "MIIEpAIBAAKCAQ" not in out
    assert "[REDACTED_JWT]" in out and "[REDACTED_AWS_KEY]" in out
    assert "[REDACTED_PRIVATE_KEY]" in out


def test_redact_text_keeps_finding_ids_and_hosts():
    text = "category secret finding on monkey.com host; password field id=7"
    out = redact_text(text)
    assert "monkey.com" in out and "secret" in out      # ids/hosts survive


def test_redact_cookie_value_keeps_flags_drops_material():
    out = redact_cookie_value("session=abc123def; Path=/; Secure; HttpOnly")
    assert "abc123def" not in out and "session=" in out
    assert "Path=/; Secure; HttpOnly" in out


def test_finding_to_dict_redacts_evidence_and_location():
    finding = Finding(
        asset=f"http://example.com/?api_key={SECRET}",
        category="sqli", title="t", severity="info", confidence="low",
        detector="d", detector_version="1",
        evidence=f"query leaked credential token={SECRET}",
        location=f"http://example.com/x?password={SECRET}")
    data = finding.to_dict()
    dumped = json.dumps(data)
    assert SECRET not in dumped


# ---------------------------------------------------------------------------
# End-to-end: a target carrying credentials in its URL
# ---------------------------------------------------------------------------
def _all_outputs_for_job(key, target):
    """Run one assessment and collect every output path that could hold the URL."""
    res = client.post("/api/assess", json={"target": target, "wait": True},
                      headers=auth(key))
    assert res.status_code == 200, res.text
    job_id = res.json()["id"]

    connection = sqlite3.connect(store.current_path())
    connection.row_factory = sqlite3.Row
    job_row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    audit_rows = connection.execute("SELECT data FROM audit_log").fetchall()
    chain_rows = connection.execute("SELECT data FROM audit_chain").fetchall()
    connection.close()

    return {
        "api_create": res.text,
        "api_job": client.get(f"/api/assess/{job_id}", headers=auth(key)).text,
        "api_list": client.get("/api/assess", headers=auth(key)).text,
        "sarif": client.get(f"/api/assess/{job_id}/sarif", headers=auth(key)).text,
        "report_html": client.get(f"/api/assess/{job_id}/report.html",
                                  headers=auth(key)).text,
        "report": client.post("/api/report", json={"target": target},
                              headers=auth(key)).text,
        "api_audit": client.get("/api/audit", headers=auth(key)).text,
        "db_job_target": job_row["target"] if job_row else "",
        "db_job_error": job_row["error"] if job_row else "",
        "db_audit": " ".join(row["data"] for row in audit_rows),
        "db_chain": " ".join(row["data"] for row in chain_rows),
    }


def test_no_output_path_retains_the_target_credentials(noop):
    key = api_keys.register("secret-co", "pro")
    outputs = _all_outputs_for_job(key, TARGET)
    for path, blob in outputs.items():
        assert SECRET not in blob, f"secret survived in {path}"
    # The sanitized target still identifies the asset everywhere it appears.
    for path in ("api_create", "api_job", "db_job_target", "report"):
        assert "example.com/dashboard" in outputs[path]


def test_error_messages_are_redacted_at_rest_and_in_responses(broken):
    key = api_keys.register("error-co", "pro")
    res = client.post("/api/assess", json={"target": "http://example.com/?q=1",
                                           "wait": True}, headers=auth(key))
    assert res.status_code == 200
    body = res.text
    connection = sqlite3.connect(store.current_path())
    connection.row_factory = sqlite3.Row
    row = connection.execute("SELECT error FROM jobs ORDER BY created_at DESC "
                             "LIMIT 1").fetchone()
    connection.close()
    assert SECRET not in body
    assert SECRET not in row["error"], "job error stored raw"
    assert f"token={SECRET}" not in row["error"]


def test_sarif_output_is_redacted():
    finding = Finding(
        asset="http://example.com/", category="cat", title="t",
        severity="info", confidence="low", detector="d", detector_version="1",
        evidence=f"evidence with password={SECRET}", location="http://example.com/?token=x")
    from strix.core.findings import to_sarif
    dumped = json.dumps(to_sarif([finding]))
    assert SECRET not in dumped


def test_audit_and_chain_entries_are_redacted_centrally():
    from strix.audit import AuditChain, AuditLog
    chain = AuditChain()
    log = AuditLog()
    log.record({"event": "e", "target": f"http://h/?token={SECRET}", "tenant": "t"})
    chain.append({"event": "e", "target": f"http://h/?token={SECRET}"})
    assert SECRET not in json.dumps(log.entries())
    assert SECRET not in json.dumps(chain.entries)


# ---------------------------------------------------------------------------
# Probe responses: Set-Cookie session material
# ---------------------------------------------------------------------------
class CookieServer:
    def __init__(self):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                payload = b"hello"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Set-Cookie",
                                 f"session={SECRET}; Path=/; Secure; HttpOnly")
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server.server_port}/"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def test_probe_response_does_not_echo_session_cookie_values(monkeypatch):
    server = CookieServer()
    try:
        monkeypatch.setattr(scope, "resolve", lambda host, port=None: ["127.0.0.1"])
        scope.configure(
            program="probe redaction", authorized_by="pytest",
            authorization_ref="probe-secret", include=["127.0.0.1"],
            authorized_networks=["127.0.0.0/8"])
        try:
            key = api_keys.register("probe-co", "pro")
            res = client.post("/api/probe", json={"url": server.url}, headers=auth(key))
            assert res.status_code == 200
            assert SECRET not in res.text, "Set-Cookie session value leaked via /api/probe"
            assert "session=" in res.text            # the flag context survives
            assert "Path=/; Secure; HttpOnly" in res.text
        finally:
            scope._active = None
    finally:
        server.close()


def test_monitor_alerts_do_not_carry_raw_targets():
    from strix.audit import AuditChain
    from strix.monitor import Monitor
    monitor = Monitor(audit_chain=AuditChain(), webhook_secret="test-webhook-secret")
    emitted = []
    monitor.alert_sinks = [type("Capture", (), {
        "send": lambda self, alert: emitted.append(alert)})()]
    import asyncio
    job = type("J", (), {"state": None, "id": "j1", "error": f"boom ?token={SECRET}",
                         "findings": []})
    asyncio.run(monitor._evaluate(f"http://example.com/?token={SECRET}", job))
    # assessment_incomplete path includes job.error and target — both redacted
    if emitted:
        assert SECRET not in json.dumps(emitted)


def test_probe_redacts_body_error_headers_and_url_query(monkeypatch):
    from strix.core.probe import EndpointProbe

    token = "probe_body_secret_982734"
    def fake_probe(self, url, *, deadline):
        return {
            "status": 200,
            "headers": {"x-debug": f"access_token={token}",
                        "set-cookie": f"session={token}; Path=/; Secure"},
            "security_headers": {"content-security-policy": f"token={token}"},
            "body_snippet": '{"access_token": "' + token + '"}',
            "error": f"request failed with token={token}",
        }
    monkeypatch.setattr(EndpointProbe, "probe", fake_probe)
    key = api_keys.register("probe-leak-co", "pro")
    response = client.post(
        "/api/probe", json={"url": f"http://example.com/?access_token={token}"},
        headers=auth(key),
    )
    assert response.status_code == 200, response.text
    assert token not in response.text
    returned = response.json()["url"]
    assert "access_token=%5BREDACTED%5D" in returned or "access_token=[REDACTED]" in returned


def test_recursive_redaction_uses_sensitive_field_names_even_for_short_values():
    from strix.core.redaction import redact

    payload = {
        "x-api-key": "short-secret",
        "Authorization": "opaque-value",
        "cookie": "sid=abc123",
        "nested": {"refresh_token": "rt-1"},
        "Set-Cookie": "session=abc123; Path=/; Secure; HttpOnly",
        "authorization_ref": "ENG-2026-01",
    }
    cleaned = redact(payload)
    encoded = json.dumps(cleaned)
    for secret in ("short-secret", "opaque-value", "sid=abc123", "rt-1", "session=abc123"):
        assert secret not in encoded
    assert "Path=/" in cleaned["Set-Cookie"] and "HttpOnly" in cleaned["Set-Cookie"]
    assert cleaned["authorization_ref"] == "ENG-2026-01"


def test_malformed_urls_do_not_bypass_query_secret_redaction():
    from strix.core.redaction import has_sensitive_query_params, sanitize_target

    malformed = "http://[bad-host/?access_token=should-not-leak"
    assert has_sensitive_query_params(malformed) is True
    assert "should-not-leak" not in sanitize_target(malformed)
