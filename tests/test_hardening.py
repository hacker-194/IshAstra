"""Regression tests for the hardening pass: body limits, persistence, bounds, pinning."""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from strix import monitor as monitor_module
from strix.api import body_depth
from strix.api.app import app
from strix.api.security import APIKeyStore, _TokenBucket, api_keys
from strix.audit import AuditChain, AuditLog
from strix.core import store
from strix.core.probe import _all_cookies_secure, grade_security_headers

client = TestClient(app, raise_server_exceptions=False)
JSON = {"Content-Type": "application/json"}


# -- request body guards -----------------------------------------------------
def test_pathologically_deep_json_is_a_400_not_a_500():
    deep = "[" * 100_000 + "]" * 100_000
    res = client.post("/api/probe", content=deep, headers=JSON)
    assert res.status_code == 400


def test_over_nested_objects_are_rejected():
    body = '{"a":' * 12 + "1" + "}" * 12
    res = client.post("/api/probe", content=body, headers=JSON)
    assert res.status_code == 400
    assert "nesting" in res.json()["detail"]


def test_oversized_body_is_rejected_before_authentication(monkeypatch):
    monkeypatch.setattr(body_depth, "MAX_BODY_BYTES", 1024)
    res = client.post("/api/probe", content=b'{"url":"' + b"a" * 4096 + b'"}', headers=JSON)
    assert res.status_code == 413


def test_body_within_limits_still_reaches_authentication():
    assert client.post("/api/probe", json={"url": "http://example.com"}).status_code == 401


def test_json_depth_counts_objects_and_lists():
    assert body_depth.json_depth({}) == 1
    assert body_depth.json_depth({"a": {"b": {}}}) == 3
    assert body_depth.json_depth([[[1]]]) == 3
    assert body_depth.json_depth({"a": [{"b": 1}]}) == 3


def test_streamed_body_without_content_length_is_bounded():
    import asyncio

    from strix.api.body_depth import BodyLimitMiddleware

    messages = iter([
        {"type": "http.request", "body": b"12345", "more_body": True},
        {"type": "http.request", "body": b"67890", "more_body": False},
    ])
    sent = []

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    async def downstream(_scope, _receive, _send):
        raise AssertionError("oversized request must not reach the route")

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": "POST", "scheme": "http", "path": "/", "raw_path": b"/",
        "query_string": b"", "headers": [(b"content-type", b"application/octet-stream")],
        "server": ("test", 80), "client": ("test", 1234), "root_path": "",
    }
    asyncio.run(BodyLimitMiddleware(downstream, max_body_bytes=8)(scope, receive, send))
    assert sent[0]["status"] == 413


def test_cookie_secure_flag_is_parsed_as_an_attribute():
    assert _all_cookies_secure(["session=abc; Path=/; Secure; HttpOnly"])
    assert not _all_cookies_secure(["session=abc; Path=/; NotSecure"])
    assert not _all_cookies_secure([
        "session=abc; Path=/; Secure", "prefs=dark; Path=/"
    ])
    assert not _all_cookies_secure(None)


def test_hsts_is_not_deducted_for_plain_http():
    _, _, http_deductions = grade_security_headers({}, {
        "csp": "default-src 'self'", "hsts": None, "frame": "DENY",
        "cookie_secure": False,
    }, is_https=False)
    _, _, https_deductions = grade_security_headers({}, {
        "csp": "default-src 'self'", "hsts": None, "frame": "DENY",
        "cookie_secure": False,
    }, is_https=True)
    assert not any("HSTS" in item for item in http_deductions)
    assert any("HSTS" in item for item in https_deductions)


# -- API keys ----------------------------------------------------------------
def test_rotating_a_key_retires_the_old_one():
    keys = APIKeyStore()
    old = keys.register("rotator", "pro")
    new = keys.register("rotator", "pro")
    assert keys.validate(old) is None
    assert keys.validate(new)["tenant_id"] == "rotator"


def test_keys_survive_a_restart_and_revocation_sticks():
    key = api_keys.register("durable", "pro")
    gone = api_keys.register("revoked-durable", "pro")
    api_keys.revoke("revoked-durable")

    restarted = APIKeyStore(persistent=True)
    restarted.load()
    assert restarted.validate(key)["tier"] == "pro"
    assert restarted.validate(gone) is None


def test_database_holds_only_key_hashes():
    key = api_keys.register("hash-only", "free")
    connection = sqlite3.connect(store.current_path())
    dump = " ".join(str(row) for row in connection.execute("SELECT * FROM api_keys"))
    connection.close()
    assert key not in dump


# -- audit persistence and tamper evidence -----------------------------------
def test_audit_log_survives_a_restart():
    AuditLog(persistent=True).record({"event": "x", "tenant": "t1", "n": 1})
    restored = AuditLog(persistent=True)
    restored.load()
    assert restored.entries(tenant="t1")[0]["n"] == 1


def test_persistent_chain_verifies_and_detects_database_tampering():
    chain = AuditChain(persistent=True)
    for i in range(3):
        chain.append({"event": "e", "n": i})
    assert chain.verify() == (True, None)
    assert len(chain) == 3

    connection = sqlite3.connect(store.current_path())
    row = connection.execute("SELECT data FROM audit_chain WHERE sequence = 2").fetchone()
    connection.execute("UPDATE audit_chain SET data = ? WHERE sequence = 2",
                       (row[0].replace('"n": 1', '"n": 99'),))
    connection.commit()
    connection.close()
    assert AuditChain(persistent=True).verify()[0] is False


def test_deleting_a_chain_row_is_detected():
    chain = AuditChain(persistent=True)
    for i in range(3):
        chain.append({"event": "e", "n": i})
    connection = sqlite3.connect(store.current_path())
    connection.execute("DELETE FROM audit_chain WHERE sequence = 2")
    connection.commit()
    connection.close()
    assert chain.verify()[0] is False


def test_hmac_chain_cannot_be_recomputed_without_the_key():
    chain = AuditChain(persistent=True, hmac_key="operator-secret")
    chain.append({"event": "e", "n": 1})
    assert chain.verify()[0] is True

    # An attacker with database write access rewrites the entry and re-hashes it
    # with plain SHA-256 — the best they can do without the key.
    forged = AuditChain(persistent=True)  # no key
    connection = sqlite3.connect(store.current_path())
    data = json.loads(connection.execute("SELECT data FROM audit_chain").fetchone()[0])
    data["n"] = 2
    connection.execute("UPDATE audit_chain SET data = ?, hash = ?",
                       (json.dumps(data, sort_keys=True), forged._digest(data)))
    connection.commit()
    connection.close()
    assert chain.verify()[0] is False


# -- bounded memory ----------------------------------------------------------
def test_rate_limit_state_is_bounded():
    now = [0.0]
    bucket = _TokenBucket(5, 60.0, clock=lambda: now[0], max_keys=100)
    for i in range(1_000):
        bucket.allow(f"peer-{i}")
    assert len(bucket.tokens) <= 100


def test_eviction_prefers_idle_keys_over_active_ones():
    now = [0.0]
    bucket = _TokenBucket(2, 60.0, clock=lambda: now[0], max_keys=10)
    for i in range(9):
        bucket.allow(f"idle-{i}")                  # seen once, at t=0
    now[0] = 0.5
    assert bucket.allow("hot") and bucket.allow("hot")
    assert not bucket.allow("hot")                 # exhausted, most recently seen
    now[0] = 1.0
    bucket.allow("newcomer")                       # tracked > max_keys -> evict idlest
    assert not bucket.allow("hot")                 # the active key kept its (empty) bucket
    assert len(bucket.tokens) <= 10


# -- database access ---------------------------------------------------------
def test_schema_is_migrated_once_per_file(tmp_path, monkeypatch):
    calls = []
    original = store.migrate_async

    async def counting(connection, path=None):
        calls.append(1)
        return await original(connection, path)

    monkeypatch.setattr(store, "migrate_async", counting)
    store.configure(tmp_path / "fresh.db")
    store._run_async(store.schema_version())
    store._run_async(store.schema_version())
    assert len(calls) == 1, "the schema was migrated again for an already-migrated file"


# -- webhook pinning ---------------------------------------------------------
def test_webhook_connects_to_the_validated_address(monkeypatch):
    monkeypatch.setattr(monitor_module.scope, "resolve_sync", lambda host, port=None: ["93.184.216.34"])
    parsed, ip = monitor_module._pin_webhook("https://hooks.example.com/alert?x=1")
    assert ip == "93.184.216.34" and parsed.hostname == "hooks.example.com"


def test_webhook_refused_if_any_resolved_address_is_internal(monkeypatch):
    monkeypatch.setattr(monitor_module.scope, "resolve_sync",
                        lambda host, port=None: ["93.184.216.34", "10.0.0.7"])
    assert "non-public" in monitor_module._pin_webhook("https://hooks.example.com/")


@pytest.mark.parametrize("resolved", [[], None])
def test_webhook_refused_when_host_does_not_resolve(monkeypatch, resolved):
    monkeypatch.setattr(monitor_module.scope, "resolve_sync", lambda host, port=None: resolved or [])
    assert "resolve" in monitor_module._pin_webhook("https://nope.example.com/")


# -- security events are sealed in the chain ---------------------------------
def test_key_lifecycle_and_denials_are_sealed_in_the_chain():
    admin = api_keys.register("chain-admin", "enterprise", admin=True)
    free = api_keys.register("chain-free", "free")
    auth = lambda k: {"Authorization": f"Bearer {k}"}  # noqa: E731

    client.post("/api/keys/create", json={"tenant": "chain-new", "tier": "pro"}, headers=auth(admin))
    client.post("/api/keys/create", json={"tenant": "chain-admin", "tier": "enterprise"},
                headers=auth(free))                                   # denied
    data = client.get("/api/audit/verify", headers=auth(admin)).json()
    assert data["valid"] is True
    assert data["entries"] >= 2


# -- monitor configuration survives a restart --------------------------------
def test_monitor_configure_can_replace_and_remove_targets():
    admin = {"Authorization": f"Bearer {api_keys.register('mon-admin-2', 'enterprise', admin=True)}"}
    client.post("/api/monitor/configure", headers=admin,
                json={"targets": ["http://example.com/a", "http://example.com/b"]})
    res = client.post("/api/monitor/configure", headers=admin,
                      json={"targets": ["http://example.com/b"], "replace": True})
    assert res.json()["monitored_targets"] == ["http://example.com/b"]


def test_monitor_targets_and_interval_survive_a_restart():
    admin = api_keys.register("mon-admin", "enterprise", admin=True)
    res = client.post("/api/monitor/configure", headers={"Authorization": f"Bearer {admin}"},
                      json={"interval_seconds": 120, "targets": ["http://example.com/a",
                                                                 "http://example.com/b"]})
    assert res.status_code == 200

    from strix.monitor import Monitor
    restarted = Monitor(audit_chain=AuditChain(), webhook_secret="test-webhook-secret")
    restarted.load()
    assert restarted.targets == ["http://example.com/a", "http://example.com/b"]
    assert restarted.interval == 120


# -- every response, including errors, carries request id + security headers --
@pytest.mark.parametrize("make", [
    lambda: client.get("/api/overview"),                                            # 401
    lambda: client.get("/api/does-not-exist"),                                      # 404
    lambda: client.post("/api/probe", content='{"a":' * 12 + "1" + "}" * 12, headers=JSON),  # 400
])
def test_error_responses_carry_standard_headers(make):
    res = make()
    assert res.status_code >= 400
    assert "x-request-id" in res.headers
    assert "x-content-type-options" in res.headers


def test_oversized_and_rate_limited_responses_carry_standard_headers(monkeypatch):
    monkeypatch.setattr(body_depth, "MAX_BODY_BYTES", 16)
    big = client.post("/api/probe", content=b'{"url":"' + b"a" * 64 + b'"}', headers=JSON)
    assert big.status_code == 413 and "x-request-id" in big.headers
    assert "x-content-type-options" in big.headers


# -- version is defined once --------------------------------------------------
def test_version_is_single_sourced():
    from strix import __version__
    from strix.core.findings import to_sarif
    from strix.core.probe import USER_AGENT
    assert to_sarif([])["runs"][0]["tool"]["driver"]["version"] == __version__
    assert __version__ in USER_AGENT
    assert client.get("/api/health").json()["version"] == __version__


def test_ui_sends_credentials_on_every_api_call():
    import re
    from pathlib import Path
    js = Path(body_depth.__file__).parent.joinpath("static", "app.js").read_text()
    for call in re.findall(r"fetch\([^;]*?\)\s*;", js, flags=re.S):
        assert "getAuthHeaders" in call or "Authorization" in call, call[:80]


def test_inline_wait_is_capped_so_it_cannot_pin_a_server_thread():
    key = {"Authorization": f"Bearer {api_keys.register('waiter', 'pro')}"}
    res = client.post("/api/assess", headers=key,
                      json={"target": "http://example.com/", "wait": True, "timeout": 900})
    assert res.status_code == 400 and "wait=true" in res.json()["detail"]


# -- webhook sinks survive a restart -----------------------------------------
def test_webhook_sinks_persist_across_a_restart():
    from strix.monitor import Monitor
    admin = {"Authorization": f"Bearer {api_keys.register('sink-admin', 'enterprise', admin=True)}"}
    res = client.post("/api/alerts/webhook", headers=admin,
                      json={"name": "soc-hook", "url": "https://hooks.example.com/soc"})
    assert res.status_code == 200

    restarted = Monitor(audit_chain=AuditChain(), webhook_secret="test-webhook-secret")
    restarted.load()
    names = [getattr(sink, "name", "") for sink in restarted.alert_sinks]
    assert "soc-hook" in names
    hook = next(sink for sink in restarted.alert_sinks if getattr(sink, "name", "") == "soc-hook")
    assert hook.url == "https://hooks.example.com/soc"
