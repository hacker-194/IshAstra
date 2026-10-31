"""Regression tests for the manual security audit (each one a confirmed finding)."""
import os
import re
import stat
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from strix.api import deps
from strix.api import security as security_module
from strix.api.app import app
from strix.api.security import api_keys
from strix.core import adapters as adapter_module
from strix.core import jobs, scope, store
from strix.core.adapters import AdapterError, NmapAdapter

client = TestClient(app, raise_server_exceptions=False)
ROOT = Path(__file__).resolve().parent.parent


# -- F1: option injection / hostname syntax ----------------------------------
@pytest.fixture
def wildcard_scope():
    scope.configure(program="p", authorized_by="a", authorization_ref="r",
                    include=["*.example.com", "example.com", "127.0.0.1", "::1"],
                    authorized_networks=["127.0.0.0/8", "::1/128"])


@pytest.mark.parametrize("url", [
    "http://-iL.example.com/",
    "http://--script=x.example.com/",
    "http://-oN.example.com/",
    "http://ex*mple.example.com/",
    "http://exa$(id).example.com/",
    "http://\u00e9.example.com/",              # IDN must be supplied as punycode
    "http://" + "a" * 64 + ".example.com/",   # label over 63
])
def test_gate_refuses_hosts_that_are_not_dns_names(wildcard_scope, url):
    assert scope.check(url)[0] == "invalid_target"


@pytest.mark.parametrize("url", [
    "http://a_b.example.com/", "https://sub.example.com:8443/x", "http://127.0.0.1:8080/",
    "http://[::1]:8080/", "http://xn--caf-dma.example.com/",
])
def test_gate_still_accepts_legitimate_hosts(wildcard_scope, url):
    assert scope.check(url)[0] == ""


def test_nmap_gets_an_end_of_options_marker(monkeypatch):
    adapter = NmapAdapter()
    monkeypatch.setattr(adapter, "available", lambda: (True, "stub"))
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        # A real -Pn scan always reports the scanned port (open or closed);
        # output with no port element is treated as no coverage by the parser.
        return 0, ('<nmaprun><host><ports><port protocol="tcp" portid="80">'
                   '<state state="closed"/></port></ports></host></nmaprun>'), ""

    monkeypatch.setattr(adapter_module, "_run_tool", fake_run)
    adapter.assess("http://example.com/", timeout=5, cancel=threading.Event())
    argv = captured["argv"]
    assert argv[-2:] == ["--", "93.184.216.34"]


# -- F2: nmap XML entity guard ------------------------------------------------
@pytest.mark.parametrize("payload", [
    '<?xml version="1.0"?><!DOCTYPE nmaprun [<!ENTITY x "boom">]><nmaprun>&x;</nmaprun>',
    '<!DOCTYPE nmaprun [<!ELEMENT nmaprun ANY>]><nmaprun/>',
])
def test_nmap_output_with_entity_declarations_is_refused(monkeypatch, payload):
    adapter = NmapAdapter()
    monkeypatch.setattr(adapter, "available", lambda: (True, "stub"))
    monkeypatch.setattr(adapter_module, "_run_tool", lambda *a, **k: (0, payload, ""))
    with pytest.raises(AdapterError, match="entity"):
        adapter.assess("http://example.com/", timeout=5, cancel=threading.Event())


# -- F3: rate limiting keys on the routing path, not the Host-derived URL -----
def test_crafted_host_header_cannot_dodge_the_rate_limiter():
    security_module.rate_limiter.reset()
    status = None
    for _ in range(security_module.ANON_LIMIT if hasattr(security_module, "ANON_LIMIT") else 200):
        status = client.get("/api/overview", headers={"Host": "x/api/health#"}).status_code
        if status == 429:
            break
    assert status == 429


# -- F4: request id handling --------------------------------------------------
def test_sane_request_id_is_echoed_and_hostile_ones_are_replaced():
    ok = client.get("/api/health", headers={"X-Request-ID": "trace-123.abc_X"})
    assert ok.headers["x-request-id"] == "trace-123.abc_X"
    for bad in ("a b", "x" * 200, "<script>", "a\u00e9"):
        try:
            res = client.get("/api/health", headers={"X-Request-ID": bad})
        except UnicodeEncodeError:
            continue
        assert re.fullmatch(r"[0-9a-f]{16}", res.headers["x-request-id"]), bad


# -- F5: CSP --------------------------------------------------------------------
def test_csp_closes_the_gaps_default_src_does_not_cover():
    csp = client.get("/api/health").headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'self'" in csp
    assert "base-uri 'self'" in csp
    assert "object-src 'none'" in csp
    script_src = next(d for d in csp.split(";") if d.strip().startswith("script-src"))
    assert script_src.strip() == "script-src 'self'"        # no external script hosts
    assert "unsafe-inline" not in script_src and "unsafe-eval" not in script_src


# -- F6: unauthenticated readiness stays cheap ----------------------------------
def test_ready_does_not_reverify_the_whole_chain_on_every_call(monkeypatch):
    calls = []
    original = deps.audit_chain.verify_async
    async def counting_verify():
        calls.append(1)
        return await original()
    monkeypatch.setattr(deps.audit_chain, "verify_async", counting_verify)
    deps.audit_chain._cached = None
    for _ in range(10):
        assert client.get("/api/ready").status_code == 200
    assert len(calls) == 1


# -- F7: private database files ---------------------------------------------------
def test_database_files_are_owner_only():
    api_keys.register("perm-check", "free")
    path = store.current_path()
    for suffix in ("", "-wal", "-shm"):
        if os.path.exists(path + suffix):
            assert stat.S_IMODE(os.stat(path + suffix).st_mode) & 0o077 == 0, suffix


# -- F8: error text does not leak server internals -------------------------------
def test_unexpected_adapter_exception_text_is_not_exposed(monkeypatch):
    class Boom:
        id, requires = "boom", ()

        def available(self):
            return True, "ok"

        def assess(self, *a, **k):
            raise RuntimeError("secret /srv/strix/internal/path token=abc123")

        def info(self):
            return {"id": "boom"}

    monkeypatch.setattr(adapter_module, "select", lambda profile: [Boom()])
    job = jobs.run_assessment("http://example.com/", profile="web", actor="t", timeout=10)
    text = str(job.to_dict())
    assert "/srv/strix" not in text and "abc123" not in text
    assert "RuntimeError" in text


def test_tool_launch_errors_do_not_reveal_filesystem_paths(monkeypatch):
    def deny(*a, **k):
        raise PermissionError(13, "Permission denied", "/opt/secret/bin/nmap")

    monkeypatch.setattr(adapter_module.subprocess, "Popen", deny)
    with pytest.raises(AdapterError) as info:
        adapter_module._run_tool(["/opt/secret/bin/nmap", "x"], timeout=5, cancel=threading.Event())
    assert "/opt/secret" not in str(info.value)


# -- F9: reserved tenant name ------------------------------------------------------
def test_reserved_tenant_name_cannot_be_minted():
    admin = {"Authorization": f"Bearer {api_keys.register('res-admin', 'enterprise', admin=True)}"}
    res = client.post("/api/keys/create", json={"tenant": "system", "tier": "free"}, headers=admin)
    assert res.status_code == 422


# -- F10: UI escaping + dependency floors -------------------------------------------
def test_ui_escapes_quotes_and_every_innerhtml_message():
    js = (ROOT / "src/strix/api/static/app.js").read_text()
    assert "&#39;" in js
    assert "${message}" not in js
    assert not re.search(r"\$\{err\.message\}", js)


def test_dependency_floors_exclude_known_vulnerable_starlette():
    text = (ROOT / "pyproject.toml").read_text()
    floor = re.search(r'"starlette>=(\d+)\.(\d+)\.(\d+)', text)
    assert floor, "starlette must be pinned explicitly"
    assert tuple(map(int, floor.groups())) >= (1, 3, 1)      # >= 0.49.1 fixes CVE-2025-62727
