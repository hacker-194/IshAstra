"""Authorization-difference testing: principals, session attachment, differentials.

Credentials are supplied through the scope document and must never leak into
findings, notes or persisted rows. Every test here also pins that boundary.
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlparse

import pytest

from strix.core import scope
from strix.core.adapters import AuthorizationDiffAdapter
from strix.core.authz import AuthConfig, Principal, body_digest, candidate_endpoints, classify, vary_id
from strix.core.jobs import run_assessment


# ---------------------------------------------------------------------------
# Principal / AuthConfig validation
# ---------------------------------------------------------------------------
def test_principal_rejects_header_injection():
    with pytest.raises(ValueError, match="cookie name"):
        Principal(id="alice", cookies=(("bad\r\nX-Injected: 1", "v"),))
    with pytest.raises(ValueError, match="control characters"):
        Principal(id="alice", cookies=(("session", "abc\nX-Injected: 1"),))
    with pytest.raises(ValueError, match="header name"):
        Principal(id="alice", headers=(("X Bad Space", "v"),))
    with pytest.raises(ValueError, match="principal id"):
        Principal(id="bad id!", cookies=(("session", "v"),))


def test_principal_from_dict_forms():
    principal = Principal.from_dict({
        "id": "bob",
        "cookies": [{"name": "session", "value": "bbb"}, "k=v"],
        "headers": {"X-Tenant": "t2"},
        "bearer": "tok",
    })
    assert principal.cookies == (("session", "bbb"), ("k", "v"))
    assert principal.headers == (("X-Tenant", "t2"),)
    assert principal.bearer == "tok"
    assert principal.has_credentials


def test_auth_config_requires_credentials_and_unique_ids():
    with pytest.raises(ValueError, match="unique"):
        AuthConfig(users=(Principal(id="a", bearer="x"), Principal(id="a", bearer="y")))
    with pytest.raises(ValueError, match="credential"):
        AuthConfig(users=(Principal(id="a"),))


def test_scope_load_rejects_malformed_auth(tmp_path):
    document = tmp_path / "scope.json"
    document.write_text(json.dumps({
        "program": "p", "authorized_by": "a", "authorization_ref": "r",
        "include": ["example.com"],
        "auth": {"users": [{"id": "alice"}]},  # no credentials at all
    }))
    with pytest.raises(ValueError, match="credential"):
        scope.load(document)


# ---------------------------------------------------------------------------
# Session attachment (real HTTP through the loopback server)
# ---------------------------------------------------------------------------
class IdentityHandler(BaseHTTPRequestHandler):
    """Echoes the identity the request carried, as JSON."""

    hits: list[dict[str, str]] = []

    def do_GET(self):
        parsed = urlparse(self.path)
        params = dict(parse_qsl(parsed.query))
        type(self).hits.append({
            "path": parsed.path,
            "cookie": self.headers.get("Cookie", ""),
            "authorization": self.headers.get("Authorization", ""),
            "x-tenant": self.headers.get("X-Tenant", ""),
        })
        owner_id = params.get("id", "0")
        # The vulnerable demo endpoint: the response does not depend on who
        # asks — anyone (even anonymous) may read any order id.
        body = json.dumps({"order": owner_id, "owner": "owner-" + owner_id,
                           "amount": 100}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def identity_site():
    IdentityHandler.hits = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), IdentityHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield type("Site", (), {"base": f"http://127.0.0.1:{server.server_port}",
                                "hits": IdentityHandler.hits})
    finally:
        server.shutdown()
        server.server_close()


def test_probe_attaches_principal_credentials(identity_site):
    from strix.core.probe import EndpointProbe
    alice = Principal(id="alice", cookies=(("session", "alice-session"),),
                      headers=(("X-Tenant", "t1"),))
    probe = EndpointProbe(timeout=5.0)
    probe._fetch(identity_site.base + "/api/orders/1001", auth=alice)
    record = IdentityHandler.hits[-1]
    assert record["cookie"] == "session=alice-session"
    assert record["x-tenant"] == "t1"

    bob = Principal(id="bob", bearer="bob-token")
    probe._fetch(identity_site.base + "/api/orders/1001", auth=bob)
    assert IdentityHandler.hits[-1]["authorization"] == "Bearer bob-token"

    probe._fetch(identity_site.base + "/api/orders/1001")
    assert IdentityHandler.hits[-1]["cookie"] == ""
    assert IdentityHandler.hits[-1]["authorization"] == ""


# ---------------------------------------------------------------------------
# Endpoint candidates and id substitution
# ---------------------------------------------------------------------------
def test_candidate_endpoints_selection():
    urls = [
        "http://app.example/api/orders/1001",
        "http://app.example/api/users?id=42",
        "http://app.example/api/items?page=3",          # pagination: not an object ref
        "http://app.example/static/logo.png",           # no id shape
        "http://app.example/api/search?q=123",          # search: excluded param
        "http://app.example/a/1/b/2",                   # first numeric segment qualifies
    ]
    picked = candidate_endpoints(urls)
    assert picked[0] == urls[0]
    assert picked[1] == urls[1]
    assert "http://app.example/api/items?page=3" not in picked
    assert "http://app.example/static/logo.png" not in picked
    assert "http://app.example/api/search?q=123" not in picked
    assert "http://app.example/a/1/b/2" in picked


def test_candidate_endpoints_cap():
    urls = [f"http://app.example/api/x/{n}" for n in range(20)]
    assert len(candidate_endpoints(urls)) == 8


def test_vary_id_replaces_object_reference():
    assert vary_id("http://app.example/api/orders/1001", "900001") == \
        "http://app.example/api/orders/900001"
    assert vary_id("http://app.example/api/orders/1001?x=1", "900001") == \
        "http://app.example/api/orders/900001?x=1"
    assert vary_id("http://app.example/api/users?id=42", "9") == \
        "http://app.example/api/users?id=9"
    assert vary_id("http://app.example/api/users?page=2", "9") is None


def test_body_digest_and_classify():
    assert body_digest("x") == body_digest("x")
    assert body_digest("x") != body_digest("y")
    result = classify(type("D", (), {"anonymous_matches_first": True,
                                     "principals_identical": True})())
    assert result == ["authorization_missing", "object_access_unscoped"]


# ---------------------------------------------------------------------------
# The differential adapter against real endpoint behavior
# ---------------------------------------------------------------------------
def _configure_auth(users: list[Principal]) -> None:
    current = scope.active()
    assert current is not None, "scope must be configured for auth tests"
    scope.configure(program=current.program, authorized_by=current.authorized_by,
                    authorization_ref=current.authorization_ref,
                    include=current.include, exclude=current.exclude,
                    authorized_networks=current.authorized_networks,
                    allowed_ports=current.allowed_ports,
                    auth=AuthConfig(users=tuple(users)))


def test_adapter_unavailable_without_principals():
    ok, detail = AuthorizationDiffAdapter().available()
    assert not ok and "principals" in detail


def test_vulnerable_endpoint_reports_both_categories(identity_site):
    """Anyone reads any order: anonymous == authenticated, both principals identical."""
    _configure_auth([Principal(id="alice", cookies=(("session", "alice-session"),)),
                     Principal(id="bob", cookies=(("session", "bob-session"),))])
    adapter = AuthorizationDiffAdapter()
    ok, _ = adapter.available()
    assert ok
    result = adapter.assess(identity_site.base + "/api/orders/1001",
                            timeout=30.0, cancel=threading.Event())
    categories = {finding.category for finding in result.findings}
    assert "authorization_missing" in categories
    # anonymous body == alice body (same json), so both categories fire
    assert "object_access_unscoped" in categories
    for finding in result.findings:
        assert finding.verification in ("observed", "inferred")
        blob = json.dumps(finding.to_dict())
        assert "alice-session" not in blob and "bob-session" not in blob


def test_enforced_authorization_is_a_note_not_a_finding(identity_site, monkeypatch):
    """Server distinguishes principals: 403 for bob and anon on alice's object."""
    class EnforcingHandler(IdentityHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            cookie = self.headers.get("Cookie", "")
            # the object reference is the numeric path segment: /api/orders/1001
            owner_id = parsed.path.rstrip("/").split("/")[-1] or "0"
            body: bytes
            if "alice-session" in cookie:
                if owner_id != "1001":
                    body = b'{"error": "not yours"}'
                    self.send_response(403)
                else:
                    body = json.dumps({"order": "1001", "owner": "alice",
                                       "amount": 100}).encode()
                    self.send_response(200)
            elif "bob-session" in cookie:
                if owner_id != "2002":
                    body = b'{"error": "not yours"}'
                    self.send_response(403)
                else:
                    body = json.dumps({"order": "2002", "owner": "bob",
                                       "amount": 250}).encode()
                    self.send_response(200)
            else:
                body = b'{"error": "auth required"}'
                self.send_response(401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), EnforcingHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        _configure_auth([Principal(id="alice", cookies=(("session", "alice-session"),)),
                         Principal(id="bob", cookies=(("session", "bob-session"),))])
        base = f"http://127.0.0.1:{server.server_port}"
        result = AuthorizationDiffAdapter().assess(
            base + "/api/orders/1001", timeout=30.0, cancel=threading.Event())
        assert result.findings == []  # enforced authorization produces no finding
        assert any("refused" in note for note in result.notes)
    finally:
        server.shutdown()
        server.server_close()


def test_cross_principal_identical_object_is_flagged(identity_site, monkeypatch):
    """Same object, identical body to alice and bob, anon gets 401: BOLA indicator."""
    class OwnerAwareHandler(IdentityHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            params = dict(parse_qsl(parsed.query))
            cookie = self.headers.get("Cookie", "")
            owner_id = params.get("id", "0")
            body = json.dumps({"order": owner_id, "owner": "owner-" + owner_id,
                               "amount": 100}).encode()
            if cookie:
                self.send_response(200)
            else:
                self.send_response(401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), OwnerAwareHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        _configure_auth([Principal(id="alice", cookies=(("session", "alice-session"),)),
                         Principal(id="bob", cookies=(("session", "bob-session"),))])
        base = f"http://127.0.0.1:{server.server_port}"
        result = AuthorizationDiffAdapter().assess(
            base + "/api/orders/1001", timeout=30.0, cancel=threading.Event())
        categories = {finding.category for finding in result.findings}
        assert "object_access_unscoped" in categories
        assert "authorization_missing" not in categories  # anon was refused
        finding = next(f for f in result.findings
                       if f.category == "object_access_unscoped")
        assert finding.cwe == "CWE-639"
        blob = json.dumps(finding.to_dict())
        assert "alice-session" not in blob  # credentials never leak
    finally:
        server.shutdown()
        server.server_close()


def test_authz_with_crawler_handoff_and_job_profile(identity_site, monkeypatch):
    """api-deep profile: crawler discovers /api/orders/2, authz tests it as well."""
    _configure_auth([Principal(id="alice", cookies=(("session", "alice-session"),)),
                     Principal(id="bob", cookies=(("session", "bob-session"),))])
    # The identity site serves every path, so the crawler will find /2 only if
    # it is linked. Serve a page with links via a one-off HTML path:
    # the handler above always returns JSON; crawl finds no links — that is
    # fine, the adapter must still test the target itself.
    import strix.core.adapters as adapter_module
    monkeypatch.setattr(adapter_module.NucleiAdapter, "available",
                        lambda self: (False, "stubbed out for unit test"))
    monkeypatch.setattr(adapter_module.NmapAdapter, "available",
                        lambda self: (False, "stubbed out for unit test"))
    job = run_assessment(identity_site.base + "/api/orders/1001",
                         profile="api-deep", timeout=90.0)
    states = {run.adapter: run.state.value for run in job.runs}
    assert states["strix-authz"] in ("ok", "unavailable")
    if states["strix-authz"] == "ok":
        authz_run = next(run for run in job.runs if run.adapter == "strix-authz")
        assert "1 endpoint" in authz_run.detail
    assert job.findings  # the vulnerable identity endpoint yields findings


def test_credentials_never_reach_job_output(identity_site):
    _configure_auth([Principal(id="alice", cookies=(("session", "alice-session"),)),
                     Principal(id="bob", cookies=(("session", "bob-session"),))])
    job = run_assessment(identity_site.base + "/api/orders/1001",
                         profile="web-crawl", timeout=60.0)
    blob = json.dumps(job.to_dict())
    assert "alice-session" not in blob and "bob-session" not in blob


def test_scope_endpoint_does_not_serialize_principal_credentials():
    from strix.api.routers.system import get_scope
    _configure_auth([Principal(id="alice", cookies=(("session", "secret-value"),))])
    payload = get_scope(tenant={"tenant_id": "t", "tier": "pro", "admin": False})
    blob = json.dumps(payload)
    assert "secret-value" not in blob
    assert payload["auth_principals"] == ["alice"]  # ids visible, values never
