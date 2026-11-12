"""Agent security hardening verification — boundary tests."""
import asyncio

import pytest
from starlette.requests import Request
from starlette.responses import Response

from strix.api.security import TenantStateMiddleware, api_keys
from strix.core import scope
from strix.core.probe import EndpointProbe


def _tenant_state(headers: list[tuple[bytes, bytes]]) -> tuple[str, str]:
    """Run the identity middleware over a bare request and return (tenant_id, tier)."""
    async def app(scope, receive, send):
        pass
    middleware = TenantStateMiddleware(app=app)
    seen: dict[str, str] = {}

    async def call_next(request):
        seen["tenant_id"] = request.state.tenant_id
        seen["tier"] = request.state.tier
        return Response()

    scope = {
        "type": "http", "method": "GET", "path": "/", "headers": headers,
        "query_string": b"", "scheme": "http", "server": ("testserver", 80),
        "root_path": "", "http_version": "1.1",
    }
    asyncio.run(middleware.dispatch(Request(scope), call_next))
    return seen["tenant_id"], seen["tier"]


def test_tenant_headers_cannot_elevate_tier():
    # A caller with no key must not be able to name its own tenant or tier
    tid, tier = _tenant_state([
        (b"x-tenant-id", b"default-soc"),
        (b"x-tenant-tier", b"enterprise"),
    ])
    assert (tid, tier) == ("anonymous", "free")


def test_invalid_key_gets_lowest_tier():
    tid, tier = _tenant_state([
        (b"authorization", b"Bearer not-a-real-key"),
        (b"x-tenant-tier", b"enterprise"),
    ])
    assert (tid, tier) == ("anonymous", "free")


def test_valid_key_sets_real_tenant_and_tier():
    key = api_keys.register("mw-tenant", "pro")
    assert _tenant_state([(b"authorization", f"Bearer {key}".encode())]) == ("mw-tenant", "pro")


def test_revoked_key_falls_back_to_anonymous():
    key = api_keys.register("mw-revoked", "enterprise")
    api_keys.revoke("mw-revoked")
    assert _tenant_state([(b"authorization", f"Bearer {key}".encode())]) == ("anonymous", "free")


def test_bearer_scheme_matches_httpbearer_case_insensitively():
    key = api_keys.register("mw-lowercase", "enterprise")
    assert _tenant_state([(b"authorization", f"bearer {key}".encode())]) == ("mw-lowercase", "enterprise")


def test_path_traversal_is_not_a_valid_target():
    denial, _reason = scope.check("../../../etc/passwd")
    assert denial == "invalid_target"


def test_assessment_refused_without_authorized_scope(monkeypatch):
    monkeypatch.setattr(scope, "_active", None)
    denial, reason = scope.check("http://evil.com/?id=1")
    assert denial == "out_of_scope"
    assert "no authorized scope" in reason


def test_host_outside_program_scope_is_refused():
    # Valid URL, valid scheme, and still not ours to touch
    denial, reason = scope.check("http://victim.example.net/?id=1")
    assert denial == "out_of_scope"
    assert "not in the authorized scope" in reason


def test_wildcard_scope_covers_subdomains_but_not_apex_or_suffix_tricks():
    current = scope.configure(
        program="wildcard program", authorized_by="pytest",
        authorization_ref="wildcard-test", include=["*.example.com"],
    )
    assert current.check("https://api.example.com/") == ("", "")
    assert current.check("https://example.com/")[0] == "out_of_scope"
    assert current.check("https://example.com.attacker.tld/")[0] == "out_of_scope"
    assert current.check("https://notexample.com/")[0] == "out_of_scope"


def test_excluded_host_wins_over_include():
    current = scope.configure(
        program="exclusion program", authorized_by="pytest",
        authorization_ref="exclusion-test",
        include=["*.example.com"], exclude=["billing.example.com"],
    )
    assert current.check("https://billing.example.com/")[0] == "out_of_scope"
    assert current.check("https://api.example.com/") == ("", "")


@pytest.mark.parametrize("target", [
    "http://127.0.0.1:8000/",              # loopback
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata
    "http://10.0.0.5/",                    # RFC1918
    "http://[::1]/",                       # IPv6 loopback
    "http://localhost:8000/",              # internal name
])
def test_scope_never_reaches_internal_addresses(target):
    current = scope.configure(
        program="ssrf program", authorized_by="pytest",
        authorization_ref="ssrf-test", include=["127.0.0.1", "169.254.169.254",
                                                "10.0.0.5", "::1", "localhost"],
    )
    denial, reason = current.check(target)
    assert denial == "out_of_scope"
    assert "non-public" in reason or "internal host name" in reason


def test_probe_refuses_before_any_request_is_sent():
    out = EndpointProbe(timeout=0.1).probe("http://169.254.169.254/latest/meta-data/")
    assert out["status"] == "blocked"
    assert out["body_snippet"] == ""
    assert "not in the authorized scope" in out["reason"]


def test_reflection_check_reports_only_echoed_parameters(local_target):
    hits = EndpointProbe(timeout=2.0).reflections(f"{local_target.url}/?q=hello&fixed=value")
    # The marker must be observed reflected, and only for the echoing parameter
    assert [hit["parameter"] for hit in hits] == ["q"]
    assert "reflected verbatim" in hits[0]["evidence"]


def test_probe_never_follows_redirects(local_target):
    out = EndpointProbe(timeout=2.0).probe(f"{local_target.url}/redirect")
    assert out["status"] == 302
    assert out["redirect_to"] == "/landing"
    # The redirect target must not have been contacted
    assert "/landing" not in local_target.hits


def test_probe_byte_limit():
    p = EndpointProbe(timeout=0.1)
    # Even on error, result must not exceed bounded size
    out = p.probe("http://127.0.0.1:59999/")
    assert len(str(out.get("body_snippet", ""))) <= 512
    assert "status" in out


def test_allowed_ports_are_enforced_before_address_resolution(monkeypatch):
    current = scope.configure(
        program="port restricted", authorized_by="pytest", authorization_ref="ports",
        include=["example.com"], allowed_ports=[443],
    )
    resolver_calls = []
    def fake_resolve(host, port=None):
        resolver_calls.append((host, port))
        return ["93.184.216.34"]
    monkeypatch.setattr(scope, "resolve_sync", fake_resolve)
    assert current.check("https://example.com/") == ("", "")
    assert current.check("http://example.com:8080/")[0] == "out_of_scope"
    assert resolver_calls == [("example.com", None)]


# ---------------------------------------------------------------------------
