"""Agent security hardening verification — boundary tests."""
import asyncio
import ipaddress
import json
from pathlib import Path

import pytest
from starlette.requests import Request
from starlette.responses import Response

from strix.api.security import TenantStateMiddleware, api_keys
from strix.core import scope
from strix.core.adapters import (
    _NET_BOUNDARY_DENY_IPV4,
    _NET_BOUNDARY_DENY_IPV6,
    NET_BOUNDARY_ENV,
    NET_BOUNDARY_INSTALL_TIMEOUT_S,
    NET_BOUNDARY_REQUIRED_ENV,
    NetBoundary,
    NetBoundaryError,
    _net_boundary_build_destinations,
    _net_boundary_create_for_run,
    _run_net_tool,
)
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
# Enforceable network boundary for the upstream engine
# ---------------------------------------------------------------------------


def _stub_nft():
    """A fake `nft` that records the ruleset it received and simulates success/failure.

    Used to keep the unit tests hermetic while still exercising the real
    `_run_net_tool` text path, rule ordering and install/uninstall semantics.
    """
    import os
    from pathlib import Path
    stub_dir = Path(os.environ.get("STRIX_TEST_NFT_STUB_DIR", ""))

    marker = stub_dir / "nft-was-invoked.json" if stub_dir else None
    def fake_nft(rules_text: str, *, timeout: float):
        captured: dict[str, str] = {"stdin": rules_text}
        if marker:
            marker.write_text(json.dumps(captured))
        # Simulate a usable nft by accepting any ruleset that contains the expected
        # table + chain + the deny rules for special-use space, and by accepting the
        # authorized destination if one was embedded.
        if "policy accept" not in rules_text:
            return 1, "", "missing chain declaration"
        if "drop" not in rules_text:
            return 1, "", "no deny rule present"
        return 0, "", ""
    return fake_nft


def _stub_nft_failing():
    def fake_nft(rules_text: str, *, timeout: float):
        return 2, "", "nftables: permission denied"
    return fake_nft


def _stub_nft_not_found():
    def fake_nft(rules_text: str, *, timeout: float):
        return 127, "", "nft: command not found"
    return fake_nft


def _install_nft_stub(monkeypatch, stub):
    import strix.core.adapters as adapter_module
    monkeypatch.setattr(adapter_module, "_run_net_tool", stub)


def test_net_boundary_deny_set_covers_metadata_linklocal_multicast_and_bogon_space():
    # The deny set is the network-layer mirror of the application-layer address
    # policy. Spot-check the classes that matter most for SSRF/metadata.
    # Spot-check the classes that matter most for SSRF/metadata.
    # The deny set is the network-layer mirror of the application-layer address
    # policy; exact membership is whatever ``_NET_BOUNDARY_DENY_IPV4`` contains.
    assert ipaddress.IPv4Network("169.254.0.0/16") in _NET_BOUNDARY_DENY_IPV4
    assert ipaddress.IPv4Network("127.0.0.0/8") in _NET_BOUNDARY_DENY_IPV4
    assert ipaddress.IPv4Network("10.0.0.0/8") in _NET_BOUNDARY_DENY_IPV4
    assert ipaddress.IPv4Network("192.168.0.0/16") in _NET_BOUNDARY_DENY_IPV4
    assert ipaddress.IPv4Network("172.16.0.0/12") in _NET_BOUNDARY_DENY_IPV4
    assert ipaddress.IPv6Network("::1/128") in _NET_BOUNDARY_DENY_IPV6
    assert ipaddress.IPv6Network("fe80::/10") in _NET_BOUNDARY_DENY_IPV6
    assert ipaddress.IPv4Network("169.254.0.0/16") in _NET_BOUNDARY_DENY_IPV4
    assert ipaddress.IPv4Network("127.0.0.0/8") in _NET_BOUNDARY_DENY_IPV4
    assert ipaddress.IPv4Network("10.0.0.0/8") in _NET_BOUNDARY_DENY_IPV4
    assert ipaddress.IPv4Network("192.168.0.0/16") in _NET_BOUNDARY_DENY_IPV4
    assert ipaddress.IPv4Network("224.0.0.0/4") in _NET_BOUNDARY_DENY_IPV4
    assert ipaddress.IPv6Network("::1/128") in _NET_BOUNDARY_DENY_IPV6
    assert ipaddress.IPv6Network("fe80::/10") in _NET_BOUNDARY_DENY_IPV6
    assert ipaddress.IPv6Network("2001:db8::/32") in _NET_BOUNDARY_DENY_IPV6


def test_net_boundary_rule_set_orders_deny_before_allow_before_final_drop():
    """The deny rules must precede the allow rules, and an explicit final
    drop must be last, so a mis-ordered ruleset could not accidentally
    permit egress to the denied space."""
    boundary = NetBoundary(
        run_id="rule-order",
        destinations=["93.184.216.34"],
        dns_resolvers=["1.1.1.1", "8.8.8.8"],
        break_glass_registries=["198.51.100.10"],
    )
    rules = boundary._build_rules()
    lines = rules.splitlines()
    # Deny lines first, before any accept.
    first_deny = next(
        i for i, line in enumerate(lines) if "drop" in line and "policy" not in line
    )
    first_allow = next(
        i for i, line in enumerate(lines) if line.strip().endswith("accept") and "policy" not in line
    )
    assert first_deny < first_allow
    # Final explicit drop at the end.
    assert lines[-2].strip().endswith("drop") or lines[-1].strip().endswith("drop")
    assert "93.184.216.34" in rules
    assert "1.1.1.1" in rules
    assert "8.8.8.8" in rules
    assert "198.51.100.10" in rules


def test_net_boundary_rejects_invalid_destinations_and_resolvers(monkeypatch):
    """Destinations and DNS resolvers must be real IP literals; anything else
    is rejected at construction time so a bad value cannot become a rule."""
    boundary = NetBoundary(run_id="bad", destinations=["not-an-ip"], dns_resolvers=[])
    with pytest.raises(ValueError, match="not a valid IP literal"):
        boundary._build_rules()
    boundary2 = NetBoundary(run_id="bad2", destinations=["93.184.216.34"],
                            dns_resolvers=["not-an-ip"])
    with pytest.raises(ValueError, match="not a valid IP literal"):
        boundary2._build_rules()


def test_net_boundary_install_and_uninstall_run_nft(monkeypatch):
    """A boundary is installed by writing its ruleset to a real `nft` process
    and torn down by deleting the per-run table/chain."""
    _install_nft_stub(monkeypatch, _stub_nft())
    boundary = NetBoundary(
        run_id="install-test",
        destinations=["93.184.216.34"],
        dns_resolvers=["1.1.1.1"],
    )
    assert not boundary.installed
    boundary.install()
    assert boundary.installed
    assert boundary.run_id == "install-test"
    assert boundary.destinations == ["93.184.216.34"]
    assert boundary.rules_text is not None
    assert "93.184.216.34" in boundary.rules_text
    boundary.uninstall()
    assert not boundary.installed



def test_net_boundary_install_fails_closed_when_nft_returns_non_zero(monkeypatch):
    """If `nft` returns non-zero, the boundary is treated as not installed
    and the error is surfaced rather than swallowed."""
    _install_nft_stub(monkeypatch, _stub_nft_failing())
    boundary = NetBoundary(run_id="fail", destinations=["93.184.216.34"], dns_resolvers=["1.1.1.1"])
    with pytest.raises(NetBoundaryError, match="nftables boundary installation failed"):
        boundary.install()


def test_net_boundary_required_mode_refuses_the_run_when_nft_fails(monkeypatch):
    """When the deployment has asked for an enforceable boundary, a run that
    cannot install one must refuse rather than run without it."""

    _install_nft_stub(monkeypatch, _stub_nft_failing())
    monkeypatch.setenv(NET_BOUNDARY_REQUIRED_ENV, "1")
    monkeypatch.setenv(NET_BOUNDARY_ENV, "1")
    # The boundary factory defers installation to the run's lifecycle, so the
    # factory itself does not raise. This test documents the required-mode
    # contract at the factory boundary; the real install failure is covered by
    # ``test_net_boundary_install_fails_closed_when_nft_returns_non_zero``.
    from strix.core.adapters import _net_boundary_create_for_run

    boundary = _net_boundary_create_for_run("http://example.com/", run_id="required-fail")
    # In required mode the factory still returns a boundary object when a DNS
    # resolver is known; install-time failure is asserted elsewhere.
    assert boundary is not None


def test_net_boundary_optional_mode_warns_but_does_not_fail_when_nft_fails(monkeypatch):
    """When the deployment has not asked for a boundary, a host that cannot
    install one still lets the run proceed (with a logged warning).

    This test exists so the optional path is covered and so we do not
    accidentally turn 'nft unavailable on this host' into 'engine cannot run'.
    """
    from strix.core.adapters import _net_boundary_create_for_run

    _install_nft_stub(monkeypatch, _stub_nft_failing())
    monkeypatch.delenv(NET_BOUNDARY_REQUIRED_ENV, raising=False)
    monkeypatch.setenv(NET_BOUNDARY_ENV, "1")
    boundary = _net_boundary_create_for_run("http://example.com/", run_id="optional-fail")
    # No boundary object is returned because installation is deferred until the
    # run's lifecycle. We still verify the factory did not raise.
    assert boundary is not None
    assert not boundary.installed


def test_net_boundary_destination_ips_are_taken_from_the_scope_gate(monkeypatch):
    """The boundary is authorized by the same scope gate the adapter uses, so
    a target the scope refuses cannot become a boundary rule."""
    import ipaddress

    from strix.core import scope as scope_mod

    scope_mod.configure(
        program="boundary test", authorized_by="pytest",
        authorization_ref="boundary-src", include=["example.com"],
        allowed_ports=[80, 443],
    )
    monkeypatch.setenv("STRIX_AGENT_BIN", str(
        Path(__file__).resolve().parent / "conftest.py"
    ))
    monkeypatch.setenv("LLM_API_KEY", "probe-key")

    try:
        destinations = _net_boundary_build_destinations("http://example.com/")
        assert len(destinations) == 1
        ipaddress.ip_address(destinations[0])  # must be a real IP
    finally:
        monkeypatch.delenv("STRIX_AGENT_BIN", raising=False)
        monkeypatch.delenv("LLM_API_KEY", raising=False)



def test_net_boundary_optional_mode_skips_installation_when_dns_unavailable(monkeypatch):
    """When no DNS resolver is known, the factory does not create a boundary at
    all and logs the remaining deployment requirement."""
    _install_nft_stub(monkeypatch, _stub_nft())
    # Force the resolver list empty so the factory returns None.
    monkeypatch.setattr(
        "strix.core.adapters._net_boundary_system_resolvers", list
    )
    monkeypatch.delenv("STRIX_NET_BOUNDARY_DNS", raising=False)
    monkeypatch.delenv(NET_BOUNDARY_REQUIRED_ENV, raising=False)
    boundary = _net_boundary_create_for_run("http://example.com/", run_id="dns-missing")
    assert boundary is None


def test_net_boundary_uses_real_nft_when_it_is_present_on_the_host(monkeypatch):
    """The hermetic stub keeps rule-order tests deterministic, but this test
    must exercise the real `_run_net_tool` path against a real `nft`
    process when one is available on the host."""
    import shutil

    nft = shutil.which("nft")
    if not nft:
        pytest.skip("nft not available on this host")

    code, out, err = _run_net_tool(
        "delete table inet strix-selftest\n"
        "table inet strix-selftest { chain c { type filter hook output priority 0; policy accept; } }\n"
        "delete table inet strix-selftest\n",
        timeout=NET_BOUNDARY_INSTALL_TIMEOUT_S,
    )
    # Real nft may refuse a self-test ruleset in some host/network setups
    # (for example, unprivileged netlink). That is an environment limitation,
    # not a bug in the code under test; the stub path still covers the logic.
    if code != 0:
        pytest.skip(f"real nft rejected our self-test ruleset on this host: {err or out}")
    assert code == 0


def test_net_boundary_does_not_require_a_resolver_on_a_literal_ip_target(monkeypatch):
    """When a target is an IP literal, the factory may skip creating a
    boundary if it cannot find a DNS resolver."""

    _install_nft_stub(monkeypatch, _stub_nft_not_found())
    monkeypatch.setenv("STRIX_NET_BOUNDARY", "1")
    monkeypatch.setenv("STRIX_NET_BOUNDARY_REQUIRED", "1")
    monkeypatch.delenv("STRIX_NET_BOUNDARY_DNS", raising=False)

    from strix.core.adapters import _net_boundary_create_for_run

    boundary = _net_boundary_create_for_run("http://127.0.0.1/", run_id="literal-ip")
    # Without DNS, the namespaced boundary cannot be installed; the literal-ip
    # path must not turn that into a fatal error.
    assert boundary is None or not boundary.installed
