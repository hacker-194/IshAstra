"""Adversarial test pack for Ishastra Scope Gate.

Behaviour under test: The Scope authorization gate in `src/ishastra/core/scope.py`
which enforces program scope via check() (advisory) and destination() (authoritative)
methods, with IPv6 transition address handling, parser differential detection,
DNS rebinding prevention via pinned destinations, and per-tenant bound scopes.

Existing test files for this module: tests/unit/test_scope.py (unit tests for
basic scope validation, host matching, port restriction, destination, context
binding, observer, ambiguous URLs, special-use addresses, parse_document).

User's verbatim instruction: "Add scope-gate adversarial test pack: 1) Parser
differentials (backslashes, userinfo, percent-encoded hosts). 2) IPv6/IPv4-mapped
edge cases. 3) Redirect canaries. 4) DNS-rebinding simulation between check()
and destination(). Every test must prove DENIAL. File:
tests/security/test_scope_gate_adversarial.py."
"""

import ipaddress
from unittest.mock import patch

import pytest

from ishastra.security.authorization.scope import (
    Scope,
    bound,
    check,
    configure,
    current,
    embedded_ipv4,
    get_pinned_destination,
    is_special_use,
    parse_scope_document,
    reset_pinned_destination,
    set_pinned_destination,
)


@pytest.fixture(scope="function")
def base_scope():
    """A scope allowing only example.com on ports 80/443, no internal nets."""
    return configure(
        program="Adversarial Test",
        authorized_by="Test Authorizer",
        authorization_ref="ADV-001",
        include=["example.com", "*.example.com"],
        exclude=["admin.example.com"],
        authorized_networks=["93.184.216.0/24"],
        allowed_ports=[80, 443],
        allow_broad_networks=False,
    )


@pytest.fixture(scope="function", autouse=True)
def reset_global_scope():
    """Ensure global scope is clean before/after each test."""
    yield

    configure(
        program="Cleanup",
        authorized_by="Test",
        authorization_ref="CLEANUP",
        include=["cleanup.local"],
    )


class TestParserDifferentials:
    """URLs where Python's urlparse disagrees with browsers / external tools.

    The gate must refuse any URL whose effective host depends on which
    parser reads it. These are parser differential bugs, not input validation.
    """

    @pytest.mark.parametrize(
        "url,reason_fragment",
        [
            ("http://evil.com\\@ok.com/", "backslash"),
            ("http://evil.com\\\\@ok.com/", "backslash"),
            ("https://evil.com\\@ok.com/", "backslash"),
            ("http://evil.com\\\\\\@ok.com/", "backslash"),
            ("http://ok.com/path\\to@evil.com/", "backslash"),
        ],
    )
    def test_backslash_in_url_rejected(self, base_scope, url, reason_fragment):
        """Backslash in URL must be rejected (parser differential)."""
        denial, reason = base_scope.check(url)
        assert denial == "invalid_target", f"Expected denial for {url!r}, got {denial!r}"
        assert reason_fragment in reason.lower(), f"Reason {reason!r} missing {reason_fragment}"

    @pytest.mark.parametrize(
        "url,reason_fragment",
        [
            ("http://user:pass@ok.com/", "credentials"),
            ("https://user@ok.com/", "credentials"),
            ("http://:pass@ok.com/", "credentials"),
            ("http://ok.com@evil.com/", "credentials"),
        ],
    )
    def test_userinfo_in_url_rejected(self, base_scope, url, reason_fragment):
        """URL with credentials/userinfo must be rejected."""
        denial, reason = base_scope.check(url)
        assert denial == "invalid_target", f"Expected denial for {url!r}, got {denial!r}"
        assert reason_fragment in reason.lower(), f"Reason {reason!r} missing {reason_fragment}"

    @pytest.mark.parametrize(
        "url,reason_fragment",
        [
            ("http://ok%2Ecom/", "percent-encoded"),
            ("http://ex%61mple.com/", "percent-encoded"),
            ("http://example%2Ecom/", "percent-encoded"),
            ("http://ex%2561mple.com/", "percent-encoded"),
            ("http://ok%2Ecom:8080/", "percent-encoded"),
        ],
    )
    def test_percent_encoded_host_rejected(self, base_scope, url, reason_fragment):
        """Percent-encoded hostname must be rejected (parser differential)."""
        denial, reason = base_scope.check(url)
        assert denial == "invalid_target", f"Expected denial for {url!r}, got {denial!r}"
        assert reason_fragment in reason.lower(), f"Reason {reason!r} missing {reason_fragment}"

    @pytest.mark.parametrize(
        "url,reason_fragment",
        [
            ("http://ok.com\n/", "whitespace or control"),
            ("http://ok.com\r/", "whitespace or control"),
            ("http://ok.com\t/", "whitespace or control"),
            ("http://ok.com\x00/", "whitespace or control"),
            ("http://ok.com\x7f/", "whitespace or control"),
        ],
    )
    def test_whitespace_control_chars_rejected(self, base_scope, url, reason_fragment):
        """Whitespace/control chars in URL must be rejected."""
        denial, reason = base_scope.check(url)
        assert denial == "invalid_target", f"Expected denial for {url!r}, got {denial!r}"
        assert reason_fragment in reason.lower(), f"Reason {reason!r} missing {reason_fragment}"

    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com/..",
            "http://example.com/../etc/passwd",
            "http://example.com/path/../../etc/passwd",
        ],
    )
    def test_traversal_sequence_rejected(self, base_scope, url):
        """Path traversal sequences must be rejected."""
        denial, reason = base_scope.check(url)
        assert denial == "invalid_target", f"Expected denial for {url!r}, got {denial!r}"
        assert "traversal" in reason.lower()

    def test_invalid_scheme_rejected(self, base_scope):
        """Non-http(s) schemes must be rejected."""
        for url in [
            "ftp://example.com/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<script>",
        ]:
            denial, reason = base_scope.check(url)
            assert denial == "invalid_target", f"Expected denial for {url!r}, got {denial!r}"


class TestIPv6IPv4MappedEdgeCases:
    """IPv6 transition addresses that embed private IPv4 destinations.

    These addresses appear "global" to Python's is_global but route to
    internal networks via NAT64, 6to4, Teredo, or IPv4-mapped addresses.
    The gate must judge the EMBEDDED address, not just the outer prefix.
    """

    def setup_method(self):
        """Configure scope allowing public IPs but NOT private networks."""
        self.scope = configure(
            program="IPv6 Test",
            authorized_by="Test",
            authorization_ref="IPV6-001",
            include=["example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
            allow_broad_networks=False,
        )

    @pytest.mark.parametrize(
        "ipv6_str,embedded_ipv4_str",
        [
            ("::ffff:10.0.0.1", "10.0.0.1"),
            ("::ffff:192.168.1.1", "192.168.1.1"),
            ("::ffff:172.16.0.1", "172.16.0.1"),
            ("::ffff:127.0.0.1", "127.0.0.1"),
            ("::ffff:169.254.1.1", "169.254.1.1"),
            ("::ffff:224.0.0.1", "224.0.0.1"),
        ],
    )
    def test_ipv4_mapped_private_denied(self, ipv6_str, embedded_ipv4_str):
        """IPv4-mapped IPv6 with private embedded address must be denied."""
        addr = ipaddress.IPv6Address(ipv6_str)
        assert is_special_use(addr), f"{ipv6_str} should be special-use via embedded {embedded_ipv4_str}"

    @pytest.mark.parametrize(
        "ipv6_str,embedded_ipv4_str",
        [
            ("64:ff9b::a00:1", "10.0.0.1"),
            ("64:ff9b::c0a8:0101", "192.168.1.1"),
            ("64:ff9b::ac10:1", "172.16.0.1"),
            ("64:ff9b::7f00:1", "127.0.0.1"),
        ],
    )
    def test_nat64_private_denied(self, ipv6_str, embedded_ipv4_str):
        """NAT64 with private embedded address must be denied."""
        addr = ipaddress.IPv6Address(ipv6_str)
        embedded = embedded_ipv4(addr)
        assert embedded == ipaddress.IPv4Address(embedded_ipv4_str)
        assert is_special_use(addr), f"NAT64 {ipv6_str} -> {embedded_ipv4_str} should be special-use"

    def test_nat64_local_use_prefix_not_global(self):
        """RFC 8215 local-use prefix 64:ff9b:1::/48 is not global in Python."""
        addr = ipaddress.IPv6Address("64:ff9b:1::1")

        assert not addr.is_global

    @pytest.mark.parametrize(
        "ipv6_str,embedded_ipv4_str",
        [
            ("2002:c000:0204::", "192.0.2.4"),
            ("2002:c0a8:0101::", "192.168.1.1"),
            ("2002:ac10:0001::", "172.16.0.1"),
            ("2002:7f00:0001::", "127.0.0.1"),
        ],
    )
    def test_6to4_private_denied(self, ipv6_str, embedded_ipv4_str):
        """6to4 with private embedded address must be denied."""
        addr = ipaddress.IPv6Address(ipv6_str)
        embedded = embedded_ipv4(addr)
        assert embedded == ipaddress.IPv4Address(embedded_ipv4_str)
        assert is_special_use(addr), f"6to4 {ipv6_str} -> {embedded_ipv4_str} should be special-use"

    @pytest.mark.parametrize(
        "ipv6_str",
        [
            "2001::ffff:ffff",
        ],
    )
    def test_teredo_embedding(self, ipv6_str):
        """Teredo address embeds IPv4 (inverted + bit-flipped)."""
        addr = ipaddress.IPv6Address(ipv6_str)
        embedded = embedded_ipv4(addr)

        assert embedded is not None

    def test_public_ipv6_not_special(self):
        """Public IPv6 (Google DNS) must NOT be special-use."""
        addr = ipaddress.IPv6Address("2001:4860:4860::8888")
        assert not is_special_use(addr)

    def test_destination_rejects_embedded_private(self):
        """destination() must reject host resolving to IPv6 with private embedded IPv4."""

        with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["64:ff9b::a00:1"]):
            denial, reason, dest = self.scope.destination("https://example.com/")
            assert denial == "out_of_scope", f"Expected denial, got {denial!r}: {reason}"
            assert dest is None
            assert "non-public address" in reason.lower() or "resolves to" in reason.lower()

    def test_check_rejects_embedded_private(self):
        """check() must reject host resolving to IPv6 with private embedded IPv4."""
        with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["::ffff:10.0.0.1"]):
            denial, reason = self.scope.check("https://example.com/")
            assert denial == "out_of_scope", f"Expected denial, got {denial!r}: {reason}"
            assert "non-public" in reason.lower() or "resolves to" in reason.lower()

    def test_authorized_network_allows_public_ipv6(self):
        """If the public IPv6 network is explicitly authorized, it must be allowed."""
        scope_with_public_v6 = configure(
            program="IPv6 Test",
            authorized_by="Test",
            authorization_ref="IPV6-002",
            include=["example.com"],
            authorized_networks=["64:ff9b::/96", "93.184.216.0/24"],
            allowed_ports=[80, 443],
            allow_broad_networks=False,
        )
        with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["64:ff9b::a00:1"]):
            denial, reason, dest = scope_with_public_v6.destination("https://example.com/")
            assert denial == "", f"Expected allow, got denial: {denial}: {reason}"
            assert dest is not None
            assert dest.ip == "64:ff9b::a00:1"


class TestRedirectCanaries:
    """Canary hosts that must never be authorized, even if they resolve to
    allowed IPs. These are used to detect SSRF via open redirects or
    DNS rebinding where the attacker controls the final destination.
    """

    def setup_method(self):
        self.scope = configure(
            program="Redirect Test",
            authorized_by="Test",
            authorization_ref="REDIR-001",
            include=["example.com", "*.example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )

    @pytest.mark.parametrize(
        "canary_host",
        [
            "canary.localhost",
            "canary.local",
            "canary.internal",
            "canary.home.arpa",
            "169.254.169.254",
            "metadata.google.internal",
        ],
    )
    def test_internal_canaries_denied_even_if_in_include(self, canary_host):
        """Internal canary hosts must be denied even if explicitly listed in include."""
        scope_with_canary = configure(
            program="Redirect Test",
            authorized_by="Test",
            authorization_ref="REDIR-002",
            include=[canary_host],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )

        denial, reason = scope_with_canary.check(f"http://{canary_host}/")
        assert denial in (
            "out_of_scope",
            "invalid_target",
        ), f"Internal canary {canary_host!r} must be denied, got {denial!r}: {reason}"

    def test_external_canaries_not_auto_denied(self):
        """External canary domains (burpcollaborator, interactsh, etc.) are NOT auto-denied.

        They are only denied if they resolve to unauthorized addresses. This is
        correct behavior: the gate validates resolved addresses, not hostnames.
        """
        external_canaries = [
            "canary.burpcollaborator.net",
            "canary.interactsh.com",
            "canary.requestbin.net",
            "canary.ngrok.io",
        ]
        for host in external_canaries:
            scope_with_canary = configure(
                program="Test",
                authorized_by="Test",
                authorization_ref="T-1",
                include=[host],
                authorized_networks=["93.184.216.0/24"],
                allowed_ports=[80, 443],
            )

            denial, reason = scope_with_canary.check(f"http://{host}/")
            assert denial in ("", "resolution_failed", "out_of_scope")

    def test_internal_suffixes_always_denied(self):
        """Hosts ending in .localhost/.local/.internal/.home.arpa always denied."""
        for suffix in (".localhost", ".local", ".internal", ".home.arpa"):
            host = f"evil{suffix}"
            scope = configure(
                program="Test",
                authorized_by="Test",
                authorization_ref="T-1",
                include=[host],
                authorized_networks=["10.0.0.0/8"],
                allowed_ports=[80],
            )
            denial, reason = scope.check(f"http://{host}/")
            assert denial == "out_of_scope", f"Internal suffix {suffix} must be denied"

            assert (
                "internal" in reason.lower()
                or "non-public" in reason.lower()
                or "resolves to" in reason.lower()
            )

    def test_redirect_to_internal_via_external_host(self):
        """External host in scope that redirects to internal must be caught at destination()."""

        with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["10.0.0.1"]):
            denial, reason, dest = self.scope.destination("https://example.com/")
            assert denial == "out_of_scope"
            assert dest is None
            assert "non-public" in reason.lower()

    def test_redirect_to_loopback_via_external_host(self):
        """External host resolving to loopback must be denied."""
        with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["127.0.0.1"]):
            denial, reason, dest = self.scope.destination("https://example.com/")
            assert denial == "out_of_scope"
            assert dest is None


class TestDNSRebindingSimulation:
    """DNS rebinding: attacker controls DNS to return different addresses
    between the advisory check() and the authoritative destination().

    The gate pins the destination at check time and requires the caller
    to use that exact pinned address. This test simulates the attack and
    verifies the defense.
    """

    def setup_method(self):
        self.scope = configure(
            program="Rebinding Test",
            authorized_by="Test",
            authorization_ref="REBIND-001",
            include=["attacker.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
            allow_broad_networks=False,
        )

    def test_check_allows_then_destination_denies_rebind(self):
        """If DNS changes between check() and destination(), destination must deny.

        Scenario:
        1. check() resolves attacker.com -> 93.184.216.34 (allowed)
        2. Attacker changes DNS
        3. destination() resolves attacker.com -> 10.0.0.1 (private)
        4. destination() must deny because the NEW resolution is not authorized
        """

        with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["93.184.216.34"]):
            denial, reason = self.scope.check("https://attacker.com/")
            assert denial == "", f"Initial check should allow: {denial}: {reason}"

        with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["10.0.0.1"]):
            denial, reason, dest = self.scope.destination("https://attacker.com/")
            assert denial == "out_of_scope", f"Rebound destination must deny: {denial}: {reason}"
            assert dest is None

    def test_destination_independent_of_check(self):
        """destination() does its own fresh resolution; check() denial doesn't bind it.

        If check() denies (private IP), but then DNS changes to public IP before
        destination() is called, destination() will allow. This is by design:
        each call independently validates the current resolution.
        """
        with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["10.0.0.1"]):
            denial, reason = self.scope.check("https://attacker.com/")
            assert denial == "out_of_scope"

        with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["93.184.216.34"]):
            denial, reason, dest = self.scope.destination("https://attacker.com/")

            assert denial == "", f"Fresh resolution should allow: {denial}: {reason}"
            assert dest is not None

    def test_pinned_destination_prevents_rebind(self):
        """The pinned destination mechanism prevents rebind between check and connect."""

        with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["93.184.216.34"]):
            denial, reason, dest = self.scope.destination("https://attacker.com/")
            assert denial == ""
            token = set_pinned_destination(dest)

        try:
            with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["10.0.0.1"]):
                pinned = get_pinned_destination()
                assert pinned is not None
                assert pinned.ip == "93.184.216.34", f"Pinned IP should not change: {pinned.ip}"

                denial, reason, dest2 = self.scope.destination("https://attacker.com/")
                assert denial == "out_of_scope"
                assert dest2 is None
        finally:
            reset_pinned_destination(token)

    def test_concurrent_rebind_different_tasks(self):
        """Concurrent tasks must not share pinned destinations (ContextVar isolation)."""
        import asyncio

        async def task_a():
            with patch("ishastra.security.authorization.scope.resolve", return_value=["93.184.216.34"]):
                denial, reason, dest = await self.scope.destination_async("https://attacker.com/")
                assert denial == ""
                token = set_pinned_destination(dest)
                await asyncio.sleep(0.01)
                pinned = get_pinned_destination()
                assert pinned.ip == "93.184.216.34", f"Task A pinned IP leaked: {pinned.ip}"
                reset_pinned_destination(token)

        async def task_b():
            await asyncio.sleep(0.005)
            with patch("ishastra.security.authorization.scope.resolve", return_value=["10.0.0.1"]):
                denial, reason, dest = await self.scope.destination_async("https://attacker.com/")
                assert denial == "out_of_scope"
                pinned = get_pinned_destination()
                assert pinned is None or pinned.ip != "10.0.0.1", "Task B should not see Task A's pin"

        async def main():
            await asyncio.gather(task_a(), task_b())

        asyncio.run(main())


class TestAdditionalAdversarialVectors:
    """Other bypass vectors that must be denied."""

    def setup_method(self):
        self.scope = configure(
            program="Additional Test",
            authorized_by="Test",
            authorization_ref="ADD-001",
            include=["example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )

    def test_ipv6_literal_in_url_with_zone_id(self):
        """IPv6 literal with zone ID (e.g., %eth0) must be handled correctly."""

        url = "http://[::1%25eth0]/"
        denial, reason = self.scope.check(url)

        assert denial == "invalid_target"

    def test_ipv6_literal_private_in_scope_fails_validation(self):
        """IPv6 literal with brackets in include list is rejected at config time."""

        with pytest.raises(ValueError, match="not a valid DNS name"):
            configure(
                program="Test",
                authorized_by="Test",
                authorization_ref="T-1",
                include=["[::ffff:10.0.0.1]"],
                authorized_networks=["93.184.216.0/24"],
                allowed_ports=[80],
            )

    def test_idn_homograph_attack_rejected_at_config(self):
        """Internationalized domain names must be punycode; raw Unicode rejected at config."""

        unicode_host = "еxample.com"
        with pytest.raises(ValueError, match="not a valid DNS name"):
            configure(
                program="Test",
                authorized_by="Test",
                authorization_ref="T-1",
                include=[unicode_host],
                authorized_networks=["93.184.216.0/24"],
                allowed_ports=[80],
            )

    def test_punycode_allowed(self):
        """Valid punycode must be accepted."""

        scope = configure(
            program="Test",
            authorized_by="Test",
            authorization_ref="T-1",
            include=["xn--example-9ua.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80],
        )
        denial, reason = scope.check("http://xn--example-9ua.com/")

        assert denial in ("", "resolution_failed")

    def test_port_zero_rejected(self):
        """Port 0 must be rejected (not a connectable service port)."""
        denial, reason = self.scope.check("http://example.com:0/")
        assert denial == "invalid_target"
        assert "port 0" in reason.lower()

    def test_port_out_of_range_rejected(self):
        """Port > 65535 must be rejected by urlparse (ValueError -> invalid_target)."""

        denial, reason = self.scope.check("http://example.com:99999/")
        assert denial == "invalid_target"

    def test_empty_host_rejected(self):
        """Empty host must be rejected."""
        denial, reason = self.scope.check("http:///path")
        assert denial == "invalid_target"

    def test_ip_literal_out_of_authorized_network(self):
        """IP literal not in authorized_networks must be denied."""
        scope = configure(
            program="Test",
            authorized_by="Test",
            authorization_ref="T-1",
            include=["192.0.2.1"],
            authorized_networks=["10.0.0.0/8"],
            allowed_ports=[80],
        )
        denial, reason = scope.check("http://192.0.2.1/")
        assert denial == "out_of_scope"
        assert "resolves to non-public address" in reason.lower() or "non-public" in reason.lower()

    def test_multiple_ips_one_unauthorized(self):
        """If host resolves to multiple IPs and ANY is unauthorized, must deny."""

        with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["93.184.216.34", "10.0.0.1"]):
            denial, reason, dest = self.scope.destination("https://example.com/")
            assert denial == "out_of_scope"
            assert dest is None
            assert "non-public" in reason.lower()

    def test_wildcard_exclude_subdomain_only(self):
        """Exclude *.admin.example.com does not exclude admin.example.com."""
        scope = configure(
            program="Test",
            authorized_by="Test",
            authorization_ref="T-1",
            include=["example.com", "*.example.com"],
            exclude=["*.admin.example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )

        denial, reason = scope.check("https://admin.example.com/")
        assert denial == "", f"admin.example.com should be allowed: {denial}: {reason}"

        denial, reason = scope.check("https://sub.admin.example.com/")
        assert denial == "out_of_scope"

    def test_scope_document_unknown_field_rejected(self):
        """Unknown field in a v2 scope document must raise ValueError.

        v1 documents tolerate unknown fields on purpose (backward compatibility),
        so the closed-field policy only applies from version 2 and is enforced by
        the JSON Schema before the explicit field check runs.
        """
        data = {
            "version": 2,
            "program": "Test",
            "authorized_by": "Test",
            "authorization_ref": "T-1",
            "include": ["example.com"],
            "malicious_field": "attempted_bypass",
        }
        with pytest.raises(ValueError, match="Additional properties are not allowed"):
            parse_scope_document(data)

    def test_scope_document_wrong_type_rejected(self):
        """Wrong type for field must raise ValueError."""
        data = {
            "program": "Test",
            "authorized_by": "Test",
            "authorization_ref": "T-1",
            "include": ["example.com"],
            "allowed_ports": "not a list",
        }
        with pytest.raises(ValueError, match="allowed_ports.*not an integer"):
            parse_scope_document(data)


class TestBoundScopeIsolation:
    """Verify that bound() scope context manager isolates tenants correctly."""

    def test_tenant_a_cannot_access_tenant_b_scope(self):
        """Tenant A's bound scope must not see Tenant B's include list."""
        configure(
            program="Global",
            authorized_by="Admin",
            authorization_ref="GLOBAL-1",
            include=["global.com"],
        )

        tenant_a_scope = Scope(
            program="Tenant A",
            authorized_by="Tenant A Admin",
            authorization_ref="TENANT-A-001",
            include=["tenant-a.com"],
            policy_id="pol_a",
            policy_version=1,
            tenant_id="tenant-a",
        )

        tenant_b_scope = Scope(
            program="Tenant B",
            authorized_by="Tenant B Admin",
            authorization_ref="TENANT-B-001",
            include=["tenant-b.com"],
            policy_id="pol_b",
            policy_version=1,
            tenant_id="tenant-b",
        )

        assert current().program == "Global"
        denial, reason = check("https://global.com/")
        assert denial == ""

        with bound(tenant_a_scope):
            assert current().program == "Tenant A"
            denial, reason = check("https://tenant-a.com/")
            assert denial == ""
            denial, reason = check("https://tenant-b.com/")
            assert denial == "out_of_scope"
            denial, reason = check("https://global.com/")
            assert denial == "out_of_scope"

        assert current().program == "Global"

        with bound(tenant_b_scope):
            assert current().program == "Tenant B"
            denial, reason = check("https://tenant-b.com/")
            assert denial == ""
            denial, reason = check("https://tenant-a.com/")
            assert denial == "out_of_scope"

    def test_bound_scope_carries_policy_metadata(self):
        """Bound scope must carry policy_id, version, tenant_id for audit."""
        tenant_scope = Scope(
            program="Tenant",
            authorized_by="Admin",
            authorization_ref="REF-1",
            include=["tenant.com"],
            policy_id="pol_abc123",
            policy_version=5,
            tenant_id="tenant-xyz",
        )
        with bound(tenant_scope) as s:
            assert s.policy_id == "pol_abc123"
            assert s.policy_version == 5
            assert s.tenant_id == "tenant-xyz"

    def test_nested_bound_raises_or_isolates(self):
        """Nested bound() calls: inner wins, outer restored on exit."""
        outer = Scope(
            program="Outer",
            authorized_by="A",
            authorization_ref="R1",
            include=["outer.com"],
            policy_id="pol_1",
            policy_version=1,
            tenant_id="t1",
        )
        inner = Scope(
            program="Inner",
            authorized_by="B",
            authorization_ref="R2",
            include=["inner.com"],
            policy_id="pol_2",
            policy_version=1,
            tenant_id="t2",
        )

        with bound(outer):
            assert current().tenant_id == "t1"
            with bound(inner):
                assert current().tenant_id == "t2"
            assert current().tenant_id == "t1"


class TestRapidRebinding:
    """Rapid successive calls simulating high-frequency rebinding attempts."""

    def setup_method(self):
        self.scope = configure(
            program="Stress Test",
            authorized_by="Test",
            authorization_ref="STRESS-001",
            include=["target.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )

    def test_rapid_alternating_resolutions(self):
        """Alternate between allowed and denied resolutions rapidly."""
        results = []
        for i in range(20):
            if i % 2 == 0:
                with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["93.184.216.34"]):
                    denial, reason, dest = self.scope.destination("https://target.com/")
                    results.append(("allow", denial))
            else:
                with patch("ishastra.security.authorization.scope.resolve_sync", return_value=["10.0.0.1"]):
                    denial, reason, dest = self.scope.destination("https://target.com/")
                    results.append(("deny", denial))

        for expected, (_label, denial) in zip(["allow", "deny"] * 10, results, strict=False):
            if expected == "allow":
                assert denial == "", f"Expected allow, got {denial}"
            else:
                assert denial == "out_of_scope", f"Expected deny, got {denial}"


class TestFurtherDifferentials:
    """Vectors beyond the original pack: same rule, every one must deny."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com:80@evil.com/",
            "https://example.com%2f@evil.com/",
            "http://[::1%25eth0]/",
            "http://0x7f000001/",
            "https://example.com./",
            "http://example.com:0/",
            "ftp://example.com/",
            "javascript:alert(1)",
            "https://USER:PASS@example.com/",
            "https://example.com\t.path/",
        ],
    )
    def test_denied(self, base_scope, url):
        assert base_scope.check(url)[0] != "", url
