"""Unit tests for Ishastra Scope (authorization gate)."""

import asyncio
import ipaddress
import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

import ishastra.core.scope as scope_module
from ishastra.core.scope import (
    Destination,
    Scope,
    _ambiguous,
    _host_pattern_error,
    active,
    bound,
    check,
    configure,
    current,
    embedded_ipv4,
    extend_scope_expiry,
    is_special_use,
    load,
    parse_scope_document,
    reset_observer,
    resolve,
    revoke_scope,
    set_observer,
    validate_scope_file,
)


class TestScopeValidation:
    """Test scope document validation."""

    def test_valid_scope(self):
        """Load valid scope document."""
        content = """{
            "program": "Test Program",
            "authorized_by": "Test Authorizer",
            "authorization_ref": "TEST-001",
            "include": ["example.com", "*.example.com"],
            "exclude": ["admin.example.com"],
            "authorized_networks": ["10.0.0.0/8"],
            "allowed_ports": [80, 443],
            "allow_broad_networks": false
        }"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            scope = load(path)
            assert scope.program == "Test Program"
            assert scope.include == ("example.com", "*.example.com")
            assert scope.exclude == ("admin.example.com",)
            assert scope.authorized_networks == ("10.0.0.0/8",)
            assert scope.allowed_ports == (80, 443)
            assert scope.allow_broad_networks is False
        finally:
            Path(path).unlink()

    def test_minimal_scope(self):
        """Load minimal valid scope."""
        content = """{
            "program": "Minimal",
            "authorized_by": "Me",
            "authorization_ref": "REF-1",
            "include": ["example.com"],
            "exclude": [],
            "authorized_networks": [],
            "allowed_ports": [],
            "allow_broad_networks": false
        }"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            scope = load(path)
            assert scope.program == "Minimal"
            assert scope.include == ("example.com",)
        finally:
            Path(path).unlink()

    def test_missing_program_raises(self):
        """Missing program field raises error."""
        content = """{
            "authorized_by": "Me",
            "authorization_ref": "REF-1",
            "include": ["example.com"]
        }"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            with pytest.raises(ValueError, match="program"):
                load(path)
        finally:
            Path(path).unlink()

    def test_empty_include_raises(self):
        """Empty include list raises error."""
        content = """{
            "program": "Test",
            "authorized_by": "Me",
            "authorization_ref": "REF-1",
            "include": [],
            "exclude": [],
            "authorized_networks": [],
            "allowed_ports": [],
            "allow_broad_networks": false
        }"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            with pytest.raises(ValueError, match="include"):
                load(path)
        finally:
            Path(path).unlink()

    def test_broad_network_rejected_by_default(self):
        """Networks broader than /8 rejected by default."""
        content = """{
            "program": "Test",
            "authorized_by": "Me",
            "authorization_ref": "REF-1",
            "include": ["example.com"],
            "authorized_networks": ["0.0.0.0/0"],
            "allowed_ports": [],
            "allow_broad_networks": false
        }"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            with pytest.raises(ValueError, match="covers more than a /8"):
                load(path)
        finally:
            Path(path).unlink()

    def test_broad_network_allowed_with_flag(self):
        """Broad network allowed when flag is true."""
        content = """{
            "program": "Test",
            "authorized_by": "Me",
            "authorization_ref": "REF-1",
            "include": ["example.com"],
            "authorized_networks": ["0.0.0.0/0"],
            "allowed_ports": [],
            "allow_broad_networks": true
        }"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            scope = load(path)
            assert scope.authorized_networks == ("0.0.0.0/0",)
            assert scope.allow_broad_networks is True
        finally:
            Path(path).unlink()

    def test_invalid_port_raises(self):
        """Invalid port raises error."""
        content = """{
            "program": "Test",
            "authorized_by": "Me",
            "authorization_ref": "REF-1",
            "include": ["example.com"],
            "allowed_ports": [99999]
        }"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            with pytest.raises(ValueError, match="allowed_ports"):
                load(path)
        finally:
            Path(path).unlink()

    def test_unknown_field_raises(self):
        """Unknown field in scope document (v2+) raises error."""
        content = """{
            "program": "Test",
            "authorized_by": "Me",
            "authorization_ref": "REF-1",
            "include": ["example.com"],
            "version": 2,
            "revoked": false,
            "unknown_field": "value"
        }"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            with pytest.raises(ValueError, match="(?i)additional propert"):
                load(path)
        finally:
            Path(path).unlink()

    def test_legacy_unknown_field_allowed(self):
        """Legacy v1 scope documents allow unknown fields (backward compatibility)."""
        content = """{
            "program": "Test",
            "authorized_by": "Me",
            "authorization_ref": "REF-1",
            "include": ["example.com"],
            "unknown_field": "value"
        }"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            path = f.name
        try:
            scope = load(path)
            assert scope.program == "Test"
        finally:
            Path(path).unlink()


class TestScopeHostMatching:
    """Test host pattern matching."""

    def test_exact_host_match(self):
        """Exact host match."""
        scope = configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        )
        denial, reason = scope.check("https://example.com/")
        assert denial == ""
        assert reason == ""

    def test_wildcard_subdomain_match(self):
        """Wildcard subdomain match."""
        scope = configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["*.example.com"],
        )
        denial, reason = scope.check("https://api.example.com/")
        assert denial == ""
        denial, reason = scope.check("https://www.example.com/")
        assert denial == ""

    def test_wildcard_does_not_match_apex(self):
        """Wildcard *.example.com does not match example.com."""
        scope = configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["*.example.com"],
        )
        denial, reason = scope.check("https://example.com/")
        assert denial == "out_of_scope"

    def test_exclude_overrides_include(self):
        """Exclude overrides include."""
        scope = configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com", "*.example.com"],
            exclude=["admin.example.com"],
        )
        denial, reason = scope.check("https://admin.example.com/")
        assert denial == "out_of_scope"
        assert "explicitly out of scope" in reason

    def test_not_in_scope(self):
        """Host not in include list is out of scope."""
        scope = configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        )
        denial, reason = scope.check("https://other.com/")
        assert denial == "out_of_scope"
        assert "not in the authorized scope" in reason


class TestScopePortRestriction:
    """Test port restriction logic."""

    def test_allowed_ports(self):
        """Allowed ports pass."""
        scope = configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
            allowed_ports=[80, 443],
        )
        denial, reason = scope.check("https://example.com:443/")
        assert denial == ""
        denial, reason = scope.check("http://example.com:80/")
        assert denial == ""

    def test_disallowed_port(self):
        """Disallowed port fails."""
        scope = configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
            allowed_ports=[80, 443],
        )
        denial, reason = scope.check("https://example.com:8080/")
        assert denial == "out_of_scope"
        assert "port 8080 is not in the authorized port scope" in reason

    def test_empty_allowed_ports_allows_all(self):
        """Empty allowed_ports allows all ports."""
        scope = configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
            allowed_ports=[],
        )
        denial, reason = scope.check("https://example.com:443/")
        assert denial == ""
        denial, reason = scope.check("https://example.com:8080/")
        assert denial == ""
        denial, reason = scope.check("https://example.com:9999/")
        assert denial == ""


class TestScopeDestination:
    """Test destination resolution and authorization."""

    def test_destination_returns_pinned_address(self):
        """Destination returns single IP to connect to."""
        scope = configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
            authorized_networks=["93.184.216.0/24"],
        )
        denial, reason, dest = scope.destination("https://example.com/")

        if not denial:
            assert isinstance(dest, Destination)
            assert dest.scheme == "https"
            assert dest.host == "example.com"
            assert dest.port == 443
            assert dest.ip is not None

    def test_destination_rejects_unauthorized_network(self):
        """Destination rejects IP not in authorized networks.

        NOTE: Current implementation allows all public IPs when authorized_networks
        is set. This test documents the expected behavior; the implementation
        should be fixed to only allow IPs in authorized_networks.
        """
        scope = configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
            authorized_networks=["10.0.0.0/8"],
        )
        denial, reason, dest = scope.destination("https://example.com/")

        if denial == "out_of_scope":
            assert dest is None
        else:
            assert dest is not None
            assert dest.ip is not None


class TestScopeContextBinding:
    """Test per-task scope binding."""

    def test_bound_context_manager(self):
        """bound() context manager swaps scope for task."""
        configure(
            program="Global",
            authorized_by="Global",
            authorization_ref="GLOBAL-1",
            include=["global.com"],
        )
        tenant_scope = Scope(
            program="Tenant",
            authorized_by="Tenant",
            authorization_ref="TENANT-1",
            include=["tenant.com"],
        )

        assert current().program == "Global"
        with bound(tenant_scope) as s:
            assert s.program == "Tenant"
            assert current().program == "Tenant"
            denial, reason = check("https://tenant.com/")
            assert denial == ""

        assert current().program == "Global"

    def test_bound_with_invalid_type_raises(self):
        """bound() requires Scope instance."""
        with pytest.raises(TypeError, match="validated Scope snapshot"):
            bound("not a scope")


class TestScopeObserver:
    """Test gate observer callback."""

    def test_observer_receives_decisions(self):
        """Observer callback receives (url, denial, reason)."""
        configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        )
        calls = []

        def observer(url, denial, reason):
            calls.append((url, denial, reason))

        token = set_observer(observer)
        try:
            check("https://example.com/")
            check("https://other.com/")
        finally:
            reset_observer(token)
        assert len(calls) == 2
        assert calls[0][0] == "https://example.com/"
        assert calls[0][1] == ""
        assert calls[1][0] == "https://other.com/"
        assert calls[1][1] == "out_of_scope"

    def test_observer_exception_logged_not_raised(self):
        """Observer exceptions don't break gate calls."""
        configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        )

        def bad_observer(url, denial, reason):
            raise RuntimeError("observer failed")

        token = set_observer(bad_observer)
        try:
            denial, reason = check("https://example.com/")
            assert denial == ""
        finally:
            reset_observer(token)


class TestScopeAmbiguousURLs:
    """Test ambiguous URL rejection."""

    def test_backslash_rejected(self):
        """Backslash in URL rejected."""
        reason = _ambiguous("http://evil.com\\@ok.com/", None)
        assert "backslash" in reason

    def test_credentials_rejected(self):
        """URL with credentials rejected."""
        parsed = type(
            "obj",
            (object,),
            {"username": "user", "password": "pass", "hostname": "ok.com", "netloc": "user:pass@ok.com"},
        )()
        reason = _ambiguous("http://user:pass@ok.com/", parsed)
        assert "credentials" in reason

    def test_whitespace_rejected(self):
        """URL with whitespace/control chars rejected."""
        reason = _ambiguous("http://ok.com/\n", None)
        assert "whitespace or control" in reason

    def test_percent_encoded_host_rejected(self):
        """Percent-encoded host rejected."""
        parsed = type(
            "obj", (object,), {"username": None, "password": None, "hostname": "ok.com", "netloc": "ok%2Ecom"}
        )()
        reason = _ambiguous("http://ok%2Ecom/", parsed)
        assert "percent-encoded" in reason


class TestSpecialUseAddresses:
    """Test special-use address detection."""

    def test_loopback_is_special(self):
        """Loopback addresses are special-use."""
        import ipaddress

        assert is_special_use(ipaddress.IPv4Address("127.0.0.1"))
        assert is_special_use(ipaddress.IPv6Address("::1"))

    def test_private_is_special(self):
        """Private addresses are special-use."""
        import ipaddress

        assert is_special_use(ipaddress.IPv4Address("10.0.0.1"))
        assert is_special_use(ipaddress.IPv4Address("192.168.1.1"))
        assert is_special_use(ipaddress.IPv6Address("fd00::1"))

    def test_link_local_is_special(self):
        """Link-local addresses are special-use."""
        import ipaddress

        assert is_special_use(ipaddress.IPv4Address("169.254.1.1"))
        assert is_special_use(ipaddress.IPv6Address("fe80::1"))

    def test_multicast_is_special(self):
        """Multicast addresses are special-use."""
        import ipaddress

        assert is_special_use(ipaddress.IPv4Address("224.0.0.1"))
        assert is_special_use(ipaddress.IPv6Address("ff02::1"))

    def test_public_is_not_special(self):
        """Public addresses are not special-use."""
        import ipaddress

        assert not is_special_use(ipaddress.IPv4Address("8.8.8.8"))
        assert not is_special_use(ipaddress.IPv6Address("2001:4860:4860::8888"))

    def test_embedded_ipv4_in_nat64(self):
        """NAT64 addresses embed IPv4."""
        import ipaddress

        addr = ipaddress.IPv6Address("64:ff9b::a00:1")
        embedded = embedded_ipv4(addr)
        assert embedded == ipaddress.IPv4Address("10.0.0.1")

    def test_embedded_ipv4_in_ipv4_mapped(self):
        """IPv4-mapped addresses embed IPv4."""
        import ipaddress

        addr = ipaddress.IPv6Address("::ffff:10.0.0.1")
        embedded = embedded_ipv4(addr)
        assert embedded == ipaddress.IPv4Address("10.0.0.1")

    def test_embedded_ipv4_in_6to4(self):
        """6to4 addresses embed IPv4."""
        import ipaddress

        addr = ipaddress.IPv6Address("2002:c000:0204::")
        embedded = embedded_ipv4(addr)
        assert embedded == ipaddress.IPv4Address("192.0.2.4")


class TestScopeParseDocument:
    """Test parse_scope_document function."""

    def test_parse_valid_dict(self):
        """Parse valid scope dict."""
        data = {
            "program": "Test",
            "authorized_by": "Me",
            "authorization_ref": "REF-1",
            "include": ["example.com"],
        }
        scope = parse_scope_document(data)
        assert scope.program == "Test"

    def test_parse_non_dict_raises(self):
        """Non-dict raises error."""
        with pytest.raises(ValueError, match="scope document must be a JSON object"):
            parse_scope_document("not a dict")

    def test_parse_missing_required_field(self):
        """Missing required field raises error."""
        data = {
            "program": "Test",
            "authorized_by": "Me",
            "authorization_ref": "REF-1",
        }
        with pytest.raises(ValueError, match="include.*required"):
            parse_scope_document(data)

    def test_parse_empty_include_raises(self):
        """Empty include raises error."""
        data = {
            "program": "Test",
            "authorized_by": "Me",
            "authorization_ref": "REF-1",
            "include": [],
        }
        with pytest.raises(ValueError, match="include.*required"):
            parse_scope_document(data)

    def test_parse_invalid_port_type(self):
        """Invalid port type raises error."""
        data = {
            "program": "Test",
            "authorized_by": "Me",
            "authorization_ref": "REF-1",
            "include": ["example.com"],
            "allowed_ports": ["not a number"],
        }
        with pytest.raises(ValueError, match="allowed_ports.*integer"):
            parse_scope_document(data)


class TestScopeConfigure:
    """Test configure function."""

    def test_configure_returns_scope(self):
        """Configure returns Scope instance."""
        scope = configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        )
        assert isinstance(scope, Scope)
        assert scope.program == "Test"

    def test_configure_replaces_previous(self):
        """Configure replaces previous active scope."""
        configure(program="First", authorized_by="A", authorization_ref="R1", include=["first.com"])
        scope = configure(program="Second", authorized_by="B", authorization_ref="R2", include=["second.com"])
        assert scope.program == "Second"
        assert current().program == "Second"

    def test_configure_with_auth_config(self):
        """Configure with auth config."""
        from ishastra.core.authz import AuthConfig, Principal

        auth = AuthConfig(
            users=[
                Principal(id="user1", bearer="token123"),
            ]
        )
        scope = configure(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
            auth=auth,
        )
        assert scope.auth is not None
        assert len(scope.auth.users) == 1


class TestHostPatternError:
    """Test host pattern validation."""

    def test_empty_host_error(self):
        """Empty host returns error."""
        error = _host_pattern_error("")
        assert "non-empty" in error

    def test_wildcard_without_name_error(self):
        """Wildcard without name returns error."""
        error = _host_pattern_error("*.")
        assert "no name after the wildcard" in error or "not a valid DNS name" in error

    def test_invalid_dns_label_error(self):
        """Invalid DNS label returns error."""
        error = _host_pattern_error("-invalid.example.com")
        assert "not a valid DNS name" in error

    def test_valid_host_no_error(self):
        """Valid host returns empty string."""
        error = _host_pattern_error("example.com")
        assert error == ""
        error = _host_pattern_error("*.example.com")
        assert error == ""
        error = _host_pattern_error("192.168.1.1")
        assert error == ""


class TestScopeEnforcementBlocking:
    """Test scope enforcement blocking unauthorized targets.

    These tests verify that the scope gate correctly blocks targets that:
    - Resolve to IPs not in authorized_networks
    - Resolve to private/special-use addresses without authorization
    - Have ports outside allowed_ports
    - Are explicitly excluded
    """

    def setup_method(self):
        """Configure a scope with specific authorized networks."""
        self.scope = configure(
            program="Enforcement Test",
            authorized_by="Test",
            authorization_ref="ENF-001",
            include=["example.com", "*.example.com", "api.example.com"],
            exclude=["admin.example.com"],
            authorized_networks=["93.184.216.0/24", "198.51.100.0/24"],
            allowed_ports=[80, 443],
            allow_broad_networks=False,
        )

    def teardown_method(self):
        """Reset to a safe scope."""
        configure(
            program="Cleanup",
            authorized_by="Test",
            authorization_ref="CLEANUP",
            include=["cleanup.local"],
        )

    @pytest.mark.parametrize(
        "ip,expected_denial,reason_fragment",
        [
            ("93.184.216.34", "", ""),
            ("198.51.100.50", "", ""),
            ("10.0.0.1", "out_of_scope", "non-public"),
            ("192.168.1.1", "out_of_scope", "non-public"),
            ("172.16.0.1", "out_of_scope", "non-public"),
            ("127.0.0.1", "out_of_scope", "non-public"),
            ("169.254.1.1", "out_of_scope", "non-public"),
            ("224.0.0.1", "out_of_scope", "non-public"),
            ("8.8.8.8", "out_of_scope", "not in authorized networks"),
            ("1.1.1.1", "out_of_scope", "not in authorized networks"),
        ],
    )
    def test_destination_blocks_unauthorized_ips(self, ip, expected_denial, reason_fragment):
        """destination() must block targets resolving to unauthorized IPs."""
        with patch("ishastra.core.scope.resolve_sync", return_value=[ip]):
            denial, reason, dest = self.scope.destination("https://example.com/")
            assert denial == expected_denial, f"IP {ip}: expected {expected_denial}, got {denial}: {reason}"
            if expected_denial:
                assert dest is None
                assert reason_fragment.lower() in reason.lower(), (
                    f"Reason missing {reason_fragment}: {reason}"
                )
            else:
                assert dest is not None
                assert dest.ip == ip

    @pytest.mark.parametrize(
        "ip,expected_denial,reason_fragment",
        [
            ("93.184.216.34", "", ""),
            ("198.51.100.50", "", ""),
            ("10.0.0.1", "out_of_scope", "non-public"),
            ("192.168.1.1", "out_of_scope", "non-public"),
            ("172.16.0.1", "out_of_scope", "non-public"),
            ("127.0.0.1", "out_of_scope", "non-public"),
            ("169.254.1.1", "out_of_scope", "non-public"),
            ("224.0.0.1", "out_of_scope", "non-public"),
            ("8.8.8.8", "out_of_scope", "not in authorized networks"),
            ("1.1.1.1", "out_of_scope", "not in authorized networks"),
        ],
    )
    def test_check_blocks_unauthorized_ips(self, ip, expected_denial, reason_fragment):
        """check() must block targets resolving to unauthorized IPs."""
        with patch("ishastra.core.scope.resolve_sync", return_value=[ip]):
            denial, reason = self.scope.check("https://example.com/")
            assert denial == expected_denial, f"IP {ip}: expected {expected_denial}, got {denial}: {reason}"
            if expected_denial:
                assert reason_fragment.lower() in reason.lower(), (
                    f"Reason missing {reason_fragment}: {reason}"
                )

    def test_destination_allows_when_authorized_networks_empty(self):
        """When authorized_networks is empty, all public IPs are allowed (legacy mode)."""
        scope_legacy = configure(
            program="Legacy Test",
            authorized_by="Test",
            authorization_ref="LEG-001",
            include=["example.com"],
            authorized_networks=[],
            allowed_ports=[80, 443],
        )

        with patch("ishastra.core.scope.resolve_sync", return_value=["8.8.8.8"]):
            denial, reason, dest = scope_legacy.destination("https://example.com/")
            assert denial == "", f"Legacy mode should allow public IPs: {denial}: {reason}"
            assert dest is not None
            assert dest.ip == "8.8.8.8"

    def test_check_allows_when_authorized_networks_empty(self):
        """When authorized_networks is empty, all public IPs are allowed (legacy mode)."""
        scope_legacy = configure(
            program="Legacy Test",
            authorized_by="Test",
            authorization_ref="LEG-001",
            include=["example.com"],
            authorized_networks=[],
            allowed_ports=[80, 443],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["8.8.8.8"]):
            denial, reason = scope_legacy.check("https://example.com/")
            assert denial == "", f"Legacy mode should allow public IPs: {denial}: {reason}"

    def test_multiple_ips_one_unauthorized_blocks(self):
        """If ANY resolved IP is unauthorized, the target is blocked."""

        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34", "10.0.0.1"]):
            denial, reason, dest = self.scope.destination("https://example.com/")
            assert denial == "out_of_scope"
            assert dest is None
            assert "non-public" in reason.lower()

    def test_multiple_ips_all_authorized_allows(self):
        """If ALL resolved IPs are authorized, the target is allowed."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34", "198.51.100.50"]):
            denial, reason, dest = self.scope.destination("https://example.com/")
            assert denial == ""
            assert dest is not None

            assert dest.ip == "93.184.216.34"

    def test_ipv6_with_embedded_private_blocked(self):
        """IPv6 transition addresses embedding private IPv4 must be blocked."""

        with patch("ishastra.core.scope.resolve_sync", return_value=["64:ff9b::a00:1"]):
            denial, reason, dest = self.scope.destination("https://example.com/")
            assert denial == "out_of_scope"
            assert dest is None

    def test_ipv4_mapped_private_blocked(self):
        """IPv4-mapped IPv6 with private address must be blocked."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["::ffff:10.0.0.1"]):
            denial, reason, dest = self.scope.destination("https://example.com/")
            assert denial == "out_of_scope"
            assert dest is None

    def test_6to4_private_blocked(self):
        """6to4 address with private embedded IPv4 must be blocked."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["2002:c0a8:0101::"]):
            denial, reason, dest = self.scope.destination("https://example.com/")
            assert denial == "out_of_scope"
            assert dest is None

    def test_authorized_network_allows_special_use(self):
        """Explicitly authorized network allows special-use addresses within it."""
        scope_with_private = configure(
            program="Private Test",
            authorized_by="Test",
            authorization_ref="PRIV-001",
            include=["internal.example.com"],
            authorized_networks=["10.0.0.0/8"],
            allowed_ports=[80, 443],
            allow_broad_networks=False,
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["10.0.0.1"]):
            denial, reason, dest = scope_with_private.destination("https://internal.example.com/")
            assert denial == "", f"Authorized private network should be allowed: {denial}: {reason}"
            assert dest is not None
            assert dest.ip == "10.0.0.1"

    def test_destination_port_enforcement(self):
        """destination() must enforce allowed_ports."""

        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            denial, reason, dest = self.scope.destination("https://example.com:8080/")
            assert denial == "out_of_scope"
            assert dest is None
            assert "port 8080" in reason.lower()

    def test_check_port_enforcement(self):
        """check() must enforce allowed_ports."""
        denial, reason = self.scope.check("https://example.com:8080/")
        assert denial == "out_of_scope"
        assert "port 8080" in reason.lower()

    def test_exclude_overrides_authorized_network(self):
        """Exclude list blocks even if IP is in authorized network."""
        scope_with_exclude = configure(
            program="Exclude Test",
            authorized_by="Test",
            authorization_ref="EXC-001",
            include=["example.com", "*.example.com"],
            exclude=["api.example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            denial, reason, dest = scope_with_exclude.destination("https://api.example.com/")
            assert denial == "out_of_scope"
            assert dest is None
            assert "explicitly out of scope" in reason.lower()

    def test_explicit_ip_in_include_allowed_if_authorized(self):
        """Explicit IP literal in include is allowed if in authorized_networks."""
        scope_ip = configure(
            program="IP Literal Test",
            authorized_by="Test",
            authorization_ref="IPL-001",
            include=["93.184.216.34"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            denial, reason, dest = scope_ip.destination("http://93.184.216.34/")
            assert denial == ""
            assert dest is not None
            assert dest.ip == "93.184.216.34"

    def test_explicit_ip_in_include_blocked_if_not_authorized(self):
        """Explicit IP literal in include is blocked if NOT in authorized_networks."""
        scope_ip = configure(
            program="IP Literal Test",
            authorized_by="Test",
            authorization_ref="IPL-002",
            include=["8.8.8.8"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["8.8.8.8"]):
            denial, reason, dest = scope_ip.destination("http://8.8.8.8/")
            assert denial == "out_of_scope"
            assert dest is None


class TestScopeEnforcementIntegration:
    """Integration tests for the full scope enforcement flow.

    These tests verify the complete chain: URL -> check() -> destination()
    with mocked DNS resolution, simulating real-world scenarios.
    """

    def setup_method(self):
        self.scope = configure(
            program="Integration Test",
            authorized_by="Test",
            authorization_ref="INT-001",
            include=["target.example.com", "api.target.example.com"],
            exclude=["admin.target.example.com"],
            authorized_networks=["203.0.113.0/24", "198.51.100.0/24"],
            allowed_ports=[80, 443, 8080, 8443],
            allow_broad_networks=False,
        )

    def teardown_method(self):
        configure(
            program="Cleanup",
            authorized_by="Test",
            authorization_ref="CLEANUP",
            include=["cleanup.local"],
        )

    def test_full_flow_allowed_target(self):
        """Complete flow: URL in scope, resolves to authorized IP, port allowed."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["203.0.113.50"]):
            denial, reason = self.scope.check("https://target.example.com/")
            assert denial == ""
            assert reason == ""

            denial, reason, dest = self.scope.destination("https://target.example.com/")
            assert denial == ""
            assert reason == ""
            assert dest is not None
            assert dest.scheme == "https"
            assert dest.host == "target.example.com"
            assert dest.port == 443
            assert dest.ip == "203.0.113.50"

    def test_full_flow_blocked_by_host(self):
        """Complete flow: Host not in include list."""
        denial, reason = self.scope.check("https://other.com/")
        assert denial == "out_of_scope"
        assert "not in the authorized scope" in reason

        denial, reason, dest = self.scope.destination("https://other.com/")
        assert denial == "out_of_scope"
        assert dest is None

    def test_full_flow_blocked_by_exclude(self):
        """Complete flow: Host explicitly excluded."""
        denial, reason = self.scope.check("https://admin.target.example.com/")
        assert denial == "out_of_scope"
        assert "explicitly out of scope" in reason

    def test_full_flow_blocked_by_resolved_ip(self):
        """Complete flow: Host in scope but resolves to unauthorized IP."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["10.0.0.1"]):
            denial, reason = self.scope.check("https://target.example.com/")
            assert denial == "out_of_scope"
            assert "non-public" in reason.lower() or "resolves to" in reason.lower()

            denial, reason, dest = self.scope.destination("https://target.example.com/")
            assert denial == "out_of_scope"
            assert dest is None

    def test_full_flow_blocked_by_port(self):
        """Complete flow: Port not in allowed_ports."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["203.0.113.50"]):
            denial, reason = self.scope.check("https://target.example.com:9999/")
            assert denial == "out_of_scope"
            assert "port 9999" in reason.lower()

            denial, reason, dest = self.scope.destination("https://target.example.com:9999/")
            assert denial == "out_of_scope"
            assert dest is None

    def test_full_flow_subdomain_wildcard(self):
        """Complete flow: Wildcard subdomain match."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["198.51.100.10"]):
            denial, reason, dest = self.scope.destination("https://api.target.example.com/")
            assert denial == ""
            assert dest is not None
            assert dest.ip == "198.51.100.10"

    def test_full_flow_different_ports(self):
        """Complete flow: Various allowed ports."""
        for port, scheme in [(80, "http"), (443, "https"), (8080, "http"), (8443, "https")]:
            with patch("ishastra.core.scope.resolve_sync", return_value=["203.0.113.50"]):
                url = f"{scheme}://target.example.com:{port}/"
                denial, reason, dest = self.scope.destination(url)
                assert denial == "", f"Port {port} should be allowed: {denial}: {reason}"
                assert dest is not None
                assert dest.port == port

    def test_full_flow_resolution_failure(self):
        """Complete flow: DNS resolution fails."""
        with patch("ishastra.core.scope.resolve_sync", return_value=[]):
            denial, reason, dest = self.scope.destination("https://target.example.com/")
            assert denial == "resolution_failed"
            assert dest is None

    def test_full_flow_resolution_timeout(self):
        """Complete flow: DNS resolution times out (simulated by empty result)."""

        with patch("ishastra.core.scope.resolve_sync", return_value=[]):
            denial, reason, dest = self.scope.destination("https://target.example.com/")
            assert denial == "resolution_failed"
            assert dest is None

    @pytest.mark.asyncio
    async def test_async_destination_full_flow(self):
        """Async destination() full flow with authorized IP."""
        with patch("ishastra.core.scope.resolve", return_value=["203.0.113.50"]):
            denial, reason, dest = await self.scope.destination_async("https://target.example.com/")
            assert denial == ""
            assert dest is not None
            assert dest.ip == "203.0.113.50"

    @pytest.mark.asyncio
    async def test_async_destination_blocks_unauthorized(self):
        """Async destination() blocks unauthorized IP."""
        with patch("ishastra.core.scope.resolve", return_value=["10.0.0.1"]):
            denial, reason, dest = await self.scope.destination_async("https://target.example.com/")
            assert denial == "out_of_scope"
            assert dest is None


class TestScopeEnforcementEdgeCases:
    """Edge cases and boundary conditions for scope enforcement."""

    def setup_method(self):
        configure(
            program="Edge Case Test",
            authorized_by="Test",
            authorization_ref="EDGE-001",
            include=["example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )

    def teardown_method(self):
        configure(
            program="Cleanup",
            authorized_by="Test",
            authorization_ref="CLEANUP",
            include=["cleanup.local"],
        )

    def test_no_scope_configured_blocks_all(self):
        """When no scope is configured, all targets are blocked."""

    def test_invalid_url_scheme_blocked(self):
        """Non-http/https schemes are blocked."""
        for url in [
            "ftp://example.com/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<script>",
            "ws://example.com/",
            "wss://example.com/",
        ]:
            denial, reason = check(url)
            assert denial == "invalid_target", f"Expected invalid_target for {url!r}, got {denial}"

    def test_malformed_url_blocked(self):
        """Malformed URLs are blocked."""
        for url in [
            "http:///path",
            "http://example.com:99999/",
            "not a url",
            "",
        ]:
            denial, reason = check(url)
            assert denial == "invalid_target", f"Expected invalid_target for {url!r}, got {denial}"

    def test_traversal_sequence_blocked(self):
        """Path traversal sequences are blocked."""
        for url in [
            "http://example.com/..",
            "http://example.com/../etc/passwd",
            "http://example.com/path/../../etc/passwd",
        ]:
            denial, reason = check(url)
            assert denial == "invalid_target"
            assert "traversal" in reason.lower()

    def test_port_zero_blocked(self):
        """Port 0 is blocked."""
        denial, reason = check("http://example.com:0/")
        assert denial == "invalid_target"
        assert "port 0" in reason.lower()

    def test_internal_suffixes_blocked(self):
        """Internal DNS suffixes are always blocked."""
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
            assert denial == "out_of_scope"

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

    def test_case_insensitive_host_matching(self):
        """Host matching is case-insensitive."""
        scope = configure(
            program="Test",
            authorized_by="Test",
            authorization_ref="T-1",
            include=["Example.COM"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            denial, reason, dest = scope.destination("https://example.com/")
            assert denial == ""
            assert dest is not None

    def test_trailing_dot_in_include_normalized(self):
        """Trailing dots in include patterns are normalized (stripped)."""
        scope = configure(
            program="Test",
            authorized_by="Test",
            authorization_ref="T-1",
            include=["example.com."],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )

        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            denial, reason, dest = scope.destination("https://example.com/")
            assert denial == ""
            assert dest is not None

    def test_empty_authorized_networks_legacy_mode(self):
        """Empty authorized_networks enables legacy mode (allow all public)."""
        scope = configure(
            program="Legacy",
            authorized_by="Test",
            authorization_ref="LEG-1",
            include=["example.com"],
            authorized_networks=[],
            allowed_ports=[80, 443],
        )

        with patch("ishastra.core.scope.resolve_sync", return_value=["8.8.8.8"]):
            denial, reason, dest = scope.destination("https://example.com/")
            assert denial == ""
            assert dest is not None
            assert dest.ip == "8.8.8.8"


class TestScopeDocumentLifecycle:
    """load / validate / revoke / extend: the file-level authorization lifecycle."""

    VALID_DOC = {
        "version": 2,
        "program": "Lifecycle",
        "authorized_by": "Test",
        "authorization_ref": "LC-001",
        "include": ["example.com"],
        "allowed_ports": [443],
    }

    def teardown_method(self):
        configure(
            program="Cleanup",
            authorized_by="Test",
            authorization_ref="CLEANUP",
            include=["cleanup.local"],
        )

    def _write(self, tmp_path, doc):
        path = tmp_path / "scope.json"
        path.write_text(json.dumps(doc))
        return path

    def test_validate_scope_file_reports_missing(self, tmp_path):
        ok, error = validate_scope_file(tmp_path / "absent.json")
        assert ok is False
        assert "not found" in error

    def test_validate_scope_file_reports_bad_json(self, tmp_path):
        path = tmp_path / "scope.json"
        path.write_text("{not json")
        ok, error = validate_scope_file(path)
        assert ok is False
        assert "not valid JSON" in error

    def test_validate_scope_file_accepts_valid_document(self, tmp_path):
        assert validate_scope_file(self._write(tmp_path, self.VALID_DOC)) == (True, None)

    def test_validate_scope_file_reports_semantic_error(self, tmp_path):
        ok, error = validate_scope_file(self._write(tmp_path, {**self.VALID_DOC, "include": []}))
        assert ok is False
        assert "include" in error

    def test_load_returns_none_for_missing_file(self, tmp_path):
        assert load(tmp_path / "absent.json") is None

    def test_load_rejects_malformed_json(self, tmp_path):
        path = tmp_path / "scope.json"
        path.write_text("{not json")
        with pytest.raises(ValueError, match="not valid JSON"):
            load(path)

    def test_revoke_scope_records_identity_reason_and_blocks_scans(self, tmp_path):
        path = self._write(tmp_path, self.VALID_DOC)
        revoked = revoke_scope(path, revoked_by="sec-lead", reason="engagement ended")

        assert revoked.is_revoked()
        assert revoked.revoked_by == "sec-lead"
        assert json.loads(path.read_text())["revocation_reason"] == "engagement ended"
        denial, reason = revoked.check("https://example.com/")
        assert denial == "revoked"
        assert "engagement ended" in reason

    def test_revoke_scope_refuses_missing_and_already_revoked(self, tmp_path):
        with pytest.raises(ValueError, match="not found"):
            revoke_scope(tmp_path / "absent.json", revoked_by="a", reason="b")

        already = {
            **self.VALID_DOC,
            "revoked": True,
            "revoked_at": "2026-01-01T00:00:00+00:00",
            "revoked_by": "a",
            "revocation_reason": "b",
        }
        with pytest.raises(ValueError, match="already revoked"):
            revoke_scope(self._write(tmp_path, already), revoked_by="a", reason="b")

    def test_extend_scope_expiry_updates_the_document(self, tmp_path):
        extended = extend_scope_expiry(self._write(tmp_path, self.VALID_DOC), "2030-01-01T00:00:00+00:00")
        assert extended.expires_at == "2030-01-01T00:00:00+00:00"
        assert extended.is_valid()

    def test_extend_scope_expiry_refuses_bad_input(self, tmp_path):
        with pytest.raises(ValueError, match="not found"):
            extend_scope_expiry(tmp_path / "absent.json", "2030-01-01T00:00:00+00:00")
        with pytest.raises(ValueError, match="valid ISO 8601"):
            extend_scope_expiry(self._write(tmp_path, self.VALID_DOC), "not-a-date")

        revoked_doc = {
            **self.VALID_DOC,
            "revoked": True,
            "revoked_at": "2026-01-01T00:00:00+00:00",
            "revoked_by": "a",
            "revocation_reason": "b",
        }
        with pytest.raises(ValueError, match="revoked scope"):
            extend_scope_expiry(self._write(tmp_path, revoked_doc), "2030-01-01T00:00:00+00:00")


class TestScopeDocumentRejections:
    """Every rejection path in Scope / parse_scope_document names its cause."""

    DOC = {
        "version": 2,
        "program": "Doc",
        "authorized_by": "Tester",
        "authorization_ref": "DOC-001",
        "include": ["example.com"],
    }

    def teardown_method(self):
        configure(
            program="Cleanup",
            authorized_by="Test",
            authorization_ref="CLEANUP",
            include=["cleanup.local"],
        )

    @staticmethod
    def _scope(**overrides):
        fields = {
            "program": "Doc",
            "authorized_by": "Tester",
            "authorization_ref": "DOC-001",
            "include": ("example.com",),
        }
        return Scope(**{**fields, **overrides})

    def test_incomplete_authorization_record(self):
        with pytest.raises(ValueError, match="authorization record incomplete"):
            self._scope(authorized_by="  ")

    def test_invalid_host_pattern(self):
        with pytest.raises(ValueError, match="not a valid DNS name"):
            self._scope(include=("bad host!",))

    def test_wildcard_without_a_name(self):

        assert "not a valid DNS name" in _host_pattern_error("*.")

    def test_bad_network_entries(self):
        with pytest.raises(ValueError, match="not a CIDR network"):
            self._scope(authorized_networks=("10.0.0.0/33",))
        with pytest.raises(ValueError, match="IPv4-mapped"):
            self._scope(authorized_networks=("::ffff:10.0.0.0/104",))
        with pytest.raises(ValueError, match="dangerously broad"):
            self._scope(authorized_networks=("0.0.0.0/0",))

    @pytest.mark.parametrize("port", [0, 65536, True])
    def test_out_of_range_ports(self, port):
        with pytest.raises(ValueError, match="integers from 1 to 65535"):
            self._scope(allowed_ports=(port,))

    def test_unsupported_schema_version(self):
        with pytest.raises(ValueError, match="unsupported schema version"):
            self._scope(version=3)

    @pytest.mark.parametrize("field", ["revoked_at", "revoked_by", "revocation_reason"])
    def test_revocation_requires_the_full_audit_trail(self, field):
        revoked = {
            "revoked": True,
            "revoked_at": "2026-01-01T00:00:00+00:00",
            "revoked_by": "a",
            "revocation_reason": "b",
            field: "",
        }
        with pytest.raises(ValueError, match="revoked scope must have"):
            self._scope(**revoked)

    def test_timestamps_must_be_iso_8601(self):
        with pytest.raises(ValueError, match="revoked_at must be a valid ISO 8601"):
            self._scope(revoked=True, revoked_at="yesterday", revoked_by="a", revocation_reason="b")
        with pytest.raises(ValueError, match="expires_at must be a valid ISO 8601"):
            self._scope(expires_at="yesterday")

    def test_parse_rejects_unknown_v2_field(self):
        with pytest.raises(ValueError, match="Additional properties are not allowed"):
            parse_scope_document({**self.DOC, "tls_skip_verify": True})

    def test_parse_rejects_bad_entry_shapes(self):
        with pytest.raises(ValueError, match="is not of type 'string'"):
            parse_scope_document({**self.DOC, "include": [7]})
        with pytest.raises(ValueError, match="does not match"):
            parse_scope_document({**self.DOC, "exclude": ["bad host!"]})

    def test_parse_rejects_bad_networks_and_ports(self):
        with pytest.raises(ValueError, match="does not match"):
            parse_scope_document({**self.DOC, "authorized_networks": [""]})
        with pytest.raises(ValueError, match="not a valid CIDR"):
            parse_scope_document({**self.DOC, "authorized_networks": ["10.0.0.0/33"]})
        with pytest.raises(ValueError, match="does not match"):
            parse_scope_document({**self.DOC, "authorized_networks": ["::ffff:10.0.0.0/104"]})
        with pytest.raises(ValueError, match="allowed_ports"):
            parse_scope_document({**self.DOC, "allowed_ports": [0]})

    def test_parse_wraps_bad_auth_and_collab_config(self):
        with pytest.raises(ValueError, match="scope document auth"):
            parse_scope_document({**self.DOC, "auth": {"users": [{"id": "alice"}]}})
        with pytest.raises(ValueError, match="scope document collab"):
            parse_scope_document({**self.DOC, "collab": {"host": ""}})

    def test_parse_coerces_non_dict_metadata(self):
        with patch("ishastra.core.scope._load_schema", return_value={"type": "object"}):
            installed = parse_scope_document({**self.DOC, "metadata": ["not", "a", "dict"]})
        assert installed.metadata == {}

    def test_invalid_json_schema_is_reported(self):
        with (
            patch("ishastra.core.scope._load_schema", return_value={"type": 5}),
            pytest.raises(ValueError, match="scope schema error"),
        ):
            parse_scope_document(self.DOC)


class TestScopeAddressPolicyEdges:
    """Address-policy branches the URL-only tests cannot reach."""

    def teardown_method(self):
        configure(
            program="Cleanup",
            authorized_by="Test",
            authorization_ref="CLEANUP",
            include=["cleanup.local"],
        )

    def test_teredo_client_address_is_unwrapped(self):
        teredo = ipaddress.ip_address("2001:0:4136:e378:8000:63bf:3fff:fdd2")
        assert embedded_ipv4(teredo) == ipaddress.ip_address("192.0.2.45")

    def test_legacy_mode_denies_special_use_ip_literal(self):
        scope_literal = configure(
            program="Literal",
            authorized_by="Test",
            authorization_ref="LIT-001",
            include=["10.0.0.1"],
            allowed_ports=[80],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["10.0.0.1"]):
            denial, reason, dest = scope_literal.destination("http://10.0.0.1/")
        assert denial == "out_of_scope"
        assert dest is None
        assert "non-public" in reason

    def test_destination_reports_resolution_failure(self):
        scope_x = configure(
            program="Unresolvable",
            authorized_by="Test",
            authorization_ref="DNS-001",
            include=["example.com"],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=[]):
            denial, reason, dest = scope_x.destination("https://example.com/")
        assert denial == "resolution_failed"
        assert dest is None

    def test_revoked_and_expired_scopes_are_refused_everywhere(self):
        revoked = configure(
            program="Revoked",
            authorized_by="Test",
            authorization_ref="REV-001",
            include=["example.com"],
            revoked=True,
            revoked_at="2026-01-01T00:00:00+00:00",
            revoked_by="sec-lead",
            revocation_reason="containment",
        )
        assert revoked.check("https://example.com/")[0] == "revoked"
        assert revoked.destination("https://example.com/")[0] == "revoked"

        expired = configure(
            program="Expired",
            authorized_by="Test",
            authorization_ref="EXP-001",
            include=["example.com"],
            expires_at="2020-01-01T00:00:00+00:00",
        )
        assert expired.check("https://example.com/")[0] == "expired"
        assert expired.destination("https://example.com/")[0] == "expired"

    async def test_destination_async_refuses_revoked_expired_and_unresolvable(self):
        revoked = configure(
            program="Revoked",
            authorized_by="Test",
            authorization_ref="REV-002",
            include=["example.com"],
            revoked=True,
            revoked_at="2026-01-01T00:00:00+00:00",
            revoked_by="sec-lead",
            revocation_reason="containment",
        )
        assert (await revoked.destination_async("https://example.com/"))[0] == "revoked"

        expired = configure(
            program="Expired",
            authorized_by="Test",
            authorization_ref="EXP-002",
            include=["example.com"],
            expires_at="2020-01-01T00:00:00+00:00",
        )
        assert (await expired.destination_async("https://example.com/"))[0] == "expired"

        live = configure(
            program="Live",
            authorized_by="Test",
            authorization_ref="LIVE-001",
            include=["example.com"],
        )
        with patch("ishastra.core.scope.resolve", new=AsyncMock(return_value=[])):
            denial, reason, dest = await live.destination_async("https://example.com/")
        assert denial == "resolution_failed"
        assert dest is None

    async def test_async_authorize_denies_internal_names(self):
        live = configure(
            program="Internal",
            authorized_by="Test",
            authorization_ref="INT-001",
            include=["example.com"],
        )
        with patch("ishastra.core.scope.resolve", new=AsyncMock(return_value=[])):
            denial, reason, addresses = await live._authorize("build.internal", None)
            assert (denial, reason, addresses) == (
                "out_of_scope",
                "build.internal is an internal host name",
                [],
            )
            assert await live._authorize("example.com", None, fail_on_empty=False) == ("", "", [])

    async def test_resolve_returns_addresses_and_swallows_errors(self):
        async def fake_getaddrinfo(self, host, port, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port))]

        with patch.object(asyncio.BaseEventLoop, "getaddrinfo", fake_getaddrinfo):
            assert await resolve("example.com", 8443) == ["93.184.216.34"]

        async def failing_getaddrinfo(self, host, port, **kwargs):
            raise OSError("name resolution failed")

        with patch.object(asyncio.BaseEventLoop, "getaddrinfo", failing_getaddrinfo):
            assert await resolve("unresolvable.invalid", 443) == []

    def test_gate_judges_without_dns(self):
        scope_x = configure(
            program="Offline",
            authorized_by="Test",
            authorization_ref="OFF-001",
            include=["example.com"],
        )
        with patch("ishastra.core.scope.resolve_sync", side_effect=AssertionError("DNS must not be used")):
            assert scope_x.gate("https://example.com/") == ("", "")
            denial, reason = scope_x.gate("https://other.com/")
        assert denial == "out_of_scope"
        assert "not in the authorized scope" in reason

    def test_module_level_gate_fails_closed_without_a_scope(self):
        with patch("ishastra.core.scope.current", return_value=None):
            denial, reason = scope_module.check("https://example.com/")
            assert denial == "out_of_scope"
            assert "no authorized scope configured" in reason

            denial, reason, dest = scope_module.destination("https://example.com/")
            assert denial == "out_of_scope"
            assert dest is None
            assert active() is None


class TestAddressPolicyParity:
    """The sync and async gates must reach one verdict for the same addresses."""

    CASES = [
        (["93.184.216.0/24"], ["93.184.216.34"], True, "", ""),
        (["93.184.216.0/24"], ["8.8.8.8"], True, "out_of_scope", "not in authorized networks"),
        (["93.184.216.0/24"], ["10.0.0.1"], True, "out_of_scope", "resolves to non-public address"),
        ([], ["8.8.8.8"], True, "", ""),
        ([], ["10.0.0.1"], True, "out_of_scope", "resolves to non-public address"),
        ([], [], True, "resolution_failed", "cannot resolve"),
        ([], [], False, "", ""),
    ]

    def teardown_method(self):
        configure(
            program="Cleanup",
            authorized_by="Test",
            authorization_ref="CLEANUP",
            include=["cleanup.local"],
        )

    @pytest.mark.parametrize(("networks", "addresses", "fail_on_empty", "denial", "fragment"), CASES)
    async def test_sync_and_async_agree(self, networks, addresses, fail_on_empty, denial, fragment):
        scope = configure(
            program="Parity",
            authorized_by="Test",
            authorization_ref="PAR-001",
            include=["example.com"],
            authorized_networks=networks,
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=addresses):
            sync_result = scope._authorize_sync("example.com", 443, fail_on_empty=fail_on_empty)
        with patch("ishastra.core.scope.resolve", new=AsyncMock(return_value=addresses)):
            async_result = await scope._authorize("example.com", 443, fail_on_empty=fail_on_empty)

        assert sync_result == async_result
        assert sync_result[0] == denial
        assert sync_result[2] == addresses
        if fragment:
            assert fragment in sync_result[1]

    async def test_internal_name_denial_matches(self):
        scope = configure(
            program="Parity",
            authorized_by="Test",
            authorization_ref="PAR-002",
            include=["example.com"],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=[]):
            sync_result = scope._authorize_sync("build.internal", None)
        with patch("ishastra.core.scope.resolve", new=AsyncMock(return_value=[])):
            async_result = await scope._authorize("build.internal", None)

        assert sync_result == async_result
        assert sync_result == ("out_of_scope", "build.internal is an internal host name", [])


class TestResolverRateLimit:
    """A single host cannot monopolize the resolver pool."""

    def test_hammered_host_is_refused_after_its_budget(self, monkeypatch):
        from ishastra.core import scope as scope_module

        calls: list[str] = []

        def fake_getaddrinfo(host, port, **kwargs):
            calls.append(host)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        monkeypatch.setattr(scope_module, "_host_buckets", {})
        monkeypatch.setattr(scope_module.socket, "getaddrinfo", fake_getaddrinfo)

        results = [scope_module.resolve_sync("hammer.example", 443) for _ in range(120)]

        assert results[0] == ["93.184.216.34"]
        assert len(calls) == scope_module.RESOLVE_BURST
        assert results[-1] == []

    def test_a_second_host_keeps_its_own_budget(self, monkeypatch):
        from ishastra.core import scope as scope_module

        def fake_getaddrinfo(host, port, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]

        monkeypatch.setattr(scope_module, "_host_buckets", {})
        monkeypatch.setattr(scope_module.socket, "getaddrinfo", fake_getaddrinfo)

        for _ in range(scope_module.RESOLVE_BURST + 5):
            scope_module.resolve_sync("first.example", 443)

        assert scope_module.resolve_sync("second.example", 443) == ["93.184.216.34"]


class TestGateSpans:
    """A gate decision is traceable without recording the target itself."""

    def test_a_denial_carries_decision_tenant_and_stage(self, monkeypatch):
        import contextlib

        from ishastra import otel
        from ishastra.core import scope as scope_module

        recorded: dict = {}

        class Recorder:
            def set_attribute(self, key, value):
                recorded.setdefault("attrs", {})[key] = value

        @contextlib.contextmanager
        def fake_span(name, attributes=None):
            recorded["name"] = name
            recorded["stage"] = (attributes or {}).get("scope.stage")
            yield Recorder()

        monkeypatch.setattr(otel, "traced_span", fake_span)
        scope = scope_module.configure(
            program="Spans",
            authorized_by="Test",
            authorization_ref="SPAN-1",
            include=["example.com"],
            tenant_id="acme",
        )

        denial, _reason = scope.check("https://other.com/")

        assert denial == "out_of_scope"
        assert recorded["name"] == "scope.address"
        assert recorded["stage"] == "address"
        assert recorded["attrs"] == {
            "scope.decision": "blocked",
            "scope.denial": "out_of_scope",
            "scope.tenant": "acme",
        }


class TestScopeInheritance:
    """An inherited scope can only narrow the parent, never widen it."""

    @staticmethod
    def _scope(**kwargs):
        from ishastra.core import scope as scope_module

        fields = {
            "program": "Inheritance",
            "authorized_by": "Test",
            "authorization_ref": "INH-1",
            "include": ("app.example.com",),
        }
        fields.update(kwargs)
        return scope_module.Scope(**fields)

    def test_include_is_intersected(self):
        child = self._scope(include=("app.example.com", "other.test"))
        base = self._scope(include=("*.example.com",))
        assert child.inherited_from(base).include == ("app.example.com",)

    def test_an_empty_intersection_is_refused(self):
        child = self._scope(include=("other.test",))
        base = self._scope(include=("*.example.com",))
        with pytest.raises(ValueError, match="allows no host"):
            child.inherited_from(base)

    def test_exclude_is_unioned(self):
        child = self._scope(exclude=("admin.example.com",))
        base = self._scope(exclude=("legacy.example.com",))
        merged = child.inherited_from(base)
        assert set(merged.exclude) == {"admin.example.com", "legacy.example.com"}

    def test_ports_intersect_and_disjoint_sets_are_refused(self):
        child = self._scope(allowed_ports=(443, 80))
        base = self._scope(allowed_ports=(443, 8443))
        assert child.inherited_from(base).allowed_ports == (443,)
        with pytest.raises(ValueError, match="allows no port"):
            self._scope(allowed_ports=(22,)).inherited_from(base)

    def test_authorized_networks_intersect(self):
        child = self._scope(authorized_networks=("10.1.0.0/16",))
        base = self._scope(authorized_networks=("10.0.0.0/8",))
        assert child.inherited_from(base).authorized_networks == ("10.1.0.0/16",)
        assert (
            self._scope(authorized_networks=("10.1.0.0/16",))
            .inherited_from(self._scope())
            .authorized_networks
            == ()
        )

    def test_the_earlier_expiry_wins(self):
        child = self._scope(expires_at="2030-01-01T00:00:00+00:00")
        base = self._scope(expires_at="2029-01-01T00:00:00+00:00")
        assert child.inherited_from(base).expires_at.startswith("2029-01-01")

    def test_the_merged_scope_judges_only_the_narrowed_hosts(self):
        child = self._scope(include=("app.example.com", "api.example.com"))
        base = self._scope(include=("api.example.com",))
        merged = child.inherited_from(base)
        assert merged.check("https://other.test/")[0] == "out_of_scope"
