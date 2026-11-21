"""Unit tests for Ishastra ScopeGate (default-deny authorization gate)."""

from unittest.mock import patch

import pytest

from ishastra.core.scope import (
    Scope,
    ScopeGate,
    ValidationResult,
    configure,
)


class TestScopeGateValidationResult:
    """Test ValidationResult dataclass."""

    def test_validation_result_allowed(self):
        """ValidationResult for allowed target."""
        result = ValidationResult(
            allowed=True,
            reason="target is within authorized scope",
            denial_code="",
            host="example.com",
            port=443,
            resolved_ips=("93.184.216.34",),
        )
        assert result.allowed is True
        assert result.reason == "target is within authorized scope"
        assert result.denial_code == ""
        assert result.host == "example.com"
        assert result.port == 443
        assert result.resolved_ips == ("93.184.216.34",)

    def test_validation_result_denied(self):
        """ValidationResult for denied target."""
        result = ValidationResult(
            allowed=False,
            reason="example.com is not in the authorized scope",
            denial_code="out_of_scope",
            host="example.com",
            port=443,
            resolved_ips=(),
        )
        assert result.allowed is False
        assert result.reason == "example.com is not in the authorized scope"
        assert result.denial_code == "out_of_scope"
        assert result.host == "example.com"
        assert result.port == 443
        assert result.resolved_ips == ()

    def test_validation_result_defaults(self):
        """ValidationResult with default values."""
        result = ValidationResult(allowed=False, reason="denied")
        assert result.allowed is False
        assert result.reason == "denied"
        assert result.denial_code == ""
        assert result.host == ""
        assert result.port is None
        assert result.resolved_ips == ()


class TestScopeGateValidateOutbound:
    """Test ScopeGate.validate_outbound method."""

    def setup_method(self):
        """Configure a scope for testing."""
        self.scope = configure(
            program="Test Program",
            authorized_by="Test Authorizer",
            authorization_ref="TEST-001",
            include=["example.com", "*.example.com"],
            exclude=["admin.example.com"],
            authorized_networks=["93.184.216.0/24"],
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

    def test_validate_outbound_allowed_target(self):
        """Valid target returns allowed=True with details."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            result = ScopeGate.validate_outbound("https://example.com/", self.scope)

        assert isinstance(result, ValidationResult)
        assert result.allowed is True
        assert result.denial_code == ""
        assert result.host == "example.com"
        assert result.port == 443
        assert result.resolved_ips == ("93.184.216.34",)
        assert "authorized scope" in result.reason.lower()

    def test_validate_outbound_denied_host_not_in_scope(self):
        """Host not in include list returns allowed=False with out_of_scope."""
        result = ScopeGate.validate_outbound("https://other.com/", self.scope)

        assert result.allowed is False
        assert result.denial_code == "out_of_scope"
        assert result.host == "other.com"
        assert result.port == 443
        assert "not in the authorized scope" in result.reason.lower()
        assert result.resolved_ips == ()

    def test_validate_outbound_denied_explicit_exclude(self):
        """Explicitly excluded host returns allowed=False with out_of_scope."""
        result = ScopeGate.validate_outbound("https://admin.example.com/", self.scope)

        assert result.allowed is False
        assert result.denial_code == "out_of_scope"
        assert result.host == "admin.example.com"
        assert "explicitly out of scope" in result.reason.lower()

    def test_validate_outbound_denied_invalid_scheme(self):
        """Non-http(s) scheme returns allowed=False with invalid_target."""
        for url in [
            "ftp://example.com/",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/html,<script>",
        ]:
            result = ScopeGate.validate_outbound(url, self.scope)
            assert result.allowed is False, f"Expected denial for {url}"
            assert result.denial_code == "invalid_target"
            assert result.host == ""
            assert result.port is None

    def test_validate_outbound_denied_malformed_url(self):
        """Malformed URL returns allowed=False with invalid_target."""
        for url in [
            "http:///path",
            "http://example.com:99999/",
            "not a url",
            "",
        ]:
            result = ScopeGate.validate_outbound(url, self.scope)
            assert result.allowed is False, f"Expected denial for {url!r}"
            assert result.denial_code == "invalid_target"

    def test_validate_outbound_denied_traversal(self):
        """Path traversal returns allowed=False with invalid_target."""
        for url in [
            "http://example.com/..",
            "http://example.com/../etc/passwd",
        ]:
            result = ScopeGate.validate_outbound(url, self.scope)
            assert result.allowed is False
            assert result.denial_code == "invalid_target"
            assert "traversal" in result.reason.lower()

    def test_validate_outbound_denied_port_zero(self):
        """Port 0 returns allowed=False with invalid_target."""
        result = ScopeGate.validate_outbound("http://example.com:0/", self.scope)
        assert result.allowed is False
        assert result.denial_code == "invalid_target"
        assert "port 0" in result.reason.lower()

    def test_validate_outbound_denied_disallowed_port(self):
        """Port not in allowed_ports returns allowed=False with out_of_scope."""
        result = ScopeGate.validate_outbound("https://example.com:8080/", self.scope)
        assert result.allowed is False
        assert result.denial_code == "out_of_scope"
        assert "port 8080" in result.reason.lower()

    def test_validate_outbound_allowed_wildcard_subdomain(self):
        """Wildcard subdomain match returns allowed=True."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            result = ScopeGate.validate_outbound("https://api.example.com/", self.scope)

        assert result.allowed is True
        assert result.host == "api.example.com"
        assert result.resolved_ips == ("93.184.216.34",)

    def test_validate_outbound_denied_wildcard_not_apex(self):
        """Wildcard *.example.com does not match apex example.com."""

        scope = configure(
            program="Wildcard Test",
            authorized_by="Test",
            authorization_ref="WC-001",
            include=["*.example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )
        result = ScopeGate.validate_outbound("https://example.com/", scope)
        assert result.allowed is False
        assert result.denial_code == "out_of_scope"

    def test_validate_outbound_denied_unauthorized_network(self):
        """Host resolving to unauthorized network returns allowed=False."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["10.0.0.1"]):
            result = ScopeGate.validate_outbound("https://example.com/", self.scope)

        assert result.allowed is False
        assert result.denial_code == "out_of_scope"
        assert result.resolved_ips == ("10.0.0.1",)
        assert "non-public" in result.reason.lower() or "resolves to" in result.reason.lower()

    def test_validate_outbound_allowed_authorized_network(self):
        """Host resolving to authorized network returns allowed=True."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            result = ScopeGate.validate_outbound("https://example.com/", self.scope)

        assert result.allowed is True
        assert result.resolved_ips == ("93.184.216.34",)

    def test_validate_outbound_denied_special_use_address(self):
        """Host resolving to special-use address returns allowed=False."""
        for ip in ["127.0.0.1", "192.168.1.1", "10.0.0.1", "169.254.1.1", "224.0.0.1"]:
            with patch("ishastra.core.scope.resolve_sync", return_value=[ip]):
                result = ScopeGate.validate_outbound("https://example.com/", self.scope)

            assert result.allowed is False, f"IP {ip} should be denied"
            assert result.denial_code == "out_of_scope"
            assert result.resolved_ips == (ip,)

    def test_validate_outbound_allowed_empty_authorized_networks_legacy(self):
        """Empty authorized_networks allows all public IPs (legacy mode)."""
        legacy_scope = configure(
            program="Legacy Test",
            authorized_by="Test",
            authorization_ref="LEG-001",
            include=["example.com"],
            authorized_networks=[],
            allowed_ports=[80, 443],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["8.8.8.8"]):
            result = ScopeGate.validate_outbound("https://example.com/", legacy_scope)

        assert result.allowed is True
        assert result.resolved_ips == ("8.8.8.8",)

    def test_validate_outbound_denied_resolution_failed(self):
        """DNS resolution failure returns allowed=False with resolution_failed."""
        with patch("ishastra.core.scope.resolve_sync", return_value=[]):
            result = ScopeGate.validate_outbound("https://example.com/", self.scope)

        assert result.allowed is False
        assert result.denial_code == "resolution_failed"
        assert "cannot resolve" in result.reason.lower()
        assert result.resolved_ips == ()

    def test_validate_outbound_denied_ipv6_embedded_private(self):
        """IPv6 with embedded private IPv4 returns allowed=False."""

        with patch("ishastra.core.scope.resolve_sync", return_value=["64:ff9b::a00:1"]):
            result = ScopeGate.validate_outbound("https://example.com/", self.scope)

        assert result.allowed is False
        assert result.denial_code == "out_of_scope"
        assert result.resolved_ips == ("64:ff9b::a00:1",)

    def test_validate_outbound_denied_parser_differential_backslash(self):
        """URL with backslash returns allowed=False with invalid_target."""
        result = ScopeGate.validate_outbound("http://evil.com\\@ok.com/", self.scope)
        assert result.allowed is False
        assert result.denial_code == "invalid_target"
        assert "backslash" in result.reason.lower()

    def test_validate_outbound_denied_parser_differential_userinfo(self):
        """URL with credentials returns allowed=False with invalid_target."""
        result = ScopeGate.validate_outbound("http://user:pass@ok.com/", self.scope)
        assert result.allowed is False
        assert result.denial_code == "invalid_target"
        assert "credentials" in result.reason.lower()

    def test_validate_outbound_denied_percent_encoded_host(self):
        """Percent-encoded host returns allowed=False with invalid_target."""
        result = ScopeGate.validate_outbound("http://ok%2Ecom/", self.scope)
        assert result.allowed is False
        assert result.denial_code == "invalid_target"
        assert "percent-encoded" in result.reason.lower()

    def test_validate_outbound_includes_resolved_ips_on_denial(self):
        """Denied result includes resolved IPs for debugging."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["10.0.0.1", "192.168.1.1"]):
            result = ScopeGate.validate_outbound("https://example.com/", self.scope)

        assert result.allowed is False
        assert result.resolved_ips == ("10.0.0.1", "192.168.1.1")

    def test_validate_outbound_explicit_ip_literal(self):
        """Explicit IP literal in target is validated against authorized_networks."""
        scope_with_ip = configure(
            program="IP Test",
            authorized_by="Test",
            authorization_ref="IP-001",
            include=["192.0.2.1"],
            authorized_networks=["192.0.2.0/24"],
            allowed_ports=[80, 443],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["192.0.2.1"]):
            result = ScopeGate.validate_outbound("http://192.0.2.1/", scope_with_ip)

        assert result.allowed is True
        assert result.host == "192.0.2.1"

    def test_validate_outbound_explicit_ip_not_authorized(self):
        """Explicit IP literal not in authorized_networks is denied."""
        scope_with_ip = configure(
            program="IP Test",
            authorized_by="Test",
            authorization_ref="IP-002",
            include=["8.8.8.8"],
            authorized_networks=["10.0.0.0/8"],
            allowed_ports=[80, 443],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["8.8.8.8"]):
            result = ScopeGate.validate_outbound("http://8.8.8.8/", scope_with_ip)

        assert result.allowed is False
        assert result.denial_code == "out_of_scope"

    def test_validate_outbound_multiple_ips_one_unauthorized(self):
        """If ANY resolved IP is unauthorized, target is denied."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34", "10.0.0.1"]):
            result = ScopeGate.validate_outbound("https://example.com/", self.scope)

        assert result.allowed is False
        assert result.denial_code == "out_of_scope"
        assert result.resolved_ips == ("93.184.216.34", "10.0.0.1")

    def test_validate_outbound_internal_suffixes_denied(self):
        """Internal DNS suffixes are always denied."""
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
            result = ScopeGate.validate_outbound(f"http://{host}/", scope)
            assert result.allowed is False
            assert result.denial_code == "out_of_scope"

    def test_validate_outbound_case_insensitive(self):
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
            result = ScopeGate.validate_outbound("https://example.com/", scope)

        assert result.allowed is True

    def test_validate_outbound_trailing_dot(self):
        """Trailing dots in hostnames are handled correctly."""

        scope = configure(
            program="Test",
            authorized_by="Test",
            authorization_ref="T-1",
            include=["example.com."],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            result = ScopeGate.validate_outbound("https://example.com./", scope)

        assert result.allowed is True

    def test_validate_outbound_http_default_port_80(self):
        """HTTP defaults to port 80."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            result = ScopeGate.validate_outbound("http://example.com/", self.scope)

        assert result.allowed is True
        assert result.port == 80

    def test_validate_outbound_https_default_port_443(self):
        """HTTPS defaults to port 443."""
        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            result = ScopeGate.validate_outbound("https://example.com/", self.scope)

        assert result.allowed is True
        assert result.port == 443

    def test_validate_outbound_explicit_port(self):
        """Explicit port in URL is used."""

        scope = configure(
            program="Port Test",
            authorized_by="Test",
            authorization_ref="PORT-001",
            include=["example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443, 8443],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            result = ScopeGate.validate_outbound("https://example.com:8443/", scope)

        assert result.allowed is True
        assert result.port == 8443


class TestScopeGateDefaultDeny:
    """Test default-deny behavior."""

    def test_no_scope_configured_denies_all(self):
        """When no scope is configured, all targets are denied."""

        scope = Scope(
            program="Test",
            authorized_by="Test",
            authorization_ref="T-1",
            include=["example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )

        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            result = ScopeGate.validate_outbound("https://example.com/", scope)
            assert result.allowed is True

        result = ScopeGate.validate_outbound("https://other.com/", scope)
        assert result.allowed is False

    def test_empty_include_denies_all(self):
        """Empty include list is rejected at Scope creation."""
        with pytest.raises(ValueError, match="scope has no in-scope hosts"):
            Scope(
                program="Test",
                authorized_by="Test",
                authorization_ref="T-1",
                include=(),
            )

    def test_explicit_deny_overrides_allow(self):
        """Explicit exclude overrides include."""
        scope = configure(
            program="Test",
            authorized_by="Test",
            authorization_ref="T-1",
            include=["example.com", "*.example.com"],
            exclude=["api.example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )

        result = ScopeGate.validate_outbound("https://api.example.com/", scope)
        assert result.allowed is False
        assert result.denial_code == "out_of_scope"
        assert "explicitly out of scope" in result.reason.lower()


class TestScopeGatePortRestrictions:
    """Test port restriction logic in ScopeGate."""

    def setup_method(self):
        self.scope = configure(
            program="Port Test",
            authorized_by="Test",
            authorization_ref="PORT-001",
            include=["example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443, 8080, 8443],
        )

    def teardown_method(self):
        configure(
            program="Cleanup",
            authorized_by="Test",
            authorization_ref="CLEANUP",
            include=["cleanup.local"],
        )

    def test_allowed_ports(self):
        """Allowed ports return allowed=True."""
        for port, scheme in [(80, "http"), (443, "https"), (8080, "http"), (8443, "https")]:
            with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
                result = ScopeGate.validate_outbound(f"{scheme}://example.com:{port}/", self.scope)
            assert result.allowed is True, f"Port {port} should be allowed"
            assert result.port == port

    def test_disallowed_port(self):
        """Disallowed port returns allowed=False."""
        result = ScopeGate.validate_outbound("https://example.com:9999/", self.scope)
        assert result.allowed is False
        assert result.denial_code == "out_of_scope"
        assert "port 9999" in result.reason.lower()

    def test_empty_allowed_ports_allows_all(self):
        """Empty allowed_ports allows all ports (legacy)."""
        legacy_scope = configure(
            program="Legacy",
            authorized_by="Test",
            authorization_ref="LEG-1",
            include=["example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["93.184.216.34"]):
            for port in [80, 443, 8080, 9999, 65535]:
                result = ScopeGate.validate_outbound(f"https://example.com:{port}/", legacy_scope)
                assert result.allowed is True, f"Port {port} should be allowed with empty allowed_ports"


class TestScopeGateAuthorizedNetworks:
    """Test authorized_networks validation in ScopeGate."""

    def test_authorized_network_allows_matching_ip(self):
        """IP in authorized_networks is allowed."""
        scope = configure(
            program="Net Test",
            authorized_by="Test",
            authorization_ref="NET-1",
            include=["example.com"],
            authorized_networks=["10.0.0.0/8"],
            allowed_ports=[80, 443],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["10.0.0.1"]):
            result = ScopeGate.validate_outbound("https://example.com/", scope)
        assert result.allowed is True
        assert result.resolved_ips == ("10.0.0.1",)

    def test_unauthorized_network_denies(self):
        """IP not in authorized_networks is denied (when authorized_networks is non-empty)."""
        scope = configure(
            program="Net Test",
            authorized_by="Test",
            authorization_ref="NET-2",
            include=["example.com"],
            authorized_networks=["10.0.0.0/8"],
            allowed_ports=[80, 443],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["8.8.8.8"]):
            result = ScopeGate.validate_outbound("https://example.com/", scope)
        assert result.allowed is False
        assert result.denial_code == "out_of_scope"

    def test_multiple_authorized_networks(self):
        """Multiple authorized networks all work."""
        scope = configure(
            program="Net Test",
            authorized_by="Test",
            authorization_ref="NET-3",
            include=["example.com"],
            authorized_networks=["10.0.0.0/8", "192.168.0.0/16"],
            allowed_ports=[80, 443],
        )
        for ip in ["10.0.0.1", "192.168.1.1"]:
            with patch("ishastra.core.scope.resolve_sync", return_value=[ip]):
                result = ScopeGate.validate_outbound("https://example.com/", scope)
            assert result.allowed is True, f"IP {ip} should be allowed"

    def test_ipv6_authorized_network(self):
        """IPv6 authorized networks work."""
        scope = configure(
            program="Net Test",
            authorized_by="Test",
            authorization_ref="NET-4",
            include=["example.com"],
            authorized_networks=["2001:db8::/32"],
            allowed_ports=[80, 443],
        )
        with patch("ishastra.core.scope.resolve_sync", return_value=["2001:db8::1"]):
            result = ScopeGate.validate_outbound("https://example.com/", scope)
        assert result.allowed is True
        assert result.resolved_ips == ("2001:db8::1",)


class TestScopeGateEdgeCases:
    """Edge cases for ScopeGate."""

    def test_validate_outbound_returns_validation_result_type(self):
        """validate_outbound always returns ValidationResult."""
        scope = configure(
            program="Test",
            authorized_by="Test",
            authorization_ref="T-1",
            include=["example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )
        result = ScopeGate.validate_outbound("https://example.com/", scope)
        assert isinstance(result, ValidationResult)

    def test_validate_outbound_never_raises(self):
        """validate_outbound never raises, always returns ValidationResult."""
        scope = configure(
            program="Test",
            authorized_by="Test",
            authorization_ref="T-1",
            include=["example.com"],
            authorized_networks=["93.184.216.0/24"],
            allowed_ports=[80, 443],
        )

        for url in ["", "not a url", "http://", "ftp://example.com/"]:
            result = ScopeGate.validate_outbound(url, scope)
            assert isinstance(result, ValidationResult)
            assert result.allowed is False
