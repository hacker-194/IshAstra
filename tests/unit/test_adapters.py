"""Tests for ishastra.core.adapters and related modules."""

from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from ishastra.core.adapter_base import Adapter, AdapterError, AdapterResult, AdapterTimeout
from ishastra.core.adapters import (
    ADAPTERS,
    PROFILES,
    AuthorizationDiffAdapter,
    CrawlerAdapter,
    DynamicValidationAdapter,
    HTTPAdapter,
    NiktoAdapter,
    NmapAdapter,
    NucleiAdapter,
    OpenAPIAdapter,
    SqlmapAdapter,
    SSRFOOBAdapter,
    select,
)
from ishastra.core.crawler import CrawlerAdapter as CoreCrawlerAdapter
from ishastra.core.exposure import GitExposureAdapter
from ishastra.core.ports import TCPPortAdapter
from ishastra.security.authorization.scope import Destination


class TestAdapterBase:
    """Tests for adapter base classes."""

    def test_adapter_result_creation(self):
        """Test AdapterResult creation."""
        result = AdapterResult(findings=[], notes=["note1"])
        assert result.findings == []
        assert result.notes == ["note1"]
        assert result.partial is False

    def test_adapter_result_empty(self):
        """Test AdapterResult with defaults."""
        result = AdapterResult()
        assert result.findings == []
        assert result.notes == []
        assert result.partial is False

    def test_adapter_error(self):
        """Test AdapterError."""
        err = AdapterError("test error")
        assert str(err) == "test error"

    def test_adapter_timeout(self):
        """Test AdapterTimeout."""
        err = AdapterTimeout("timeout")
        assert str(err) == "timeout"
        assert isinstance(err, AdapterError)

    def test_adapter_not_applicable(self):
        """Test AdapterNotApplicable."""
        from ishastra.core.adapter_base import AdapterNotApplicable

        err = AdapterNotApplicable("not applicable")
        assert str(err) == "not applicable"
        assert isinstance(err, AdapterError)


class TestHTTPAdapter:
    """Tests for HTTPAdapter."""

    @pytest.fixture
    def adapter(self):
        return HTTPAdapter()

    def test_adapter_creation(self, adapter):
        """Test HTTPAdapter creation."""
        assert adapter.id == "ishastra-http"
        assert adapter.asset_types == ("web",)

    def test_adapter_info(self, adapter):
        """Test adapter info."""
        info = adapter.info()
        assert info["id"] == "ishastra-http"
        assert info["asset_types"] == ["web"]
        assert info["available"] is True

    def test_assess_method_exists(self, adapter):
        """Test assess method exists."""
        assert hasattr(adapter, "assess")


class TestTCPPortAdapter:
    """Tests for TCPPortAdapter."""

    @pytest.fixture
    def adapter(self):
        return TCPPortAdapter()

    def test_adapter_creation(self, adapter):
        """Test TCPPortAdapter creation."""
        assert adapter.id == "ishastra-tcp"
        assert adapter.asset_types == ("web", "api", "network")

    def test_adapter_info(self, adapter):
        """Test adapter info."""
        info = adapter.info()
        assert info["id"] == "ishastra-tcp"
        assert info["asset_types"] == ["web", "api", "network"]


class TestGitExposureAdapter:
    """Tests for GitExposureAdapter."""

    @pytest.fixture
    def adapter(self):
        return GitExposureAdapter()

    def test_adapter_creation(self, adapter):
        """Test GitExposureAdapter creation."""
        assert adapter.id == "ishastra-git-exposure"
        assert adapter.asset_types == ("web", "api")

    def test_adapter_info(self, adapter):
        """Test adapter info."""
        info = adapter.info()
        assert info["id"] == "ishastra-git-exposure"
        assert info["asset_types"] == ["web", "api"]


class TestCrawlerAdapter:
    """Tests for adapters.CrawlerAdapter."""

    @pytest.fixture
    def adapter(self):
        return CrawlerAdapter()

    def test_adapter_creation(self, adapter):
        """Test CrawlerAdapter creation."""
        assert adapter.id == "ishastra-crawl"
        assert adapter.asset_types == ("web",)

    def test_adapter_info(self, adapter):
        """Test adapter info."""
        info = adapter.info()
        assert info["id"] == "ishastra-crawl"
        assert info["asset_types"] == ["web"]


class TestCoreCrawlerAdapter:
    """Tests for core.crawler.CrawlerAdapter."""

    @pytest.fixture
    def adapter(self):
        return CoreCrawlerAdapter()

    def test_adapter_creation(self, adapter):
        """Test core CrawlerAdapter creation."""
        assert adapter.id == "ishastra-crawl"
        assert adapter.asset_types == ("web",)


class TestDynamicValidationAdapter:
    """Tests for DynamicValidationAdapter."""

    @pytest.fixture
    def adapter(self):
        return DynamicValidationAdapter()

    def test_adapter_creation(self, adapter):
        """Test DynamicValidationAdapter creation."""
        assert adapter.id == "ishastra-dynamic-validation"
        assert adapter.asset_types == ("web",)

    def test_adapter_info(self, adapter):
        """Test adapter info."""
        info = adapter.info()
        assert info["id"] == "ishastra-dynamic-validation"
        assert info["asset_types"] == ["web"]


class TestOpenAPIAdapter:
    """Tests for OpenAPIAdapter."""

    @pytest.fixture
    def adapter(self):
        return OpenAPIAdapter()

    def test_adapter_creation(self, adapter):
        """Test OpenAPIAdapter creation."""
        assert adapter.id == "ishastra-openapi"
        assert adapter.asset_types == ("web",)

    def test_adapter_info(self, adapter):
        """Test adapter info."""
        info = adapter.info()
        assert info["id"] == "ishastra-openapi"
        assert info["asset_types"] == ["web"]


class TestAuthorizationDiffAdapter:
    """Tests for AuthorizationDiffAdapter."""

    @pytest.fixture
    def adapter(self):
        return AuthorizationDiffAdapter()

    def test_adapter_creation(self, adapter):
        """Test AuthorizationDiffAdapter creation."""
        assert adapter.id == "ishastra-authz"
        assert adapter.asset_types == ("web", "api")

    def test_adapter_info(self, adapter):
        """Test adapter info."""
        info = adapter.info()
        assert info["id"] == "ishastra-authz"
        assert "web" in info["asset_types"]
        assert "api" in info["asset_types"]


class TestSSRFOOBAdapter:
    """Tests for SSRFOOBAdapter."""

    @pytest.fixture
    def adapter(self):
        return SSRFOOBAdapter()

    def test_adapter_creation(self, adapter):
        """Test SSRFOOBAdapter creation."""
        assert adapter.id == "ishastra-ssrf-oob"
        assert adapter.asset_types == ("web", "api")

    def test_adapter_info(self, adapter):
        """Test adapter info."""
        info = adapter.info()
        assert info["id"] == "ishastra-ssrf-oob"
        assert info["asset_types"] == ["web", "api"]


class TestNmapAdapter:
    """Tests for NmapAdapter."""

    @pytest.fixture
    def adapter(self):
        return NmapAdapter()

    def test_adapter_creation(self, adapter):
        """Test NmapAdapter creation."""
        assert adapter.id == "nmap"
        assert adapter.asset_types == ("web", "host")

    def test_adapter_info(self, adapter):
        """Test adapter info."""
        info = adapter.info()
        assert info["id"] == "nmap"
        assert info["asset_types"] == ["web", "host"]

    def test_adapter_available_when_nmap_installed(self, adapter):
        """Test nmap adapter availability."""
        with patch("shutil.which", return_value="/usr/bin/nmap"), patch("subprocess.run") as mock_run:
            mock_run.return_value.stdout = "Nmap version 7.98 ( https://nmap.org )\n"
            ok, detail = adapter.available()
            assert ok is True
            assert "nmap" in detail.lower()

    def test_adapter_unavailable_when_nmap_missing(self, adapter):
        """Test nmap adapter unavailable when not installed."""
        with patch("shutil.which", return_value=None):
            ok, detail = adapter.available()
            assert ok is False
            assert "not installed" in detail.lower()

    def test_adapter_contract_enforcement_proxy(self, adapter):
        """Test adapter contract declares enforcement=proxy."""
        contract = adapter.contract()
        assert contract["enforcement"] == "proxy"
        assert contract["scan_modes"] == ["connect"]
        assert "tcp" in contract["protocols"]

    # Valid nmap XML with one open port for testing
    NMAP_XML_WITH_PORT = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<nmaprun scanner="nmap" args="nmap -sT -Pn -n -p 80 -oX - -- 192.0.2.1" '
        'version="7.98" xmloutputversion="1.04">\n'
        '  <scaninfo type="connect" protocol="tcp" numservices="1" services="80"/>\n'
        '  <verbose level="0"/>\n'
        '  <debugging level="0"/>\n'
        "  <host>\n"
        '    <status state="up" reason="syn-ack" reason_ttl="0"/>\n'
        '    <address addr="192.0.2.1" addrtype="ipv4"/>\n'
        "    <hostnames/>\n"
        "    <ports>\n"
        '      <port protocol="tcp" portid="80">\n'
        '        <state state="open" reason="syn-ack" reason_ttl="0"/>\n'
        '        <service name="http" product="nginx" version="1.18.0"/>\n'
        "      </port>\n"
        "    </ports>\n"
        "  </host>\n"
        "  <runstats>\n"
        '    <finished time="1700000000" timestr="Fri Nov 15 12:00:00 2024" '
        'elapsed="1.23" '
        'summary="Nmap done: 1 IP address (1 host up) scanned in 1.23 seconds" '
        'exit="success"/>\n'
        "  </runstats>\n"
        "</nmaprun>"
    )

    def _destination(self) -> Destination:
        return Destination(scheme="http", host="example.com", port=80, ip="192.0.2.1")

    def test_adapter_uses_tcp_connect_only_no_syn(self, adapter):
        """Test nmap uses -sT (TCP connect) only, not -sS (SYN) which bypasses proxy."""
        adapter._version = "test"
        with (
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination()),
            patch("ishastra.core.adapters.shutil.which", return_value="/usr/bin/nmap"),
            patch("ishastra.core.adapters._run_tool", return_value=(0, self.NMAP_XML_WITH_PORT, "")) as run,
            patch("ishastra.core.scope.active", return_value=None),
        ):
            adapter.assess(
                "http://example.com/",
                timeout=30,
                cancel=threading.Event(),
                context={"gateway_url": "http://gateway:8080"},
            )
        argv = run.call_args.args[0]
        assert "-sT" in argv, "Must use TCP connect scan (-sT)"
        assert "-sS" not in argv, "SYN scan (-sS) bypasses proxy and is forbidden"
        assert "-Pn" in argv, "Must use no-ping (-Pn) for proxy enforcement"

    def test_adapter_uses_proxy_from_context(self, adapter):
        """Test nmap uses --proxies with gateway_url from context."""
        adapter._version = "test"
        with (
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination()),
            patch("ishastra.core.adapters.shutil.which", return_value="/usr/bin/nmap"),
            patch("ishastra.core.adapters._run_tool", return_value=(0, self.NMAP_XML_WITH_PORT, "")) as run,
            patch("ishastra.core.scope.active", return_value=None),
        ):
            adapter.assess(
                "http://example.com/",
                timeout=30,
                cancel=threading.Event(),
                context={"gateway_url": "http://proxy.example.com:3128"},
            )
        argv = run.call_args.args[0]
        assert "--proxies" in argv
        proxy_idx = argv.index("--proxies")
        assert argv[proxy_idx + 1] == "http://proxy.example.com:3128"

    def test_adapter_refuses_without_gateway(self, adapter):
        """Test nmap refuses to run instead of connecting directly."""
        adapter._version = "test"
        with (
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination()),
            patch("ishastra.core.adapters.shutil.which", return_value="/usr/bin/nmap"),
            patch("ishastra.core.adapters._run_tool") as run,
            patch("ishastra.core.scope.active", return_value=None),
        ):
            with pytest.raises(AdapterError, match="gateway"):
                adapter.assess(
                    "http://example.com/",
                    timeout=30,
                    cancel=threading.Event(),
                    context={},
                )
            run.assert_not_called()


class TestNucleiAdapter:
    """Tests for NucleiAdapter."""

    @pytest.fixture
    def adapter(self):
        return NucleiAdapter()

    def test_adapter_creation(self, adapter):
        """Test NucleiAdapter creation."""
        assert adapter.id == "nuclei"
        assert adapter.asset_types == ("web",)

    def test_adapter_info(self, adapter):
        """Test adapter info."""
        info = adapter.info()
        assert info["id"] == "nuclei"
        assert info["asset_types"] == ["web"]

    def test_adapter_available_when_nuclei_installed(self, adapter):
        """Test nuclei adapter availability when binary exists but templates missing."""
        with (
            patch("shutil.which", return_value="/usr/bin/nuclei"),
            patch.object(NucleiAdapter, "templates_dir", return_value=Path("/nonexistent")),
        ):
            ok, detail = adapter.available()
            assert ok is False
            assert "not installed" in detail.lower()

    def test_adapter_unavailable_when_nuclei_missing(self, adapter):
        """Test nuclei adapter unavailable when not installed."""
        with patch("shutil.which", return_value=None):
            ok, detail = adapter.available()
            assert ok is False
            assert "not installed" in detail.lower()


class TestAdapterRegistry:
    """Tests for adapter registry (ADAPTERS dict)."""

    def test_adapters_imported(self):
        """Test all adapters are importable."""
        assert "ishastra-http" in ADAPTERS
        assert "ishastra-crawl" in ADAPTERS
        assert "ishastra-dynamic-validation" in ADAPTERS
        assert "ishastra-openapi" in ADAPTERS
        assert "ishastra-authz" in ADAPTERS
        assert "ishastra-ssrf-oob" in ADAPTERS
        assert "ishastra-git-exposure" in ADAPTERS
        assert "ishastra-tcp" in ADAPTERS
        assert "nmap" in ADAPTERS
        assert "nuclei" in ADAPTERS

    def test_adapters_are_classes(self):
        """Test all adapters are classes."""
        for _name, adapter_cls in ADAPTERS.items():
            assert issubclass(type(adapter_cls), Adapter)


class TestProfiles:
    """Tests for PROFILES dict."""

    def test_profiles_exist(self):
        """Test profiles are defined."""
        assert "web" in PROFILES
        assert "web-crawl" in PROFILES
        assert "web-deep" in PROFILES
        assert "api" in PROFILES
        assert "api-deep" in PROFILES
        assert "ports" in PROFILES
        assert "network" in PROFILES

    def test_profile_contents(self):
        """Test profile contents are tuples of adapter names."""
        for _profile_name, adapters in PROFILES.items():
            assert isinstance(adapters, tuple)
            for adapter_name in adapters:
                assert isinstance(adapter_name, str)
                assert adapter_name in ADAPTERS


class TestSelectProfile:
    """Tests for select function."""

    def test_select_web(self):
        """Test selecting web profile."""
        adapters = select("web")
        assert len(adapters) == 2
        assert adapters[0].id == "ishastra-http"
        assert adapters[1].id == "ishastra-git-exposure"

    def test_select_web_deep(self):
        """Test selecting web-deep profile."""
        adapters = select("web-deep")
        assert len(adapters) == 6
        ids = [a.id for a in adapters]
        assert "ishastra-crawl" in ids
        assert "ishastra-http" in ids
        assert "ishastra-dynamic-validation" in ids
        assert "ishastra-git-exposure" in ids
        assert "nuclei" in ids
        assert "nikto" in ids

    def test_select_unknown_profile(self):
        """Test selecting unknown profile raises error."""
        with pytest.raises(ValueError, match="unknown profile"):
            select("unknown")


class TestAdapterNetBoundary:
    """Tests for net_boundary_state method."""

    def test_http_adapter_boundary(self):
        """Test HTTP adapter boundary state."""
        adapter = HTTPAdapter()
        state = adapter.net_boundary_state()
        assert state == "none"

    def test_tcp_port_adapter_boundary(self):
        """Test TCP port adapter boundary state."""
        adapter = TCPPortAdapter()
        state = adapter.net_boundary_state()
        assert state == "none"

    def test_git_exposure_adapter_boundary(self):
        """Test git exposure adapter boundary state."""
        adapter = GitExposureAdapter()
        state = adapter.net_boundary_state()
        assert state == "none"


class TestExternalScannerPinning:
    """Nikto and SQLMap must use the gate's resolved IP, not resolve again."""

    @staticmethod
    def _destination(scheme: str = "https", port: int = 443) -> Destination:
        return Destination(scheme=scheme, host="example.com", port=port, ip="203.0.113.10")

    def test_nikto_uses_pinned_ip_and_vhost(self):
        adapter = NiktoAdapter()
        adapter._version = "test"
        with (
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination()),
            patch("ishastra.core.adapters.shutil.which", return_value="/usr/bin/nikto"),
            patch("ishastra.core.adapters._run_tool", return_value=(0, "[]", "")) as run,
        ):
            adapter.assess(
                "https://example.com/",
                timeout=5,
                cancel=threading.Event(),
                context={"gateway_url": "http://gateway:8080"},
            )
        argv = run.call_args.args[0]
        assert argv[argv.index("-host") + 1] == "203.0.113.10"
        assert argv[argv.index("-vhost") + 1] == "example.com"
        assert argv[argv.index("-useproxy") + 1] == "http://gateway:8080"
        assert "-ssl" in argv

    def test_sqlmap_refuses_without_high_risk_authorization(self):
        adapter = SqlmapAdapter()
        adapter._version = "test"
        with (
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination()),
            patch("ishastra.core.adapters.shutil.which", return_value="/usr/bin/sqlmap"),
            pytest.raises(AdapterError, match="high-risk authorization"),
        ):
            adapter.assess("https://example.com/search?q=1", timeout=20, cancel=threading.Event())

    def test_sqlmap_refuses_unproxied_https_without_gateway(self):
        adapter = SqlmapAdapter()
        adapter._version = "test"
        # With high-risk auth but no gateway for HTTPS
        with (
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination()),
            patch("ishastra.core.adapters.shutil.which", return_value="/usr/bin/sqlmap"),
            pytest.raises(AdapterError, match="gateway"),
        ):
            adapter.assess(
                "https://example.com/search?q=1",
                timeout=20,
                cancel=threading.Event(),
                context={"high_risk": True},
            )

    def test_sqlmap_uses_gateway_and_ignores_redirects(self):
        adapter = SqlmapAdapter()
        adapter._version = "test"
        with (
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination("http", 80)),
            patch("ishastra.core.adapters.shutil.which", return_value="/usr/bin/sqlmap"),
            patch("ishastra.core.adapters._run_tool", return_value=(0, "", "")) as run,
        ):
            adapter.assess(
                "http://example.com/search?q=1",
                timeout=20,
                cancel=threading.Event(),
                context={"high_risk": True, "gateway_url": "http://gateway:8080"},
            )
        argv = run.call_args.args[0]
        assert argv[argv.index("-u") + 1] == "http://example.com/search?q=1"
        assert argv[argv.index("--proxy") + 1] == "http://gateway:8080"
        assert "--ignore-redirects" in argv


class TestExternalToolGatewayRequired:
    """External tools refuse to run instead of falling back to a direct connection."""

    @staticmethod
    def _destination(scheme: str = "http", port: int = 80) -> Destination:
        return Destination(scheme=scheme, host="example.com", port=port, ip="203.0.113.10")

    def test_nmap_refuses_without_gateway(self):
        adapter = NmapAdapter()
        adapter._version = "test"
        with (
            patch.object(NmapAdapter, "available", return_value=(True, "ok")),
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination()),
            patch("ishastra.core.adapters._run_tool") as run,
            patch("ishastra.core.scope.active", return_value=None),
        ):
            with pytest.raises(AdapterError, match="gateway"):
                adapter.assess(
                    "http://example.com/",
                    timeout=30,
                    cancel=threading.Event(),
                    context={},
                )
            run.assert_not_called()

    def test_nikto_refuses_without_gateway(self):
        adapter = NiktoAdapter()
        adapter._version = "test"
        with (
            patch.object(NiktoAdapter, "available", return_value=(True, "ok")),
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination()),
            patch("ishastra.core.adapters._run_tool") as run,
        ):
            with pytest.raises(AdapterError, match="gateway"):
                adapter.assess(
                    "http://example.com/",
                    timeout=30,
                    cancel=threading.Event(),
                    context=None,
                )
            run.assert_not_called()

    def test_sqlmap_refuses_without_gateway(self):
        adapter = SqlmapAdapter()
        adapter._version = "test"
        with (
            patch.object(SqlmapAdapter, "available", return_value=(True, "ok")),
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination()),
            patch("ishastra.core.adapters._run_tool") as run,
        ):
            with pytest.raises(AdapterError, match="gateway"):
                adapter.assess(
                    "http://example.com/search?q=1",
                    timeout=20,
                    cancel=threading.Event(),
                    context={"high_risk": True},
                )
            run.assert_not_called()

    def test_nmap_passes_proxy_flag_when_gateway_present(self):
        adapter = NmapAdapter()
        adapter._version = "test"
        with (
            patch.object(NmapAdapter, "available", return_value=(True, "ok")),
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination()),
            patch("ishastra.core.adapters._run_tool", return_value=(1, "", "failed")) as run,
            patch("ishastra.core.scope.active", return_value=None),
            pytest.raises(AdapterError),
        ):
            adapter.assess(
                "http://example.com/",
                timeout=30,
                cancel=threading.Event(),
                context={"gateway_url": "http://gateway:8080"},
            )
        argv = run.call_args.args[0]
        assert argv[argv.index("--proxies") + 1] == "http://gateway:8080"

    def test_nikto_passes_proxy_flag_when_gateway_present(self):
        adapter = NiktoAdapter()
        adapter._version = "test"
        with (
            patch.object(NiktoAdapter, "available", return_value=(True, "ok")),
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination()),
            patch("ishastra.core.adapters._run_tool", return_value=(1, "", "failed")) as run,
            pytest.raises(AdapterError),
        ):
            adapter.assess(
                "http://example.com/",
                timeout=30,
                cancel=threading.Event(),
                context={"gateway_url": "http://gateway:8080"},
            )
        argv = run.call_args.args[0]
        assert argv[argv.index("-useproxy") + 1] == "http://gateway:8080"

    @pytest.mark.parametrize("adapter_cls", [NmapAdapter, NiktoAdapter, SqlmapAdapter])
    def test_tool_not_spawned_when_destination_denied(self, adapter_cls):
        """A gate denial must propagate before any process is started."""
        adapter = adapter_cls()
        adapter._version = "test"
        with (
            patch.object(adapter_cls, "available", return_value=(True, "ok")),
            patch(
                "ishastra.core.adapters.checked_destination",
                side_effect=PermissionError("out of scope"),
            ),
            patch("ishastra.core.adapters._run_tool") as run,
            patch("ishastra.core.scope.active", return_value=None),
        ):
            with pytest.raises(PermissionError, match="out of scope"):
                adapter.assess(
                    "http://evil.example/",
                    timeout=20,
                    cancel=threading.Event(),
                    context={"high_risk": True, "gateway_url": "http://gateway:8080"},
                )
            run.assert_not_called()

    def test_sqlmap_https_with_gateway_proxy_preserves_hostname(self):
        adapter = SqlmapAdapter()
        adapter._version = "test"
        with (
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination()),
            patch("ishastra.core.adapters.shutil.which", return_value="/usr/bin/sqlmap"),
            patch("ishastra.core.adapters._run_tool", return_value=(0, "", "")) as run,
        ):
            # High-risk auth + gateway proxy via context
            adapter.assess(
                "https://example.com/search?q=1",
                timeout=20,
                cancel=threading.Event(),
                context={"high_risk": True, "gateway_url": "http://gateway:8080"},
            )
        argv = run.call_args.args[0]
        assert argv[argv.index("-u") + 1] == "https://example.com/search?q=1"
        assert argv[argv.index("--proxy") + 1] == "http://gateway:8080"

    def test_sqlmap_uses_gateway_proxy_from_context(self):
        adapter = SqlmapAdapter()
        adapter._version = "test"
        with (
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination("http", 80)),
            patch("ishastra.core.adapters.shutil.which", return_value="/usr/bin/sqlmap"),
            patch("ishastra.core.adapters._run_tool", return_value=(0, "", "")) as run,
        ):
            # High-risk auth + gateway proxy via context for HTTP
            adapter.assess(
                "http://example.com/search?q=1",
                timeout=20,
                cancel=threading.Event(),
                context={"high_risk": True, "gateway_url": "http://gateway:8080"},
            )
        argv = run.call_args.args[0]
        assert argv[argv.index("--proxy") + 1] == "http://gateway:8080"

    def test_sqlmap_high_risk_from_rules_of_engagement(self):
        adapter = SqlmapAdapter()
        adapter._version = "test"
        with (
            patch("ishastra.core.adapters.checked_destination", return_value=self._destination("http", 80)),
            patch("ishastra.core.adapters.shutil.which", return_value="/usr/bin/sqlmap"),
            patch("ishastra.core.adapters._run_tool", return_value=(0, "", "")) as run,
        ):
            # High-risk auth via rules_of_engagement, with the required gateway
            adapter.assess(
                "http://example.com/search?q=1",
                timeout=20,
                cancel=threading.Event(),
                context={
                    "rules_of_engagement": {"high_risk_allowed": True},
                    "gateway_url": "http://gateway:8080",
                },
            )
        argv = run.call_args.args[0]
        assert argv[argv.index("--proxy") + 1] == "http://gateway:8080"
