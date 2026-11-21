"""Tests for ishastra.core.adapters and related modules."""

from __future__ import annotations

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
    NmapAdapter,
    NucleiAdapter,
    OpenAPIAdapter,
    SSRFOOBAdapter,
    select,
)
from ishastra.core.crawler import CrawlerAdapter as CoreCrawlerAdapter
from ishastra.core.exposure import GitExposureAdapter
from ishastra.core.ports import TCPPortAdapter


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
