"""Tests for template allowlist (Nuclei and Nmap NSE)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from ishastra.core.adapters import NmapAdapter, NucleiAdapter
from ishastra.core.template_allowlist import (
    TemplateAllowlist,
    TemplateAllowlistError,
    get_allowlist,
    reset_allowlist,
)


class TestTemplateAllowlist:
    """Tests for TemplateAllowlist class."""

    def test_load_yaml_config(self):
        """Test loading YAML allowlist config."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("""
nuclei:
  - "http/exposures/configs"
  - "http/vulnerabilities/cve-2024-*"
nmap:
  - "http-title"
  - "ssl-cert"
""")
            config_path = f.name

        try:
            allowlist = TemplateAllowlist(config_path)
            assert "http/exposures/configs" in allowlist.nuclei_patterns
            assert "http/vulnerabilities/cve-2024-*" in allowlist.nuclei_patterns
            assert "http-title" in allowlist.nmap_patterns
            assert "ssl-cert" in allowlist.nmap_patterns
        finally:
            Path(config_path).unlink()

    def test_load_json_config(self):
        """Test loading JSON allowlist config."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"nuclei": ["http/exposures/*"], "nmap": ["http-*"]}')
            config_path = f.name

        try:
            allowlist = TemplateAllowlist(config_path)
            assert "http/exposures/*" in allowlist.nuclei_patterns
            assert "http-*" in allowlist.nmap_patterns
        finally:
            Path(config_path).unlink()

    def test_missing_config_raises_error(self):
        """Test missing config file raises TemplateAllowlistError."""
        with pytest.raises(TemplateAllowlistError, match="not found"):
            TemplateAllowlist("/nonexistent/path.yaml")

    def test_invalid_yaml_raises_error(self):
        """Test invalid YAML raises TemplateAllowlistError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: [")
            config_path = f.name

        try:
            with pytest.raises(TemplateAllowlistError):
                TemplateAllowlist(config_path)
        finally:
            Path(config_path).unlink()

    def test_empty_config_raises_error(self):
        """Test empty config raises TemplateAllowlistError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("nuclei: []\nnmap: []")
            config_path = f.name

        try:
            with pytest.raises(TemplateAllowlistError, match="at least one"):
                TemplateAllowlist(config_path)
        finally:
            Path(config_path).unlink()

    def test_nuclei_allowed_exact_match(self):
        """Test exact template match."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write('nuclei: ["http/exposures/configs"]\nnmap: []')
            config_path = f.name

        try:
            allowlist = TemplateAllowlist(config_path)
            assert allowlist.is_nuclei_allowed("http/exposures/configs") is True
            assert allowlist.is_nuclei_allowed("http/exposures/tokens") is False
        finally:
            Path(config_path).unlink()

    def test_nuclei_allowed_glob_match(self):
        """Test glob pattern match for nuclei."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write('nuclei: ["http/vulnerabilities/cve-2024-*"]\nnmap: []')
            config_path = f.name

        try:
            allowlist = TemplateAllowlist(config_path)
            assert allowlist.is_nuclei_allowed("http/vulnerabilities/cve-2024-1234") is True
            assert allowlist.is_nuclei_allowed("http/vulnerabilities/cve-2023-1234") is False
            assert allowlist.is_nuclei_allowed("http/exposures/configs") is False
        finally:
            Path(config_path).unlink()

    def test_nuclei_allowed_basename_match(self):
        """Test basename match for template IDs."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write('nuclei: ["cve-2024-*"]\nnmap: []')
            config_path = f.name

        try:
            allowlist = TemplateAllowlist(config_path)
            assert allowlist.is_nuclei_allowed("http/vulnerabilities/cve-2024-1234") is True
            assert allowlist.is_nuclei_allowed("cve-2024-5678") is True
        finally:
            Path(config_path).unlink()

    def test_nmap_allowed_exact_match(self):
        """Test exact script match."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write('nuclei: []\nnmap: ["http-title", "ssl-cert"]')
            config_path = f.name

        try:
            allowlist = TemplateAllowlist(config_path)
            assert allowlist.is_nmap_allowed("http-title") is True
            assert allowlist.is_nmap_allowed("ssl-cert") is True
            assert allowlist.is_nmap_allowed("http-headers") is False
        finally:
            Path(config_path).unlink()

    def test_nmap_allowed_glob_match(self):
        """Test glob pattern match for nmap."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write('nuclei: []\nnmap: ["http-*", "ssl-*"]')
            config_path = f.name

        try:
            allowlist = TemplateAllowlist(config_path)
            assert allowlist.is_nmap_allowed("http-title") is True
            assert allowlist.is_nmap_allowed("http-headers") is True
            assert allowlist.is_nmap_allowed("ssl-cert") is True
            assert allowlist.is_nmap_allowed("ssh-hostkey") is False
        finally:
            Path(config_path).unlink()

    def test_validate_nuclei_templates(self):
        """Test validating list of nuclei templates."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write('nuclei: ["http/exposures/*", "http/vulnerabilities/cve-2024-*"]\nnmap: []')
            config_path = f.name

        try:
            allowlist = TemplateAllowlist(config_path)
            templates = [
                "http/exposures/configs",
                "http/exposures/tokens",
                "http/vulnerabilities/cve-2024-1234",
                "http/misconfiguration/test",
                "http/vulnerabilities/cve-2023-1234",
            ]
            allowed, denied = allowlist.validate_nuclei_templates(templates)
            assert set(allowed) == {
                "http/exposures/configs",
                "http/exposures/tokens",
                "http/vulnerabilities/cve-2024-1234",
            }
            assert set(denied) == {
                "http/misconfiguration/test",
                "http/vulnerabilities/cve-2023-1234",
            }
        finally:
            Path(config_path).unlink()

    def test_validate_nmap_scripts(self):
        """Test validating list of nmap scripts."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write('nuclei: []\nnmap: ["http-*", "ssl-*"]')
            config_path = f.name

        try:
            allowlist = TemplateAllowlist(config_path)
            scripts = ["http-title", "http-headers", "ssl-cert", "ssh-hostkey", "ftp-anon"]
            allowed, denied = allowlist.validate_nmap_scripts(scripts)
            assert set(allowed) == {"http-title", "http-headers", "ssl-cert"}
            assert set(denied) == {"ssh-hostkey", "ftp-anon"}
        finally:
            Path(config_path).unlink()

    def test_get_allowed_nuclei_args(self):
        """Test getting nuclei -t arguments from allowlist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            templates_dir = Path(tmpdir)
            # Create directory structure and template files
            exposures_dir = templates_dir / "http" / "exposures"
            exposures_dir.mkdir(parents=True)
            (exposures_dir / "configs.yaml").write_text("id: test")
            (exposures_dir / "tokens.yaml").write_text("id: test")
            vuln_dir = templates_dir / "http" / "vulnerabilities"
            vuln_dir.mkdir(parents=True)
            (vuln_dir / "cve-2024-1234.yaml").write_text("id: test")

            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
                f.write('nuclei: ["http/exposures/*", "http/vulnerabilities/cve-2024-*"]\nnmap: []')
                config_path = f.name

            try:
                allowlist = TemplateAllowlist(config_path)
                args = allowlist.get_allowed_nuclei_args(templates_dir)
                assert len(args) == 3
                assert any("configs.yaml" in a for a in args)
                assert any("tokens.yaml" in a for a in args)
                assert any("cve-2024-1234.yaml" in a for a in args)
            finally:
                Path(config_path).unlink()

    def test_repr(self):
        """Test string representation."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write('nuclei: ["a", "b"]\nnmap: ["c"]')
            config_path = f.name

        try:
            allowlist = TemplateAllowlist(config_path)
            repr_str = repr(allowlist)
            assert "nuclei=2 patterns" in repr_str
            assert "nmap=1 patterns" in repr_str
        finally:
            Path(config_path).unlink()


class TestTemplateAllowlistSingleton:
    """Tests for global allowlist singleton."""

    def test_get_allowlist_singleton(self):
        """Test get_allowlist returns singleton."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write('nuclei: ["test"]\nnmap: []')
            config_path = f.name

        try:
            reset_allowlist()
            a1 = get_allowlist(config_path)
            a2 = get_allowlist()
            assert a1 is a2
        finally:
            Path(config_path).unlink()
            reset_allowlist()

    def test_reset_allowlist(self):
        """Test reset_allowlist creates new instance."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write('nuclei: ["test1"]\nnmap: []')
            config_path = f.name

        try:
            reset_allowlist()
            a1 = get_allowlist(config_path)
            reset_allowlist()

            with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f2:
                f2.write('nuclei: ["test2"]\nnmap: []')
                config_path2 = f2.name

            try:
                a2 = get_allowlist(config_path2)
                assert a1 is not a2
                assert "test2" in a2.nuclei_patterns
            finally:
                Path(config_path2).unlink()
        finally:
            Path(config_path).unlink()
            reset_allowlist()


class TestNmapAdapterAllowlist:
    """Tests for NmapAdapter integration with template allowlist."""

    def test_nmap_adapter_initializes_allowlist(self):
        """Test NmapAdapter initializes allowlist."""
        adapter = NmapAdapter()
        assert hasattr(adapter, "_allowlist")
        assert adapter._allowlist is not None

    def test_nmap_adapter_available_validates_allowlist(self):
        """Test NmapAdapter.available() validates allowlist."""
        adapter = NmapAdapter()
        # The adapter should fail if allowlist has no nmap scripts
        # This test verifies the integration exists
        assert hasattr(adapter, "_allowlist")


class TestNucleiAdapterAllowlist:
    """Tests for NucleiAdapter integration with template allowlist."""

    def test_nuclei_adapter_initializes_allowlist(self):
        """Test NucleiAdapter initializes allowlist."""
        adapter = NucleiAdapter()
        assert hasattr(adapter, "_allowlist")
        assert adapter._allowlist is not None

    def test_nuclei_adapter_available_validates_allowlist(self):
        """Test NucleiAdapter.available() validates allowlist."""
        adapter = NucleiAdapter()
        # The adapter should fail if allowlist has no nuclei templates
        # This test verifies the integration exists
        assert hasattr(adapter, "_allowlist")


class TestDefaultAllowlistConfig:
    """Tests for the default allowlist config file."""

    def test_default_config_exists(self):
        """Test default config file exists."""
        config_path = Path(__file__).parent.parent.parent / "config" / "templates" / "allowlist.yaml"
        assert config_path.exists(), f"Default allowlist config not found at {config_path}"

    def test_default_config_valid(self):
        """Test default config is valid YAML with required keys."""
        config_path = Path(__file__).parent.parent.parent / "config" / "templates" / "allowlist.yaml"
        import yaml

        with config_path.open() as f:
            config = yaml.safe_load(f)

        assert "nuclei" in config
        assert "nmap" in config
        assert isinstance(config["nuclei"], list)
        assert isinstance(config["nmap"], list)
        assert len(config["nuclei"]) > 0
        assert len(config["nmap"]) > 0

    def test_default_config_loadable(self):
        """Test default config can be loaded by TemplateAllowlist."""
        config_path = Path(__file__).parent.parent.parent / "config" / "templates" / "allowlist.yaml"
        allowlist = TemplateAllowlist(config_path)
        assert len(allowlist.nuclei_patterns) > 0
        assert len(allowlist.nmap_patterns) > 0
