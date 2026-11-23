"""Template Allowlist for Nuclei and Nmap NSE.

Config-driven allow-list (YAML/JSON) that restricts which templates/scripts
can be executed. Validation occurs at adapter startup.
"""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path
from typing import Any

import yaml


class TemplateAllowlistError(Exception):
    """Raised when template allowlist validation fails."""
    pass


class TemplateAllowlist:
    """Manages the template allowlist for external scanners."""

    def __init__(self, config_path: str | Path | None = None):
        """Initialize the allowlist from a YAML/JSON config file.

        Args:
            config_path: Path to the allowlist config file. If None, uses
                ISHASTRA_TEMPLATE_ALLOWLIST env var or defaults to
                config/templates/allowlist.yaml relative to the project root.
        """
        if config_path is None:
            config_path = os.environ.get(
                "ISHASTRA_TEMPLATE_ALLOWLIST",
                Path(__file__).parent.parent.parent.parent / "config" / "templates" / "allowlist.yaml"
            )
        self.config_path = Path(config_path)
        self._nuclei_patterns: list[str] = []
        self._nmap_patterns: list[str] = []
        self._load()

    def _load(self) -> None:
        """Load and parse the allowlist configuration."""
        if not self.config_path.exists():
            raise TemplateAllowlistError(
                f"Template allowlist config not found: {self.config_path}"
            )

        with self.config_path.open() as f:
            if self.config_path.suffix in (".yaml", ".yml"):
                config = yaml.safe_load(f)
            elif self.config_path.suffix == ".json":
                import json
                config = json.load(f)
            else:
                raise TemplateAllowlistError(
                    f"Unsupported config format: {self.config_path.suffix}. Use .yaml, .yml, or .json"
                )

        if not isinstance(config, dict):
            raise TemplateAllowlistError("Allowlist config must be a YAML/JSON object")

        nuclei = config.get("nuclei", [])
        nmap = config.get("nmap", [])

        if not isinstance(nuclei, list):
            raise TemplateAllowlistError("'nuclei' must be a list of template patterns")
        if not isinstance(nmap, list):
            raise TemplateAllowlistError("'nmap' must be a list of script patterns")

        self._nuclei_patterns = [str(p).strip() for p in nuclei if str(p).strip()]
        self._nmap_patterns = [str(p).strip() for p in nmap if str(p).strip()]

        if not self._nuclei_patterns and not self._nmap_patterns:
            raise TemplateAllowlistError("Allowlist must contain at least one nuclei or nmap pattern")

    @property
    def nuclei_patterns(self) -> tuple[str, ...]:
        """Get the allowed Nuclei template patterns."""
        return tuple(self._nuclei_patterns)

    @property
    def nmap_patterns(self) -> tuple[str, ...]:
        """Get the allowed Nmap NSE script patterns."""
        return tuple(self._nmap_patterns)

    def is_nuclei_allowed(self, template_path: str) -> bool:
        """Check if a Nuclei template is allowed by the allowlist.

        Args:
            template_path: The template path or ID to check (e.g., "http/exposures/configs")

        Returns:
            True if the template matches an allowed pattern, False otherwise.
        """
        for pattern in self._nuclei_patterns:
            if fnmatch.fnmatch(template_path, pattern):
                return True
            # Also check basename for template IDs like "cve-2024-1234"
            if fnmatch.fnmatch(Path(template_path).name, pattern):
                return True
        return False

    def is_nmap_allowed(self, script_name: str) -> bool:
        """Check if an Nmap NSE script is allowed by the allowlist.

        Args:
            script_name: The script name to check (e.g., "http-title")

        Returns:
            True if the script matches an allowed pattern, False otherwise.
        """
        for pattern in self._nmap_patterns:
            if fnmatch.fnmatch(script_name, pattern):
                return True
        return False

    def validate_nuclei_templates(self, template_paths: list[str]) -> tuple[list[str], list[str]]:
        """Validate a list of Nuclei template paths against the allowlist.

        Args:
            template_paths: List of template paths to validate

        Returns:
            Tuple of (allowed_templates, denied_templates)
        """
        allowed = []
        denied = []
        for path in template_paths:
            if self.is_nuclei_allowed(path):
                allowed.append(path)
            else:
                denied.append(path)
        return allowed, denied

    def validate_nmap_scripts(self, script_names: list[str]) -> tuple[list[str], list[str]]:
        """Validate a list of Nmap script names against the allowlist.

        Args:
            script_names: List of script names to validate

        Returns:
            Tuple of (allowed_scripts, denied_scripts)
        """
        allowed = []
        denied = []
        for name in script_names:
            if self.is_nmap_allowed(name):
                allowed.append(name)
            else:
                denied.append(name)
        return allowed, denied

    def get_allowed_nuclei_args(self, templates_dir: Path) -> list[str]:
        """Get the -t arguments for nuclei with only allowed templates.

        Args:
            templates_dir: Root directory of nuclei templates

        Returns:
            List of template paths to pass to nuclei -t
        """
        args = []
        for pattern in self._nuclei_patterns:
            # Expand glob pattern to actual template paths
            matches = list(templates_dir.rglob(pattern))
            for match in matches:
                if match.is_dir() or match.suffix in (".yaml", ".yml"):
                    args.append(str(match))
        return args

    def __repr__(self) -> str:
        return f"TemplateAllowlist(nuclei={len(self._nuclei_patterns)} patterns, nmap={len(self._nmap_patterns)} patterns)"


# Global instance for easy access
_allowlist: TemplateAllowlist | None = None


def get_allowlist(config_path: str | Path | None = None) -> TemplateAllowlist:
    """Get the global template allowlist instance (singleton)."""
    global _allowlist
    if _allowlist is None or config_path is not None:
        _allowlist = TemplateAllowlist(config_path)
    return _allowlist


def reset_allowlist() -> None:
    """Reset the global allowlist instance (for testing)."""
    global _allowlist
    _allowlist = None