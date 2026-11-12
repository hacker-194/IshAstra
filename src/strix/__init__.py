"""Strix: authorized security assessment platform."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

try:  # installed: pyproject.toml is the only place the version lives
    __version__ = _distribution_version("strix")
except PackageNotFoundError:  # pragma: no cover - source tree without an install
    __version__ = "0.0.0+unknown"
