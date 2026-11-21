"""Ishastra: authorized security assessment platform."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version

try:
    __version__ = _distribution_version("ishastra")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
