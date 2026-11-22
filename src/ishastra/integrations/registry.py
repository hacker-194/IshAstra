"""Connector registry for dynamic connector loading."""

from __future__ import annotations

from typing import Any, Optional

from ishastra.integrations.base import BaseConnector, BaseConnectorConfig

_connector_registry: dict[str, type[BaseConnector]] = {}
_config_registry: dict[str, type[BaseConnectorConfig]] = {}


def register_connector(
    name: str,
    connector_cls: type[BaseConnector],
    config_cls: type[BaseConnectorConfig],
) -> None:
    """Register a connector and its config class."""
    _connector_registry[name] = connector_cls
    _config_registry[name] = config_cls


def get_connector(name: str) -> Optional[BaseConnector]:
    """Get a connector instance by name."""
    connector_cls = _connector_registry.get(name)
    if connector_cls is None:
        return None
    return connector_cls()


def get_config_class(name: str) -> Optional[type[BaseConnectorConfig]]:
    """Get a connector config class by name."""
    return _config_registry.get(name)


def list_connectors() -> list[str]:
    """List all registered connector names."""
    return sorted(_connector_registry.keys())