"""Ishastra Integration Connectors.

This package provides connectors for sending findings to SIEMs, creating tickets,
sending chat alerts, triggering CI/CD pipelines, and managing secrets.
"""

from ishastra.integrations.base import (
    BaseConnector,
    BaseConnectorConfig,
    ConnectorResult,
    get_connector,
)

__all__ = [
    "BaseConnector",
    "BaseConnectorConfig",
    "ConnectorResult",
    "get_connector",
]