"""Base classes for integration connectors."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BaseConnectorConfig:
    """Base configuration for all connectors."""

    enabled: bool = True
    timeout_seconds: float = 30.0
    retry_attempts: int = 3
    retry_backoff_seconds: float = 1.0


@dataclass
class ConnectorResult:
    """Result of a connector operation."""

    success: bool
    message: str
    external_id: str | None = None
    details: dict[str, Any] | None = None


class BaseConnector(ABC):
    """Base class for all integration connectors."""

    def __init__(self, config: BaseConnectorConfig | None = None):
        self.config = config or BaseConnectorConfig()

    @abstractmethod
    async def send(
        self,
        payload: dict[str, Any],
        timeout: float | None = None,
        cancel: threading.Event | None = None,
    ) -> ConnectorResult:
        """Send payload to the external system.

        Args:
            payload: The data to send.
            timeout: Override timeout in seconds.
            cancel: Cancellation event.

        Returns:
            ConnectorResult with success status and details.
        """
        pass

    def _is_cancelled(self, cancel: threading.Event | None) -> bool:
        """Check if operation was cancelled."""
        return cancel is not None and cancel.is_set()

    def _calculate_backoff(self, attempt: int) -> float:
        """Calculate exponential backoff with jitter."""
        import random

        base = self.config.retry_backoff_seconds * (2 ** attempt)
        jitter = random.uniform(0, base * 0.1)
        return base + jitter