"""Base classes for integration connectors."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from ishastra.core.redaction import redact

log = logging.getLogger(__name__)


@dataclass
class ConnectorResult:
    """Result of a connector send operation."""

    success: bool
    message: str
    external_id: str | None = None
    details: dict[str, Any] | None = None


class BaseConnectorConfig(BaseModel):
    """Base configuration for all connectors."""

    enabled: bool = True
    timeout_seconds: float = 30.0
    retry_attempts: int = 3
    retry_backoff_seconds: float = 1.0

    model_config = {"extra": "allow"}

    def redact(self) -> dict[str, Any]:
        """Return a redacted copy of the config for logging."""
        return redact(self.model_dump())


class BaseConnector(ABC):
    """Base class for all integration connectors."""

    def __init__(self, config: BaseConnectorConfig | None = None) -> None:
        self.config = config

    @abstractmethod
    async def send(
        self,
        payload: dict[str, Any],
        timeout: float | None = None,
        cancel: Any | None = None,
    ) -> ConnectorResult:
        """Send payload to the external system.

        Args:
            payload: The data to send (finding, batch, etc.)
            timeout: Override the default timeout in seconds
            cancel: Optional cancellation token (threading.Event or asyncio.Event)

        Returns:
            ConnectorResult with success status, message, external_id, and details
        """

    def _require_config(self) -> BaseConnectorConfig:
        """Return the config or fail loudly; connectors cannot run unconfigured."""
        if self.config is None:
            raise RuntimeError(f"{self.__class__.__name__} has no configuration")
        return self.config

    def _get_timeout(self, timeout: float | None) -> float:
        """Get effective timeout."""
        return timeout if timeout is not None else self._require_config().timeout_seconds

    def _get_retry_config(self) -> tuple[int, float]:
        """Get retry attempts and backoff."""
        config = self._require_config()
        return config.retry_attempts, config.retry_backoff_seconds

    def _log_attempt(self, attempt: int, max_attempts: int, error: Exception | None = None) -> None:
        """Log retry attempt with redacted config."""
        if error:
            log.warning(
                "Connector %s attempt %d/%d failed: %s (config: %s)",
                self.__class__.__name__,
                attempt,
                max_attempts,
                error,
                self.config.redact() if self.config else {},
            )
        else:
            log.debug(
                "Connector %s attempt %d/%d",
                self.__class__.__name__,
                attempt,
                max_attempts,
            )
