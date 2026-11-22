"""Slack connector for sending findings via webhook."""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, Optional

import httpx
from pydantic import ConfigDict, Field, SecretStr

from ishastra.integrations.base import BaseConnector, BaseConnectorConfig, ConnectorResult
from ishastra.integrations.registry import register_connector

logger = logging.getLogger(__name__)


class SlackConfig(BaseConnectorConfig):
    """Configuration for Slack webhook connector."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    webhook_url: SecretStr = Field(description="Slack incoming webhook URL")
    default_channel: Optional[str] = Field(
        default=None, description="Default channel override (e.g., '#security-alerts')"
    )
    username: str = Field(default="ishastra", description="Username to display in Slack")
    icon_emoji: Optional[str] = Field(default=":shield:", description="Emoji icon (e.g., ':shield:')")
    icon_url: Optional[str] = Field(default=None, description="Icon URL (alternative to emoji)")


class SlackConnector(BaseConnector):
    """Slack webhook connector for sending security findings."""

    config: SlackConfig

    def __init__(self, config: SlackConfig | None = None) -> None:
        super().__init__(config)
        self._client: Optional[httpx.AsyncClient] = None

    @classmethod
    def default_config(cls) -> SlackConfig:
        """Return default Slack configuration."""
        return SlackConfig(
            enabled=True,
            webhook_url=SecretStr(""),
            timeout_seconds=15.0,
            retry_attempts=3,
            retry_backoff_seconds=1.0,
        )

    async def _get_client(self, timeout: float) -> httpx.AsyncClient:
        """Get or create HTTP client with timeout."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=timeout)
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def _build_slack_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Build Slack message payload from finding data."""
        finding = payload.get("finding", {})
        job = payload.get("job", {})
        target = payload.get("target", "")
        timestamp = payload.get("timestamp", 0)

        severity = finding.get("severity", "unknown").upper()
        category = finding.get("category", "unknown")
        title = finding.get("title", "Security Finding")
        location = finding.get("location", "")
        cwe = finding.get("cwe", "")
        evidence = finding.get("evidence", "")
        fingerprint = finding.get("fingerprint", "")
        remediation = finding.get("remediation", "")
        confidence = finding.get("confidence", "")
        verification = finding.get("verification", "")

        job_id = job.get("id", "unknown")
        profile = job.get("profile", "unknown")
        actor = job.get("actor", "ishastra")

        color_map = {
            "CRITICAL": "#FF0000",
            "HIGH": "#FF4500",
            "MEDIUM": "#FFA500",
            "LOW": "#FFFF00",
            "INFO": "#00FFFF",
        }
        color = color_map.get(severity, "#808080")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔍 {title}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                    {"type": "mrkdwn", "text": f"*Category:*\n{category}"},
                    {"type": "mrkdwn", "text": f"*Confidence:*\n{confidence}"},
                    {"type": "mrkdwn", "text": f"*Verification:*\n{verification}"},
                ],
            },
        ]

        if location:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Location:*\n{location}"},
                }
            )

        if cwe:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*CWE:*\n{cwe}"},
                }
            )

        if fingerprint:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Fingerprint:*\n`{fingerprint}`"},
                }
            )

        if evidence:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Evidence:*\n```{evidence[:3000]}```"},
                }
            )

        if remediation:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Remediation:*\n{remediation}"},
                }
            )

        blocks.extend(
            [
                {"type": "divider"},
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"*Job:* {job_id} | *Profile:* {profile} | *Actor:* {actor}"},
                        {"type": "mrkdwn", "text": f"*Target:* {target} | *Timestamp:* {timestamp}"},
                    ],
                },
            ]
        )

        slack_payload: dict[str, Any] = {
            "username": self.config.username,
            "blocks": blocks,
            "attachments": [
                {
                    "color": color,
                    "blocks": blocks,
                }
            ],
        }

        if self.config.icon_emoji:
            slack_payload["icon_emoji"] = self.config.icon_emoji
        if self.config.icon_url:
            slack_payload["icon_url"] = self.config.icon_url
        if self.config.default_channel:
            slack_payload["channel"] = self.config.default_channel

        return slack_payload

    async def send(
        self,
        payload: dict[str, Any],
        timeout: Optional[float] = None,
        cancel: Optional[threading.Event] = None,
    ) -> ConnectorResult:
        """Send finding to Slack via webhook.

        Args:
            payload: Finding payload (single or batch)
            timeout: Request timeout override
            cancel: Cancellation event

        Returns:
            ConnectorResult with success status and details
        """
        if not self.config.enabled:
            return ConnectorResult(
                success=False,
                message="Slack connector is disabled",
            )

        if not self.config.webhook_url or not self.config.webhook_url.get_secret_value():
            return ConnectorResult(
                success=False,
                message="Slack webhook URL not configured",
            )

        effective_timeout = timeout or self.config.timeout_seconds
        webhook_url = self.config.webhook_url.get_secret_value()

        slack_payload = self._build_slack_payload(payload)

        log_payload = self._redact_secrets(slack_payload)
        logger.debug("Sending to Slack: %s", log_payload)

        last_exception: Optional[Exception] = None

        for attempt in range(self.config.retry_attempts + 1):
            if cancel and cancel.is_set():
                return ConnectorResult(
                    success=False,
                    message="Operation cancelled",
                )

            try:
                client = await self._get_client(effective_timeout)

                response = await client.post(
                    webhook_url,
                    json=slack_payload,
                    headers={"Content-Type": "application/json"},
                )

                response.raise_for_status()

                return ConnectorResult(
                    success=True,
                    message="Successfully sent to Slack",
                    external_id=response.headers.get("X-Slack-Request-Id"),
                    details={"status_code": response.status_code},
                )

            except httpx.TimeoutException as e:
                last_exception = e
                logger.warning(
                    "Slack request timeout (attempt %d/%d): %s",
                    attempt + 1,
                    self.config.retry_attempts + 1,
                    e,
                )
            except httpx.HTTPStatusError as e:
                last_exception = e
                if e.response.status_code >= 500:
                    logger.warning(
                        "Slack server error (attempt %d/%d): %s",
                        attempt + 1,
                        self.config.retry_attempts + 1,
                        e,
                    )
                else:
                    logger.error("Slack client error: %s", e)
                    return ConnectorResult(
                        success=False,
                        message=f"Slack API error: {e.response.status_code} - {e.response.text}",
                        details={"status_code": e.response.status_code, "response": e.response.text},
                    )
            except httpx.RequestError as e:
                last_exception = e
                logger.warning(
                    "Slack request error (attempt %d/%d): %s",
                    attempt + 1,
                    self.config.retry_attempts + 1,
                    e,
                )

            if attempt < self.config.retry_attempts:
                backoff = self.config.retry_backoff_seconds * (2**attempt)
                logger.debug("Retrying in %.1f seconds...", backoff)
                await asyncio.sleep(backoff)

        return ConnectorResult(
            success=False,
            message=f"Failed after {self.config.retry_attempts + 1} attempts: {last_exception}",
            details={"error": str(last_exception) if last_exception else "Unknown error"},
        )


register_connector("slack", SlackConnector, SlackConfig)