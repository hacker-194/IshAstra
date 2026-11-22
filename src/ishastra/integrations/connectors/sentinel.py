"""Azure Sentinel (Log Analytics) connector for Ishastra."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from ishastra.integrations.connectors.base import BaseConnector, BaseConnectorConfig, ConnectorResult

logger = logging.getLogger(__name__)


class SentinelConfig(BaseConnectorConfig):
    """Configuration for Azure Sentinel connector.

    Args:
        enabled: Whether the connector is enabled.
        workspace_id: Azure Log Analytics workspace ID.
        shared_key: Base64-encoded shared key for authentication.
        log_type: Custom log type name (alphanumeric only).
        timeout_seconds: Request timeout in seconds.
        retry_attempts: Number of retry attempts.
        retry_backoff_seconds: Base backoff between retries.
    """

    workspace_id: str
    shared_key: str
    log_type: str = "IshastraFindings"

    def __post_init__(self):
        if not self.workspace_id:
            raise ValueError("workspace_id is required")
        if not self.shared_key:
            raise ValueError("shared_key is required")
        if not self.log_type.replace("_", "").isalnum():
            raise ValueError("log_type must be alphanumeric (underscores allowed)")


class SentinelConnector(BaseConnector):
    """Connector for sending findings to Azure Sentinel via Log Analytics Data Collector API."""

    def __init__(self, config: SentinelConfig | None = None):
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None

    @property
    def config(self) -> SentinelConfig:
        return super().config  # type: ignore[return-value]

    @config.setter
    def config(self, value: SentinelConfig):
        self._config = value

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.timeout_seconds),
                limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
            )
        return self._client

    async def close(self):
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def _build_signature(
        self,
        date: str,
        content_length: int,
        method: str,
        content_type: str,
        resource: str,
    ) -> str:
        """Build the SharedKey authorization signature."""
        string_to_hash = f"{method}\n{content_length}\n{content_type}\nx-ms-date:{date}\n{resource}"
        bytes_to_hash = string_to_hash.encode("utf-8")
        decoded_key = base64.b64decode(self.config.shared_key)
        encoded_hash = base64.b64encode(
            hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
        ).decode()
        return f"SharedKey {self.config.workspace_id}:{encoded_hash}"

    def _prepare_log_entries(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Convert payload to Sentinel log entries."""
        entries = []

        # Handle both single finding and batch payloads
        findings = payload.get("findings")
        if findings is None:
            # Single finding wrapped in finding key
            finding = payload.get("finding")
            if finding:
                findings = [finding]
            else:
                findings = []

        job = payload.get("job", {})
        target = payload.get("target", "")
        timestamp = payload.get("timestamp", time.time())

        for finding in findings:
            entry = {
                "TimeGenerated": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
                "FindingCategory": finding.get("category", ""),
                "FindingSeverity": finding.get("severity", ""),
                "FindingTitle": finding.get("title", ""),
                "FindingLocation": finding.get("location", ""),
                "FindingCWE": finding.get("cwe", ""),
                "FindingConfidence": finding.get("confidence", ""),
                "FindingVerification": finding.get("verification", ""),
                "FindingEvidence": finding.get("evidence", ""),
                "FindingFingerprint": finding.get("fingerprint", ""),
                "FindingRemediation": finding.get("remediation", ""),
                "JobId": job.get("id", ""),
                "JobProfile": job.get("profile", ""),
                "JobActor": job.get("actor", ""),
                "JobPolicyId": job.get("policy", {}).get("policy_id", ""),
                "JobTenantId": job.get("policy", {}).get("tenant_id", ""),
                "Target": target,
                "SourceSystem": "Ishastra",
            }
            entries.append(entry)

        return entries

    async def send(
        self,
        payload: dict[str, Any],
        timeout: float | None = None,
        cancel: threading.Event | None = None,
    ) -> ConnectorResult:
        """Send findings to Azure Sentinel.

        Args:
            payload: Finding payload (single or batch).
            timeout: Override timeout in seconds.
            cancel: Cancellation event.

        Returns:
            ConnectorResult with success status and details.
        """
        if not self.config.enabled:
            return ConnectorResult(
                success=False,
                message="Sentinel connector is disabled",
            )

        if self._is_cancelled(cancel):
            return ConnectorResult(
                success=False,
                message="Operation cancelled",
            )

        entries = self._prepare_log_entries(payload)
        if not entries:
            return ConnectorResult(
                success=False,
                message="No findings to send",
            )

        body = json.dumps(entries)
        content_length = len(body.encode("utf-8"))
        method = "POST"
        content_type = "application/json"
        resource = "/api/logs"
        date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

        signature = self._build_signature(
            date=date,
            content_length=content_length,
            method=method,
            content_type=content_type,
            resource=resource,
        )

        url = f"https://{self.config.workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        headers = {
            "Authorization": signature,
            "Log-Type": self.config.log_type,
            "x-ms-date": date,
            "time-generated-field": "TimeGenerated",
            "Content-Type": content_type,
        }

        last_error: Exception | None = None
        timeout_val = timeout or self.config.timeout_seconds

        for attempt in range(self.config.retry_attempts + 1):
            if self._is_cancelled(cancel):
                return ConnectorResult(
                    success=False,
                    message="Operation cancelled during retry",
                )

            try:
                client = await self._get_client()
                response = await client.post(
                    url,
                    content=body,
                    headers=headers,
                    timeout=httpx.Timeout(timeout_val),
                )

                if response.status_code == 200:
                    return ConnectorResult(
                        success=True,
                        message=f"Successfully sent {len(entries)} log entries to Sentinel",
                        external_id=f"sentinel-{int(time.time())}",
                        details={"entries_sent": len(entries), "status_code": response.status_code},
                    )

                if response.status_code == 401:
                    return ConnectorResult(
                        success=False,
                        message="Authentication failed - check workspace_id and shared_key",
                        details={"status_code": response.status_code, "response": response.text[:500]},
                    )

                if response.status_code == 400:
                    return ConnectorResult(
                        success=False,
                        message="Bad request - check log_type and payload format",
                        details={"status_code": response.status_code, "response": response.text[:500]},
                    )

                # Retry on server errors
                if response.status_code >= 500:
                    last_error = httpx.HTTPStatusError(
                        f"Server error: {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                    logger.warning(
                        "Sentinel request failed (attempt %d/%d): %s",
                        attempt + 1,
                        self.config.retry_attempts + 1,
                        response.status_code,
                    )
                else:
                    return ConnectorResult(
                        success=False,
                        message=f"Unexpected status code: {response.status_code}",
                        details={"status_code": response.status_code, "response": response.text[:500]},
                    )

            except httpx.TimeoutException as e:
                last_error = e
                logger.warning("Sentinel request timeout (attempt %d/%d)", attempt + 1, self.config.retry_attempts + 1)
            except httpx.RequestError as e:
                last_error = e
                logger.warning("Sentinel request error (attempt %d/%d): %s", attempt + 1, self.config.retry_attempts + 1, e)

            if attempt < self.config.retry_attempts:
                backoff = self._calculate_backoff(attempt)
                if cancel:
                    cancel.wait(timeout=backoff)
                else:
                    time.sleep(backoff)

        return ConnectorResult(
            success=False,
            message=f"Failed after {self.config.retry_attempts + 1} attempts: {last_error}",
            details={"error": str(last_error) if last_error else "Unknown error"},
        )