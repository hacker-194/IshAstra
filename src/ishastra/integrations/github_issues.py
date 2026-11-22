"""GitHub Issues connector for creating issues from findings."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any

import httpx
from pydantic import BaseModel, Field

from ishastra.core.redaction import redact
from ishastra.integrations.base import BaseConnector, BaseConnectorConfig, ConnectorResult

log = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"
DEFAULT_TIMEOUT = 30.0


class GithubIssuesConfig(BaseConnectorConfig):
    """Configuration for GitHub Issues connector."""

    token: str = Field(..., description="GitHub personal access token or GitHub App token")
    owner: str = Field(..., description="Repository owner (user or organization)")
    repo: str = Field(..., description="Repository name")
    labels: list[str] = Field(default_factory=list, description="Labels to apply to created issues")
    assignees: list[str] = Field(default_factory=list, description="Usernames to assign to created issues")
    projects: list[int] = Field(default_factory=list, description="Project IDs to add issues to")

    model_config = {"extra": "allow"}


class GithubIssuesConnector(BaseConnector):
    """Connector for creating GitHub Issues from security findings."""

    def __init__(self, config: GithubIssuesConfig | None = None) -> None:
        super().__init__(config)
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self, timeout: float) -> httpx.AsyncClient:
        """Get or create HTTP client with timeout."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=GITHUB_API_BASE,
                timeout=httpx.Timeout(timeout),
                headers={
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    def _build_issue_body(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Build the GitHub issue payload from finding data."""
        finding = payload.get("finding", payload)
        job = payload.get("job", {})
        target = payload.get("target", "")
        timestamp = payload.get("timestamp", "")

        # Build issue title
        title = finding.get("title", "Security Finding")
        category = finding.get("category", "unknown")
        severity = finding.get("severity", "info").upper()
        title_prefix = f"[{severity}] [{category.upper()}]"
        if not title.startswith("["):
            title = f"{title_prefix} {title}"

        # Build issue body with markdown
        body_parts = [
            f"## Security Finding: {finding.get('title', 'Unknown')}",
            "",
            f"**Category:** {finding.get('category', 'unknown')}",
            f"**Severity:** {finding.get('severity', 'info')}",
            f"**Confidence:** {finding.get('confidence', 'unknown')}",
            f"**Verification:** {finding.get('verification', 'unverified')}",
            f"**CWE:** {finding.get('cwe', 'N/A')}",
            f"**Target:** {target}",
            f"**Location:** {finding.get('location', 'N/A')}",
            f"**Fingerprint:** `{finding.get('fingerprint', 'N/A')}`",
            f"**Timestamp:** {timestamp}",
            "",
            "### Evidence",
            finding.get("evidence", "No evidence provided"),
            "",
        ]

        if finding.get("remediation"):
            body_parts.extend([
                "### Remediation",
                finding["remediation"],
                "",
            ])

        if job:
            body_parts.extend([
                "### Job Context",
                f"- **Job ID:** {job.get('id', 'N/A')}",
                f"- **Profile:** {job.get('profile', 'N/A')}",
                f"- **Actor:** {job.get('actor', 'N/A')}",
                f"- **Policy:** {job.get('policy', {}).get('policy_id', 'N/A')}",
                f"- **Tenant:** {job.get('policy', {}).get('tenant_id', 'N/A')}",
                "",
            ])

        body_parts.append("---")
        body_parts.append("*Created automatically by Ishastra Security Assessment Platform*")

        issue_data: dict[str, Any] = {
            "title": title,
            "body": "\n".join(body_parts),
        }

        if self.config and self.config.labels:
            issue_data["labels"] = self.config.labels
        if self.config and self.config.assignees:
            issue_data["assignees"] = self.config.assignees

        return issue_data

    async def _create_issue(
        self,
        client: httpx.AsyncClient,
        issue_data: dict[str, Any],
    ) -> httpx.Response:
        """Create a GitHub issue via the API."""
        if not self.config:
            raise ValueError("Configuration not set")

        headers = {
            "Authorization": f"Bearer {self.config.token}",
        }

        response = await client.post(
            f"/repos/{self.config.owner}/{self.config.repo}/issues",
            json=issue_data,
            headers=headers,
        )
        return response

    async def _add_to_projects(self, client: httpx.AsyncClient, issue_number: int) -> list[dict[str, Any]]:
        """Add issue to configured projects (requires GraphQL)."""
        if not self.config or not self.config.projects:
            return []

        # Note: Adding to projects requires GraphQL API
        # This is a placeholder for future implementation
        log.debug("Project linking not yet implemented for projects: %s", self.config.projects)
        return []

    async def send(
        self,
        payload: dict[str, Any],
        timeout: float | None = None,
        cancel: Any | None = None,
    ) -> ConnectorResult:
        """Send finding to GitHub Issues.

        Args:
            payload: Finding payload (single finding or batch)
            timeout: Override default timeout in seconds
            cancel: Optional cancellation token (threading.Event or asyncio.Event)

        Returns:
            ConnectorResult with success status and issue details
        """
        if not self.config:
            return ConnectorResult(
                success=False,
                message="GitHub Issues connector not configured",
            )

        if not self.config.enabled:
            return ConnectorResult(
                success=False,
                message="GitHub Issues connector is disabled",
            )

        effective_timeout = self._get_timeout(timeout)
        retry_attempts, retry_backoff = self._get_retry_config()

        # Build issue data
        issue_data = self._build_issue_body(payload)

        # Handle cancellation
        cancel_event: asyncio.Event | None = None
        if cancel is not None:
            if isinstance(cancel, threading.Event):
                cancel_event = asyncio.Event()

                def check_cancel() -> None:
                    while not cancel.is_set():
                        asyncio.get_event_loop().call_later(0.1, check_cancel)
                        return
                    cancel_event.set()

                asyncio.get_event_loop().call_soon(check_cancel)
            elif isinstance(cancel, asyncio.Event):
                cancel_event = cancel

        last_error: Exception | None = None

        for attempt in range(1, retry_attempts + 1):
            if cancel_event and cancel_event.is_set():
                return ConnectorResult(
                    success=False,
                    message="Operation cancelled",
                )

            try:
                client = await self._get_client(effective_timeout)

                self._log_attempt(attempt, retry_attempts)

                response = await self._create_issue(client, issue_data)

                if response.status_code == 201:
                    issue = response.json()
                    issue_number = issue.get("number")
                    issue_url = issue.get("html_url")

                    # Try to add to projects
                    await self._add_to_projects(client, issue_number)

                    log.info(
                        "Created GitHub issue #%d in %s/%s (config: %s)",
                        issue_number,
                        self.config.owner,
                        self.config.repo,
                        self.config.redact(),
                    )

                    return ConnectorResult(
                        success=True,
                        message=f"Created issue #{issue_number}",
                        external_id=str(issue_number),
                        details={
                            "issue_number": issue_number,
                            "issue_url": issue_url,
                            "title": issue.get("title"),
                            "state": issue.get("state"),
                        },
                    )

                # Handle rate limiting
                if response.status_code == 403:
                    reset_header = response.headers.get("X-RateLimit-Reset")
                    if reset_header:
                        reset_time = int(reset_header)
                        import time
                        wait_time = max(reset_time - int(time.time()), 0) + 1
                        log.warning(
                            "GitHub rate limit exceeded, waiting %ds (attempt %d/%d)",
                            wait_time,
                            attempt,
                            retry_attempts,
                        )
                        if attempt < retry_attempts:
                            await asyncio.sleep(wait_time)
                            continue

                # Handle other errors
                error_body = response.text
                try:
                    error_json = response.json()
                    error_message = error_json.get("message", error_body)
                except json.JSONDecodeError:
                    error_message = error_body

                last_error = httpx.HTTPStatusError(
                    f"GitHub API error: {response.status_code} - {error_message}",
                    request=response.request,
                    response=response,
                )

                # Don't retry on client errors (4xx except 429)
                if 400 <= response.status_code < 500 and response.status_code != 429:
                    log.error(
                        "GitHub API client error (no retry): %s (config: %s)",
                        last_error,
                        self.config.redact(),
                    )
                    return ConnectorResult(
                        success=False,
                        message=f"GitHub API error: {error_message}",
                        details={"status_code": response.status_code, "response": error_body},
                    )

            except httpx.TimeoutException as exc:
                last_error = exc
                self._log_attempt(attempt, retry_attempts, exc)

            except httpx.HTTPError as exc:
                last_error = exc
                self._log_attempt(attempt, retry_attempts, exc)

            except Exception as exc:
                last_error = exc
                log.exception(
                    "Unexpected error in GitHub Issues connector (attempt %d/%d): %s",
                    attempt,
                    retry_attempts,
                    exc,
                )

            # Wait before retry with exponential backoff
            if attempt < retry_attempts:
                wait_time = retry_backoff * (2 ** (attempt - 1))
                log.debug("Waiting %.2fs before retry %d/%d", wait_time, attempt + 1, retry_attempts)
                await asyncio.sleep(wait_time)

        # All retries exhausted
        error_msg = str(last_error) if last_error else "Unknown error"
        log.error(
            "GitHub Issues connector failed after %d attempts: %s (config: %s)",
            retry_attempts,
            error_msg,
            self.config.redact(),
        )

        return ConnectorResult(
            success=False,
            message=f"Failed after {retry_attempts} attempts: {error_msg}",
            details={"error": error_msg, "attempts": retry_attempts},
        )