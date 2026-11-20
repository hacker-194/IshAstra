"""Continuous monitoring: re-assess registered targets and alert on change.

Each cycle runs the same authorized assessment pipeline as an on-demand job
(scope gate, adapters, persisted results), then alerts on findings that were
not present in that target's previous cycle. The first cycle only establishes a
baseline, so enabling monitoring never alerts on pre-existing issues.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import ipaddress
import json
import logging
import threading
import time
from typing import Any

import httpx

from ishastra.audit import AuditChain
from ishastra.core import jobs, policies, scope, store
from ishastra.core.locks import _ReentrantAsyncLock, async_locked
from ishastra.core.redaction import (
    has_sensitive_query_params,
    redact,
    redact_text,
    sanitize_target,
)
from ishastra.core.urls import parse_url
from ishastra.crypto import EncryptionError, decrypt, encrypt

log = logging.getLogger(__name__)

ALERT_SEVERITIES = frozenset({"critical", "high"})
MONITOR_TENANT = "system"
WEBHOOK_TIMEOUT = 5.0


DELIVERY_ATTEMPTS = 3
DELIVERY_BACKOFF_SECONDS = 0.25


class AlertSink:
    def __init__(self, name: str) -> None:
        self.name = name

    async def send(self, alert: dict[str, Any]) -> None:
        raise NotImplementedError


class LogAlertSink(AlertSink):
    async def send(self, alert: dict[str, Any]) -> None:
        log.warning(
            "ALERT [%s] %s: %s",
            alert["severity"].upper(),
            alert["rule_name"],
            alert["message"],
        )


def _pin_webhook(url: str) -> tuple[Any, str] | str:
    """Validate ``url`` and pick the address to connect to.

    Returns ``(parsed_url, ip)`` or a refusal reason. Every address the name
    resolves to must be public; the caller then connects to ``ip`` itself, so a
    DNS answer that changes after this check cannot redirect the request.
    """
    parsed = parse_url(url)
    if parsed is None or parsed.scheme != "https" or not parsed.hostname:
        return "webhook URL must be an https URL"
    if parsed.username or parsed.password:
        return "webhook URL must not embed credentials"
    if has_sensitive_query_params(url):
        return "webhook URL must not contain credentials in query parameters"
    addresses = scope.resolve_sync(parsed.hostname, parsed.port)
    if not addresses:
        return "webhook host did not resolve"
    if any(scope.is_special_use(ipaddress.ip_address(a.split("%")[0])) for a in addresses):
        return "webhook host resolves to a non-public address"
    return parsed, addresses[0]


async def _pin_webhook_async(url: str) -> tuple[Any, str] | str:
    """Async version of _pin_webhook for use in async contexts."""
    parsed = parse_url(url)
    if parsed is None or parsed.scheme != "https" or not parsed.hostname:
        return "webhook URL must be an https URL"
    if parsed.username or parsed.password:
        return "webhook URL must not embed credentials"
    if has_sensitive_query_params(url):
        return "webhook URL must not contain credentials in query parameters"
    addresses = await scope.resolve(parsed.hostname, parsed.port)
    if not addresses:
        return "webhook host did not resolve"
    if any(scope.is_special_use(ipaddress.ip_address(a.split("%")[0])) for a in addresses):
        return "webhook host resolves to a non-public address"
    return parsed, addresses[0]


def validate_webhook_url(url: str) -> str | None:
    """Refusal reason, or None when ``url`` is a safe webhook destination."""
    result = _pin_webhook(url)
    return result if isinstance(result, str) else None


async def validate_webhook_url_async(url: str) -> str | None:
    """Async version of validate_webhook_url for use in async contexts."""
    result = await _pin_webhook_async(url)
    return result if isinstance(result, str) else None


class WebhookAlertSink(AlertSink):
    def __init__(self, name: str, url: str, secret: str = "") -> None:
        super().__init__(name)
        self.url = url

        self.secret = secret

        self._pinned_ip: str | None = None
        self._pinned_parsed = None

    def _headers(self, body: bytes) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "User-Agent": "ishastra-alerts/1"}
        if self.secret:
            digest = hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-Strix-Signature"] = f"sha256={digest}"
            headers["X-Strix-Signature-Alg"] = "HMAC-SHA256"
        return headers

    async def _ensure_pinned(self) -> tuple[Any, str]:
        """Get or create pinned (parsed_url, ip). Raises ValueError if invalid."""
        if self._pinned_ip is not None and self._pinned_parsed is not None:
            return self._pinned_parsed, self._pinned_ip
        pinned = await _pin_webhook_async(self.url)
        if isinstance(pinned, str):
            raise ValueError(pinned)
        self._pinned_parsed, self._pinned_ip = pinned
        return pinned

    async def _post_async(self, client: httpx.AsyncClient, body: bytes) -> None:
        """Post alert using shared async HTTP client."""
        parsed, ip = await self._ensure_pinned()
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        url = f"https://{ip}{path}"
        headers = self._headers(body)
        headers["Host"] = parsed.hostname

        response = await client.post(url, content=body, headers=headers, timeout=WEBHOOK_TIMEOUT)
        response.read()
        if response.status_code >= 400:
            raise OSError(f"HTTP {response.status_code}")

    async def send(self, alert: dict[str, Any]) -> None:
        from ishastra import metrics

        body = json.dumps(redact(alert)).encode()
        last: Exception | None = None
        for attempt in range(1, DELIVERY_ATTEMPTS + 1):
            try:
                from ishastra.api.deps import get_http_client

                client = await get_http_client()
                await self._post_async(client, body)
                metrics.record_webhook_delivery("delivered", None)
                return
            except ValueError as exc:
                log.warning("webhook %s refused: %s", self.name, exc)
                metrics.record_webhook_delivery("refused", None)
                metrics.record_webhook_failure("refused", None)
                return
            except (OSError, httpx.HTTPError) as exc:
                last = exc
                if attempt < DELIVERY_ATTEMPTS:
                    await asyncio.sleep(DELIVERY_BACKOFF_SECONDS * attempt)
        log.warning(
            "webhook %s delivery failed after %d attempt(s): %s",
            self.name,
            DELIVERY_ATTEMPTS,
            last,
        )
        error_type = "timeout" if isinstance(last, httpx.TimeoutException) else "network"
        metrics.record_webhook_delivery("failed", None)
        metrics.record_webhook_failure(error_type, None)


async def notify_job_finished(job: Any, settings: Any = None) -> bool:
    """POST a finished-job summary to ``ISHASTRA_NOTIFY_WEBHOOK_URL``.

    Reuses :class:`WebhookAlertSink`, so the destination is https-only,
    DNS-pinned, HMAC-signed when ``ISHASTRA_WEBHOOK_SECRET`` is set, and a
    delivery failure is logged and counted instead of breaking the job record.
    Returns False when no destination is configured.
    """
    if settings is None:
        from ishastra.config import get_settings

        settings = get_settings()
    url = getattr(settings, "notify_webhook_url", "")
    if not url:
        return False

    findings = list(getattr(job, "findings", []))
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity = str(getattr(finding, "severity", "info"))
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    state = getattr(job.state, "value", str(job.state))
    target = sanitize_target(job.target)
    severities = ", ".join(f"{name}: {count}" for name, count in sorted(severity_counts.items()))
    if not severities:
        severities = "none"

    payload = {
        "event": "assessment_job",
        "job": job.id,
        "target": target,
        "state": state,
        "verdict": job.verdict,
        "findings": len(findings),
        "severity_counts": severity_counts,
        # Slack incoming webhooks render ``blocks`` (and fall back to ``text``);
        # other receivers read the structured fields above and ignore these.
        "text": f"[{state}] {target} — {job.verdict or 'no verdict'} ({len(findings)} finding(s))",
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": f"Assessment {state}"}},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Target*\n{target}"},
                    {"type": "mrkdwn", "text": f"*Job*\n{job.id}"},
                    {"type": "mrkdwn", "text": f"*Verdict*\n{job.verdict or '—'}"},
                    {"type": "mrkdwn", "text": f"*Findings*\n{len(findings)} ({severities})"},
                ],
            },
        ],
    }
    sink = WebhookAlertSink("job-events", url, getattr(settings, "webhook_secret", ""))
    await sink.send(payload)
    return True


class Monitor:
    MAX_BASELINE_TARGETS = 10000

    def __init__(
        self,
        *,
        audit_chain: AuditChain,
        interval_seconds: int = 300,
        profile: str = "web",
        job_timeout: float = 120.0,
        scope_mode: str = "auto",
        webhook_secret: str,
        encryption_key: str = "",
    ) -> None:
        self.audit_chain = audit_chain
        self.scope_mode = scope_mode
        self.webhook_secret = webhook_secret
        self.encryption_key = encryption_key
        self._config_lock = threading.RLock()
        self._async_lock: _ReentrantAsyncLock | None = None
        self.interval = interval_seconds
        self.profile = profile
        self.job_timeout = job_timeout
        self.targets: list[str] = []
        self.alert_sinks: list[AlertSink] = [LogAlertSink("log")]
        self._baseline: dict[str, set[str]] = {}
        self._baseline_order: list[str] = []
        self._running = False
        self._task: asyncio.Task[None] | None = None

    def _get_async_lock(self) -> _ReentrantAsyncLock:
        """Get or create the async lock in the current event loop."""

        if self._async_lock is not None:
            return self._async_lock

        with self._config_lock:
            if self._async_lock is None:
                self._async_lock = _ReentrantAsyncLock()
            return self._async_lock

    def load(self) -> None:
        """Restore targets, interval and alert sinks saved by a previous run (sync)."""
        targets, interval = asyncio.run(store.load_monitor_config())
        unsafe_targets = [target for target in targets if has_sensitive_query_params(target)]
        self.targets = [target for target in targets if not has_sensitive_query_params(target)]
        if interval:
            self.interval = interval
        if unsafe_targets:
            log.warning(
                "discarded %d legacy monitor target(s) with credential query parameters",
                len(unsafe_targets),
            )
            asyncio.run(store.save_monitor_config(self.targets, self.interval))

        self._baseline = asyncio.run(store.load_monitor_baseline())

        self._baseline_order = list(self._baseline.keys())
        existing = {getattr(sink, "name", "") for sink in self.alert_sinks}
        for row in asyncio.run(store.load_webhook_sinks()):
            if not self.encryption_key:
                raise RuntimeError("ISHASTRA_ENCRYPTION_KEY is required to load persisted webhook sinks")
            stored_url = row["url"]
            migrated = False
            try:
                url = decrypt(stored_url, self.encryption_key)
            except EncryptionError:
                url = stored_url
                migrated = True
                if parse_url(url) is None:
                    log.warning("failed to decrypt persisted webhook sink %s, skipping", row["name"])
                    continue
            parsed = parse_url(url) if url else None
            if parsed is None or parsed.username or parsed.password or has_sensitive_query_params(url):
                log.warning("discarding unsafe persisted webhook sink %s", row["name"])
                asyncio.run(store.delete_webhook_sink(row["name"]))
                continue
            if migrated:
                try:
                    encrypted_url = encrypt(url, self.encryption_key)
                    asyncio.run(store.save_webhook_sink(row["name"], encrypted_url))
                except EncryptionError:
                    log.exception("failed to encrypt legacy webhook sink %s", row["name"])
                    raise
            if row["name"] in existing:
                continue
            self.alert_sinks.append(WebhookAlertSink(name=row["name"], url=url, secret=self.webhook_secret))
            existing.add(row["name"])

    @async_locked
    async def load_async(self) -> None:
        """Async version of load (for async callers)."""
        targets, interval = await store.load_monitor_config()
        unsafe_targets = [target for target in targets if has_sensitive_query_params(target)]
        self.targets = [target for target in targets if not has_sensitive_query_params(target)]
        if interval:
            self.interval = interval
        if unsafe_targets:
            log.warning(
                "discarded %d legacy monitor target(s) with credential query parameters",
                len(unsafe_targets),
            )
            await store.save_monitor_config(self.targets, self.interval)
        self._baseline = await store.load_monitor_baseline()

        self._baseline_order = list(self._baseline.keys())
        existing = {getattr(sink, "name", "") for sink in self.alert_sinks}
        for row in await store.load_webhook_sinks():
            if not self.encryption_key:
                raise RuntimeError("ISHASTRA_ENCRYPTION_KEY is required to load persisted webhook sinks")
            stored_url = row["url"]
            migrated = False
            try:
                url = decrypt(stored_url, self.encryption_key)
            except EncryptionError:
                url = stored_url
                migrated = True
                if parse_url(url) is None:
                    log.warning("failed to decrypt persisted webhook sink %s, skipping", row["name"])
                    continue
            parsed = parse_url(url) if url else None
            if parsed is None or parsed.username or parsed.password or has_sensitive_query_params(url):
                log.warning("discarding unsafe persisted webhook sink %s", row["name"])
                await store.delete_webhook_sink(row["name"])
                continue
            if migrated:
                try:
                    encrypted_url = encrypt(url, self.encryption_key)
                    await store.save_webhook_sink(row["name"], encrypted_url)
                except EncryptionError:
                    log.exception("failed to encrypt legacy webhook sink %s", row["name"])
                    raise
            if row["name"] in existing:
                continue
            self.alert_sinks.append(WebhookAlertSink(name=row["name"], url=url, secret=self.webhook_secret))
            existing.add(row["name"])

    def save(self) -> None:
        asyncio.run(store.save_monitor_config(self.targets, self.interval))

    @async_locked
    async def save_async(self) -> None:
        await store.save_monitor_config(self.targets, self.interval)

    def add_sink(self, sink: AlertSink) -> None:
        """Persist a unique sink before making it visible to the event loop (sync)."""
        with self._config_lock:
            if any(existing.name == sink.name for existing in self.alert_sinks):
                raise ValueError(f"alert sink {sink.name!r} already exists")
            if isinstance(sink, WebhookAlertSink):
                if not self.encryption_key:
                    raise RuntimeError("ISHASTRA_ENCRYPTION_KEY is required to persist webhook sinks")

                asyncio.run(sink._ensure_pinned())

                encrypted_url = encrypt(sink.url, self.encryption_key)
                asyncio.run(store.save_webhook_sink(sink.name, encrypted_url))
            self.alert_sinks.append(sink)

    @async_locked
    async def add_sink_async(self, sink: AlertSink) -> None:
        """Async version of add_sink (for async callers)."""
        with self._config_lock:
            if any(existing.name == sink.name for existing in self.alert_sinks):
                raise ValueError(f"alert sink {sink.name!r} already exists")
            if isinstance(sink, WebhookAlertSink):
                if not self.encryption_key:
                    raise RuntimeError("ISHASTRA_ENCRYPTION_KEY is required to persist webhook sinks")

                await sink._ensure_pinned()
                encrypted_url = encrypt(sink.url, self.encryption_key)
                await store.save_webhook_sink(sink.name, encrypted_url)
            self.alert_sinks.append(sink)

    def set_targets(self, targets: list[str]) -> None:
        """Monitor exactly ``targets``; forget baselines of any that were removed (sync)."""
        if any(has_sensitive_query_params(target) for target in targets):
            raise ValueError("monitored targets cannot contain credential-bearing query parameters")
        with self._config_lock:
            self.targets = list(dict.fromkeys(targets))
            kept = {sanitize_target(target) for target in self.targets}
            for dropped in set(self._baseline) - kept:
                del self._baseline[dropped]
                self._baseline_order = [k for k in self._baseline_order if k != dropped]
                asyncio.run(store.delete_monitor_baseline(dropped))

            self._baseline_order = [k for k in self._baseline_order if k in kept]

    @async_locked
    async def set_targets_async(self, targets: list[str]) -> None:
        """Async version of set_targets (for async callers)."""
        if any(has_sensitive_query_params(target) for target in targets):
            raise ValueError("monitored targets cannot contain credential-bearing query parameters")
        with self._config_lock:
            self.targets = list(dict.fromkeys(targets))
            kept = {sanitize_target(target) for target in self.targets}
            for dropped in set(self._baseline) - kept:
                del self._baseline[dropped]
                self._baseline_order = [k for k in self._baseline_order if k != dropped]
                await store.delete_monitor_baseline(dropped)

            self._baseline_order = [k for k in self._baseline_order if k in kept]

    def add_target(self, target: str) -> None:
        if has_sensitive_query_params(target):
            raise ValueError("monitored targets cannot contain credential-bearing query parameters")
        with self._config_lock:
            if target not in self.targets:
                self.targets.append(target)

    async def _assess(self, target: str) -> jobs.Job:

        snapshot: scope.Scope | None = None
        mode = self.scope_mode
        managed = mode == "managed" or (mode == "auto" and bool(await policies.registry.list_async()))
        if mode not in {"auto", "global", "managed"}:
            managed = True
        if managed:
            snapshot, reason = await policies.tenant_scope_snapshot_async(MONITOR_TENANT)
            if snapshot is None:
                job = jobs.Job(target=target, profile=self.profile, actor=MONITOR_TENANT, policy={})
                job.state = jobs.JobState.FAILED
                job.error = f"out_of_scope: {reason}"
                job.finished_at = time.time()
                await store.save_job(job, tenant=MONITOR_TENANT)
                return job
        job = jobs.run_assessment(
            target,
            profile=self.profile,
            actor=MONITOR_TENANT,
            timeout=self.job_timeout,
            scope_snapshot=snapshot,
        )
        await store.save_job(job, tenant=MONITOR_TENANT)
        return job

    async def _emit(self, alert: dict[str, Any]) -> None:

        alert = redact(
            {
                "target": sanitize_target(str(alert.get("target", ""))),
                **{k: v for k, v in alert.items() if k != "target"},
            }
        )
        await self.audit_chain.append_async({"type": "alert", **alert})
        for sink in self.alert_sinks:
            with contextlib.suppress(Exception):
                await sink.send(alert)

    async def run_cycle(self) -> None:
        for target in list(self.targets):
            try:
                job = await self._assess(target)
            except Exception as exc:
                log.warning(
                    "monitor assessment crashed for %s: %s",
                    sanitize_target(target),
                    redact_text(str(exc)),
                )
                await self._emit(
                    {
                        "rule_name": "assessment_error",
                        "severity": "high",
                        "target": target,
                        "message": f"assessment failed: {redact_text(str(exc))}",
                    }
                )
                continue
            await self._evaluate(target, job)

    async def _evaluate(self, target: str, job: jobs.Job) -> None:
        if job.state in (jobs.JobState.FAILED, jobs.JobState.CANCELLED):
            await self._emit(
                {
                    "rule_name": "assessment_incomplete",
                    "severity": "medium",
                    "target": target,
                    "job": job.id,
                    "message": f"assessment {job.state.value}: {job.error or 'no detail'}",
                }
            )
            return
        current = {finding.fingerprint: finding for finding in job.findings}

        key = sanitize_target(target)
        previous = self._baseline.get(key)
        self._baseline[key] = set(current)

        if key in self._baseline_order:
            self._baseline_order.remove(key)
        self._baseline_order.append(key)

        while len(self._baseline_order) > self.MAX_BASELINE_TARGETS:
            oldest = self._baseline_order.pop(0)
            self._baseline.pop(oldest, None)
            await store.delete_monitor_baseline(oldest)
        await store.save_monitor_baseline(target, set(current))
        if previous is None:
            return
        new = [f for fp, f in current.items() if fp not in previous and f.severity in ALERT_SEVERITIES]
        if new:
            await self._emit(
                {
                    "rule_name": "new_finding",
                    "severity": ("critical" if any(f.severity == "critical" for f in new) else "high"),
                    "target": target,
                    "job": job.id,
                    "message": f"{len(new)} new high-severity finding(s)",
                    "findings": [
                        {
                            "category": f.category,
                            "severity": f.severity,
                            "title": f.title,
                            "location": f.location,
                        }
                        for f in new
                    ],
                }
            )

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _loop(self) -> None:
        while self._running:
            await self.run_cycle()
            await asyncio.sleep(self.interval)

    @property
    def running(self) -> bool:
        return self._running

    async def status_async(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "interval_seconds": self.interval,
            "targets_monitored": len(self.targets),
            "audit_entries": await self.audit_chain.len_async(),
            "active_alerts": len(self.alert_sinks),
        }
