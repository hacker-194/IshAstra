"""Prometheus metrics collection and exposition for Strix.

Provides counters, histograms, and gauges for observability.
Served at /api/metrics; requires an administrator key (see strix.api.app).
"""

from __future__ import annotations

import time

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from strix import __version__

# Module-level metrics registry
_registry: CollectorRegistry | None = None

# Request metrics
REQUEST_COUNT: Counter | None = None
REQUEST_LATENCY: Histogram | None = None
REQUEST_IN_PROGRESS: Gauge | None = None

# Report metrics
REPORTS_TOTAL: Counter | None = None

# Rate limit metrics
RATE_LIMIT_HITS: Counter | None = None
RATE_LIMIT_EXCEEDED: Counter | None = None


SCOPE_GATE_DECISIONS: Counter | None = None
SCOPE_GATE_DECISION_DURATION: Histogram | None = None

# Job metrics
JOBS_TOTAL: Counter | None = None
JOBS_ACTIVE: Gauge | None = None
JOB_DURATION: Histogram | None = None
JOB_QUEUE_DURATION: Histogram | None = None
JOB_TRANSITIONS: Counter | None = None

# Queue / worker metrics
QUEUE_DEPTH: Gauge | None = None
WORKERS_TOTAL: Gauge | None = None
WORKER_BUSY: Gauge | None = None

# Adapter metrics
ADAPTER_DURATION: Histogram | None = None
ADAPTER_ERRORS: Counter | None = None
ADAPTER_TIMEOUTS: Counter | None = None

# Auth metrics
AUTH_SUCCESS: Counter | None = None
AUTH_FAILURES: Counter | None = None

# Webhook metrics
WEBHOOK_DELIVERIES: Counter | None = None
WEBHOOK_FAILURES: Counter | None = None

# Findings metrics
FINDINGS_TOTAL: Counter | None = None

# Audit metrics
AUDIT_EVENTS: Counter | None = None
AUDIT_CHAIN_LENGTH: Gauge | None = None
AUDIT_CHAIN_VERIFIED: Gauge | None = None

# Scope violations (denials other than the routine out-of-scope miss)

# Break-glass metrics
BREAK_GLASS_ACTIVATIONS: Counter | None = None

# Database metrics
DB_POOL_SIZE: Gauge | None = None
DB_POOL_AVAILABLE: Gauge | None = None
DB_POOL_ACQUIRE: Histogram | None = None
DB_SIZE: Gauge | None = None


def init_metrics() -> CollectorRegistry:
    """Initialize Prometheus metrics. Call once at startup."""
    global _registry, REQUEST_COUNT, REQUEST_LATENCY, REQUEST_IN_PROGRESS
    global REPORTS_TOTAL
    global RATE_LIMIT_HITS, RATE_LIMIT_EXCEEDED
    global SCOPE_GATE_DECISIONS, SCOPE_GATE_DECISION_DURATION
    global BREAK_GLASS_ACTIVATIONS
    global JOBS_TOTAL, JOBS_ACTIVE, JOB_DURATION, JOB_QUEUE_DURATION, JOB_TRANSITIONS
    global QUEUE_DEPTH, WORKERS_TOTAL, WORKER_BUSY
    global ADAPTER_DURATION, ADAPTER_ERRORS, ADAPTER_TIMEOUTS
    global DB_POOL_SIZE, DB_POOL_AVAILABLE, DB_POOL_ACQUIRE, DB_SIZE
    global AUTH_SUCCESS, AUTH_FAILURES, WEBHOOK_DELIVERIES, WEBHOOK_FAILURES
    global FINDINGS_TOTAL, AUDIT_EVENTS, AUDIT_CHAIN_LENGTH, AUDIT_CHAIN_VERIFIED

    if _registry is not None:
        return _registry

    _registry = CollectorRegistry()

    # HTTP request metrics
    REQUEST_COUNT = Counter(
        "strix_http_requests_total",
        "Total HTTP requests",
        ["method", "endpoint", "status"],
        registry=_registry,
    )

    REQUEST_LATENCY = Histogram(
        "strix_http_request_duration_seconds",
        "HTTP request latency in seconds",
        ["method", "endpoint"],
        buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
        registry=_registry,
    )

    REQUEST_IN_PROGRESS = Gauge(
        "strix_http_requests_in_progress",
        "HTTP requests currently being processed",
        ["method", "endpoint"],
        registry=_registry,
    )

    REPORTS_TOTAL = Counter(
        "strix_reports_total",
        "Total evidence reports generated",
        ["kind"],
        registry=_registry,
    )

    # Rate limit metrics
    RATE_LIMIT_HITS = Counter(
        "strix_rate_limit_hits_total",
        "Total rate limit checks",
        ["route_class", "tier", "allowed"],
        registry=_registry,
    )

    RATE_LIMIT_EXCEEDED = Counter(
        "strix_rate_limit_exceeded_total",
        "Total rate limit exceeded responses",
        ["route_class", "tier", "identity_type"],
        registry=_registry,
    )

    # Scope gate decisions: the label set docs/support-runbook.md and
    # docs/runbooks/scope-gate-failures.md query.
    SCOPE_GATE_DECISIONS = Counter(
        "strix_scope_gate_decisions_total",
        "Scope gate decisions by outcome, denial reason and tenant",
        ["decision", "reason", "tenant"],
        registry=_registry,
    )
    SCOPE_GATE_DECISION_DURATION = Histogram(
        "strix_scope_gate_decision_duration_seconds",
        "End-to-end authorization decision latency",
        ["decision"],
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
        registry=_registry,
    )

    # Break-glass activations: dual-approval emergency scope authorizations
    BREAK_GLASS_ACTIVATIONS = Counter(
        "strix_break_glass_activations_total",
        "Break-glass emergency scope activations by tenant and result",
        ["tenant", "result"],
        registry=_registry,
    )

    # Job lifecycle. ``strix_jobs_total`` counts every state a job enters;
    # ``strix_job_state_transitions_total`` is the same event with the pair, so
    # a dashboard can ask "running -> failed" without post-processing.
    JOBS_TOTAL = Counter(
        "strix_jobs_total",
        "Assessment jobs by state entered",
        ["state", "tenant"],
        registry=_registry,
    )
    JOBS_ACTIVE = Gauge(
        "strix_jobs_active",
        "Assessment jobs currently queued or running",
        ["tenant"],
        registry=_registry,
    )
    JOB_DURATION = Histogram(
        "strix_job_duration_seconds",
        "Assessment job wall-clock duration",
        ["profile", "tenant"],
        buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600),
        registry=_registry,
    )
    JOB_QUEUE_DURATION = Histogram(
        "strix_job_queue_duration_seconds",
        "Time between job creation and worker start",
        ["profile"],
        buckets=(0.5, 1, 5, 15, 30, 60, 120, 300, 600, 1800),
        registry=_registry,
    )
    JOB_TRANSITIONS = Counter(
        "strix_job_state_transitions_total",
        "Assessment job state transitions",
        ["from", "to"],
        registry=_registry,
    )

    # Queue and worker occupancy. ``mode`` is the queue backend (inprocess,
    # k8s-jobs) so a dashboard can tell which deployment it is looking at.
    QUEUE_DEPTH = Gauge(
        "strix_queue_depth",
        "Jobs waiting for a worker",
        ["mode"],
        registry=_registry,
    )
    WORKERS_TOTAL = Gauge(
        "strix_workers_total",
        "Worker slots configured",
        ["mode"],
        registry=_registry,
    )
    WORKER_BUSY = Gauge(
        "strix_worker_busy",
        "Worker slots currently running a job",
        ["mode"],
        registry=_registry,
    )

    # Adapter outcomes. Errors are labelled by outcome class (failed, timeout,
    # cancelled, rejected, crashed) rather than exception text, which would
    # explode cardinality.
    ADAPTER_DURATION = Histogram(
        "strix_adapter_duration_seconds",
        "Adapter run duration",
        ["adapter", "tenant"],
        buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300),
        registry=_registry,
    )
    ADAPTER_ERRORS = Counter(
        "strix_adapter_errors_total",
        "Adapter runs that did not produce a clean result",
        ["adapter", "error_type", "tenant"],
        registry=_registry,
    )
    ADAPTER_TIMEOUTS = Counter(
        "strix_adapter_timeout_total",
        "Adapter deadlines exceeded",
        ["adapter", "tenant"],
        registry=_registry,
    )

    # Authentication outcomes and webhook deliveries. Label sets match the
    # alerts and dashboards under deploy/monitoring.
    AUTH_SUCCESS = Counter(
        "strix_auth_success_total",
        "Successful authentications",
        ["tenant", "tier"],
        registry=_registry,
    )
    AUTH_FAILURES = Counter(
        "strix_auth_failures_total",
        "Rejected authentication attempts",
        ["tenant", "reason"],
        registry=_registry,
    )
    WEBHOOK_DELIVERIES = Counter(
        "strix_webhook_deliveries_total",
        "Webhook deliveries by outcome",
        ["tenant", "status"],
        registry=_registry,
    )
    WEBHOOK_FAILURES = Counter(
        "strix_webhook_failures_total",
        "Webhook delivery failures",
        ["tenant", "error_type"],
        registry=_registry,
    )
    FINDINGS_TOTAL = Counter(
        "strix_findings_total",
        "Findings produced, by severity and detector",
        ["tenant", "severity", "adapter"],
        registry=_registry,
    )
    AUDIT_EVENTS = Counter(
        "strix_audit_events_total",
        "Audit chain entries appended",
        ["tenant", "event_type"],
        registry=_registry,
    )
    AUDIT_CHAIN_LENGTH = Gauge(
        "strix_audit_chain_length",
        "Audit chain entries",
        registry=_registry,
    )
    AUDIT_CHAIN_VERIFIED = Gauge(
        "strix_audit_chain_verified",
        "1 when the audit chain verified at its last check, 0 otherwise",
        registry=_registry,
    )
    # Database pool. SQLite reports its fixed connection ceiling; PostgreSQL
    # reports asyncpg's live pool counters.
    DB_POOL_SIZE = Gauge(
        "strix_db_pool_size",
        "Database connection pool size",
        ["dialect"],
        registry=_registry,
    )
    DB_POOL_AVAILABLE = Gauge(
        "strix_db_pool_available",
        "Database connections available without waiting",
        ["dialect"],
        registry=_registry,
    )
    DB_POOL_ACQUIRE = Histogram(
        "strix_db_pool_acquire_seconds",
        "Time spent waiting for a pooled connection",
        ["dialect"],
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
        registry=_registry,
    )
    DB_SIZE = Gauge(
        "strix_db_size_bytes",
        "Database size on disk",
        ["dialect"],
        registry=_registry,
    )

    # Which build produced these numbers; a constant 1 gauge is the Prometheus
    # idiom for exposing version info as a label.
    Gauge(
        "strix_build_info",
        "Build information",
        ["version"],
        registry=_registry,
    ).labels(version=__version__).set(1)

    return _registry


def get_registry() -> CollectorRegistry:
    """Get the metrics registry, initializing if needed."""
    if _registry is None:
        return init_metrics()
    return _registry


def metrics_endpoint() -> Response:
    """Prometheus /metrics endpoint handler."""
    registry = get_registry()
    return Response(
        content=generate_latest(registry),
        media_type=CONTENT_TYPE_LATEST,
    )


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware to collect HTTP request metrics."""

    async def dispatch(self, request: Request, call_next):
        # Skip metrics for the metrics endpoint itself to avoid recursion
        if request.url.path in ("/metrics", "/api/metrics"):
            return await call_next(request)

        method = request.method
        # Normalize path to avoid cardinality explosion
        path = self._normalize_path(request.url.path)

        # Track in-progress
        if REQUEST_IN_PROGRESS:
            REQUEST_IN_PROGRESS.labels(method=method, endpoint=path).inc()

        start_time = time.perf_counter()
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception:
            status_code = 500
            raise
        finally:
            duration = time.perf_counter() - start_time

            if REQUEST_COUNT:
                REQUEST_COUNT.labels(method=method, endpoint=path, status=str(status_code)).inc()
            if REQUEST_LATENCY:
                REQUEST_LATENCY.labels(method=method, endpoint=path).observe(duration)
            if REQUEST_IN_PROGRESS:
                REQUEST_IN_PROGRESS.labels(method=method, endpoint=path).dec()

        return response

    def _normalize_path(self, path: str) -> str:
        """Normalize path to reduce label cardinality."""
        # Replace UUIDs, IDs, etc. with placeholders
        import re

        # UUID pattern
        path = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "/{uuid}",
            path,
        )
        # Numeric IDs
        path = re.sub(r"/\d+(?=/|$)", "/{id}", path)
        # API keys (long alphanumeric)
        return re.sub(r"/[a-zA-Z0-9]{32,}(?=/|$)", "/{key}", path)


# Convenience functions for recording metrics


def record_report(kind: str) -> None:
    """Record a generated report."""
    if REPORTS_TOTAL:
        REPORTS_TOTAL.labels(kind=kind).inc()


def record_rate_limit_check(route_class: str, tier: str, allowed: bool) -> None:
    """Record a rate limit check."""
    if RATE_LIMIT_HITS:
        RATE_LIMIT_HITS.labels(route_class=route_class, tier=tier, allowed=str(allowed).lower()).inc()


def record_rate_limit_exceeded(route_class: str, tier: str, identity_type: str) -> None:
    """Record a rate limit exceeded response."""
    if RATE_LIMIT_EXCEEDED:
        RATE_LIMIT_EXCEEDED.labels(route_class=route_class, tier=tier, identity_type=identity_type).inc()


def record_scope_decision(decision: str, reason: str, tenant: str) -> None:
    """Record one scope gate decision, creating the registry on first use.

    Initializing here (rather than relying on /metrics being scraped first) means
    a decision taken before the first scrape is still counted.
    """
    if m := _metric("SCOPE_GATE_DECISIONS"):
        m.labels(decision=decision, reason=reason, tenant=tenant).inc()


def observe_scope_decision(decision: str, seconds: float) -> None:
    """Observe time spent authorizing a target."""
    if m := _metric("SCOPE_GATE_DECISION_DURATION"):
        m.labels(decision=decision).observe(max(0.0, seconds))


def tenant_label(tenant: str | None) -> str:
    """Bounded tenant label: no tenant configured is ``global``."""
    return tenant or "global"


def _metric(name: str):
    """The metric named ``name``, initializing the registry on first use.

    Looks the global up *after* init: reading it first would capture None and
    silently drop an event recorded before the first scrape.
    """
    metric = globals().get(name)
    if metric is None:
        get_registry()
        metric = globals().get(name)
    return metric


def record_job_state(previous: str, state: str, tenant: str | None) -> None:
    """Record a job entering ``state``.

    Also moves the active gauge: a job is active while queued or running and
    stops being active at any terminal state.
    """
    if m := _metric("JOBS_TOTAL"):
        m.labels(state=state, tenant=tenant_label(tenant)).inc()
    if JOB_TRANSITIONS:
        JOB_TRANSITIONS.labels(**{"from": previous, "to": state}).inc()
    # Only running jobs count as active: a job that fails before it starts
    # must not decrement a gauge it never incremented.
    if JOBS_ACTIVE:
        if state == "running":
            JOBS_ACTIVE.labels(tenant=tenant_label(tenant)).inc()
        elif previous == "running":
            JOBS_ACTIVE.labels(tenant=tenant_label(tenant)).dec()


def observe_job_duration(profile: str, tenant: str, seconds: float) -> None:
    """Record how long a job took end to end."""
    if m := _metric("JOB_DURATION"):
        m.labels(profile=profile or "web", tenant=tenant_label(tenant)).observe(seconds)


def record_queue_depth(depth: int, mode: str) -> None:
    """Set the number of jobs waiting for a worker."""
    if m := _metric("QUEUE_DEPTH"):
        m.labels(mode=mode).set(max(0, depth))


def record_worker_occupancy(total: int, busy: int, mode: str) -> None:
    """Set worker slots and how many are running a job."""
    if m := _metric("WORKERS_TOTAL"):
        m.labels(mode=mode).set(max(0, total))
    if WORKER_BUSY:
        WORKER_BUSY.labels(mode=mode).set(max(0, busy))


def observe_adapter(adapter: str, tenant: str | None, seconds: float) -> None:
    """Record a completed adapter run."""
    if m := _metric("ADAPTER_DURATION"):
        m.labels(adapter=adapter, tenant=tenant_label(tenant)).observe(seconds)


def record_adapter_error(adapter: str, error_type: str, tenant: str | None, *, timeout: bool = False) -> None:
    """Record an adapter run that did not produce a clean result."""
    if m := _metric("ADAPTER_ERRORS"):
        m.labels(adapter=adapter, error_type=error_type, tenant=tenant_label(tenant)).inc()
    if timeout and ADAPTER_TIMEOUTS:
        ADAPTER_TIMEOUTS.labels(adapter=adapter, tenant=tenant_label(tenant)).inc()


def observe_db_acquire(dialect: str, seconds: float) -> None:
    """Record time spent waiting for a pooled connection."""
    if m := _metric("DB_POOL_ACQUIRE"):
        m.labels(dialect=dialect).observe(max(0.0, seconds))


def record_db_pool(dialect: str, size: int, available: int) -> None:
    """Set pool size and free connections."""
    if m := _metric("DB_POOL_SIZE"):
        m.labels(dialect=dialect).set(max(0, size))
    if DB_POOL_AVAILABLE:
        DB_POOL_AVAILABLE.labels(dialect=dialect).set(max(0, available))


def record_db_size(dialect: str, size_bytes: float) -> None:
    """Set database size on disk."""
    if m := _metric("DB_SIZE"):
        m.labels(dialect=dialect).set(max(0.0, size_bytes))


def record_auth_success(tenant: str | None, tier: str = "api_key") -> None:
    """Record a successful authentication."""
    if m := _metric("AUTH_SUCCESS"):
        m.labels(tenant=tenant_label(tenant), tier=tier).inc()


def record_auth_failure(reason: str, tenant: str | None) -> None:
    """Record a rejected authentication attempt."""
    if m := _metric("AUTH_FAILURES"):
        m.labels(tenant=tenant_label(tenant), reason=reason).inc()


def record_webhook_delivery(status: str, tenant: str | None) -> None:
    """Record one webhook delivery outcome (delivered, failed, refused)."""
    if m := _metric("WEBHOOK_DELIVERIES"):
        m.labels(tenant=tenant_label(tenant), status=status).inc()


def record_webhook_failure(error_type: str, tenant: str | None) -> None:
    """Record a webhook failure by class (http, timeout, network, refused)."""
    if m := _metric("WEBHOOK_FAILURES"):
        m.labels(tenant=tenant_label(tenant), error_type=error_type).inc()


def record_finding(severity: str, adapter: str, tenant: str | None) -> None:
    """Record one finding produced by an adapter."""
    if m := _metric("FINDINGS_TOTAL"):
        m.labels(tenant=tenant_label(tenant), severity=severity, adapter=adapter).inc()


def record_audit_event(event_type: str, tenant: str | None) -> None:
    """Record one audit chain append."""
    if m := _metric("AUDIT_EVENTS"):
        m.labels(tenant=tenant_label(tenant), event_type=event_type).inc()


def set_audit_chain_length(length: int) -> None:
    """Publish the number of entries in the audit chain."""
    if m := _metric("AUDIT_CHAIN_LENGTH"):
        m.set(max(0, length))


def set_audit_chain(length: int, verified: bool) -> None:
    """Publish length and verification result at once."""
    set_audit_chain_length(length)
    if m := _metric("AUDIT_CHAIN_VERIFIED"):
        m.set(1 if verified else 0)


def observe_job_queue(profile: str, seconds: float) -> None:
    """Record how long a job waited before a worker started it."""
    if m := _metric("JOB_QUEUE_DURATION"):
        m.labels(profile=profile or "web").observe(max(0.0, seconds))
