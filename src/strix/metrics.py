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

# Job metrics
JOBS_TOTAL: Counter | None = None
JOBS_ACTIVE: Gauge | None = None

# Findings metrics
FINDINGS_TOTAL: Counter | None = None

# Report metrics
REPORTS_TOTAL: Counter | None = None

# Adapter metrics
ADAPTER_DURATION: Histogram | None = None
ADAPTER_ERRORS: Counter | None = None

# Rate limit metrics
RATE_LIMIT_HITS: Counter | None = None
RATE_LIMIT_EXCEEDED: Counter | None = None

# Database pool metrics
DB_POOL_SIZE: Gauge | None = None
DB_POOL_AVAILABLE: Gauge | None = None
DB_POOL_ACQUIRE_TIME: Histogram | None = None

# Webhook metrics
WEBHOOK_DELIVERIES: Counter | None = None
WEBHOOK_FAILURES: Counter | None = None

# Authentication metrics
AUTH_SUCCESS: Counter | None = None
AUTH_FAILURES: Counter | None = None


def init_metrics() -> CollectorRegistry:
    """Initialize Prometheus metrics. Call once at startup."""
    global _registry, REQUEST_COUNT, REQUEST_LATENCY, REQUEST_IN_PROGRESS
    global JOBS_TOTAL, JOBS_ACTIVE, FINDINGS_TOTAL, REPORTS_TOTAL
    global ADAPTER_DURATION, ADAPTER_ERRORS
    global RATE_LIMIT_HITS, RATE_LIMIT_EXCEEDED
    global DB_POOL_SIZE, DB_POOL_AVAILABLE, DB_POOL_ACQUIRE_TIME
    global WEBHOOK_DELIVERIES, WEBHOOK_FAILURES
    global AUTH_SUCCESS, AUTH_FAILURES

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

    # Job metrics
    JOBS_TOTAL = Counter(
        "strix_jobs_total",
        "Total jobs by state",
        ["state", "tenant"],
        registry=_registry,
    )

    JOBS_ACTIVE = Gauge(
        "strix_jobs_active",
        "Currently running jobs",
        ["tenant"],
        registry=_registry,
    )

    # Findings metrics
    FINDINGS_TOTAL = Counter(
        "strix_findings_total",
        "Total findings by severity",
        ["severity", "adapter", "tenant"],
        registry=_registry,
    )

    REPORTS_TOTAL = Counter(
        "strix_reports_total",
        "Total evidence reports generated",
        ["kind"],
        registry=_registry,
    )

    # Adapter metrics
    ADAPTER_DURATION = Histogram(
        "strix_adapter_duration_seconds",
        "Adapter execution duration in seconds",
        ["adapter", "tenant"],
        buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0),
        registry=_registry,
    )

    ADAPTER_ERRORS = Counter(
        "strix_adapter_errors_total",
        "Total adapter errors",
        ["adapter", "error_type", "tenant"],
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

    # Database pool metrics
    DB_POOL_SIZE = Gauge(
        "strix_db_pool_size",
        "Database connection pool size",
        ["dialect"],
        registry=_registry,
    )

    DB_POOL_AVAILABLE = Gauge(
        "strix_db_pool_available",
        "Available database connections in pool",
        ["dialect"],
        registry=_registry,
    )

    DB_POOL_ACQUIRE_TIME = Histogram(
        "strix_db_pool_acquire_seconds",
        "Time to acquire database connection from pool",
        ["dialect"],
        buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
        registry=_registry,
    )

    # Webhook metrics
    WEBHOOK_DELIVERIES = Counter(
        "strix_webhook_deliveries_total",
        "Total webhook deliveries",
        ["status", "tenant"],
        registry=_registry,
    )

    WEBHOOK_FAILURES = Counter(
        "strix_webhook_failures_total",
        "Total webhook delivery failures",
        ["error_type", "tenant"],
        registry=_registry,
    )

    # Authentication metrics
    AUTH_SUCCESS = Counter(
        "strix_auth_success_total",
        "Successful authentications",
        ["tenant", "tier"],
        registry=_registry,
    )

    AUTH_FAILURES = Counter(
        "strix_auth_failures_total",
        "Failed authentication attempts",
        ["reason"],
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
                REQUEST_COUNT.labels(
                    method=method, endpoint=path, status=str(status_code)
                ).inc()
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

def record_job_started(tenant: str) -> None:
    """Record a job starting."""
    if JOBS_TOTAL:
        JOBS_TOTAL.labels(state="started", tenant=tenant).inc()
    if JOBS_ACTIVE:
        JOBS_ACTIVE.labels(tenant=tenant).inc()


def record_job_completed(tenant: str, state: str = "completed") -> None:
    """Record a job completing."""
    if JOBS_TOTAL:
        JOBS_TOTAL.labels(state=state, tenant=tenant).inc()
    if JOBS_ACTIVE:
        JOBS_ACTIVE.labels(tenant=tenant).dec()


def record_finding(severity: str, adapter: str, tenant: str) -> None:
    """Record a finding."""
    if FINDINGS_TOTAL:
        FINDINGS_TOTAL.labels(severity=severity, adapter=adapter, tenant=tenant).inc()


def record_report(kind: str) -> None:
    """Record a generated report."""
    if REPORTS_TOTAL:
        REPORTS_TOTAL.labels(kind=kind).inc()


def record_adapter_duration(adapter: str, tenant: str, duration: float) -> None:
    """Record adapter execution duration."""
    if ADAPTER_DURATION:
        ADAPTER_DURATION.labels(adapter=adapter, tenant=tenant).observe(duration)


def record_adapter_error(adapter: str, error_type: str, tenant: str) -> None:
    """Record an adapter error."""
    if ADAPTER_ERRORS:
        ADAPTER_ERRORS.labels(adapter=adapter, error_type=error_type, tenant=tenant).inc()


def record_rate_limit_check(route_class: str, tier: str, allowed: bool) -> None:
    """Record a rate limit check."""
    if RATE_LIMIT_HITS:
        RATE_LIMIT_HITS.labels(
            route_class=route_class, tier=tier, allowed=str(allowed).lower()
        ).inc()


def record_rate_limit_exceeded(route_class: str, tier: str, identity_type: str) -> None:
    """Record a rate limit exceeded response."""
    if RATE_LIMIT_EXCEEDED:
        RATE_LIMIT_EXCEEDED.labels(
            route_class=route_class, tier=tier, identity_type=identity_type
        ).inc()


def record_db_pool_acquire(dialect: str, duration: float) -> None:
    """Record database pool acquire time."""
    if DB_POOL_ACQUIRE_TIME:
        DB_POOL_ACQUIRE_TIME.labels(dialect=dialect).observe(duration)


def update_db_pool_stats(dialect: str, size: int, available: int) -> None:
    """Update database pool stats."""
    if DB_POOL_SIZE:
        DB_POOL_SIZE.labels(dialect=dialect).set(size)
    if DB_POOL_AVAILABLE:
        DB_POOL_AVAILABLE.labels(dialect=dialect).set(available)


def record_webhook_delivery(tenant: str, success: bool, error_type: str | None = None) -> None:
    """Record a webhook delivery attempt."""
    if WEBHOOK_DELIVERIES:
        WEBHOOK_DELIVERIES.labels(status="success" if success else "failure", tenant=tenant).inc()
    if not success and WEBHOOK_FAILURES and error_type:
        WEBHOOK_FAILURES.labels(error_type=error_type, tenant=tenant).inc()


def record_auth_success(tenant: str, tier: str) -> None:
    """Record successful authentication."""
    if AUTH_SUCCESS:
        AUTH_SUCCESS.labels(tenant=tenant, tier=tier).inc()


def record_auth_failure(reason: str) -> None:
    """Record failed authentication."""
    if AUTH_FAILURES:
        AUTH_FAILURES.labels(reason=reason).inc()


def reset_metrics() -> None:
    """Reset all metrics (for testing)."""
    global _registry, REQUEST_COUNT, REQUEST_LATENCY, REQUEST_IN_PROGRESS
    global JOBS_TOTAL, JOBS_ACTIVE, FINDINGS_TOTAL, REPORTS_TOTAL
    global ADAPTER_DURATION, ADAPTER_ERRORS
    global RATE_LIMIT_HITS, RATE_LIMIT_EXCEEDED
    global DB_POOL_SIZE, DB_POOL_AVAILABLE, DB_POOL_ACQUIRE_TIME
    global WEBHOOK_DELIVERIES, WEBHOOK_FAILURES
    global AUTH_SUCCESS, AUTH_FAILURES

    _registry = None
    REQUEST_COUNT = REQUEST_LATENCY = REQUEST_IN_PROGRESS = None
    JOBS_TOTAL = JOBS_ACTIVE = FINDINGS_TOTAL = None
    REPORTS_TOTAL = None
    ADAPTER_DURATION = ADAPTER_ERRORS = None
    RATE_LIMIT_HITS = RATE_LIMIT_EXCEEDED = None
    DB_POOL_SIZE = DB_POOL_AVAILABLE = DB_POOL_ACQUIRE_TIME = None
    WEBHOOK_DELIVERIES = WEBHOOK_FAILURES = None
    AUTH_SUCCESS = AUTH_FAILURES = None
