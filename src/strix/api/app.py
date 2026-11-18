"""Application factory."""

from __future__ import annotations

import logging
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

from strix import __version__
from strix.api import deps
from strix.api.body_depth import BodyLimitMiddleware
from strix.api.csrf import CSRFMiddleware
from strix.api.dependencies import (
    close_http_client,
    close_redis,
    get_audit_chain,
    get_audit_log,
    get_monitor,
    get_redis,
    get_settings,
    init_http_client,
    init_redis,
)
from strix.api.dependencies import (
    settings as deps_settings,
)
from strix.api.middleware import SecurityHeadersMiddleware
from strix.api.routers import assessments, assets, exceptions, findings, monitoring, probe, system, tenants
from strix.api.routers import auth as auth_router
from strix.api.routers import compliance as compliance_router
from strix.api.routers import mssp as mssp_router
from strix.api.routers import organizations_v2 as organizations_v2_router
from strix.api.routers import orgs as orgs_router
from strix.api.routers import policies as policies_router
from strix.api.routers import pricing as pricing_router
from strix.api.routers import proof as proof_router
from strix.api.routers import scheduler as scheduler_router
from strix.api.routers import scim as scim_router
from strix.api.security import (
    RateLimitMiddleware,
    RedisRateLimitMiddleware,
    RequestIDMiddleware,
    SessionCookieMiddleware,
    TenantStateMiddleware,
    api_keys,
    rate_limiter,
)
from strix.api.sensitive_rate_limit import SensitiveRateLimitMiddleware
from strix.core import policies, scope, store
from strix.core.compliance_report import ComplianceScheduler, create_compliance_scheduler
from strix.core.queue import get_assessment_worker
from strix.core.scheduler import Scheduler, create_scheduler
from strix.metrics import MetricsMiddleware, metrics_endpoint
from strix.otel import setup_opentelemetry, shutdown_opentelemetry
from strix.retention import RetentionWorker

log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"
# retention_worker initialized lazily in lifespan to allow test config
_retention_worker: RetentionWorker | None = None
_scheduler: Scheduler | None = None
_compliance_scheduler: ComplianceScheduler | None = None
_ha_manager = None  # HA manager for multi-node deployments


async def _bootstrap_admin_key_async() -> None:
    """Adopt the operator-supplied key; generated keys are only shown once."""
    if not deps_settings.api_key:
        log.warning(
            "STRIX_API_KEY is not set — no credential exists, so every authenticated request will be refused"
        )
        return
    try:
        await api_keys.adopt_async("admin", "unlimited", deps_settings.api_key)
    except ValueError as exc:
        # Do not continue with an older persisted admin key after the operator
        # supplied an invalid replacement; that would make a failed rotation
        # look successful to the deployment.
        log.critical("STRIX_API_KEY rejected; refusing startup: %s", exc)
        raise RuntimeError("Invalid STRIX_API_KEY; refusing to start") from exc


async def _load_scope_async() -> None:
    """Deny everything until an authorization record is supplied.

    A scope document that fails validation is fatal for scanning (the process
    serves, but refuses every target): it is never half-loaded, and a failed
    reload never widens or silently replaces an active policy.
    """
    try:
        scope.configure_intel_from_env()
    except ValueError as exc:
        log.critical("scope intel file rejected; no target may be assessed: %s", exc)
        return
    if deps_settings.scope_jwks:
        try:
            scope.configure_signing(deps_settings.scope_jwks, max_age=deps_settings.scope_max_age)
        except (OSError, ValueError) as exc:
            log.critical("scope signing key set rejected; no target may be assessed: %s", exc)
            return
    try:
        installed = scope.load(deps_settings.scope_file)
    except (OSError, ValueError) as exc:
        log.warning(
            "scope document %s rejected: %s — no target may be assessed",
            deps_settings.scope_file,
            exc,
        )
        return
    if installed is not None:
        log.info(
            "scope document %s active: program=%s include=%d host(s)",
            deps_settings.scope_file,
            installed.program,
            len(installed.include),
        )


def _warn_incomplete_secrets() -> None:
    """Optional keys whose absence quietly weakens a guarantee are warned about,
    not refused: the deployment still works, it just proves/protects less."""
    if not deps_settings.audit_hmac_key:
        log.warning(
            "STRIX_AUDIT_HMAC_KEY is not set — the audit chain is hashed with a "
            "public algorithm, so someone who can edit the database can rebuild a "
            "consistent chain. Set a random key to make the chain unforgeable."
        )


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    import defusedxml

    defusedxml.defuse_stdlib()

    # Initialize OpenTelemetry if configured
    if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        setup_opentelemetry(_app)
        log.info("OpenTelemetry initialized")

    store.configure(deps_settings.db_path)
    # Initialize async resources before policy loading (store opens its pool lazily)
    await init_http_client()
    await api_keys.load_async()
    await policies.registry.load_async()  # engagement policies govern managed mode
    await get_audit_log().load_async()
    await get_monitor().load_async()
    await _load_scope_async()

    await _bootstrap_admin_key_async()
    _warn_incomplete_secrets()

    # Verify audit chain integrity at startup; never discard evidence here.
    ok, reason = await get_audit_chain().verify_async()
    from strix import metrics

    chain_length = await get_audit_chain().len_async()
    metrics.set_audit_chain(chain_length, ok)
    if not ok:
        log.critical("Audit chain verification failed at startup: %s", reason)
        raise RuntimeError(f"Audit chain tampered: {reason}")
    log.info("Audit chain verified: %d entries", chain_length)

    # Initialize retention worker now that settings are available
    global _retention_worker
    _retention_worker = RetentionWorker(deps_settings.retention_days)

    # Initialize HA manager (handles leader election, health checks, graceful shutdown)
    global _ha_manager
    ha_mode = os.environ.get("STRIX_HA_MODE", "false").lower() == "true"
    if ha_mode and deps_settings.db_path.startswith(("postgresql://", "postgres://")):
        from strix.core.ha import LeaderElectionConfig, create_ha_manager

        _ha_manager = await create_ha_manager(
            settings=deps_settings,
            audit_chain=get_audit_chain(),
            election_config=LeaderElectionConfig(
                lock_name="strix_leader_election",
                ttl_seconds=30,
                retry_interval=5.0,
            ),
            drain_timeout=30.0,
        )
        log.info("HA mode enabled: node_id=%s, is_leader=%s", _ha_manager.node_id, _ha_manager.is_leader)
    else:
        if ha_mode:
            log.warning("HA mode requested but requires PostgreSQL; running in single-node mode")
        _ha_manager = None
        log.info("Running in single-node mode")

    # Initialize scheduler (only on leader in HA mode, always in single-node)
    global _scheduler
    is_leader = _ha_manager is None or _ha_manager.is_leader
    if is_leader:
        _scheduler = await create_scheduler(
            audit_chain=get_audit_chain(),
            monitor=get_monitor(),
            settings=deps_settings,
            job_timeout=300.0,
            scope_mode=deps_settings.scope_mode,
        )
        log.info("Scheduler initialized on leader node")
    else:
        _scheduler = None
        log.info("Scheduler not started on standby node")

    # Initialize compliance scheduler (only on leader in HA mode)
    global _compliance_scheduler
    if is_leader:
        _compliance_scheduler = await create_compliance_scheduler(
            audit_chain=get_audit_chain(),
            monitor=get_monitor(),
            settings=deps_settings,
        )
        log.info("Compliance scheduler initialized on leader node")
    else:
        _compliance_scheduler = None

    # Skip Redis initialization in tests (STRIX_SKIP_REDIS_INIT=1)
    if not os.environ.get("STRIX_SKIP_REDIS_INIT"):
        await init_redis()

        # Fail fast if Redis is required but unavailable
        if deps_settings.redis_required:
            try:
                redis_client = await get_redis()
                await redis_client.ping()
            except Exception as e:
                log.critical("STRIX_REDIS_REQUIRED=1 but Redis unavailable: %s", e)
                raise RuntimeError("Redis required but unreachable") from e

    test_mode = os.environ.get("STRIX_TEST_MODE") == "1"
    if not test_mode:
        worker = get_assessment_worker()
        await worker.start()
    else:
        worker = None
    _retention_worker.start()
    await get_monitor().start()
    if _scheduler:
        await _scheduler.start()
    if _compliance_scheduler:
        await _compliance_scheduler.start()
    try:
        yield
    finally:
        if _retention_worker is not None:
            _retention_worker.shutdown()
        if _scheduler:
            await _scheduler.stop()
        if _compliance_scheduler:
            await _compliance_scheduler.stop()
        await get_monitor().stop()
        # Shutdown worker threads BEFORE closing DB pool so they can cleanly
        # return connections and close their own per-thread pools
        if worker is not None:
            await worker.shutdown()
        # ``store`` keeps a process-wide pool; leaving it open keeps aiosqlite's
        # non-daemon threads alive and the process never exits.
        await store.close_db_pool()
        await close_http_client()
        await close_redis()
        # Shutdown HA manager (releases leadership lock)
        if _ha_manager:
            await _ha_manager.stop()
        # Shutdown OpenTelemetry
        shutdown_opentelemetry()


class ErrorResponse(BaseModel):
    detail: str


def create_app() -> FastAPI:
    docs_enabled = not deps_settings.disable_docs
    app = FastAPI(
        title="Strix",
        version=__version__,
        lifespan=_lifespan,
        description="Authorized security assessment platform",
        docs_url="/docs" if docs_enabled else None,
        redoc_url="/redoc" if docs_enabled else None,
        openapi_url="/openapi.json" if docs_enabled else None,
        responses={
            401: {"model": ErrorResponse, "description": "Unauthorized"},
            403: {"model": ErrorResponse, "description": "Forbidden"},
            422: {"model": ErrorResponse, "description": "Validation Error"},
            429: {"model": ErrorResponse, "description": "Rate Limit Exceeded"},
            500: {"model": ErrorResponse, "description": "Internal Server Error"},
            503: {"model": ErrorResponse, "description": "Service Unavailable"},
        },
    )

    # Global exception handlers - prevent stack trace leaks in production
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
        )

    def _serializable_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Make Pydantic validation errors JSON-serializable."""
        out: list[dict[str, Any]] = []
        for err in errors:
            e: dict[str, Any] = dict(err)
            ctx = e.get("ctx")
            if ctx is not None:
                e["ctx"] = {k: str(v) for k, v in ctx.items()}
            # Also serialize 'input' field which can be bytes (raw request body)
            if "input" in e and isinstance(e["input"], bytes):
                e["input"] = e["input"].decode("utf-8", errors="replace")
            out.append(e)
        return out

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "detail": "Invalid request",
                "errors": _serializable_errors(list(exc.errors())),
            },
        )

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        # Log the full exception for debugging (not returned to client)
        log.exception("Unhandled exception on %s %s", request.method, request.url.path)
        if get_settings().debug:
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "Internal server error",
                    "type": type(exc).__name__,
                    "message": str(exc),
                },
            )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    # Test mode: disable rate limiters entirely (STRIX_TEST_MODE=1)
    # This avoids fragile middleware patching in tests.
    test_mode = os.environ.get("STRIX_TEST_MODE") == "1"

    # Starlette runs the LAST middleware added first (outermost).
    # Intended order outside-in: CORS -> security headers ->
    # session cookie -> sensitive rate limit -> CSRF -> request id ->
    # rate limit (Redis) -> body limits -> tenant state -> metrics.
    # So we add them in REVERSE order (innermost first).
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(TenantStateMiddleware)
    app.add_middleware(
        BodyLimitMiddleware,
        max_body_bytes=deps_settings.max_body_bytes,
        max_nesting_depth=deps_settings.max_nesting_depth,
    )
    if not test_mode:
        # Single rate limiter: Redis when required or multi-worker; in-memory otherwise.
        # This avoids dual-enforcement where in-memory permits requests Redis would deny.
        if deps_settings.redis_required or deps_settings.workers > 1:
            # Redis-backed limiter (fails closed if Redis unavailable)
            app.add_middleware(RedisRateLimitMiddleware)
        else:
            # In-memory limiter (single worker, Redis not required)
            app.add_middleware(RateLimitMiddleware, limiter=rate_limiter)
    # Sensitive endpoint rate limiting (stricter per-IP limits for auth/key endpoints)
    app.add_middleware(SensitiveRateLimitMiddleware)
    # CSRF protection for browser-based mutations
    app.add_middleware(CSRFMiddleware)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    # Session cookie handling (must be after security headers to set secure cookies)
    app.add_middleware(SessionCookieMiddleware)
    if deps_settings.cors_origins:  # the bundled UI is same-origin and needs none
        # Validate no wildcards in CORS origins when credentials would be enabled
        if "*" in deps_settings.cors_origins:
            log.warning("CORS origin '*' is not recommended; ignoring wildcard")
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[o for o in deps_settings.cors_origins if o != "*"],
            allow_credentials=False,
            allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-CSRF-Token"],
        )

    # Prometheus metrics expose per-target and per-status request paths, so they
    # require the same administrator key as every other cross-tenant read. A
    # scraper holding that key is counted by the default limit like any caller.
    @app.get("/api/metrics", include_in_schema=False)
    async def prometheus_metrics(_: Any = Depends(deps.require_admin)):
        return metrics_endpoint()

    # HA status endpoint
    @app.get("/api/ha/status", include_in_schema=False)
    async def ha_status(_: Any = Depends(deps.require_admin)):
        if _ha_manager is None:
            return {"ha_mode": False, "message": "HA mode not enabled"}
        return await _ha_manager.get_status()

    for module in (
        system,
        assessments,
        assets,
        exceptions,
        findings,
        probe,
        tenants,
        monitoring,
        policies_router,
        proof_router,
        scheduler_router,
        compliance_router,
        orgs_router,
        organizations_v2_router,
        auth_router,
        scim_router,
        pricing_router,
        mssp_router,
    ):
        app.include_router(module.router)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    return app


app = create_app()
