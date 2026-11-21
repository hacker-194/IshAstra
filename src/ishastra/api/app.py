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

from ishastra import __version__
from ishastra.api import deps
from ishastra.api.body_depth import BodyLimitMiddleware
from ishastra.api.csrf import CSRFMiddleware
from ishastra.api.deps import (
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
from ishastra.api.deps import (
    settings as deps_settings,
)
from ishastra.api.middleware import RLSTenantMiddleware, SecurityHeadersMiddleware
from ishastra.api.routers import assessments, assets, exceptions, findings, monitoring, probe, system, tenants
from ishastra.api.routers import auth as auth_router
from ishastra.api.routers import compliance as compliance_router
from ishastra.api.routers import mssp as mssp_router
from ishastra.api.routers import organizations_v2 as organizations_v2_router
from ishastra.api.routers import policies as policies_router
from ishastra.api.routers import pricing as pricing_router
from ishastra.api.routers import proof as proof_router
from ishastra.api.routers import scheduler as scheduler_router
from ishastra.api.routers import scim as scim_router
from ishastra.api.security import (
    RateLimitMiddleware,
    RedisRateLimitMiddleware,
    RequestIDMiddleware,
    SessionCookieMiddleware,
    TenantStateMiddleware,
    api_keys,
    rate_limiter,
)
from ishastra.api.sensitive_rate_limit import SensitiveRateLimitMiddleware
from ishastra.core import policies, scope, store
from ishastra.core.compliance_report import ComplianceScheduler, create_compliance_scheduler
from ishastra.core.queue import get_assessment_worker
from ishastra.core.scheduler import Scheduler, create_scheduler
from ishastra.metrics import MetricsMiddleware, metrics_endpoint
from ishastra.otel import setup_opentelemetry, shutdown_opentelemetry
from ishastra.retention import RetentionWorker

log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).parent / "static"

_retention_worker: RetentionWorker | None = None
_scheduler: Scheduler | None = None
_compliance_scheduler: ComplianceScheduler | None = None


async def _bootstrap_admin_key_async() -> None:
    """Adopt the operator-supplied key; generated keys are only shown once."""
    if not deps_settings.api_key:
        log.warning(
            "ISHASTRA_API_KEY is not set — no credential exists, so every authenticated "
            "request will be refused"
        )
        return
    try:
        await api_keys.adopt_async("admin", "unlimited", deps_settings.api_key)
    except ValueError as exc:
        log.critical("Startup validation failed: %s", exc)
        raise RuntimeError("Invalid ISHASTRA_API_KEY; refusing to start") from exc


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
            "ISHASTRA_AUDIT_HMAC_KEY is not set — the audit chain is hashed with a "
            "public algorithm, so someone who can edit the database can rebuild a "
            "consistent chain. Set a random key to make the chain unforgeable."
        )


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    import defusedxml

    defusedxml.defuse_stdlib()

    if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        setup_opentelemetry(_app)
        log.info("OpenTelemetry initialized")

    store.configure(deps_settings.db_path)

    await init_http_client()
    await api_keys.load_async()
    await policies.registry.load_async()
    await get_audit_log().load_async()
    await get_monitor().load_async()
    await _load_scope_async()

    await _bootstrap_admin_key_async()
    _warn_incomplete_secrets()

    ok, reason = await get_audit_chain().verify_async()
    from ishastra import metrics

    chain_length = await get_audit_chain().len_async()
    metrics.set_audit_chain(chain_length, ok)
    if not ok:
        log.critical("Audit chain verification failed at startup: %s", reason)
        raise RuntimeError(f"Audit chain tampered: {reason}")
    log.info("Audit chain verified: %d entries", chain_length)

    global _retention_worker
    _retention_worker = RetentionWorker(deps_settings.retention_days)

    global _scheduler
    _scheduler = await create_scheduler(
        audit_chain=get_audit_chain(),
        monitor=get_monitor(),
        settings=deps_settings,
        job_timeout=300.0,
        scope_mode=deps_settings.scope_mode,
    )
    log.info("Scheduler initialized")

    global _compliance_scheduler
    _compliance_scheduler = await create_compliance_scheduler(
        audit_chain=get_audit_chain(),
        monitor=get_monitor(),
        settings=deps_settings,
    )
    log.info("Compliance scheduler initialized")

    if not os.environ.get("ISHASTRA_SKIP_REDIS_INIT"):
        await init_redis()

        if deps_settings.redis_required:
            try:
                redis_client = await get_redis()
                await redis_client.ping()
            except Exception as e:
                log.critical("ISHASTRA_REDIS_REQUIRED=1 but Redis unavailable: %s", e)
                raise RuntimeError("Redis required but unreachable") from e

    test_mode = os.environ.get("ISHASTRA_TEST_MODE") == "1"
    if not test_mode:
        worker = get_assessment_worker()
        await worker.start()
    else:
        worker = None
    _retention_worker.start()

    monitor_enabled = os.environ.get("ISHASTRA_MONITOR_ENABLED", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }
    if monitor_enabled:
        await get_monitor().start()
    else:
        log.info("Monitor loop not started (ISHASTRA_MONITOR_ENABLED=0)")

    scheduler_enabled = os.environ.get("ISHASTRA_SCHEDULER_ENABLED", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }
    if not scheduler_enabled:
        log.info("Background schedulers not started (ISHASTRA_SCHEDULER_ENABLED=0)")
    elif _scheduler:
        await _scheduler.start()
    if scheduler_enabled and _compliance_scheduler:
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

        if worker is not None:
            await worker.shutdown()

        await store.close_db_pool()
        await close_http_client()
        await close_redis()

        shutdown_opentelemetry()


class ErrorResponse(BaseModel):
    detail: str


def create_app() -> FastAPI:
    docs_enabled = not deps_settings.disable_docs
    app = FastAPI(
        title="Ishastra",
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

    test_mode = os.environ.get("ISHASTRA_TEST_MODE") == "1"

    app.add_middleware(MetricsMiddleware)
    app.add_middleware(RLSTenantMiddleware)
    app.add_middleware(TenantStateMiddleware)
    app.add_middleware(
        BodyLimitMiddleware,
        max_body_bytes=deps_settings.max_body_bytes,
        max_nesting_depth=deps_settings.max_nesting_depth,
    )
    if not test_mode:
        if deps_settings.redis_required or deps_settings.workers > 1:
            app.add_middleware(RedisRateLimitMiddleware)
        else:
            app.add_middleware(RateLimitMiddleware, limiter=rate_limiter)

    app.add_middleware(SensitiveRateLimitMiddleware)

    app.add_middleware(CSRFMiddleware)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    app.add_middleware(SessionCookieMiddleware)
    if deps_settings.cors_origins:
        if "*" in deps_settings.cors_origins:
            log.warning("CORS origin '*' is not recommended; ignoring wildcard")
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[o for o in deps_settings.cors_origins if o != "*"],
            allow_credentials=False,
            allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-CSRF-Token"],
        )

    @app.get("/api/metrics", include_in_schema=False)
    async def prometheus_metrics(_: Any = Depends(deps.require_admin)):
        return metrics_endpoint()

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
