"""Application factory."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from strix import __version__
from strix.api import deps
from strix.api.body_depth import BodyLimitMiddleware
from strix.api.dependencies import (
    close_db_pool,
    close_http_client,
    close_redis,
    get_rate_limiter,
    init_db_pool,
    init_http_client,
    init_redis,
)
from strix.api.routers import assessments, monitoring, probe, system, tenants
from strix.api.routers import policies as policies_router
from strix.api.security import (
    RedisRateLimitMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
    TenantStateMiddleware,
    api_keys,
    rate_limiter,
)
from strix.core import policies, scope, store
from strix.core.worker import assessment_worker, set_main_loop
from strix.metrics import MetricsMiddleware
from strix.retention import RetentionWorker

log = logging.getLogger(__name__)
STATIC_DIR = Path(__file__).resolve().parent / "static"
retention_worker = RetentionWorker(deps.settings.retention_days)


async def _bootstrap_admin_key_async() -> None:
    """Adopt the operator-supplied key; generated keys are only shown once."""
    if not deps.settings.api_key:
        log.warning("STRIX_API_KEY is not set — no credential exists, so every "
                    "authenticated request will be refused")
        return
    try:
        await api_keys.adopt_async("admin", "enterprise", deps.settings.api_key)
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
        installed = scope.load(deps.settings.scope_file)
    except (OSError, ValueError) as exc:
        log.warning("scope document %s rejected: %s — no target may be assessed",
                    deps.settings.scope_file, exc)
        return
    if installed is not None:
        log.info("scope document %s active: program=%s include=%d host(s)",
                 deps.settings.scope_file, installed.program, len(installed.include))


def _warn_incomplete_secrets() -> None:
    """Optional keys whose absence quietly weakens a guarantee are warned about,
    not refused: the deployment still works, it just proves/protects less."""
    if not deps.settings.audit_hmac_key:
        log.warning(
            "STRIX_AUDIT_HMAC_KEY is not set — the audit chain is hashed with a "
            "public algorithm, so someone who can edit the database can rebuild a "
            "consistent chain. Set a random key to make the chain unforgeable.")


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    store.configure(deps.settings.db_path)
    await api_keys.load_async()
    await policies.registry.load_async()   # engagement policies govern managed mode
    await deps.audit_log.load_async()
    await deps.monitor.load_async()
    await _load_scope_async()
    await _bootstrap_admin_key_async()
    _warn_incomplete_secrets()

    # Initialize async resources
    await init_db_pool()
    await init_http_client()
    await init_redis()

    # Set main event loop for worker thread async submission
    set_main_loop(asyncio.get_running_loop())
    await assessment_worker.start()  # also fails jobs a previous process left running
    retention_worker.start()   # no-op unless STRIX_RETENTION_DAYS is set
    await deps.monitor.start()
    try:
        yield
    finally:
        retention_worker.shutdown()
        await deps.monitor.stop()
        await assessment_worker.shutdown()
        await close_http_client()
        await close_redis()
        await close_db_pool()


def create_app() -> FastAPI:
    app = FastAPI(title="Strix", version=__version__, lifespan=_lifespan,
                  description="Authorized security assessment platform")

    # Starlette runs the LAST middleware added first (outermost). Order, outside
    # in: CORS -> security headers -> request id -> rate limit -> body limits ->
    # tenant state. Every response — including 400/413/429 — therefore carries a
    # request id and the security headers, and oversized or hostile bodies are
    # rate limited before they are inspected.
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(TenantStateMiddleware)
    app.add_middleware(BodyLimitMiddleware)
    app.add_middleware(RedisRateLimitMiddleware, get_rate_limiter_func=get_rate_limiter, limiter=rate_limiter)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    if deps.settings.cors_origins:  # the bundled UI is same-origin and needs none
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(deps.settings.cors_origins),
            allow_credentials=False,
            allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        )

    for module in (system, assessments, probe, tenants, monitoring, policies_router):
        app.include_router(module.router)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    return app


app = create_app()
