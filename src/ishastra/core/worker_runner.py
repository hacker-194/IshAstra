"""Dedicated worker entrypoint for the Redis Streams assessment queue.

Runs a standalone consumer process for ``ishastra:assessments`` stream.
Exposes Prometheus metrics and health checks for KEDA autoscaling.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
import threading
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from ishastra.config import get_settings
from ishastra.core.redis_queue import RedisStreamsAssessmentQueue, get_redis_streams_assessment_queue
from ishastra.metrics import get_registry, init_metrics

log = logging.getLogger(__name__)


_worker: RedisStreamsAssessmentQueue | None = None
_shutdown_event = threading.Event()
_server: Any = None
_server_thread: threading.Thread | None = None
_started_at = time.time()


def _configure_logging() -> None:
    """Configure structured JSON logging for the worker."""
    settings = get_settings()
    handler = logging.StreamHandler()
    if settings.log_format == "json":
        import json

        class _JsonFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                entry = {
                    "time": self.formatTime(record),
                    "level": record.levelname,
                    "logger": record.name,
                    "message": record.getMessage(),
                }
                if record.exc_info:
                    entry["exception"] = self.formatException(record.exc_info)
                return json.dumps(entry)

        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=settings.log_level, handlers=[handler])


async def _start_worker() -> RedisStreamsAssessmentQueue:
    """Create and start the Redis Streams assessment queue worker."""
    global _worker
    settings = get_settings()

    concurrency = int(os.environ.get("ISHASTRA_WORKERS", settings.workers))
    queue_max = int(os.environ.get("ISHASTRA_QUEUE_MAX", settings.queue_max))

    queue = get_redis_streams_assessment_queue(
        concurrency=concurrency,
        queue_max=queue_max,
    )
    await queue.start()
    _worker = queue
    log.info(
        "Redis Streams worker started: stream=%s group=%s concurrency=%d",
        queue.stream,
        queue.group,
        queue.concurrency,
    )
    return queue


async def _shutdown_worker(timeout: float = 30.0) -> None:
    """Gracefully shutdown the worker."""
    global _worker
    if _worker is None:
        return

    log.info("Shutting down Redis Streams worker...")
    await _worker.shutdown(timeout=timeout)
    _worker = None
    log.info("Worker shutdown complete")


def _handle_signal(signum: int, frame: Any) -> None:
    """Handle shutdown signals."""
    sig_name = signal.Signals(signum).name
    log.info("Received signal %s, initiating graceful shutdown...", sig_name)
    _shutdown_event.set()


def _setup_signal_handlers() -> None:
    """Register signal handlers for graceful shutdown."""
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, _handle_signal)


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    """FastAPI lifespan for the metrics/health server."""

    init_metrics()

    await _start_worker()

    yield

    await _shutdown_worker()


def create_health_app() -> FastAPI:
    """Create the FastAPI app with health checks and metrics endpoints."""
    app = FastAPI(
        title="Ishastra Worker",
        version="0.1.0",
        lifespan=_lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/health/live", include_in_schema=False)
    async def liveness() -> Response:
        """Kubernetes liveness probe - process is running."""
        return Response(content="OK", media_type="text/plain")

    @app.get("/health/ready", include_in_schema=False)
    async def readiness() -> Response:
        """Kubernetes readiness probe - worker is accepting jobs."""
        if _worker is None:
            return Response(content="NOT READY", status_code=503, media_type="text/plain")

        try:
            await _worker.redis.ping()
        except Exception as e:
            log.warning("Readiness check failed: Redis ping error: %s", e)
            return Response(content="NOT READY", status_code=503, media_type="text/plain")

        return Response(content="OK", media_type="text/plain")

    @app.get("/metrics", include_in_schema=False)
    async def metrics() -> Response:
        """Prometheus metrics endpoint."""
        registry = get_registry()
        return Response(
            content=generate_latest(registry),
            media_type=CONTENT_TYPE_LATEST,
        )

    return app


def _run_metrics_server(app: FastAPI, host: str, port: int) -> None:
    """Run the metrics/health server in a separate thread."""
    import uvicorn

    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )
    global _server
    _server = uvicorn.Server(config)
    _server.run()


def main() -> int:
    """Main entrypoint for the ishastra worker."""
    _configure_logging()
    _setup_signal_handlers()

    settings = get_settings()

    health_host = os.environ.get("ISHASTRA_WORKER_HEALTH_HOST", "0.0.0.0")
    health_port = int(os.environ.get("ISHASTRA_WORKER_HEALTH_PORT", "8080"))

    workers = int(os.environ.get("ISHASTRA_WORKERS", settings.workers))
    queue_max = int(os.environ.get("ISHASTRA_QUEUE_MAX", settings.queue_max))

    log.info(
        "Starting Ishastra Redis Streams Worker: redis_url=%s stream=%s group=%s workers=%d queue_max=%d",
        settings.redis_url,
        os.environ.get("ISHASTRA_REDIS_QUEUE_STREAM", "ishastra:assessments"),
        os.environ.get("ISHASTRA_REDIS_QUEUE_GROUP", "ishastra-workers"),
        workers,
        queue_max,
    )

    app = create_health_app()
    global _server_thread
    _server_thread = threading.Thread(
        target=_run_metrics_server,
        args=(app, health_host, health_port),
        name="ishastra-worker-health",
        daemon=True,
    )
    _server_thread.start()
    log.info("Health/metrics server listening on %s:%d", health_host, health_port)

    _shutdown_event.wait()

    log.info("Shutdown signal received, stopping...")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(_shutdown_worker(timeout=30.0))
    finally:
        loop.close()

    log.info("Worker stopped cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
