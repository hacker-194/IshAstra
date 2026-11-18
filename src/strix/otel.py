"""OpenTelemetry instrumentation for Strix FastAPI application.

Provides distributed tracing, metrics export, and structured logging.
Configure via environment variables:
- OTEL_EXPORTER_OTLP_ENDPOINT: OTLP collector endpoint (default: http://localhost:4317)
- OTEL_SERVICE_NAME: Service name (default: strix)
- OTEL_RESOURCE_ATTRIBUTES: Additional resource attributes
- OTEL_PYTHON_FASTAPI_EXCLUDED_URLS: URLs to exclude from tracing

Optional dependencies: pip install -e ".[otel]"
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager, contextmanager
from typing import Any

from fastapi import FastAPI, Request
from prometheus_client import generate_latest
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse

from strix import __version__ as _package_version
from strix.metrics import get_registry

log = logging.getLogger(__name__)

# Optional OpenTelemetry imports - loaded lazily
_trace: Any = None
_OTLPSpanExporter: Any = None
_OTLPMetricExporter: Any = None
_PrometheusMetricReader: Any = None
_FastAPIInstrumentor: Any = None
_HTTPXClientInstrumentor: Any = None
_RedisInstrumentor: Any = None
_SQLAlchemyInstrumentor: Any = None
_URLLibInstrumentor: Any = None
_LoggingInstrumentor: Any = None
_get_meter_provider: Any = None
_set_meter_provider: Any = None
_MeterProvider: Any = None
_PeriodicExportingMetricReader: Any = None
_Resource: Any = None
_SERVICE_NAME: Any = None
_TracerProvider: Any = None
_BatchSpanProcessor: Any = None
_SpanKind: Any = None

_otel_available = False


def _load_otel_modules() -> bool:
    """Lazy load OpenTelemetry modules. Returns True if successful."""
    global _trace, _OTLPSpanExporter, _OTLPMetricExporter, _PrometheusMetricReader
    global _FastAPIInstrumentor, _HTTPXClientInstrumentor, _RedisInstrumentor
    global _SQLAlchemyInstrumentor, _URLLibInstrumentor, _LoggingInstrumentor
    global _get_meter_provider, _set_meter_provider, _MeterProvider
    global _PeriodicExportingMetricReader, _Resource, _SERVICE_NAME
    global _TracerProvider, _BatchSpanProcessor, _SpanKind, _otel_available

    if _otel_available:
        return True

    try:
        from opentelemetry import trace as _trace_mod
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
            OTLPMetricExporter as _OTLPMetricExporter_mod,
        )
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter as _OTLPSpanExporter_mod,
        )
        from opentelemetry.exporter.prometheus import PrometheusMetricReader as _PrometheusMetricReader_mod
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor as _FastAPIInstrumentor_mod
        from opentelemetry.instrumentation.httpx import (
            HTTPXClientInstrumentor as _HTTPXClientInstrumentor_mod,
        )
        from opentelemetry.instrumentation.logging import LoggingInstrumentor as _LoggingInstrumentor_mod
        from opentelemetry.instrumentation.redis import RedisInstrumentor as _RedisInstrumentor_mod
        from opentelemetry.instrumentation.sqlalchemy import (
            SQLAlchemyInstrumentor as _SQLAlchemyInstrumentor_mod,
        )
        from opentelemetry.instrumentation.urllib import URLLibInstrumentor as _URLLibInstrumentor_mod
        from opentelemetry.metrics import get_meter_provider as _get_meter_provider_mod
        from opentelemetry.metrics import set_meter_provider as _set_meter_provider_mod
        from opentelemetry.sdk.metrics import MeterProvider as _MeterProvider_mod
        from opentelemetry.sdk.metrics.export import (
            PeriodicExportingMetricReader as _PeriodicExportingMetricReader_mod,
        )
        from opentelemetry.sdk.resources import SERVICE_NAME as _SERVICE_NAME_mod
        from opentelemetry.sdk.resources import Resource as _Resource_mod
        from opentelemetry.sdk.trace import TracerProvider as _TracerProvider_mod
        from opentelemetry.sdk.trace.export import BatchSpanProcessor as _BatchSpanProcessor_mod
        from opentelemetry.trace import SpanKind as _SpanKind_mod

        _trace = _trace_mod
        _OTLPSpanExporter = _OTLPSpanExporter_mod
        _OTLPMetricExporter = _OTLPMetricExporter_mod
        _PrometheusMetricReader = _PrometheusMetricReader_mod
        _FastAPIInstrumentor = _FastAPIInstrumentor_mod
        _HTTPXClientInstrumentor = _HTTPXClientInstrumentor_mod
        _RedisInstrumentor = _RedisInstrumentor_mod
        _SQLAlchemyInstrumentor = _SQLAlchemyInstrumentor_mod
        _URLLibInstrumentor = _URLLibInstrumentor_mod
        _LoggingInstrumentor = _LoggingInstrumentor_mod
        _get_meter_provider = _get_meter_provider_mod
        _set_meter_provider = _set_meter_provider_mod
        _MeterProvider = _MeterProvider_mod
        _PeriodicExportingMetricReader = _PeriodicExportingMetricReader_mod
        _Resource = _Resource_mod
        _SERVICE_NAME = _SERVICE_NAME_mod
        _TracerProvider = _TracerProvider_mod
        _BatchSpanProcessor = _BatchSpanProcessor_mod
        _SpanKind = _SpanKind_mod

        _otel_available = True
        return True
    except ImportError as e:
        log.debug("OpenTelemetry modules not available: %s", e)
        return False


# Global state
_tracer_provider: Any = None
_meter_provider: Any = None
_is_initialized = False


def _get_resource():
    """Create OpenTelemetry resource with service information."""
    if not _load_otel_modules():
        return None
    service_name = os.getenv("OTEL_SERVICE_NAME", "strix")
    attributes = {
        _SERVICE_NAME: service_name,
        "service.version": os.getenv("STRIX_VERSION") or _package_version,
        "deployment.environment": os.getenv("STRIX_ENV", "production"),
    }

    # Parse additional resource attributes from OTEL_RESOURCE_ATTRIBUTES
    extra_attrs = os.getenv("OTEL_RESOURCE_ATTRIBUTES", "")
    if extra_attrs:
        for pair in extra_attrs.split(","):
            if "=" in pair:
                k, v = pair.split("=", 1)
                attributes[k.strip()] = v.strip()

    return _Resource.create(attributes)


def _get_otlp_endpoint() -> str:
    """Get OTLP endpoint from environment."""
    return os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")


def init_tracing():
    """Initialize OpenTelemetry tracing with OTLP exporter."""
    global _tracer_provider, _is_initialized

    if not _load_otel_modules():
        log.warning("OpenTelemetry not available - install with: pip install -e '.[otel]'")
        return None

    if _tracer_provider is not None:
        return _tracer_provider

    resource = _get_resource()
    _tracer_provider = _TracerProvider(resource=resource)

    # OTLP exporter for traces
    otlp_endpoint = _get_otlp_endpoint()
    try:
        span_exporter = _OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        _tracer_provider.add_span_processor(_BatchSpanProcessor(span_exporter))
        log.info("OpenTelemetry tracing initialized with OTLP endpoint: %s", otlp_endpoint)
    except Exception as e:
        log.warning("Failed to initialize OTLP trace exporter: %s", e)

    _trace.set_tracer_provider(_tracer_provider)
    _is_initialized = True
    return _tracer_provider


def init_metrics():
    """Initialize OpenTelemetry metrics with Prometheus and OTLP exporters."""
    global _meter_provider

    if not _load_otel_modules():
        log.warning("OpenTelemetry not available - install with: pip install -e '.[otel]'")
        return None

    if _meter_provider is not None:
        return _meter_provider

    resource = _get_resource()

    # Prometheus metric reader (for /api/metrics)
    prometheus_reader = _PrometheusMetricReader()

    # OTLP metric reader (for collector)
    otlp_endpoint = _get_otlp_endpoint()
    readers = [prometheus_reader]
    try:
        otlp_metric_exporter = _OTLPMetricExporter(endpoint=otlp_endpoint, insecure=True)
        otlp_reader = _PeriodicExportingMetricReader(otlp_metric_exporter, export_interval_millis=30000)
        readers.append(otlp_reader)
        log.info("OpenTelemetry metrics initialized with OTLP endpoint: %s", otlp_endpoint)
    except Exception as e:
        log.warning("Failed to initialize OTLP metric exporter: %s", e)

    _meter_provider = _MeterProvider(resource=resource, metric_readers=readers)
    _set_meter_provider(_meter_provider)
    return _meter_provider


def instrument_fastapi(app: FastAPI) -> None:
    """Instrument FastAPI application with OpenTelemetry."""
    if not _load_otel_modules():
        return

    if not _is_initialized:
        init_tracing()
        init_metrics()

    # Instrument FastAPI
    _FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=_tracer_provider,
        meter_provider=_meter_provider,
        excluded_urls=os.getenv("OTEL_PYTHON_FASTAPI_EXCLUDED_URLS", "/api/metrics,/health,/ready"),
    )

    # Instrument HTTP clients
    _HTTPXClientInstrumentor().instrument()
    _URLLibInstrumentor().instrument()

    # Instrument Redis
    _RedisInstrumentor().instrument()

    # Instrument SQLAlchemy (if used)
    _SQLAlchemyInstrumentor().instrument()

    # Instrument logging
    _LoggingInstrumentor().instrument(set_logging_format=True)

    log.info("OpenTelemetry instrumentation applied to FastAPI app")


class OpenTelemetryMiddleware(BaseHTTPMiddleware):
    """Middleware to add trace context to responses and handle custom attributes."""

    async def dispatch(self, request: Request, call_next):
        if not _load_otel_modules() or not _is_initialized:
            return await call_next(request)

        # Get or create span for this request
        span = _trace.get_current_span()
        if span and span.is_recording():
            # Add request attributes
            span.set_attribute("http.method", request.method)
            span.set_attribute("http.url", str(request.url))
            span.set_attribute("http.scheme", request.url.scheme)
            span.set_attribute("http.host", request.url.hostname or "")
            span.set_attribute("http.target", request.url.path)
            span.set_attribute(
                "net.host.port",
                str(request.url.port or (443 if request.url.scheme == "https" else 80)),
            )

            # Add tenant info if available
            if hasattr(request.state, "tenant"):
                span.set_attribute("strix.tenant", request.state.tenant)

        response = await call_next(request)

        if span and span.is_recording():
            span.set_attribute("http.status_code", response.status_code)
            if response.headers.get("content-length"):
                span.set_attribute("http.response_content_length", response.headers["content-length"])

        # Add trace headers to response
        if span and span.is_recording():
            trace_id = format(span.get_span_context().trace_id, "032x")
            response.headers["X-Trace-ID"] = trace_id

        return response


def setup_opentelemetry(app: FastAPI) -> None:
    """Complete OpenTelemetry setup for a FastAPI application."""
    if not _load_otel_modules():
        log.info("OpenTelemetry not available - skipping setup (install with: pip install -e '.[otel]')")
        return
    init_tracing()
    init_metrics()
    instrument_fastapi(app)
    app.add_middleware(OpenTelemetryMiddleware)
    log.info("OpenTelemetry setup complete")


@asynccontextmanager
async def traced_operation(name: str, attributes: dict[str, Any] | None = None):
    """Context manager for tracing custom operations."""
    if not _load_otel_modules() or not _is_initialized:
        yield None
        return

    tracer = _trace.get_tracer(__name__)
    with tracer.start_as_current_span(name, kind=_SpanKind.INTERNAL) as span:
        if attributes:
            for k, v in attributes.items():
                span.set_attribute(k, v)
        yield span


@contextmanager
def traced_span(name: str, attributes: dict[str, Any] | None = None):
    """Synchronous span for code outside the event loop; yields None when OTel is off."""
    if not _load_otel_modules() or not _is_initialized:
        yield None
        return

    tracer = _trace.get_tracer(__name__)
    with tracer.start_as_current_span(name, kind=_SpanKind.INTERNAL) as span:
        if attributes:
            for key, value in attributes.items():
                span.set_attribute(key, value)
        yield span


def get_tracer(name: str = __name__):
    """Get a tracer instance."""
    if not _load_otel_modules():
        return None
    return _trace.get_tracer(name)


def get_meter(name: str = __name__):
    """Get a meter instance."""
    if not _load_otel_modules():
        return None
    return _get_meter_provider().get_meter(name)


# Prometheus metrics endpoint that includes OpenTelemetry metrics
def otel_metrics_endpoint() -> PlainTextResponse:
    """Prometheus metrics endpoint including OpenTelemetry metrics."""
    registry = get_registry()
    # The PrometheusMetricReader automatically adds OTel metrics to the default registry
    # We just need to expose the combined output
    return PlainTextResponse(
        content=generate_latest(registry),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


def shutdown_opentelemetry() -> None:
    """Gracefully shutdown OpenTelemetry providers."""
    global _tracer_provider, _meter_provider, _is_initialized

    if _tracer_provider:
        _tracer_provider.shutdown()
        _tracer_provider = None

    if _meter_provider:
        _meter_provider.shutdown()
        _meter_provider = None

    _is_initialized = False
    log.info("OpenTelemetry shutdown complete")
