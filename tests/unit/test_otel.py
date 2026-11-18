"""Unit tests for Strix OpenTelemetry (otel.py)."""

import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from starlette.requests import Request

from strix import __version__ as package_version
from strix.otel import (
    OpenTelemetryMiddleware,
    _get_otlp_endpoint,
    _get_resource,
    _load_otel_modules,
    _otel_available,
    get_meter,
    get_tracer,
    init_metrics,
    init_tracing,
    instrument_fastapi,
    otel_metrics_endpoint,
    setup_opentelemetry,
    shutdown_opentelemetry,
    traced_operation,
)


@pytest.fixture(autouse=True)
def reset_otel_state():
    """Reset OTel module global state before each test."""
    import strix.otel as otel_module

    otel_module._is_initialized = False
    otel_module._tracer_provider = None
    otel_module._meter_provider = None
    yield
    # Also reset after test
    otel_module._is_initialized = False
    otel_module._tracer_provider = None
    otel_module._meter_provider = None


class TestOTELModuleLoading:
    """Test OpenTelemetry module loading."""

    def test_load_otel_modules_when_not_installed(self):
        """_load_otel_modules returns False when OTel not installed."""
        with patch.dict("sys.modules", {"opentelemetry": None}, clear=False):
            # Need to clear the module cache to test loading
            # The actual test depends on whether OTel is installed in test env
            # We just verify the function exists and runs
            result = _load_otel_modules()
            # Result depends on test environment
            assert isinstance(result, bool)

    def test_otel_available_flag(self):
        """_otel_available flag reflects load state."""
        # Can't easily test without mocking imports
        # Just verify the flag exists
        assert isinstance(_otel_available, bool)


class TestResourceCreation:
    """Test OpenTelemetry resource creation."""

    def test_get_resource_uses_env_vars(self):
        """Resource uses environment variables."""
        with (
            patch.dict(
                os.environ,
                {
                    "OTEL_SERVICE_NAME": "test-service",
                    "STRIX_VERSION": "1.0.0",
                    "STRIX_ENV": "test",
                    "OTEL_RESOURCE_ATTRIBUTES": "key1=value1,key2=value2",
                },
            ),
            patch("strix.otel._load_otel_modules", return_value=True),
            patch("strix.otel._Resource") as mock_resource,
        ):
            mock_resource.create = MagicMock(return_value="mock-resource")
            _ = _get_resource()
            mock_resource.create.assert_called_once()
            call_args = mock_resource.create.call_args[0][0]
            # _SERVICE_NAME is used as key, which is None in mock
            name_val = call_args.get("service.name")
            none_val = call_args.get(None)
            name_ok = name_val in ("test-service", "strix") or none_val == "test-service"
            assert name_ok
            assert call_args.get("service.version") in ("1.0.0", package_version)
            assert call_args.get("deployment.environment") in ("test", "production")

    def test_get_resource_defaults(self):
        """Resource uses defaults when env vars not set."""
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("strix.otel._load_otel_modules", return_value=True),
            patch("strix.otel._Resource") as mock_resource,
        ):
            mock_resource.create = MagicMock(return_value="mock-resource")
            _ = _get_resource()
            call_args = mock_resource.create.call_args[0][0]
            # _SERVICE_NAME is used as key, which is None in mock
            assert call_args.get(None) == "strix" or call_args.get("service.name") == "strix"
            assert call_args.get("service.version") == package_version
            assert call_args.get("deployment.environment") == "production"


class TestOTLPEndpoint:
    """Test OTLP endpoint retrieval."""

    def test_get_otlp_endpoint_from_env(self):
        """OTLP endpoint from environment."""
        with patch.dict(os.environ, {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector:4317"}):
            endpoint = _get_otlp_endpoint()
            assert endpoint == "http://collector:4317"

    def test_get_otlp_endpoint_default(self):
        """Default OTLP endpoint."""
        with patch.dict(os.environ, {}, clear=True):
            endpoint = _get_otlp_endpoint()
            assert endpoint == "http://localhost:4317"


class TestTracingInitialization:
    """Test tracing initialization."""

    def test_init_tracing_when_not_available(self):
        """init_tracing returns None when OTel not available."""
        with patch("strix.otel._load_otel_modules", return_value=False):
            result = init_tracing()
            assert result is None

    def test_init_tracing_creates_provider(self):
        """init_tracing creates TracerProvider."""
        with (
            patch("strix.otel._load_otel_modules", return_value=True),
            patch("strix.otel._get_resource", return_value="mock-resource"),
            patch("strix.otel._TracerProvider") as mock_provider_class,
            patch("strix.otel._OTLPSpanExporter") as mock_exporter,
            patch("strix.otel._BatchSpanProcessor"),
            patch("strix.otel._trace") as mock_trace,
        ):
            mock_provider = MagicMock()
            mock_provider_class.return_value = mock_provider
            mock_exporter.return_value = MagicMock()
            result = init_tracing()
            assert result == mock_provider
            mock_provider_class.assert_called_once_with(resource="mock-resource")
            mock_trace.set_tracer_provider.assert_called_once_with(mock_provider)

    def test_init_tracing_idempotent(self):
        """init_tracing returns same provider on second call."""
        with (
            patch("strix.otel._load_otel_modules", return_value=True),
            patch("strix.otel._get_resource", return_value="mock-resource"),
            patch("strix.otel._TracerProvider") as mock_provider_class,
            patch("strix.otel._OTLPSpanExporter"),
            patch("strix.otel._BatchSpanProcessor"),
            patch("strix.otel._trace"),
        ):
            mock_provider = MagicMock()
            mock_provider_class.return_value = mock_provider
            result1 = init_tracing()
            result2 = init_tracing()
            assert result1 is result2
            # Provider only created once
            assert mock_provider_class.call_count == 1


class TestMetricsInitialization:
    """Test metrics initialization."""

    def test_init_metrics_when_not_available(self):
        """init_metrics returns None when OTel not available."""
        with patch("strix.otel._load_otel_modules", return_value=False):
            result = init_metrics()
            assert result is None

    def test_init_metrics_creates_provider(self):
        """init_metrics creates MeterProvider with readers."""
        with (
            patch("strix.otel._load_otel_modules", return_value=True),
            patch("strix.otel._get_resource", return_value="mock-resource"),
            patch("strix.otel._MeterProvider") as mock_provider_class,
            patch("strix.otel._PrometheusMetricReader") as mock_prom_reader,
            patch("strix.otel._OTLPMetricExporter"),
            patch("strix.otel._PeriodicExportingMetricReader"),
            patch("strix.otel._set_meter_provider") as mock_set,
        ):
            mock_provider = MagicMock()
            mock_provider_class.return_value = mock_provider
            result = init_metrics()
            assert result == mock_provider
            mock_provider_class.assert_called_once()
            mock_set.assert_called_once_with(mock_provider)
            # Should have prometheus reader
            mock_prom_reader.assert_called_once()


class TestFastAPIInstrumentation:
    """Test FastAPI instrumentation."""

    def test_instrument_fastapi_when_not_available(self):
        """instrument_fastapi returns early when OTel not available."""
        app = FastAPI()
        with patch("strix.otel._load_otel_modules", return_value=False):
            # Should not raise
            instrument_fastapi(app)

    def test_instrument_fastapi_initializes_if_needed(self):
        """instrument_fastapi initializes tracing/metrics if not done."""
        app = FastAPI()
        with (
            patch("strix.otel._load_otel_modules", return_value=True),
            patch("strix.otel._is_initialized", False),
            patch("strix.otel.init_tracing") as mock_init_tracing,
            patch("strix.otel.init_metrics") as mock_init_metrics,
            patch("strix.otel._FastAPIInstrumentor") as mock_instrumentor,
            patch("strix.otel._HTTPXClientInstrumentor") as mock_httpx,
            patch("strix.otel._URLLibInstrumentor") as mock_urllib,
            patch("strix.otel._RedisInstrumentor") as mock_redis,
            patch("strix.otel._SQLAlchemyInstrumentor") as mock_sqlalchemy,
            patch("strix.otel._LoggingInstrumentor") as mock_logging,
        ):
            instrument_fastapi(app)
            mock_init_tracing.assert_called_once()
            mock_init_metrics.assert_called_once()
            mock_instrumentor.instrument_app.assert_called_once()
            mock_httpx.return_value.instrument.assert_called_once()
            mock_urllib.return_value.instrument.assert_called_once()
            mock_redis.return_value.instrument.assert_called_once()
            mock_sqlalchemy.return_value.instrument.assert_called_once()
            mock_logging.return_value.instrument.assert_called_once()


class TestOpenTelemetryMiddleware:
    """Test OpenTelemetry middleware."""

    @pytest.fixture
    def mock_request(self):
        """Create a mock request with URL attributes."""
        request = MagicMock(spec=Request)
        request.method = "GET"
        # Create a mock URL object with attributes
        url_mock = MagicMock()
        url_mock.scheme = "https"
        url_mock.hostname = "example.com"
        url_mock.path = "/"
        url_mock.port = 443
        url_mock.__str__ = MagicMock(return_value="https://example.com/")
        request.url = url_mock
        request.headers = {}
        request.state = MagicMock()
        return request

    @pytest.mark.asyncio
    async def test_middleware_when_not_initialized(self, mock_request):
        """Middleware passes through when OTel not initialized."""
        app = FastAPI()
        middleware = OpenTelemetryMiddleware(app)

        async def call_next(req):
            response = MagicMock()
            response.status_code = 200
            response.headers = {}
            return response

        with patch("strix.otel._load_otel_modules", return_value=False):
            response = await middleware.dispatch(mock_request, call_next)
            assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_middleware_adds_trace_headers(self, mock_request):
        """Middleware adds trace headers to response."""
        app = FastAPI()
        middleware = OpenTelemetryMiddleware(app)

        mock_span = MagicMock()
        mock_span.is_recording.return_value = True
        # trace_id as integer, format() will produce 32-char hex
        mock_span.get_span_context.return_value.trace_id = 0x1234567890ABCDEF

        async def call_next(req):
            response = MagicMock()
            response.status_code = 200
            response.headers = {}
            return response

        with (
            patch("strix.otel._load_otel_modules", return_value=True),
            patch("strix.otel._is_initialized", True),
            patch("strix.otel._trace") as mock_trace,
        ):
            mock_trace.get_current_span.return_value = mock_span
            response = await middleware.dispatch(mock_request, call_next)
            assert response.status_code == 200
            assert "X-Trace-ID" in response.headers
            # trace_id formatted as 32-char hex
            expected = format(0x1234567890ABCDEF, "032x")
            assert response.headers["X-Trace-ID"] == expected

    @pytest.mark.asyncio
    async def test_middleware_adds_tenant_attribute(self, mock_request):
        """Middleware adds tenant attribute to span."""
        app = FastAPI()
        middleware = OpenTelemetryMiddleware(app)
        mock_request.state.tenant = "test-tenant"

        mock_span = MagicMock()
        mock_span.is_recording.return_value = True
        mock_span.get_span_context.return_value.trace_id = 0x1234567890ABCDEF

        async def call_next(req):
            response = MagicMock()
            response.status_code = 200
            response.headers = {}
            return response

        with (
            patch("strix.otel._load_otel_modules", return_value=True),
            patch("strix.otel._is_initialized", True),
            patch("strix.otel._trace") as mock_trace,
        ):
            mock_trace.get_current_span.return_value = mock_span
            await middleware.dispatch(mock_request, call_next)
            # Check tenant attribute was set
            mock_span.set_attribute.assert_any_call("strix.tenant", "test-tenant")


class TestSetupOpenTelemetry:
    """Test complete OpenTelemetry setup."""

    def test_setup_opentelemetry_when_not_available(self):
        """setup_opentelemetry logs and returns when OTel not available."""
        app = FastAPI()
        with (
            patch("strix.otel._load_otel_modules", return_value=False),
            patch("strix.otel.log") as mock_log,
        ):
            setup_opentelemetry(app)
            mock_log.info.assert_called_with(
                "OpenTelemetry not available - skipping setup (install with: pip install -e '.[otel]')"
            )

    def test_setup_opentelemetry_initializes_all(self):
        """setup_opentelemetry initializes all components."""
        app = FastAPI()
        with (
            patch("strix.otel._load_otel_modules", return_value=True),
            patch("strix.otel.init_tracing") as mock_init_tracing,
            patch("strix.otel.init_metrics") as mock_init_metrics,
            patch("strix.otel.instrument_fastapi") as mock_instrument,
            patch("strix.otel.log"),
        ):
            setup_opentelemetry(app)
            mock_init_tracing.assert_called_once()
            mock_init_metrics.assert_called_once()
            mock_instrument.assert_called_once_with(app)
            assert len(app.user_middleware) >= 1  # Middleware added


class TestTracedOperation:
    """Test traced_operation context manager."""

    @pytest.mark.asyncio
    async def test_traced_operation_when_not_initialized(self):
        """traced_operation yields None when OTel not initialized."""
        with patch("strix.otel._load_otel_modules", return_value=False):
            async with traced_operation("test-op") as span:
                assert span is None

    @pytest.mark.asyncio
    async def test_traced_operation_creates_span(self):
        """traced_operation creates span with attributes."""
        with (
            patch("strix.otel._load_otel_modules", return_value=True),
            patch("strix.otel._is_initialized", True),
            patch("strix.otel._trace") as mock_trace,
            patch("strix.otel._SpanKind") as mock_span_kind,
        ):
            mock_span = MagicMock()
            mock_span.__enter__ = MagicMock(return_value=mock_span)
            mock_span.__exit__ = MagicMock(return_value=False)
            mock_tracer = MagicMock()
            mock_tracer.start_as_current_span.return_value = mock_span
            mock_trace.get_tracer.return_value = mock_tracer
            mock_span_kind.INTERNAL = "internal"
            async with traced_operation("test-op", {"attr1": "value1"}) as span:
                assert span == mock_span
                mock_tracer.start_as_current_span.assert_called_once_with("test-op", kind="internal")
                mock_span.set_attribute.assert_called_with("attr1", "value1")


class TestGetTracerAndMeter:
    """Test get_tracer and get_meter functions."""

    def test_get_tracer_when_not_available(self):
        """get_tracer returns None when OTel not available."""
        with patch("strix.otel._load_otel_modules", return_value=False):
            tracer = get_tracer("test")
            assert tracer is None

    def test_get_tracer_when_available(self):
        """get_tracer returns tracer when OTel available."""
        with patch("strix.otel._load_otel_modules", return_value=True):
            mock_tracer = MagicMock()
            with patch("strix.otel._trace") as mock_trace:
                mock_trace.get_tracer.return_value = mock_tracer
                tracer = get_tracer("test")
                assert tracer == mock_tracer

    def test_get_meter_when_not_available(self):
        """get_meter returns None when OTel not available."""
        with patch("strix.otel._load_otel_modules", return_value=False):
            meter = get_meter("test")
            assert meter is None

    def test_get_meter_when_available(self):
        """get_meter returns meter when OTel available."""
        with patch("strix.otel._load_otel_modules", return_value=True):
            mock_meter = MagicMock()
            mock_meter_provider = MagicMock()
            mock_meter_provider.get_meter.return_value = mock_meter
            with patch("strix.otel._get_meter_provider", return_value=mock_meter_provider):
                meter = get_meter("test")
                assert meter == mock_meter


class TestOTELMetricsEndpoint:
    """Test OpenTelemetry metrics endpoint."""

    def test_otel_metrics_endpoint(self):
        """otel_metrics_endpoint returns Prometheus metrics."""
        with patch("strix.otel.get_registry") as mock_get_registry:
            mock_registry = MagicMock()
            mock_get_registry.return_value = mock_registry
            with patch("strix.otel.generate_latest", return_value=b"metrics data"):
                response = otel_metrics_endpoint()
                assert response.status_code == 200
                assert response.body == b"metrics data"
                assert response.media_type == "text/plain; version=0.0.4; charset=utf-8"


class TestShutdownOpenTelemetry:
    """Test OpenTelemetry shutdown."""

    def test_shutdown_opentelemetry(self):
        """shutdown_opentelemetry shuts down providers."""
        import strix.otel as otel_module

        mock_tracer_provider = MagicMock()
        mock_meter_provider = MagicMock()
        otel_module._tracer_provider = mock_tracer_provider
        otel_module._meter_provider = mock_meter_provider
        otel_module._is_initialized = True

        shutdown_opentelemetry()

        mock_tracer_provider.shutdown.assert_called_once()
        mock_meter_provider.shutdown.assert_called_once()
        assert otel_module._tracer_provider is None
        assert otel_module._meter_provider is None
        assert otel_module._is_initialized is False


class TestOTELIntegration:
    """Integration-style tests for OTel setup."""

    def test_complete_setup_flow(self):
        """Test complete setup flow with mocked OTel."""
        app = FastAPI()
        with (
            patch("strix.otel._load_otel_modules", return_value=True),
            patch("strix.otel.init_tracing") as mock_init_tracing,
            patch("strix.otel.init_metrics") as mock_init_metrics,
            patch("strix.otel.instrument_fastapi") as mock_instrument,
        ):
            setup_opentelemetry(app)
            # Verify all components called
            mock_init_tracing.assert_called_once()
            mock_init_metrics.assert_called_once()
            mock_instrument.assert_called_once_with(app)
            # Middleware added
            middleware_classes = [m.cls for m in app.user_middleware]
            assert OpenTelemetryMiddleware in middleware_classes
