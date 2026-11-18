"""Unit tests for Strix body depth middleware (src/strix/api/body_depth.py).

Tests cover: json_depth calculation, rejection responses, and BodyLimitMiddleware
ASGI middleware behavior for size and nesting limits.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from strix.api.body_depth import (
    _BODY_METHODS,
    MAX_BODY_BYTES,
    MAX_NESTING_DEPTH,
    BodyLimitMiddleware,
    _get_max_body_bytes,
    _send_rejection,
    json_depth,
)

# ---------------------------------------------------------------------------
# json_depth Unit Tests
# ---------------------------------------------------------------------------


class TestJsonDepth:
    """Tests for the json_depth function."""

    def test_empty_object(self):
        """Test depth of empty object."""
        assert json_depth({}) == 1

    def test_empty_array(self):
        """Test depth of empty array."""
        assert json_depth([]) == 1

    def test_simple_object(self):
        """Test depth of flat object."""
        assert json_depth({"a": 1, "b": "string", "c": True}) == 1

    def test_simple_array(self):
        """Test depth of flat array."""
        assert json_depth([1, "string", True, None]) == 1

    def test_nested_object(self):
        """Test depth of nested object."""
        assert json_depth({"a": {"b": {"c": 1}}}) == 3

    def test_nested_array(self):
        """Test depth of nested array."""
        assert json_depth([[[1]]]) == 3

    def test_mixed_nesting(self):
        """Test depth with mixed objects and arrays."""
        data = {"a": [{"b": {"c": [1, 2, 3]}}]}
        # dict > list > dict > dict > list: five containers
        assert json_depth(data) == 5

    def test_siblings_at_different_depths(self):
        """Test depth takes maximum across siblings."""
        data = {"shallow": 1, "deep": {"a": {"b": {"c": 1}}}}
        assert json_depth(data) == 4

    def test_large_flat_structure(self):
        """Test large flat structure has depth 1."""
        data = {f"key{i}": i for i in range(1000)}
        assert json_depth(data) == 1

    def test_max_nesting_at_limit(self):
        """Test depth at exactly MAX_NESTING_DEPTH."""
        data = {"a": 1}
        for _ in range(MAX_NESTING_DEPTH - 1):
            data = {"nested": data}
        assert json_depth(data) == MAX_NESTING_DEPTH

    def test_max_nesting_exceeds_limit(self):
        """Test depth exceeding MAX_NESTING_DEPTH."""
        data = {"a": 1}
        for _ in range(MAX_NESTING_DEPTH):
            data = {"nested": data}
        assert json_depth(data) == MAX_NESTING_DEPTH + 1

    def test_primitives_return_zero(self):
        """Test primitives (not containers) return depth 0."""
        assert json_depth("string") == 0
        assert json_depth(123) == 0
        assert json_depth(12.34) == 0
        assert json_depth(True) == 0
        assert json_depth(False) == 0
        assert json_depth(None) == 0

    def test_string_in_container(self):
        """Test strings inside containers don't increase depth."""
        assert json_depth({"a": "very long string value"}) == 1
        assert json_depth(["item1", "item2"]) == 1


# ---------------------------------------------------------------------------
# _send_rejection Unit Tests
# ---------------------------------------------------------------------------


class TestSendRejection:
    """Tests for the _send_rejection helper function."""

    @pytest.mark.asyncio
    async def test_send_rejection_basic(self):
        """Test basic rejection response."""
        scope = {"type": "http", "method": "POST", "state": {}}
        receive = AsyncMock()
        send = AsyncMock()

        await _send_rejection(scope, receive, send, 413, "Request too large")

        send.assert_called()
        # Verify response was sent via JSONResponse
        calls = send.call_args_list
        assert len(calls) >= 2  # start + body

    @pytest.mark.asyncio
    async def test_send_rejection_with_request_id(self):
        """Test rejection includes request ID from scope state."""
        scope = {
            "type": "http",
            "method": "POST",
            "state": {"request_id": "req-123"},
        }
        receive = AsyncMock()
        send = AsyncMock()

        await _send_rejection(scope, receive, send, 400, "Bad request")

        # Check that response includes X-Request-ID header
        send_calls = send.call_args_list
        start_call = send_calls[0]
        assert start_call[0][0]["type"] == "http.response.start"
        headers = dict(start_call[0][0]["headers"])
        assert b"x-request-id" in headers
        assert headers[b"x-request-id"] == b"req-123"

    @pytest.mark.asyncio
    async def test_send_rejection_with_custom_headers(self):
        """Test rejection includes custom headers."""
        scope = {"type": "http", "method": "POST", "state": {}}
        receive = AsyncMock()
        send = AsyncMock()
        custom_headers = {"X-Custom": "value"}

        await _send_rejection(scope, receive, send, 400, "Bad request", headers=custom_headers)

        send_calls = send.call_args_list
        start_call = send_calls[0]
        headers = dict(start_call[0][0]["headers"])
        assert b"x-custom" in headers
        assert headers[b"x-custom"] == b"value"

    @pytest.mark.asyncio
    async def test_send_rejection_status_and_body(self):
        """Test rejection has correct status code and JSON body."""
        scope = {"type": "http", "method": "POST", "state": {}}
        receive = AsyncMock()
        send = AsyncMock()

        await _send_rejection(scope, receive, send, 413, "Request body exceeds 100 bytes")

        send_calls = send.call_args_list
        start_call = send_calls[0]
        body_call = send_calls[1]

        assert start_call[0][0]["status"] == 413
        assert body_call[0][0]["type"] == "http.response.body"
        body = body_call[0][0]["body"]
        assert b"Request body exceeds 100 bytes" in body


# ---------------------------------------------------------------------------
# _get_max_body_bytes Unit Tests
# ---------------------------------------------------------------------------


class TestGetMaxBodyBytes:
    """Tests for the _get_max_body_bytes lazy accessor."""

    def test_uses_settings_when_constant_zero(self):
        """Test it uses Settings when MAX_BODY_BYTES is 0."""
        with (
            patch("strix.api.body_depth.MAX_BODY_BYTES", 0),
            patch("strix.api.body_depth.get_settings") as mock_settings,
        ):
            mock_settings.return_value.max_body_bytes = 5000
            result = _get_max_body_bytes()
            assert result == 5000

    def test_uses_constant_when_nonzero(self):
        """Test it uses MAX_BODY_BYTES when set."""
        with patch("strix.api.body_depth.MAX_BODY_BYTES", 10000):
            result = _get_max_body_bytes()
            assert result == 10000


# ---------------------------------------------------------------------------
# BodyLimitMiddleware Unit Tests
# ---------------------------------------------------------------------------


class TestBodyLimitMiddleware:
    """Tests for BodyLimitMiddleware ASGI middleware."""

    @pytest.fixture
    def mock_app(self):
        """Create a mock ASGI app."""
        return AsyncMock()

    @pytest.fixture
    def base_scope(self):
        """Base HTTP scope for testing."""
        return {
            "type": "http",
            "method": "POST",
            "path": "/test",
            "headers": [],
            "state": {},
        }

    @pytest.fixture
    def mock_receive(self):
        """Create a mock receive callable."""
        return AsyncMock()

    @pytest.fixture
    def mock_send(self):
        """Create a mock send callable."""
        return AsyncMock()

    # --- Non-HTTP and non-body method passthrough ---

    @pytest.mark.asyncio
    async def test_passthrough_non_http(self, mock_app, mock_receive, mock_send):
        """Middleware passes through non-HTTP scopes."""
        scope = {"type": "websocket", "method": "POST"}
        middleware = BodyLimitMiddleware(mock_app)

        await middleware(scope, mock_receive, mock_send)

        mock_app.assert_awaited_once_with(scope, mock_receive, mock_send)

    @pytest.mark.asyncio
    async def test_passthrough_get_method(self, mock_app, mock_receive, mock_send, base_scope):
        """Middleware passes through GET requests (no body expected)."""
        base_scope["method"] = "GET"
        middleware = BodyLimitMiddleware(mock_app)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once_with(base_scope, mock_receive, mock_send)

    @pytest.mark.asyncio
    async def test_passthrough_head_method(self, mock_app, mock_receive, mock_send, base_scope):
        """Middleware passes through HEAD requests."""
        base_scope["method"] = "HEAD"
        middleware = BodyLimitMiddleware(mock_app)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once_with(base_scope, mock_receive, mock_send)

    @pytest.mark.asyncio
    async def test_passthrough_options_method(self, mock_app, mock_receive, mock_send, base_scope):
        """Middleware passes through OPTIONS requests."""
        base_scope["method"] = "OPTIONS"
        middleware = BodyLimitMiddleware(mock_app)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once_with(base_scope, mock_receive, mock_send)

    @pytest.mark.asyncio
    async def test_processes_post_method(self, mock_app, mock_receive, mock_send, base_scope):
        """Middleware processes POST requests."""
        base_scope["method"] = "POST"
        base_scope["headers"] = [(b"content-length", b"10")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"hello", "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        # App should be called with replay_receive
        mock_app.assert_awaited_once()
        call_args = mock_app.call_args
        assert call_args[0][0] == base_scope
        # The receive function should be our replay_receive
        replay_receive = call_args[0][1]
        assert callable(replay_receive)

    @pytest.mark.asyncio
    async def test_processes_put_method(self, mock_app, mock_receive, mock_send, base_scope):
        """Middleware processes PUT requests."""
        base_scope["method"] = "PUT"
        base_scope["headers"] = [(b"content-length", b"10")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"hello", "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_processes_patch_method(self, mock_app, mock_receive, mock_send, base_scope):
        """Middleware processes PATCH requests."""
        base_scope["method"] = "PATCH"
        base_scope["headers"] = [(b"content-length", b"10")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"hello", "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_processes_delete_method(self, mock_app, mock_receive, mock_send, base_scope):
        """Middleware processes DELETE requests."""
        base_scope["method"] = "DELETE"
        base_scope["headers"] = [(b"content-length", b"10")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"hello", "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_case_insensitive_method(self, mock_app, mock_receive, mock_send, base_scope):
        """Middleware handles method case-insensitively."""
        base_scope["method"] = "post"  # lowercase
        base_scope["headers"] = [(b"content-length", b"10")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"hello", "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once()

    # --- Content-Length validation ---

    @pytest.mark.asyncio
    async def test_invalid_content_length_non_numeric(self, mock_app, mock_receive, mock_send, base_scope):
        """Rejects request with non-numeric Content-Length."""
        base_scope["headers"] = [(b"content-length", b"not-a-number")]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_not_awaited()
        mock_send.assert_called()
        start_call = mock_send.call_args_list[0]
        assert start_call[0][0]["status"] == 400
        body_call = mock_send.call_args_list[1]
        assert b"Invalid Content-Length" in body_call[0][0]["body"]

    @pytest.mark.asyncio
    async def test_invalid_content_length_negative(self, mock_app, mock_receive, mock_send, base_scope):
        """Rejects request with negative Content-Length."""
        base_scope["headers"] = [(b"content-length", b"-100")]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_not_awaited()
        mock_send.assert_called()
        start_call = mock_send.call_args_list[0]
        assert start_call[0][0]["status"] == 400

    @pytest.mark.asyncio
    async def test_content_length_exceeds_limit_rejected(self, mock_app, mock_receive, mock_send, base_scope):
        """Rejects request when Content-Length exceeds limit."""
        base_scope["headers"] = [(b"content-length", b"200")]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_not_awaited()
        mock_send.assert_called()
        start_call = mock_send.call_args_list[0]
        assert start_call[0][0]["status"] == 413
        body_call = mock_send.call_args_list[1]
        assert b"exceeds 100 bytes" in body_call[0][0]["body"]

    @pytest.mark.asyncio
    async def test_content_length_at_limit_accepted(self, mock_app, mock_receive, mock_send, base_scope):
        """Accepts request when Content-Length equals limit."""
        base_scope["headers"] = [(b"content-length", b"100")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"x" * 100, "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_no_content_length_streaming(self, mock_app, mock_receive, mock_send, base_scope):
        """Handles requests without Content-Length by counting chunks."""
        base_scope["headers"] = []  # No Content-Length
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"chunk1", "more_body": True},
            {"type": "http.request", "body": b"chunk2", "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once()

    # --- Body size limit during streaming ---

    @pytest.mark.asyncio
    async def test_streaming_body_exceeds_limit_rejected(self, mock_app, mock_receive, mock_send, base_scope):
        """Rejects streaming request when accumulated body exceeds limit."""
        base_scope["headers"] = []
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"x" * 50, "more_body": True},
            {"type": "http.request", "body": b"x" * 60, "more_body": False},  # Total 110 > 100
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_not_awaited()
        mock_send.assert_called()
        start_call = mock_send.call_args_list[0]
        assert start_call[0][0]["status"] == 413
        body_call = mock_send.call_args_list[1]
        assert b"exceeds 100 bytes" in body_call[0][0]["body"]

    @pytest.mark.asyncio
    async def test_streaming_body_at_limit_accepted(self, mock_app, mock_receive, mock_send, base_scope):
        """Accepts streaming request when accumulated body equals limit."""
        base_scope["headers"] = []
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"x" * 50, "more_body": True},
            {"type": "http.request", "body": b"x" * 50, "more_body": False},  # Total 100
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once()

    # --- Request disconnect handling ---

    @pytest.mark.asyncio
    async def test_client_disconnect_before_complete(self, mock_app, mock_receive, mock_send, base_scope):
        """Handles client disconnect during body reading."""
        base_scope["headers"] = []
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"partial", "more_body": True},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        # Should not call app when client disconnects
        mock_app.assert_not_awaited()
        # Should not send rejection response (peer already gone)
        # The middleware just returns silently

    # --- JSON nesting depth validation ---

    @pytest.mark.asyncio
    async def test_json_within_nesting_limit(self, mock_app, mock_receive, mock_send, base_scope):
        """Accepts JSON body within nesting limit."""
        body = json.dumps({"a": {"b": {"c": 1}}})  # depth 3
        base_scope["headers"] = [(b"content-type", b"application/json")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": body.encode(), "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000, max_nesting_depth=10)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_json_exceeds_nesting_limit_rejected(self, mock_app, mock_receive, mock_send, base_scope):
        """Rejects JSON body exceeding nesting limit."""
        # Create JSON with depth 11 (exceeds default MAX_NESTING_DEPTH of 10)
        data = {"a": 1}
        for _ in range(11):
            data = {"nested": data}
        body = json.dumps(data)

        base_scope["headers"] = [(b"content-type", b"application/json")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": body.encode(), "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000, max_nesting_depth=10)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_not_awaited()
        mock_send.assert_called()
        start_call = mock_send.call_args_list[0]
        assert start_call[0][0]["status"] == 400
        body_call = mock_send.call_args_list[1]
        assert b"nesting depth" in body_call[0][0]["body"]
        assert b"exceeds maximum allowed" in body_call[0][0]["body"]

    @pytest.mark.asyncio
    async def test_json_nesting_limit_custom(self, mock_app, mock_receive, mock_send, base_scope):
        """Respects custom max_nesting_depth parameter."""
        # Depth 5 JSON
        data = {"a": 1}
        for _ in range(4):
            data = {"nested": data}
        body = json.dumps(data)  # depth 5

        base_scope["headers"] = [(b"content-type", b"application/json")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": body.encode(), "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000, max_nesting_depth=4)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_not_awaited()
        mock_send.assert_called()
        start_call = mock_send.call_args_list[0]
        assert start_call[0][0]["status"] == 400

    @pytest.mark.asyncio
    async def test_invalid_json_passes_through(self, mock_app, mock_receive, mock_send, base_scope):
        """Invalid JSON passes through (downstream parser handles it)."""
        base_scope["headers"] = [(b"content-type", b"application/json")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"{ invalid json }", "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000)

        await middleware(base_scope, mock_receive, mock_send)

        # Should pass through to downstream app (which will handle JSON parse error)
        mock_app.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_non_json_body_skips_nesting_check(self, mock_app, mock_receive, mock_send, base_scope):
        """Non-JSON bodies skip nesting depth validation."""
        base_scope["headers"] = [(b"content-type", b"text/plain")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"plain text body", "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000, max_nesting_depth=1)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_json_detected_by_body_start(self, mock_app, mock_receive, mock_send, base_scope):
        """JSON detected by body starting with { or [ even without content-type."""
        body = b'{"key": "value"}'
        base_scope["headers"] = [(b"content-type", b"text/plain")]  # Wrong content-type
        mock_receive.side_effect = [
            {"type": "http.request", "body": body, "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000, max_nesting_depth=10)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_array_json_detected(self, mock_app, mock_receive, mock_send, base_scope):
        """JSON array detected by body starting with [."""
        body = b"[1, 2, 3]"
        base_scope["headers"] = [(b"content-type", b"text/plain")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": body, "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000, max_nesting_depth=10)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_whitespace_before_json_brace(self, mock_app, mock_receive, mock_send, base_scope):
        """JSON detected with leading whitespace."""
        body = b'  \n\t{"key": "value"}'
        base_scope["headers"] = [(b"content-type", b"text/plain")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": body, "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000, max_nesting_depth=10)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once()

    # --- Body replay to downstream app ---

    @pytest.mark.asyncio
    async def test_body_replayed_to_downstream(self, mock_app, mock_receive, mock_send, base_scope):
        """Body is replayed to downstream app via custom receive."""
        original_body = b'{"test": "data"}'
        base_scope["headers"] = [(b"content-length", str(len(original_body)).encode())]
        mock_receive.side_effect = [
            {"type": "http.request", "body": original_body, "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000)

        await middleware(base_scope, mock_receive, mock_send)

        # Get the replay_receive function passed to app
        call_args = mock_app.call_args
        replay_receive = call_args[0][1]

        # Call replay_receive to get the body
        message = await replay_receive()
        assert message["type"] == "http.request"
        assert message["body"] == original_body
        assert message["more_body"] is False

    @pytest.mark.asyncio
    async def test_replay_receive_called_once(self, mock_app, mock_receive, mock_send, base_scope):
        """Replay receive returns body only once, then delegates to original receive."""
        original_body = b"test"
        base_scope["headers"] = [(b"content-length", str(len(original_body)).encode())]
        mock_receive.side_effect = [
            {"type": "http.request", "body": original_body, "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000)

        await middleware(base_scope, mock_receive, mock_send)

        call_args = mock_app.call_args
        replay_receive = call_args[0][1]

        # First call returns buffered body
        msg1 = await replay_receive()
        assert msg1["body"] == original_body

        # Second call delegates to original receive
        mock_receive.reset_mock()
        mock_receive.return_value = {"type": "http.disconnect"}
        msg2 = await replay_receive()
        assert msg2["type"] == "http.disconnect"
        mock_receive.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_empty_body_replayed(self, mock_app, mock_receive, mock_send, base_scope):
        """Empty body is replayed correctly."""
        base_scope["headers"] = [(b"content-length", b"0")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"", "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000)

        await middleware(base_scope, mock_receive, mock_send)

        call_args = mock_app.call_args
        replay_receive = call_args[0][1]

        message = await replay_receive()
        assert message["body"] == b""
        assert message["more_body"] is False

    # --- Max body bytes override ---

    @pytest.mark.asyncio
    async def test_max_body_bytes_override_via_constructor(
        self, mock_app, mock_receive, mock_send, base_scope
    ):
        """Constructor max_body_bytes overrides module constant."""
        with (
            patch("strix.api.body_depth.MAX_BODY_BYTES", 0),
            patch("strix.api.body_depth.get_settings") as mock_settings,
        ):
            mock_settings.return_value.max_body_bytes = 5000
            base_scope["headers"] = [(b"content-length", b"100")]
            mock_receive.side_effect = [
                {"type": "http.request", "body": b"x" * 100, "more_body": False},
                {"type": "http.disconnect"},
            ]
            # Override with 50 bytes limit
            middleware = BodyLimitMiddleware(mock_app, max_body_bytes=50)

            await middleware(base_scope, mock_receive, mock_send)

            mock_app.assert_not_awaited()
            mock_send.assert_called()
            start_call = mock_send.call_args_list[0]
            assert start_call[0][0]["status"] == 413

    @pytest.mark.asyncio
    async def test_max_body_bytes_from_settings(self, mock_app, mock_receive, mock_send, base_scope):
        """Uses Settings when constructor param is None and MAX_BODY_BYTES is 0."""
        with (
            patch("strix.api.body_depth.MAX_BODY_BYTES", 0),
            patch("strix.api.body_depth.get_settings") as mock_settings,
        ):
            mock_settings.return_value.max_body_bytes = 200
            base_scope["headers"] = [(b"content-length", b"150")]
            mock_receive.side_effect = [
                {"type": "http.request", "body": b"x" * 150, "more_body": False},
                {"type": "http.disconnect"},
            ]
            middleware = BodyLimitMiddleware(mock_app, max_body_bytes=None)

            await middleware(base_scope, mock_receive, mock_send)

            mock_app.assert_awaited_once()

    # --- Edge cases ---

    @pytest.mark.asyncio
    async def test_multiple_chunks_combined(self, mock_app, mock_receive, mock_send, base_scope):
        """Multiple body chunks are combined correctly."""
        base_scope["headers"] = []
        mock_receive.side_effect = [
            {"type": "http.request", "body": b"chunk1", "more_body": True},
            {"type": "http.request", "body": b"chunk2", "more_body": True},
            {"type": "http.request", "body": b"chunk3", "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000)

        await middleware(base_scope, mock_receive, mock_send)

        call_args = mock_app.call_args
        replay_receive = call_args[0][1]
        message = await replay_receive()
        assert message["body"] == b"chunk1chunk2chunk3"

    @pytest.mark.asyncio
    async def test_content_type_case_insensitive(self, mock_app, mock_receive, mock_send, base_scope):
        """Content-Type check is case-insensitive."""
        body = json.dumps({"a": {"b": 1}})
        base_scope["headers"] = [(b"content-type", b"APPLICATION/JSON")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": body.encode(), "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000, max_nesting_depth=1)

        await middleware(base_scope, mock_receive, mock_send)

        # Depth is 2, limit is 1, so should reject
        mock_app.assert_not_awaited()
        mock_send.assert_called()

    @pytest.mark.asyncio
    async def test_content_type_with_charset(self, mock_app, mock_receive, mock_send, base_scope):
        """Content-Type with charset still detected as JSON."""
        body = json.dumps({"a": 1})
        base_scope["headers"] = [(b"content-type", b"application/json; charset=utf-8")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": body.encode(), "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000, max_nesting_depth=10)

        await middleware(base_scope, mock_receive, mock_send)

        mock_app.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_recursion_error_in_json_parse(self, mock_app, mock_receive, mock_send, base_scope):
        """RecursionError during JSON parsing is caught and rejected."""
        body = b'{"a": 1}'
        base_scope["headers"] = [(b"content-type", b"application/json")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": body, "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000)

        with patch("strix.api.body_depth.json.loads", side_effect=RecursionError()):
            await middleware(base_scope, mock_receive, mock_send)

            mock_app.assert_not_awaited()
            mock_send.assert_called()
            start_call = mock_send.call_args_list[0]
            assert start_call[0][0]["status"] == 400
            body_call = mock_send.call_args_list[1]
            assert b"nesting is too deep" in body_call[0][0]["body"]

    @pytest.mark.asyncio
    async def test_request_id_in_rejection_response(self, mock_app, mock_receive, mock_send, base_scope):
        """Request ID from scope state included in rejection response."""
        base_scope["state"] = {"request_id": "test-req-456"}
        base_scope["headers"] = [(b"content-length", b"200")]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=100)

        await middleware(base_scope, mock_receive, mock_send)

        mock_send.assert_called()
        start_call = mock_send.call_args_list[0]
        headers = dict(start_call[0][0]["headers"])
        assert headers.get(b"x-request-id") == b"test-req-456"

    @pytest.mark.asyncio
    async def test_nesting_depth_header_in_rejection(self, mock_app, mock_receive, mock_send, base_scope):
        """X-Nesting-Depth header included when nesting limit exceeded."""
        data = {"a": 1}
        for _ in range(11):
            data = {"nested": data}
        body = json.dumps(data)

        base_scope["headers"] = [(b"content-type", b"application/json")]
        mock_receive.side_effect = [
            {"type": "http.request", "body": body.encode(), "more_body": False},
            {"type": "http.disconnect"},
        ]
        middleware = BodyLimitMiddleware(mock_app, max_body_bytes=1000, max_nesting_depth=10)

        await middleware(base_scope, mock_receive, mock_send)

        mock_send.assert_called()
        start_call = mock_send.call_args_list[0]
        headers = dict(start_call[0][0]["headers"])
        assert b"x-nesting-depth" in headers
        assert headers[b"x-nesting-depth"] == b"12"


# ---------------------------------------------------------------------------
# Module Constants Tests
# ---------------------------------------------------------------------------


class TestModuleConstants:
    """Tests for module-level constants."""

    def test_max_nesting_depth_value(self):
        """MAX_NESTING_DEPTH has expected default value."""
        assert MAX_NESTING_DEPTH == 10

    def test_max_body_bytes_default_zero(self):
        """MAX_BODY_BYTES defaults to 0 (use Settings)."""
        assert MAX_BODY_BYTES == 0

    def test_body_methods_set(self):
        """_BODY_METHODS contains expected HTTP methods."""
        assert frozenset({"POST", "PUT", "PATCH", "DELETE"}) == _BODY_METHODS

    def test_body_methods_immutable(self):
        """_BODY_METHODS is a frozenset (immutable)."""
        assert isinstance(_BODY_METHODS, frozenset)
