"""Bound request bodies before downstream middleware or route code sees them.

This is an ASGI middleware rather than a request-body convenience wrapper: it
counts bytes while streaming, so missing or inaccurate Content-Length headers
cannot make the application buffer an arbitrary payload. The accepted body is
replayed once to the downstream application after validation.
"""

from __future__ import annotations

import json
from typing import Any

from starlette.responses import JSONResponse

from strix.config import get_settings

MAX_NESTING_DEPTH = 10
MAX_BODY_BYTES = 0  # 0 = use get_settings().max_body_bytes
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _get_max_body_bytes() -> int:
    """Lazy accessor to avoid module-level settings capture."""
    return MAX_BODY_BYTES if MAX_BODY_BYTES > 0 else get_settings().max_body_bytes


def json_depth(value: Any) -> int:
    """Return maximum JSON container depth (both objects and arrays count)."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            container_depth = depth + 1
            deepest = max(deepest, container_depth)
            stack.extend((child, container_depth) for child in node.values())
        elif isinstance(node, list):
            container_depth = depth + 1
            deepest = max(deepest, container_depth)
            stack.extend((child, container_depth) for child in node)
    return deepest


async def _send_rejection(
    scope: dict[str, Any],
    receive: Any,
    send: Any,
    status_code: int,
    detail: str,
    headers: dict[str, str] | None = None,
) -> None:
    # Include request ID if available from RequestIDMiddleware
    request_id = scope.get("state", {}).get("request_id")
    response_headers = dict(headers or {})
    if request_id:
        response_headers["X-Request-ID"] = request_id
    response = JSONResponse(status_code=status_code, content={"detail": detail}, headers=response_headers)
    await response(scope, receive, send)


class BodyLimitMiddleware:
    """Enforce size and JSON nesting caps while consuming ASGI request chunks."""

    def __init__(
        self,
        app: Any,
        *,
        max_body_bytes: int | None = None,
        max_nesting_depth: int = MAX_NESTING_DEPTH,
    ):
        self.app = app
        self.max_body_bytes = max_body_bytes
        self.max_nesting_depth = max_nesting_depth

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("method", "").upper() not in _BODY_METHODS:
            await self.app(scope, receive, send)
            return

        # Allow runtime override via module-level constant for testing
        limit = _get_max_body_bytes()
        if self.max_body_bytes is not None and MAX_BODY_BYTES == 0:
            limit = self.max_body_bytes
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length.decode("ascii"))
                if declared_size < 0:
                    raise ValueError
            except (UnicodeDecodeError, ValueError):
                await _send_rejection(scope, receive, send, 400, "Invalid Content-Length")
                return
            if declared_size > limit:
                await _send_rejection(scope, receive, send, 413, f"Request body exceeds {limit} bytes")
                return

        # Buffer only after counting each chunk. This is bounded by max_body_bytes
        # even when Content-Length is absent, false, or the request is streamed.
        chunks: list[bytes] = []
        total = 0
        disconnected = False
        while True:
            message = await receive()
            message_type = message.get("type")
            if message_type == "http.disconnect":
                disconnected = True
                break
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > limit:
                await _send_rejection(scope, receive, send, 413, f"Request body exceeds {limit} bytes")
                return
            if chunk:
                chunks.append(chunk)
            if not message.get("more_body", False):
                break

        if disconnected:
            # The peer already disconnected; do not invoke handlers with partial data.
            return

        body = b"".join(chunks)
        content_type = headers.get(b"content-type", b"").decode("latin-1").lower()
        if body and ("application/json" in content_type or body.lstrip().startswith((b"{", b"["))):
            try:
                value = json.loads(body)
            except RecursionError:
                await _send_rejection(scope, receive, send, 400, "Request body nesting is too deep")
                return
            except (ValueError, UnicodeDecodeError):
                # The Pydantic/route parser returns the more specific invalid JSON error.
                value = None
            if value is not None:
                depth = json_depth(value)
                if depth > self.max_nesting_depth:
                    await _send_rejection(
                        scope,
                        receive,
                        send,
                        400,
                        f"Request body nesting depth ({depth}) exceeds maximum allowed "
                        f"({self.max_nesting_depth})",
                        headers={"X-Nesting-Depth": str(depth)},
                    )
                    return

        replayed = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            # After the buffered body, keep normal disconnect semantics.
            return await receive()

        await self.app(scope, replay_receive, send)
