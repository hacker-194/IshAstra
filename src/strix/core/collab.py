"""Out-of-band canary listener (``strix-collab``) and its client.

Blind SSRF cannot be confirmed from the HTTP response alone, so the scanner
injects a unique canary URL pointing at this listener: a callback for that
exact token is direct evidence the application fetched it.

``CollabLog`` records callbacks (bounded; headers truncated, body never
stored), ``CollabServer`` is a minimal HTTP server that also answers
``GET /poll/<token>`` so a separate process can consume them, and
``CollabClient`` polls it. Tokens are 128-bit random hex.
"""
from __future__ import annotations

import argparse
import json
import re
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit
from urllib.request import urlopen

from strix.core.redaction import redact_text

TOKEN_PATTERN = re.compile(r"^[0-9a-f]{16,64}$")
MAX_CALLBACKS = 10_000
MAX_HEADER_BYTES = 2048


def new_token() -> str:
    """Return a 128-bit opaque callback token (32 hexadecimal characters)."""
    return secrets.token_hex(16)


@dataclass(frozen=True)
class CollabConfig:
    """Where the canary listener lives, from the scope document.

    ``port`` 0 means "start the in-process listener on ``host``" — the mode
    used for local engagements and the test suite. A positive port points at
    a listener managed elsewhere (``strix-collab`` or any compatible poll API).
    """

    host: str = "127.0.0.1"
    port: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CollabConfig:
        if not isinstance(data, dict):
            raise ValueError("collab configuration must be an object")
        host = str(data.get("host", "")).strip()
        if not host or len(host) > 253:
            raise ValueError("collab.host must be a usable host name or address")
        port = data.get("port", 0)
        if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
            raise ValueError("collab.port must be an integer from 0 to 65535")
        return cls(host=host, port=port)


class CollabLog:
    """Thread-safe, bounded store of callback events."""

    def __init__(self, max_entries: int = MAX_CALLBACKS) -> None:
        self._entries: deque[dict[str, Any]] = deque(maxlen=max_entries)
        self._lock = threading.Lock()

    def record(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self._entries.append(entry)

    def poll(self, token: str) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(entry) for entry in self._entries if entry.get("token") == token]

    def count(self) -> int:
        with self._lock:
            return len(self._entries)


class _CanaryHandler(BaseHTTPRequestHandler):
    """Records canary callbacks; serves the /poll API for external consumers."""

    log_store: CollabLog = CollabLog()

    def _respond(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _record(self) -> str | None:
        path = urlsplit(self.path).path
        token = path.lstrip("/").split("/", 1)[0]
        if not TOKEN_PATTERN.fullmatch(token):
            return None
        headers: dict[str, str] = {}
        sensitive_headers = {
            "authorization", "proxy-authorization", "cookie", "set-cookie",
            "x-api-key", "api-key", "x-auth-token", "x-access-token",
            "x-forwarded-access-token", "x-csrf-token",
        }
        budget = MAX_HEADER_BYTES
        for name, value in self.headers.items():
            if budget <= 0:
                break
            key = name.lower()[:64]
            clipped = value[:budget]
            budget -= len(clipped)
            headers[key] = "[REDACTED]" if key in sensitive_headers else redact_text(clipped)
        self.log_store.record({
            "token": token,
            "method": self.command,
            "path": redact_text(self.path[:512]),
            "peer": self.client_address[0] if self.client_address else "",
            "ts": time.time(),
            "headers": headers,
        })
        return token

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        if self.path.startswith("/poll/"):
            token = self.path[len("/poll/"):].strip("/")
            if not TOKEN_PATTERN.fullmatch(token):
                self._respond(400, b'{"error": "invalid token"}',
                              "application/json")
                return
            payload = json.dumps({"token": token,
                                  "callbacks": self.log_store.poll(token)}).encode()
            self._respond(200, payload, "application/json")
            return
        if self._record() is not None:
            self._respond(200, b"ok", "text/plain")
            return
        self._respond(404, b"", "text/plain")

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        # The body of a callback is never stored; only the fact of the call.
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            self.close_connection = True
            self._respond(400, b'{"error":"invalid content length"}', "application/json")
            return
        if length < 0:
            self.close_connection = True
            self._respond(400, b'{"error":"invalid content length"}', "application/json")
            return
        if length > 4096:
            self.close_connection = True
            self._respond(413, b'{"error":"callback body too large"}', "application/json")
            return
        if length:
            self.rfile.read(length)
        if self._record() is not None:
            self._respond(200, b"ok", "text/plain")
            return
        self._respond(404, b"", "text/plain")

    def log_message(self, *args):
        pass  # the log is the record; server chatter stays out of stderr


class CollabServer:
    """Runnable canary listener. Binds to ``host:port`` (port 0 = ephemeral)."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0,
                 log: CollabLog | None = None) -> None:
        self.host = host
        self.port = port
        self.log = log or CollabLog()

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def canary_url(self, token: str) -> str:
        return f"{self.base_url}/{token}"

    def poll(self, token: str) -> list[dict[str, Any]]:
        """Same shape as CollabClient.poll, for in-process consumers."""
        return self.log.poll(token)

    def start(self) -> None:
        handler = type("_BoundHandler", (_CanaryHandler,), {"log_store": self.log})
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self.port = self._server.server_address[1]  # resolved when port was 0
        thread = threading.Thread(target=self._server.serve_forever,
                                  name="strix-collab", daemon=True)
        thread.start()

    def stop(self) -> None:
        server = getattr(self, "_server", None)
        if server is not None:
            server.shutdown()
            server.server_close()


_collab_server: CollabServer | None = None
_collab_lock = threading.Lock()


def shared_inprocess_server(host: str = "127.0.0.1") -> CollabServer:
    """One listener per process, created on demand (in-process mode)."""
    global _collab_server
    with _collab_lock:
        if _collab_server is None:
            _collab_server = CollabServer(host=host)
            _collab_server.start()
        return _collab_server


class CollabClient:
    """Polls a listener running in another process (or another host)."""

    def __init__(self, host: str, port: int, timeout: float = 3.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout

    def poll(self, token: str) -> list[dict[str, Any]]:
        url = f"http://{self.host}:{self.port}/poll/{token}"
        with urlopen(url, timeout=self.timeout) as response:
            payload = json.loads(response.read(65536).decode("utf-8", errors="replace"))
        callbacks = payload.get("callbacks", []) if isinstance(payload, dict) else []
        return [item for item in callbacks if isinstance(item, dict)]

    def canary_url(self, token: str) -> str:
        return f"http://{self.host}:{self.port}/{token}"


def main(argv: list[str] | None = None) -> None:
    """``strix-collab --host 0.0.0.0 --port 8765`` — run the canary listener."""
    parser = argparse.ArgumentParser(
        prog="strix-collab",
        description="Strix out-of-band canary listener; callbacks are recorded "
                    "and served at /poll/<token>")
    parser.add_argument("--host", default="127.0.0.1",
                        help="interface to bind (default: 127.0.0.1; engagements "
                             "need an address the target can reach)")
    parser.add_argument("--port", type=int, default=8765, help="port to bind")
    args = parser.parse_args(argv)
    server = CollabServer(host=args.host, port=args.port)
    server.start()
    print(f"strix-collab listening on {server.base_url} "
          f"(poll API: {server.base_url}/poll/<token>)")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
