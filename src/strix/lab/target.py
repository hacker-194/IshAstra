"""Deliberately vulnerable loopback target with fixed, documented behavior.

Every route is a static decision -- no request content is executed or
persisted -- and the server refuses to bind anywhere but loopback.

Route map, mirrored one-to-one by ``oracle.json``. Positive routes the
scanner should report: ``/`` (no CSP), ``/search?q=`` (reflects q),
``/redirect?to=`` (302 to the given location), ``/sqlerror?id=`` (SQLite error
signature), ``/.git/config`` (git exposure bait). Negative routes it must not
report: ``/safe`` (CSP, no reflection), ``/login?next=`` (ignores next),
``/item?id=`` (static, no error), ``/public`` (plain 200).
"""

from __future__ import annotations

import argparse
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlparse

_INDEX_HTML = (
    "<!doctype html><html><head><title>Strix Detection Lab</title></head>"
    "<body><h1>Strix Detection Lab</h1>"
    "<p>This intentionally vulnerable application exists to measure scanner "
    "behavior. It serves static bait and negative fixtures on loopback only.</p>"
    '<ul><li><a href="/search?q=lab">search</a></li>'
    '<li><a href="/redirect?to=https://example.com/">redirect</a></li>'
    '<li><a href="/sqlerror?id=1">item lookup</a></li>'
    '<li><a href="/safe?q=lab">safe</a></li>'
    '<li><a href="/item?id=7">item</a></li>'
    '<li><a href="/public">public</a></li></ul>'
    "</body></html>"
)

_SQL_ERROR_BODY = (
    "Traceback (most recent call last):\n"
    '  File "/app/db.py", line 41, in lookup\n'
    'sqlite3.OperationalError: near "\'": syntax error\n'
)

_HARDENED_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}


class LabHandler(BaseHTTPRequestHandler):
    """Closed routing table; every response is deterministic."""

    protocol_version = "HTTP/1.1"
    server_version = "StrixLab/1.0"
    sys_version = ""

    # -- helpers -----------------------------------------------------------
    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _params(self) -> dict[str, str]:
        parsed = urlparse(self.path)
        return dict(parse_qsl(parsed.query, keep_blank_values=True))

    def log_message(self, *args):  # noqa: D102 - silence default stderr chatter
        pass

    # -- routing -----------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        parsed = urlparse(self.path)
        route = parsed.path
        params = self._params()

        if route == "/":
            # Positive: no CSP anywhere on the lab's default routes.
            self._send(200, _INDEX_HTML.encode(), "text/html; charset=utf-8")

        elif route == "/search":
            # Positive: verbatim reflection of the q parameter into HTML.
            # Reflection alone is an indicator, never a confirmed XSS.
            q = params.get("q", "")
            body = (
                f"<!doctype html><html><head><title>Search</title></head>"
                f"<body><h1>Results</h1><p>Results for: {q}</p>"
                f"<p>No documents matched.</p></body></html>"
            )
            self._send(200, body.encode(), "text/html; charset=utf-8")

        elif route == "/redirect":
            # Positive: the destination is chosen entirely by the client.
            # Scanners must report this without ever following it.
            to = params.get("to", "")
            if to.lower().startswith(("http://", "https://")):
                self._send(302, b"", "text/plain", {"Location": to})
            else:
                self._send(
                    400,
                    b"missing absolute 'to' parameter\n",
                    "text/plain; charset=utf-8",
                )

        elif route == "/sqlerror":
            # Positive: quote mutation produces a database error signature.
            # This is evidence of an injection path, not proof of exploitability.
            identifier = params.get("id", "")
            payload: bytes
            if "'" in identifier:
                payload = _SQL_ERROR_BODY.encode()
            else:
                payload = b"Lookup ok: 1 record matched your query.\n"
            self._send(200, payload, "text/plain; charset=utf-8")

        elif route == "/.git/config":
            # Positive: the exact bait the official nuclei `git-config`
            # exposure template matches (word match on [core], status 200,
            # body must not be HTML).
            bait = (
                b"[core]\n\trepositoryformatversion = 0\n"
                b"\tfilemode = true\n\tbare = false\n"
            )
            self._send(200, bait, "text/plain")

        elif route == "/.git/HEAD":
            # Positive: matches the adapter's check for a valid ref.
            bait = b"ref: refs/heads/main\n"
            self._send(200, bait, "text/plain")

        elif route == "/safe":
            # Negative: parameter is accepted and completely ignored, and the
            # hardened headers must suppress the missing-CSP check.
            self._send(
                200,
                b"Nothing to see here.\n",
                "text/plain; charset=utf-8",
                dict(_HARDENED_HEADERS),
            )

        elif route == "/login":
            # Negative: redirect target is a fixed same-origin path; the
            # next parameter is never copied into Location.
            self._send(302, b"", "text/plain", {"Location": "/dashboard"})

        elif route == "/item":
            # Negative: static catalog text; a quote mutation changes nothing.
            identifier = params.get("id", "")
            text = f"Catalog item {identifier!r}: widget, $9.99, in stock.\n"
            self._send(
                200, text.encode(), "text/plain; charset=utf-8", dict(_HARDENED_HEADERS)
            )

        elif route == "/public":
            # Negative: hardened page with no bait files anywhere near it.
            self._send(
                200,
                b"Public lab index. No exposures here.\n",
                "text/plain; charset=utf-8",
                dict(_HARDENED_HEADERS),
            )

        else:
            self._send(404, b"not found\n", "text/plain; charset=utf-8")

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib naming
        self.do_GET()


class LabServer(ThreadingHTTPServer):
    """Threaded loopback server; refuses non-loopback bind addresses."""

    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address) -> None:
        # Scanners routinely reset connections mid-response; that is client
        # behavior, not a lab fault, and must not spray tracebacks on stderr.
        import sys

        exc = sys.exception()
        if isinstance(exc, (ConnectionResetError, BrokenPipeError, TimeoutError)):
            return
        super().handle_error(request, client_address)

    def __init__(self, addr: tuple[str, int]) -> None:
        host, port = addr
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("the detection lab must bind to loopback only")
        super().__init__((host, port), LabHandler)


class LabTarget:
    """Context manager that runs the lab on an ephemeral loopback port."""

    def __init__(self) -> None:
        self._server: LabServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> LabTarget:
        self._server = LabServer(("127.0.0.1", 0))
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="strix-lab-target", daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("lab target is not running")
        return self._server.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


def main() -> int:
    """Serve the lab for manual inspection (Ctrl+C to stop)."""
    parser = argparse.ArgumentParser(
        description="Serve the Strix detection lab on loopback (deliberately "
        "vulnerable static bait; never bind it to a public interface)."
    )
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    server = LabServer(("127.0.0.1", args.port))
    print(
        f"strix detection lab on http://127.0.0.1:{server.server_address[1]} "
        "(Ctrl+C to stop)"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
