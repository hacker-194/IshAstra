"""Real HTTP endpoint probe -- sends requests and reads responses.

Every request passes the scope gate first and then connects to the single
address that gate validated: TCP, TLS SNI and certificate checks all use that
IP and hostname, so a DNS answer that changes afterwards cannot move the
connection. Redirects are never followed -- a redirect target is scope-checked
and reported, not contacted. Header names are normalized to lowercase so a
server sending lowercase headers is not misreported as missing them.
"""
from __future__ import annotations

import contextlib
import http.client
import re
import secrets
import select
import socket
import ssl
import threading
import time
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse

from strix import __version__
from strix.core.scope import check as scope_check
from strix.core.scope import destination as scope_destination
from strix.core.urls import parse_url

MAX_BODY = 65536
MAX_PARAMS = 5
REDIRECT_TEST_PARAMS = 3
SQL_ERROR_PATTERNS = (
    re.compile(r"SQLSTATE\[[A-Z0-9]+\]", re.I),
    re.compile(r"(?:mysql|mariadb).{0,80}(?:syntax|error|warning)", re.I | re.S),
    re.compile(r"You have an error in your SQL syntax", re.I),
    re.compile(r"(?:PostgreSQL|psycopg2).{0,80}(?:error|exception)", re.I | re.S),
    re.compile(r"sqlite3\.(?:OperationalError|DatabaseError)", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"Unclosed quotation mark after the character string", re.I),
    re.compile(r"syntax error at or near", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
)


class _MarkerContextParser(HTMLParser):
    """Record where a harmless alphanumeric reflection appears in parsed HTML."""

    def __init__(self, marker: str):
        super().__init__(convert_charrefs=True)
        self.marker = marker
        self.contexts: list[str] = []
        self._in_script = False
        self._in_style = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lower = tag.lower()
        if lower == "script":
            self._in_script = True
        elif lower == "style":
            self._in_style = True
        for name, value in attrs:
            if value and self.marker in value:
                self.contexts.append(f"attribute:{lower}.{name.lower()}")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self._in_script = False
        elif tag.lower() == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if self.marker in data:
            if self._in_script:
                context = "script_text"
            elif self._in_style:
                context = "style_text"
            else:
                context = "html_text"
            self.contexts.append(context)

    def handle_comment(self, data: str) -> None:
        if self.marker in data:
            self.contexts.append("html_comment")


def _cookie_values(raw: Any) -> list[str]:
    if isinstance(raw, str):
        return [raw] if raw else []
    if isinstance(raw, (tuple, list)):
        return [item for item in raw if isinstance(item, str) and item]
    return []


def _all_cookies_secure(raw: Any) -> bool:
    """True only if at least one cookie exists and every cookie has Secure attr."""
    cookies = _cookie_values(raw)
    if not cookies:
        return False
    for cookie in cookies:
        attributes = [part.strip() for part in cookie.split(";")[1:]]
        if not any(attribute.partition("=")[0].strip().lower() == "secure"
                   for attribute in attributes):
            return False
    return True


USER_AGENT = f"strix-probe/{__version__} (+authorized-testing)"


def _read_response_with_deadline(sock: socket.socket, deadline: float | None,
                                 request_timeout: float):
    """Read HTTP response status line and headers with deadline enforcement.

    This prevents slowloris-style attacks where the server sends headers
    one byte at a time. We read directly from the socket with per-read
    deadline checks.
    Returns a response object with read1() and getheaders() methods.
    """
    # Create a file-like object for reading
    sock_file = sock.makefile('rb')
    try:
        # Read status line with deadline enforcement
        status_line_bytes = _read_line_with_deadline(sock_file, sock, deadline, request_timeout)
        if not status_line_bytes:
            raise http.client.BadStatusLine("empty status line")
        status_line = status_line_bytes.decode('iso-8859-1').strip()

        # Parse status line: HTTP/1.1 200 OK
        parts = status_line.split(' ', 2)
        if len(parts) < 2:
            raise http.client.BadStatusLine(status_line)
        status_code = int(parts[1])
        reason_phrase = parts[2] if len(parts) > 2 else ''

        # Read headers with deadline enforcement
        headers_list = []
        while True:
            line_bytes = _read_line_with_deadline(sock_file, sock, deadline, request_timeout)
            if not line_bytes or line_bytes == b'\r\n' or line_bytes == b'\n':
                break  # End of headers
            line = line_bytes.decode('iso-8859-1').rstrip('\r\n')
            if ':' in line:
                key, value = line.split(':', 1)
                headers_list.append((key.strip(), value.strip()))

        # Return a simple response object with the needed methods
        class _DeadlineResponse:
            def __init__(self, sock_file, status_code, reason_phrase, headers_list):
                self._sock_file = sock_file
                self.status = status_code
                self.reason = reason_phrase
                self._headers = headers_list

            def read1(self, size=-1):
                return self._sock_file.read(size)

            def getheaders(self):
                return self._headers

            def close(self):
                self._sock_file.close()

        return _DeadlineResponse(sock_file, status_code, reason_phrase, headers_list)
    except Exception:
        sock_file.close()
        raise


def _read_line_with_deadline(sock_file, sock: socket.socket,
                              deadline: float | None, request_timeout: float) -> bytes:
    """Read a line from socket with deadline enforcement."""
    chunks = []
    while True:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("request deadline exhausted while reading headers")
            # Set socket timeout for this read
            if sock.fileno() >= 0:
                sock.settimeout(max(0.001, min(request_timeout, remaining)))
        try:
            chunk = sock_file.read(1)
            if not chunk:
                break  # EOF
            chunks.append(chunk)
            if chunk == b'\n':
                break
        except TimeoutError:
            raise
        except Exception as e:
            # Socket timeout or other error
            raise TimeoutError(f"timeout reading response: {e}") from e
    return b''.join(chunks)


class EndpointProbe:
    def __init__(self, timeout: float = 8.0, max_body: int = MAX_BODY):
        self.timeout = timeout
        self.max_body = max_body

    def _fetch(self, url: str, *, timeout: float | None = None,
               deadline: float | None = None,
               auth: Any | None = None) -> dict[str, Any]:
        denial, reason, dest = scope_destination(url)
        if denial or dest is None:
            return {"url": url, "status": "blocked", "reason": reason or "destination refused",
                    "headers": {}, "body": ""}

        parsed = urlparse(url)
        target = parsed.path or "/"
        if parsed.query:
            target += "?" + parsed.query

        timeout_values = [self.timeout]
        if timeout is not None:
            timeout_values.append(timeout)
        if deadline is not None:
            timeout_values.append(deadline - time.monotonic())
        request_timeout = min(timeout_values)
        if request_timeout <= 0:
            return {"url": url, "status": "timeout", "error": "request deadline exhausted",
                    "headers": {}, "body": ""}
        request_timeout = max(0.001, request_timeout)
        connection = None
        sock = None
        try:
            # Connect to the validated IP only. HTTPConnection is given a live
            # socket so it never resolves the hostname itself; for https the
            # handshake still verifies the certificate against the real host.
            connection = http.client.HTTPConnection(dest.host, dest.port,
                                                    timeout=request_timeout)
            sock = socket.create_connection((dest.ip, dest.port), timeout=request_timeout)
            sock.settimeout(request_timeout)
            if dest.scheme == "https":
                sock = ssl.create_default_context().wrap_socket(
                    sock, server_hostname=dest.host)
            # Ensure timeout is set on the (possibly SSL-wrapped) socket
            sock.settimeout(request_timeout)
            connection.sock = sock
            request_headers = {"User-Agent": USER_AGENT, "Connection": "close"}
            if auth is not None:
                if auth.cookies:
                    request_headers["Cookie"] = "; ".join(
                        f"{name}={value}" for name, value in auth.cookies)
                if auth.bearer:
                    request_headers["Authorization"] = f"Bearer {auth.bearer}"
                for name, value in auth.headers:
                    request_headers[name] = value
            connection.request("GET", target, headers=request_headers)
            # Enforce deadline before waiting for response headers
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("request deadline exhausted before response headers")
                if sock.fileno() >= 0:
                    sock.settimeout(max(0.001, min(request_timeout, remaining)))
            # Use select to wait for the socket to become readable (response headers arrived)
            # This enforces the timeout even when getresponse() doesn't respect socket timeout
            # Use request_timeout (which accounts for probe's own timeout) not the caller's deadline
            if sock.fileno() >= 0:
                select_timeout = request_timeout
                ready = select.select([sock], [], [], select_timeout)
                if not ready[0]:
                    raise TimeoutError("timeout waiting for response headers")
            # Read response status line and headers manually with deadline enforcement
            # to prevent slowloris-style slow header attacks
            response = _read_response_with_deadline(sock, deadline, request_timeout)
            body_chunks: list[bytes] = []
            body_size = 0
            while body_size < self.max_body:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("request deadline exhausted while reading response")
                    # HTTPConnection may detach/close its socket after a
                    # Connection: close response. Update timeout only while the
                    # socket object is still live; buffered response bytes can
                    # still be consumed afterward.
                    if sock.fileno() >= 0:
                        sock.settimeout(max(0.001, min(request_timeout, remaining)))
                chunk = response.read1(min(8192, self.max_body - body_size))
                if not chunk:
                    break
                body_chunks.append(chunk)
                body_size += len(chunk)
            body = b"".join(body_chunks).decode("utf-8", errors="ignore")
            headers: dict[str, Any] = {}
            for key, value in response.getheaders():
                lowered = key.lower()
                if lowered == "set-cookie":
                    headers.setdefault(lowered, []).append(value)
                elif lowered in headers:
                    existing = headers[lowered]
                    headers[lowered] = f"{existing}, {value}"
                else:
                    headers[lowered] = value
            result: dict[str, Any] = {
                "url": url,
                "status": response.status,
                "headers": headers,
                "body": body,
            }
            connection.close()
        except Exception as exc:
            # Make every failure path release the TCP/TLS connection promptly.
            if connection is not None:
                with contextlib.suppress(Exception):
                    connection.close()
            if sock is not None:
                with contextlib.suppress(Exception):
                    sock.close()
            return {"url": url, "status": "error", "error": str(exc)[:300],
                    "headers": {}, "body": ""}

        location = headers.get("location")
        if location:
            # Never followed — only judged, so an in-scope host cannot bounce a
            # request onto an internal address.
            result["redirect_to"] = location
            try:
                redirect_denial, redirect_reason = scope_check(urljoin(url, location))
            except ValueError:  # a hostile server can send an unparseable Location
                redirect_denial, redirect_reason = "invalid_target", "unparseable redirect target"
            result["redirect_in_scope"] = not redirect_denial
            if redirect_denial:
                result["redirect_reason"] = redirect_reason
        return result

    def probe(self, url: str, *, deadline: float | None = None) -> dict[str, Any]:
        result = self._fetch(url, deadline=deadline)
        headers = result.get("headers", {})
        out = {
            "url": url,
            "status": result.get("status"),
            "headers": headers,
            "body_snippet": result.get("body", "")[:200],
            "security_headers": {
                "csp": headers.get("content-security-policy"),
                "hsts": headers.get("strict-transport-security"),
                "frame": headers.get("x-frame-options"),
                "cookie_secure": _all_cookies_secure(headers.get("set-cookie")),
            },
        }
        for key in ("reason", "error", "redirect_to", "redirect_in_scope", "redirect_reason"):
            if key in result:
                out[key] = result[key]
        return out

    def reflections(self, url: str, *, cancel: threading.Event | None = None,
                    deadline: float | None = None) -> list[dict[str, Any]]:
        """Check benign marker reflections, respecting a caller's deadline/cancel event.

        Reflection alone is not proof of XSS; this method reports only the raw
        observation so the adapter can label it unverified.
        """
        parsed = parse_url(url)
        if parsed is None:
            return []
        params = parse_qsl(parsed.query, keep_blank_values=True)
        found: list[dict[str, Any]] = []
        for index, (name, _) in enumerate(params[:MAX_PARAMS]):
            if cancel is not None and cancel.is_set():
                break
            remaining = self.timeout
            if deadline is not None:
                remaining = min(remaining, deadline - time.monotonic())
                if remaining <= 0:
                    break
            marker = f"strix{secrets.token_hex(6)}"
            marked = list(params)
            marked[index] = (name, marker)
            marked_url = parsed._replace(query=urlencode(marked)).geturl()
            result = self._fetch(marked_url, timeout=remaining, deadline=deadline)
            body = result.get("body", "")
            if marker in body:
                context_parser = _MarkerContextParser(marker)
                # The response is untrusted HTML; parser errors must not
                # make a failed context check look like a clean result.
                with contextlib.suppress(Exception):
                    context_parser.feed(body)
                contexts = list(dict.fromkeys(context_parser.contexts)) or ["raw_response"]
                found.append({
                    "parameter": name,
                    "url": marked_url,
                    "contexts": contexts,
                    "evidence": (f"marker reflected verbatim for parameter '{name}' in "
                                 f"context(s) {', '.join(contexts)}; "
                                 "execution context was not tested"),
                })
        return found

    def redirect_tests(self, url: str, *, cancel: threading.Event | None = None,
                       deadline: float | None = None) -> list[dict[str, Any]]:
        """Safely test query values for a server-controlled redirect.

        The canary destination is under the reserved .invalid TLD and is never
        followed. A result is returned only if the target's Location header
        points to the unique canary URL, which provides direct behavioral proof
        without contacting the canary host.
        """
        parsed = parse_url(url)
        if parsed is None:
            return []
        params = parse_qsl(parsed.query, keep_blank_values=True)
        found: list[dict[str, Any]] = []
        for index, (name, _) in enumerate(params[:REDIRECT_TEST_PARAMS]):
            if cancel is not None and cancel.is_set():
                break
            remaining = self.timeout
            if deadline is not None:
                remaining = min(remaining, deadline - time.monotonic())
                if remaining <= 0:
                    break
            token = f"strix-{secrets.token_hex(6)}"
            canary_host = f"{token}.invalid"
            canary = f"https://{canary_host}/{token}"
            marked = list(params)
            marked[index] = (name, canary)
            marked_url = parsed._replace(query=urlencode(marked)).geturl()
            response = self._fetch(marked_url, timeout=remaining, deadline=deadline)
            location = response.get("headers", {}).get("location")
            if not isinstance(location, str) or not location:
                continue
            try:
                destination = urlparse(urljoin(marked_url, location))
            except ValueError:
                continue
            # Exact unique host, not a substring match, avoids attacker-shaped
            # values such as strix-<token>.invalid.attacker.example.
            if destination.hostname and destination.hostname.lower() == canary_host:
                found.append({
                    "parameter": name,
                    "status": response.get("status"),
                    "request_url": marked_url,
                    "location": location,
                    "canary": canary,
                    "evidence": (f"parameter '{name}' controlled the Location destination: "
                                 f"HTTP {response.get('status')} Location={location!r}; "
                                 "redirect was not followed"),
                })
        return found

    def database_error_tests(self, url: str, *, cancel: threading.Event | None = None,
                             deadline: float | None = None) -> list[dict[str, Any]]:
        """Look for database error leakage after a low-impact quote mutation.

        This is evidence of a possible injection path, not proof of exploitable
        SQL injection. Only existing query parameters and GET requests are used;
        no data extraction or state-changing payload is attempted.
        """
        parsed = parse_url(url)
        if parsed is None:
            return []
        params = parse_qsl(parsed.query, keep_blank_values=True)
        found: list[dict[str, Any]] = []
        for index, (name, _) in enumerate(params[:MAX_PARAMS]):
            if cancel is not None and cancel.is_set():
                break
            remaining = self.timeout
            if deadline is not None:
                remaining = min(remaining, deadline - time.monotonic())
                if remaining <= 0:
                    break
            marked = list(params)
            marked[index] = (name, "'")
            marked_url = parsed._replace(query=urlencode(marked)).geturl()
            response = self._fetch(marked_url, timeout=remaining, deadline=deadline)
            body = response.get("body", "")
            pattern = next((p for p in SQL_ERROR_PATTERNS if p.search(body)), None)
            match = pattern.search(body) if pattern is not None else None
            if pattern is not None and match is not None:
                sample = body[max(0, match.start() - 60): match.end() + 100]
                found.append({
                    "parameter": name,
                    "status": response.get("status"),
                    "request_url": marked_url,
                    "signature": pattern.pattern,
                    "evidence": f"database error signature after quote mutation: {sample[:300]!r}",
                })
        return found


# Weighted deductions for missing hardening headers.
_HEADER_DEDUCTIONS = (
    ("csp", 30, "Missing Content-Security-Policy header"),
    ("hsts", 25, "Missing HSTS (Strict-Transport-Security) header"),
    ("frame", 15, "Missing X-Frame-Options header"),
)
_GRADES = ((85, "A"), (70, "B"), (50, "C"))


def grade_security_headers(headers: dict[str, Any],
                           security_headers: dict[str, Any], *,
                           is_https: bool = True) -> tuple[int, str, list[str]]:
    """Score a received response; HSTS is evaluated only for HTTPS responses."""
    score = 100
    deductions: list[str] = []
    for key, points, message in _HEADER_DEDUCTIONS:
        if key == "hsts" and not is_https:
            continue
        if not security_headers.get(key):
            score -= points
            deductions.append(f"{message} (-{points})")
    sets_cookie = bool(_cookie_values(headers.get("set-cookie")))
    if sets_cookie and not security_headers.get("cookie_secure"):
        score -= 20
        deductions.append("Cookies missing 'Secure' flag (-20)")
    score = max(0, score)
    grade = next((letter for floor, letter in _GRADES if score >= floor), "F")
    return score, grade, deductions
