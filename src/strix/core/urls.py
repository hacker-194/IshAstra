"""One safe way to parse a target URL.

``urllib.parse`` raises ``ValueError`` for malformed input (a bad port such as
``:abc`` or ``:99999``, an unterminated IPv6 literal) — sometimes only when
``.port`` is read. Every parse of caller-supplied text goes through here so a
hostile URL is a refusal, never an unhandled exception.
"""
from __future__ import annotations

from urllib.parse import ParseResult, urlparse


def parse_url(url: str) -> ParseResult | None:
    """Parsed URL, or ``None`` when it cannot be parsed or has an invalid port/host."""
    try:
        parsed = urlparse(url)
        _ = (parsed.port, parsed.hostname)  # each raises ValueError when malformed
    except ValueError:
        return None
    return parsed
