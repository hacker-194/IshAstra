"""Request-target signature checks.

Pattern matching against the URL itself. This is *inference*, not observation:
a match means the request looks like an attack, not that the target is
vulnerable. Findings built from it must be reported as such.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

from strix.core.urls import parse_url

_PATTERNS: dict[str, re.Pattern[str]] = {
    "xss": re.compile(r"<!--|-->|<\s*script", re.IGNORECASE),
    "sqli": re.compile(r"\b(?:OR|AND|UNION|SELECT|DROP)\b", re.IGNORECASE),
    "secret": re.compile(
        r"(?:api[_-]?key|secret|password|token)\s*[:=]\s*\S+", re.IGNORECASE
    ),
    "open_redirect": re.compile(r"(?:redirect|url)\s*=\s*https?://", re.IGNORECASE),
    "path_traversal": re.compile(r"(?:\.\./)+|(?:\.\.\\)+"),
    # The internal host must be the parameter's value, not a substring of a domain.
    "ssrf": re.compile(
        r"[?&](?:url|redirect|next|to)=[^&]*?(?:localhost|127\.0\.0\.1|0\.0\.0\.0)",
        re.IGNORECASE,
    ),
}


def match_url_signatures(url: str) -> list[str]:
    """Categories whose signature appears in the (URL-decoded) target."""
    parsed = parse_url(url)
    if parsed is None or parsed.scheme not in ("http", "https") or not parsed.netloc:
        return []
    decoded = unquote(url)
    return [name for name, pattern in _PATTERNS.items() if pattern.search(decoded)]
