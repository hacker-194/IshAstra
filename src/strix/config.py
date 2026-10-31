"""Runtime configuration, read once from the environment.

Fail-closed: a value that would quietly change security behavior (unknown
scope mode, placeholder bootstrap key, unparsable trusted proxy, unknown log
format) raises at startup instead of being coerced into something plausible.
A bad integer falls back to its documented default -- it cannot widen access.
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass

# Example values shipped in .env.example and documentation. A deployment that
# keeps one of these is protected by a published secret, so it must not start.
_PLACEHOLDER = re.compile(
    r"change[-_ ]?me|replace[-_ ]?me|your[-_ ]?(api[-_ ]?key|secret|token)|"
    r"placeholder|example|dummy|^secret$|^test$")

MIN_SECRET_LENGTH = 16
_LOG_FORMATS = frozenset({"text", "json"})
_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


def _int(name: str, default: int, *, minimum: int = 1) -> int:
    try:
        return max(minimum, int(os.environ.get(name, default)))
    except ValueError:
        return default


def _csv(name: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in os.environ.get(name, "").split(",") if item.strip())


def _secret(name: str, value: str) -> str:
    """A bootstrap secret, or '' when unset; refuses weak/placeholder values."""
    if not value:
        return ""
    if len(value) < MIN_SECRET_LENGTH:
        raise ValueError(f"{name} must be at least {MIN_SECRET_LENGTH} characters")
    if _PLACEHOLDER.search(value.strip().lower()):
        raise ValueError(
            f"{name} still contains an example/placeholder value; generate a "
            "random secret (e.g. `openssl rand -base64 32`)")
    return value


def _choice(name: str, value: str, allowed: frozenset[str], *, lower: bool) -> str:
    normalized = value.strip().lower() if lower else value.strip().upper()
    if normalized not in allowed:
        raise ValueError(f"{name} must be one of: {', '.join(sorted(allowed))}")
    return normalized


def _proxies(name: str, entries: tuple[str, ...]) -> frozenset[str]:
    """Trusted proxy addresses. A CIDR would never match a peer string, so it is
    refused rather than silently trusting nothing (or everything)."""
    for entry in entries:
        try:
            ipaddress.ip_address(entry)
        except ValueError:
            raise ValueError(
                f"{name} entries must be literal IP addresses (got {entry!r}); "
                "list each proxy address explicitly") from None
    return frozenset(entries)


@dataclass(frozen=True)
class Settings:
    scope_file: str = "scope.json"
    db_path: str = "strix.db"
    api_key: str = ""                       # bootstrap admin key
    # Authorization operating mode: "global" (single organization, scope file),
    # "managed" (per-tenant engagement policies), or "auto" (managed as soon as
    # a policy exists in the database, global before that).
    scope_mode: str = "auto"
    workers: int = 1
    queue_max: int = 32
    cors_origins: tuple[str, ...] = ()
    trusted_proxies: frozenset[str] = frozenset()
    rate_limit_disabled: bool = False
    redis_required: bool = False
    audit_max_entries: int = 10_000
    audit_hmac_key: str = ""
    webhook_secret: str = ""               # HMAC key for alert webhook signatures
    # 0 disables retention: evidence is never deleted silently on upgrade. A
    # positive value prunes finished jobs/findings and plain audit entries that
    # old; the sealed audit chain is always kept in full.
    retention_days: int = 0
    max_body_bytes: int = 1_048_576
    log_format: str = "text"
    log_level: str = "INFO"
    redis_url: str = "redis://localhost:6379/0"

    @classmethod
    def from_env(cls) -> Settings:
        scope_mode = os.environ.get("STRIX_SCOPE_MODE", "auto").strip().lower()
        if scope_mode not in {"auto", "global", "managed"}:
            raise ValueError("STRIX_SCOPE_MODE must be one of: auto, global, managed")
        return cls(
            scope_file=os.environ.get("STRIX_SCOPE_FILE", "scope.json"),
            db_path=os.environ.get("STRIX_DB", "strix.db"),
            api_key=_secret("STRIX_API_KEY", os.environ.get("STRIX_API_KEY", "").strip()),
            scope_mode=scope_mode,
            workers=_int("STRIX_WORKERS", 1),
            queue_max=_int("STRIX_QUEUE_MAX", 32),
            cors_origins=_csv("STRIX_CORS_ORIGINS"),
            trusted_proxies=_proxies("STRIX_TRUSTED_PROXIES",
                                     _csv("STRIX_TRUSTED_PROXIES")),
            rate_limit_disabled=os.environ.get("STRIX_RATE_LIMIT_DISABLED") == "1",
            redis_required=os.environ.get("STRIX_REDIS_REQUIRED") == "1",
            audit_max_entries=_int("STRIX_AUDIT_MAX_ENTRIES", 10_000),
            audit_hmac_key=_secret("STRIX_AUDIT_HMAC_KEY",
                                   os.environ.get("STRIX_AUDIT_HMAC_KEY", "").strip()),
            webhook_secret=_secret("STRIX_WEBHOOK_SECRET",
                                   os.environ.get("STRIX_WEBHOOK_SECRET", "").strip()),
            retention_days=_int("STRIX_RETENTION_DAYS", 0, minimum=0),
            max_body_bytes=_int("STRIX_MAX_BODY_BYTES", 1_048_576),
            log_format=_choice("STRIX_LOG_FORMAT",
                               os.environ.get("STRIX_LOG_FORMAT", "text"),
                               _LOG_FORMATS, lower=True),
            log_level=_choice("STRIX_LOG_LEVEL",
                              os.environ.get("STRIX_LOG_LEVEL", "INFO"),
                              _LOG_LEVELS, lower=False),
            redis_url=os.environ.get("STRIX_REDIS_URL", "redis://localhost:6379/0"),
        )
