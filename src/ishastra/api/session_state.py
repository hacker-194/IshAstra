"""Short-lived authentication-flow state, shared across API replicas.

OIDC state, PKCE verifiers, nonces and SAML request ids were held in
process-local dicts, so a login that started on one replica failed on another.
They live in Redis when it is available; the process-local dict remains as the
fallback for tests and single-process runs.

Values are read once and deleted where the flow requires it (state and PKCE
material must not be replayable); every entry also carries a TTL so an
abandoned login cannot accumulate.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

log = logging.getLogger(__name__)

_PREFIX = "ishastra:auth:"

_memory: dict[str, tuple[Any, float]] = {}


def _redis_enabled() -> bool:

    return not os.environ.get("ISHASTRA_SKIP_REDIS_INIT")


async def _client() -> Any | None:
    if not _redis_enabled():
        return None
    try:
        from ishastra.api.deps import get_redis

        return await get_redis()
    except Exception:
        return None


def _purge(now: float | None = None) -> None:
    stamp = time.time() if now is None else now
    for key, (_value, expires_at) in list(_memory.items()):
        if expires_at <= stamp:
            _memory.pop(key, None)


async def put(namespace: str, key: str, value: Any, ttl: float) -> None:
    """Store one flow value for ``ttl`` seconds, replacing any previous value."""
    full = f"{_PREFIX}{namespace}:{key}"
    client = await _client()
    if client is not None:
        try:
            await client.set(full, json.dumps(value), ex=max(1, int(ttl)))
            return
        except Exception as exc:
            log.warning(
                "auth state store unavailable (%s); falling back to process memory",
                type(exc).__name__,
            )
    _memory[f"{namespace}:{key}"] = (value, time.time() + ttl)
    _purge()


async def get(namespace: str, key: str) -> Any | None:
    """Read one flow value without consuming it."""
    client = await _client()
    if client is not None:
        try:
            raw = await client.get(f"{_PREFIX}{namespace}:{key}")
            return json.loads(raw) if raw is not None else None
        except Exception:
            pass
    item = _memory.get(f"{namespace}:{key}")
    if item is None:
        return None
    value, expires_at = item
    if expires_at <= time.time():
        _memory.pop(f"{namespace}:{key}", None)
        return None
    return value


async def take(namespace: str, key: str) -> Any | None:
    """Read one flow value and delete it: single use, so it cannot be replayed."""
    client = await _client()
    if client is not None:
        try:
            full = f"{_PREFIX}{namespace}:{key}"
            raw = await client.getdel(full)
            return json.loads(raw) if raw is not None else None
        except Exception:
            pass
    return await _take_memory(namespace, key)


async def _take_memory(namespace: str, key: str) -> Any | None:
    item = _memory.pop(f"{namespace}:{key}", None)
    if item is None:
        return None
    value, expires_at = item
    return value if expires_at > time.time() else None


async def discard(namespace: str, key: str) -> None:
    """Drop one flow value (used to retire state after a successful callback)."""
    client = await _client()
    if client is not None:
        try:
            await client.delete(f"{_PREFIX}{namespace}:{key}")
            return
        except Exception:
            pass
    _memory.pop(f"{namespace}:{key}", None)
