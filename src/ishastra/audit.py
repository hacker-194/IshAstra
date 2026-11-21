"""Audit trail: a tenant-attributed log plus a tamper-evident hash chain.

Each chain link is HMAC-SHA256 when ``hmac_key`` is set, so someone who can
edit the database but does not hold the key cannot rebuild a consistent chain.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import threading
import time
from collections import deque
from typing import Any

from ishastra.core import store
from ishastra.core.findings import redact
from ishastra.core.locks import _ReentrantAsyncLock, _SimpleAsyncLock, async_locked

log = logging.getLogger(__name__)
GENESIS_HASH = "0" * 64


class AuditLog:
    """Recent audit events, newest last. Credentials are redacted on write."""

    def __init__(self, max_entries: int = 10_000, *, persistent: bool = False) -> None:
        self._max = max_entries
        self._persistent = persistent
        self._entries: deque[dict[str, Any]] = deque(maxlen=max_entries)
        self._lock = threading.RLock()
        self._async_lock: _SimpleAsyncLock | None = None

    def _get_async_lock(self) -> _SimpleAsyncLock:
        """Get or create the async lock in the current event loop."""

        if self._async_lock is not None:
            return self._async_lock

        with self._lock:
            if self._async_lock is None:
                self._async_lock = _SimpleAsyncLock()
            return self._async_lock

    def load(self) -> None:
        """Restore the most recent entries from the database (call at startup)."""
        if not self._persistent:
            return
        with self._lock:
            self._entries.clear()
            self._entries.extend(asyncio.run(store.recent_audit(self._max)))

    def record(self, entry: dict[str, Any]) -> None:
        stamped = redact({"timestamp": time.time(), **entry})
        with self._lock:
            self._entries.append(stamped)
        if self._persistent:
            try:
                asyncio.run(store.append_audit(stamped))
            except Exception:
                log.exception("audit write failed: %s", stamped.get("event"))

    def entries(self, *, tenant: str | None = None) -> list[dict[str, Any]]:
        """Entries oldest-first; ``tenant=None`` means every tenant (admin view)."""
        with self._lock:
            snapshot = list(self._entries)
        if tenant is None:
            return snapshot
        return [entry for entry in snapshot if entry.get("tenant") == tenant]

    @async_locked
    async def load_async(self) -> None:
        """Async version of load (for async callers)."""
        if not self._persistent:
            return
        rows = await store.recent_audit(self._max)
        self._entries.clear()
        self._entries.extend(rows)

    @async_locked
    async def record_async(self, entry: dict[str, Any]) -> None:
        """Async version of record (for async callers)."""
        stamped = redact({"timestamp": time.time(), **entry})
        self._entries.append(stamped)
        if self._persistent:
            try:
                await store.append_audit(stamped)
            except Exception:
                log.exception("audit write failed: %s", stamped.get("event"))


class AuditChain:
    """Hash chain: each sealed entry commits to the one before it."""

    def __init__(self, *, persistent: bool = False, hmac_key: str = "") -> None:
        self._persistent = persistent
        self._key = hmac_key.encode()
        self._entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self._cached: tuple[float, tuple[bool, str | None]] | None = None
        self._async_lock: _ReentrantAsyncLock | None = None

    def __getstate__(self):
        """Exclude non-picklable locks for APScheduler job serialization."""
        state = self.__dict__.copy()
        state["_lock"] = None
        state["_cache_lock"] = None
        state["_async_lock"] = None
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)

        self._lock = threading.Lock()
        self._cache_lock = threading.Lock()
        self._async_lock = None

    def _get_async_lock(self) -> _ReentrantAsyncLock:
        """Get or create the async lock in the current event loop."""

        if self._async_lock is not None:
            return self._async_lock

        with self._lock:
            if self._async_lock is None:
                self._async_lock = _ReentrantAsyncLock()
            return self._async_lock

    def _digest(self, body: dict[str, Any]) -> str:
        payload = json.dumps(body, sort_keys=True).encode()
        if self._key:
            return hmac.new(self._key, payload, hashlib.sha256).hexdigest()
        return hashlib.sha256(payload).hexdigest()

    def _note_append(self, sequence: int, body: dict[str, Any]) -> None:
        """Export one sealed entry: the event counter and the chain length."""
        from ishastra import metrics

        metrics.record_audit_event(
            str(body.get("type") or body.get("event") or "unknown"), body.get("tenant")
        )
        metrics.set_audit_chain_length(sequence)

    def _seal(self, entry: dict[str, Any], sequence: int, previous: str) -> tuple[str, dict[str, Any]]:
        """Body and digest for ``sequence``. The caller owns where it is stored."""
        body = {
            **entry,
            "previous_hash": previous,
            "sequence": sequence,
            "timestamp": time.time(),
        }
        return self._digest(body), body

    def append(self, entry: dict[str, Any]) -> str:

        entry = redact(entry)
        with self._lock:
            if self._persistent:
                sequence, digest, body = asyncio.run(
                    store.chain_append(
                        lambda seq, prev: self._seal(entry, seq, prev),
                        genesis=GENESIS_HASH,
                    )
                )
            else:
                sequence = len(self._entries) + 1
                previous = self._entries[-1]["hash"] if self._entries else GENESIS_HASH
                digest, body = self._seal(entry, sequence, previous)
                self._entries.append({**body, "hash": digest})
            self._note_append(sequence, body)
            return digest

    @async_locked
    async def append_async(self, entry: dict[str, Any]) -> str:
        """Async version of append (for async callers)."""
        entry = redact(entry)
        if self._persistent:
            sequence, digest, body = await store.chain_append(
                lambda seq, prev: self._seal(entry, seq, prev),
                genesis=GENESIS_HASH,
            )
        else:
            sequence = len(self._entries) + 1
            previous = self._entries[-1]["hash"] if self._entries else GENESIS_HASH
            digest, body = self._seal(entry, sequence, previous)
            self._entries.append({**body, "hash": digest})
        self._note_append(sequence, body)
        return digest

    def _iter_entries(self):
        if not self._persistent:
            for entry in list(self._entries):
                yield (
                    entry.get("sequence"),
                    entry.get("previous_hash"),
                    entry.get("hash"),
                    {k: v for k, v in entry.items() if k != "hash"},
                )
            return

        async def _collect():
            result = []
            async for row in store.chain_rows():
                result.append(
                    (
                        row["sequence"],
                        row["previous_hash"],
                        row["hash"],
                        json.loads(row["data"]),
                    )
                )
            return result

        yield from asyncio.run(_collect())

    async def _iter_entries_async(self):
        """Async generator for chain entries.

                Rows are materialized into a list and yielded afterwards.
                The generator itself does NOT hold the async lock: lock management is
                the responsibility of ``verify_async`` and callers that need serialized
                access. Holding the lock across a ``yield`` used to raise
                ``RuntimeError: Lock released by non-owner`` when a caller returned
                early from ``async for`` (e.g. a broken-chain verification), because
        the generator frame would close from a different task and release the
        lock non-transactionally.
        """
        entries: list[tuple[Any, Any, Any, Any]] = []
        if not self._persistent:
            entries = [
                (
                    entry.get("sequence"),
                    entry.get("previous_hash"),
                    entry.get("hash"),
                    {k: v for k, v in entry.items() if k != "hash"},
                )
                for entry in list(self._entries)
            ]
        else:
            async for row in store.chain_rows():
                entries.append((row["sequence"], row["previous_hash"], row["hash"], json.loads(row["data"])))
        for entry in entries:
            yield entry

    def verify(self) -> tuple[bool, str | None]:
        expected_previous, expected_sequence = GENESIS_HASH, 1
        for sequence, previous, digest, body in self._iter_entries():
            if sequence != expected_sequence:
                return (
                    False,
                    f"Chain broken: expected sequence {expected_sequence}, found {sequence}",
                )
            if previous != expected_previous or body.get("previous_hash") != expected_previous:
                return (
                    False,
                    f"Chain broken at sequence {sequence} (prev hash mismatch)",
                )
            if not hmac.compare_digest(self._digest(body), digest or ""):
                return False, f"Hash mismatch at sequence {sequence}"
            expected_previous, expected_sequence = digest, expected_sequence + 1
        return True, None

    @async_locked
    async def verify_async(self) -> tuple[bool, str | None]:
        """Async version of verify (for async callers)."""
        expected_previous, expected_sequence = GENESIS_HASH, 1
        async for sequence, previous, digest, body in self._iter_entries_async():
            if sequence != expected_sequence:
                return (
                    False,
                    f"Chain broken: expected sequence {expected_sequence}, found {sequence}",
                )
            if previous != expected_previous or body.get("previous_hash") != expected_previous:
                return (
                    False,
                    f"Chain broken at sequence {sequence} (prev hash mismatch)",
                )
            if not hmac.compare_digest(self._digest(body), digest or ""):
                return False, f"Hash mismatch at sequence {sequence}"
            expected_previous, expected_sequence = digest, expected_sequence + 1
        return True, None

    def verify_cached(self, max_age: float = 30.0) -> tuple[bool, str | None]:
        """``verify()`` at most once per ``max_age`` seconds, for unauthenticated probes.

        Only caches successful verifications. Failed verifications are never cached
        so they always re-verify on next call.
        """
        now = time.monotonic()
        with self._cache_lock:
            if self._cached and now - self._cached[0] < max_age:
                return self._cached[1]
        result = self.verify()

        if result[0]:
            with self._cache_lock:
                self._cached = (now, result)
        return result

    @async_locked
    async def verify_cached_async(self, max_age: float = 30.0) -> tuple[bool, str | None]:
        """Async version of verify_cached (for async callers).

        Only caches successful verifications. Failed verifications are never cached
        so they always re-verify on next call.
        """
        now = time.monotonic()
        with self._cache_lock:
            if self._cached and now - self._cached[0] < max_age:
                return self._cached[1]
        result = await self.verify_async()

        if result[0]:
            with self._cache_lock:
                self._cached = (now, result)
        return result

    def __len__(self) -> int:
        return asyncio.run(store.chain_count()) if self._persistent else len(self._entries)

    @async_locked
    async def len_async(self) -> int:
        """Async version of __len__ (for async callers)."""
        if self._persistent:
            return await store.chain_count()
        return len(self._entries)

    @property
    def entries(self) -> list[dict[str, Any]]:
        """In-memory chain (tests / non-persistent mode only)."""
        return list(self._entries)
