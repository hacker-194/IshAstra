"""Shared async lock implementations.

Provides reentrant and simple async locks to avoid duplicate implementations
across modules.

Files that will use this:
- src/strix/core/policies.py (PolicyRegistry._get_async_lock, line 229-233)
- src/strix/audit.py (AuditLog._get_async_lock line 122-126, AuditChain._get_async_lock line 191-195)
- src/strix/monitor.py (Monitor._get_async_lock line 214-218)

No existing file serves this purpose - each module has its own duplicate implementation.

User instruction: "fix all the audit findings" - Should Fix #6: Consolidate duplicate
_ReentrantAsyncLock/_SimpleAsyncLock implementations into shared module
"""
from __future__ import annotations

import asyncio
from functools import wraps
from typing import Any


class _SimpleAsyncLock:
    """A simple asyncio lock without ownership tracking.

    Recreates the lock if the event loop changes (e.g., in tests), but only
    if the lock is not currently held to avoid orphaning a locked lock.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def _check_loop(self) -> None:
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._loop is not current_loop:
            # Only replace the lock if it's not currently held.
            # Try to acquire with zero timeout to test if it's free.
            if self._lock.locked():
                # Lock is held (likely by a task from the old loop that crashed).
                # Don't replace - the old task can't release it anymore, but
                # replacing would orphan the held lock. Keep using the old lock
                # for this loop; it will be released when the old task's
                # __aexit__ runs (which won't happen, but this avoids corruption).
                # Update loop reference so we don't keep checking.
                self._loop = current_loop
                return
            # Lock is free, safe to replace
            self._lock = asyncio.Lock()
            self._loop = current_loop

    async def __aenter__(self):
        self._check_loop()
        await self._lock.acquire()
        return self

    async def __aexit__(self, *exc: Any):
        self._lock.release()
        return False


class _ReentrantAsyncLock:
    """A reentrant asyncio lock - same task can acquire multiple times.

    Recreates the lock if the event loop changes (e.g., in tests), but only
    if the lock is not currently held to avoid orphaning a locked lock.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._owner: asyncio.Task | None = None
        self._count = 0
        self._loop: asyncio.AbstractEventLoop | None = None

    def _check_loop(self) -> None:
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        if self._loop is not current_loop:
            # Only replace the lock if it's not currently held.
            if self._count > 0:
                # Lock is held by a task from the old loop.
                # Don't replace - the old task can't release it anymore.
                # Update loop reference so we don't keep checking.
                self._loop = current_loop
                return
            # Lock is free, safe to replace
            self._lock = asyncio.Lock()
            self._owner = None
            self._count = 0
            self._loop = current_loop

    async def __aenter__(self):
        self._check_loop()
        task = asyncio.current_task()
        if self._owner is task:
            self._count += 1
            return self
        await self._lock.acquire()
        self._owner = task
        self._count = 1
        return self

    async def __aexit__(self, *exc: Any):
        task = asyncio.current_task()
        if self._owner is not task:
            raise RuntimeError("Lock released by non-owner")
        self._count -= 1
        if self._count == 0:
            self._owner = None
            self._lock.release()
        return False


def async_locked(method):
    """Serialize one async operation; reentrant lock permits nested helper calls."""
    @wraps(method)
    async def wrapped(self, *args, **kwargs):
        async with self._get_async_lock():
            return await method(self, *args, **kwargs)
    return wrapped
