"""Shared async locks and the ``@async_locked`` decorator.

A process can run the API loop and several worker-thread loops. The locks are
therefore loop-independent: waiting happens in a thread while a plain
``threading.Lock`` provides mutual exclusion across every loop in the process.
Reentrancy is tracked by (loop, task), not by a task object that belongs to one
loop.
"""

from __future__ import annotations

import asyncio
import threading
from functools import wraps
from typing import Any


class _SimpleAsyncLock:
    """A process-wide asynchronous lock usable from any event loop."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

    async def __aenter__(self):
        await asyncio.to_thread(self._lock.acquire)
        return self

    async def __aexit__(self, *exc: Any):
        self._lock.release()
        return False


class _ReentrantAsyncLock:
    """A process-wide reentrant async lock usable from any event loop.

    The same task may re-enter; different tasks wait for the owner to leave the
    outermost ``async with`` block.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._owner: tuple[int, int] | None = None
        self._count = 0

    @staticmethod
    def _current_owner() -> tuple[int, int]:
        task = asyncio.current_task()
        return (id(asyncio.get_running_loop()), id(task) if task is not None else 0)

    async def __aenter__(self):
        owner = self._current_owner()
        if self._owner == owner:
            self._count += 1
            return self
        await asyncio.to_thread(self._lock.acquire)
        self._owner = owner
        self._count = 1
        return self

    async def __aexit__(self, *exc: Any):
        owner = self._current_owner()
        if self._owner != owner:
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
