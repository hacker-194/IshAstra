"""Background worker for risk exception lifecycle management.

This module provides a background job that processes finding_records with
exception_state in ('pending', 'approved') to:
- Auto-expire exceptions past exception_until timestamp
- Auto-transition resolution_state: fix_verified → closed for approved exceptions
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field

from strix.audit import AuditChain
from strix.config import Settings
from strix.core import exceptions, store
from strix.core.exceptions import (
    EVENT_EXCEPTION_EXPIRED,
    EXCEPTION_EXPIRED,
)

log = logging.getLogger(__name__)

# Resolution states
RESOLUTION_OPEN = "open"
RESOLUTION_FIX_VERIFIED = "fix_verified"
RESOLUTION_CLOSED = "closed"

# Global reference for picklable job callback
_exceptions_worker: ExceptionsWorker | None = None


def _run_exceptions_worker_job() -> None:
    """Module-level job callback for APScheduler (picklable).

    Called by the scheduler to run one iteration of the exceptions worker.
    """
    import asyncio

    worker = _exceptions_worker
    if worker is None:
        log.warning("Exceptions worker job triggered but worker not initialized")
        return
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        return
    if loop.is_running():
        loop.create_task(worker._run_iteration_async())
    else:
        log.warning("Event loop not running for exceptions worker job")


@dataclass
class ExceptionsWorkerResult:
    """Result of an exceptions worker iteration."""

    expired_count: int = 0
    auto_closed_count: int = 0
    errors: list[str] = field(default_factory=list)


class ExceptionsWorker:
    """Background worker for exception lifecycle management.

    Runs periodically via APScheduler (registered in scheduler.py) to:
    1. Expire exceptions that have passed their exception_until timestamp
    2. Auto-close findings with approved exceptions that are fix_verified
    """

    def __init__(
        self,
        *,
        audit_chain: AuditChain,
        settings: Settings,
    ) -> None:
        self.audit_chain = audit_chain
        self.settings = settings

        self._running = False
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Initialize the worker (register global reference for job callback)."""
        global _exceptions_worker
        _exceptions_worker = self
        self._running = True
        log.info("Exceptions worker initialized")

    async def stop(self) -> None:
        """Stop the worker."""
        self._running = False
        log.info("Exceptions worker stopped")

    async def _run_iteration_async(self) -> ExceptionsWorkerResult:
        """Run one iteration of the exceptions worker."""
        result = ExceptionsWorkerResult()

        try:
            # 1. Expire exceptions past their timestamp
            expired = await self._expire_exceptions()
            result.expired_count = expired

            # 2. Auto-close fix_verified findings with approved exceptions
            auto_closed = await self._auto_close_fix_verified()
            result.auto_closed_count = auto_closed

            if expired or auto_closed:
                log.info(
                    "Exceptions worker iteration: expired=%d, auto_closed=%d",
                    expired,
                    auto_closed,
                )

        except asyncio.CancelledError:
            log.info("Exceptions worker iteration cancelled")
            raise
        except Exception as exc:
            log.exception("Error in exceptions worker iteration")
            result.errors.append(str(exc))

        return result

    async def _expire_exceptions(self) -> int:
        """Expire exceptions that have passed their exception_until timestamp.

        Processes finding_records with exception_state in ('pending', 'approved')
        and exception_until <= now.
        """
        now = time.time()
        expired_count = 0

        db = await store.get_database()
        async with db.transaction() as conn:
            # Find exceptions to expire: pending or approved with exception_until passed
            rows = await store._fetchall(
                conn,
                """SELECT tenant, fingerprint, exception_state, exception_until,
                          exception_reason, exception_requested_by, exception_decided_by,
                          exception_note, exception_requested_at, exception_decided_at
                     FROM finding_records
                    WHERE exception_state IN ('pending', 'approved')
                      AND exception_until IS NOT NULL
                      AND exception_until <= ?""",
                now,
            )

            for row in rows:
                await store._execute(
                    conn,
                    """UPDATE finding_records
                          SET exception_state = ?, updated_at = ?
                        WHERE tenant = ? AND fingerprint = ?""",
                    EXCEPTION_EXPIRED,
                    now,
                    row["tenant"],
                    row["fingerprint"],
                )

                # Record the expiration in audit chain
                await self.audit_chain.append_async(
                    {
                        "event": EVENT_EXCEPTION_EXPIRED,
                        "tenant": row["tenant"],
                        "fingerprint": row["fingerprint"],
                        "previous_state": row["exception_state"],
                        "expired_at": now,
                        "exception_until": row["exception_until"],
                    }
                )

                # Notify via webhook
                await exceptions._notify_exception_event(
                    tenant_id=row["tenant"],
                    fingerprint=row["fingerprint"],
                    event=EVENT_EXCEPTION_EXPIRED,
                    exception_state=EXCEPTION_EXPIRED,
                    exception_until=row["exception_until"],
                    exception_reason=row["exception_reason"],
                    requested_by=row["exception_requested_by"],
                    decided_by=row["exception_decided_by"],
                    note=f"Exception expired at {time.ctime(now)}",
                )

                expired_count += 1

        if expired_count:
            log.info("Expired %d risk exception(s)", expired_count)
        return expired_count

    async def _auto_close_fix_verified(self) -> int:
        """Auto-close findings with approved exceptions that are fix_verified.

        For findings that have an approved exception and resolution_state = 'fix_verified',
        transition to 'closed' since the exception acknowledges the risk and the fix is verified.
        """
        now = time.time()
        auto_closed_count = 0

        db = await store.get_database()
        async with db.transaction() as conn:
            # Find findings with approved exception and fix_verified resolution_state
            rows = await store._fetchall(
                conn,
                """SELECT tenant, fingerprint, resolution_state, exception_state
                     FROM finding_records
                    WHERE exception_state = 'approved'
                      AND resolution_state = 'fix_verified'""",
            )

            for row in rows:
                await store._execute(
                    conn,
                    """UPDATE finding_records
                          SET resolution_state = ?, resolved_at = ?, updated_at = ?
                        WHERE tenant = ? AND fingerprint = ?""",
                    RESOLUTION_CLOSED,
                    now,
                    now,
                    row["tenant"],
                    row["fingerprint"],
                )

                # Record in audit chain
                await self.audit_chain.append_async(
                    {
                        "event": "exception_auto_closed",
                        "tenant": row["tenant"],
                        "fingerprint": row["fingerprint"],
                        "previous_resolution_state": row["resolution_state"],
                        "exception_state": row["exception_state"],
                        "closed_at": now,
                        "reason": "Approved exception with verified fix auto-closed",
                    }
                )

                auto_closed_count += 1

        if auto_closed_count:
            log.info("Auto-closed %d fix_verified finding(s) with approved exceptions", auto_closed_count)
        return auto_closed_count

    async def run_once(self) -> ExceptionsWorkerResult:
        """Run a single iteration manually (for testing or manual trigger)."""
        return await self._run_iteration_async()

    @property
    def running(self) -> bool:
        return self._running


async def create_exceptions_worker(
    audit_chain: AuditChain,
    settings: Settings,
) -> ExceptionsWorker:
    """Factory function to create and initialize an exceptions worker."""
    worker = ExceptionsWorker(
        audit_chain=audit_chain,
        settings=settings,
    )
    await worker.initialize()
    return worker
