"""Opt-in data retention: prune old finished jobs, findings and audit entries.

Without retention the SQLite file grows without bound; with
``STRIX_RETENTION_DAYS=N`` a background sweep deletes jobs/findings and plain
audit entries older than N days (the sealed audit chain is never pruned).
Disabled by default: deleting evidence must be a deliberate operator choice,
and the first sweep runs in a background thread so startup never blocks on it.
"""

from __future__ import annotations

import logging
import threading
import time

from strix.core import store

log = logging.getLogger(__name__)

# Retention lag is measured in days, so sweeping a few times a day is ample.
SWEEP_INTERVAL_SECONDS = 6 * 3600.0


async def _prune_async(cutoff: float) -> tuple[int, int]:
    jobs = await store.prune_finished_jobs(cutoff)
    audit_entries = await store.prune_audit_log(cutoff)
    if jobs or audit_entries:
        await store.vacuum()
    return jobs, audit_entries


def prune(days: int, *, now: float | None = None) -> dict[str, int]:
    """Delete rows older than ``days``; returns how many rows each sweep removed."""
    if days <= 0:
        return {"jobs": 0, "audit_entries": 0}
    cutoff = (time.time() if now is None else now) - days * 86400
    jobs, audit_entries = store._run_async(_prune_async(cutoff))
    return {"jobs": jobs, "audit_entries": audit_entries}


class RetentionWorker:
    """One daemon thread: prune at startup, then re-check every sweep interval."""

    def __init__(self, days: int) -> None:
        self.days = days
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """No-op when retention is disabled (the default)."""
        if self.days <= 0 or self._thread is not None:
            return
        self._stopping.clear()
        self._thread = threading.Thread(
            target=self._loop, name="strix-retention", daemon=True
        )
        self._thread.start()

    def shutdown(self, timeout: float = 5.0) -> None:
        self._stopping.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    def _loop(self) -> None:
        while not self._stopping.is_set():
            try:
                removed = prune(self.days)
                if removed["jobs"] or removed["audit_entries"]:
                    log.info(
                        "retention (>%d days): pruned %d job(s), %d audit entry(ies)",
                        self.days,
                        removed["jobs"],
                        removed["audit_entries"],
                    )
            except Exception:  # a failed sweep must never kill the sweeper
                log.exception("retention sweep failed")
            self._stopping.wait(SWEEP_INTERVAL_SECONDS)
