"""Single-process background worker for assessment jobs.

``submit`` returns immediately with a durable job id; worker threads claim
queued jobs and run them off the HTTP request path, and cancellation reaches
the adapter's kill switch, down to killing a running subprocess.

Built for the single-process deployment this ships as: the queue is in memory
(run one process, or replace the queue before scaling out), job rows live in
SQLite so a restart marks rows left queued/running as failed rather than
losing them, and concurrency and queue depth are bounded with overflow
refused.
"""

from __future__ import annotations

import asyncio
import contextlib
import gc
import logging
import os
import queue
import threading
import time
from collections.abc import Callable
from typing import Any

import ishastra.core.jobs as jobs_module
from ishastra.config import Settings, get_settings
from ishastra.core import store
from ishastra.core.jobs import Job

log = logging.getLogger(__name__)


PROCESS_STARTED_AT = time.time()


_MEMORY_CHECK_INTERVAL = 25
_jobs_since_mem_check = 0


def _worker_settings() -> Settings:

    return get_settings()


class AssessmentQueueFull(RuntimeError):
    """The bounded queue refused the job — nothing was enqueued."""


class WorkerLeaseError(RuntimeError):
    """Another process already runs the worker for this database."""


_lease_files: dict[str, Any] = {}


def _lease_path() -> str:
    target = store.current_path()
    if target.startswith(("postgresql://", "postgres://")):
        import hashlib
        import tempfile
        from urllib.parse import urlsplit

        parts = urlsplit(target)
        key = f"{parts.hostname}:{parts.port or 5432}{parts.path}"
        digest = hashlib.sha256(key.encode()).hexdigest()[:16]
        return os.path.join(tempfile.gettempdir(), f"ishastra-{digest}.worker-lock")
    return os.path.abspath(target) + ".worker-lock"


def _acquire_lock_posix(handle) -> None:
    """Acquire exclusive lock on POSIX using fcntl.flock."""
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _acquire_lock_windows(handle) -> None:
    """Acquire exclusive lock on Windows using msvcrt.locking."""
    import msvcrt

    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)  # type: ignore[attr-defined]


def _release_lock_posix(handle) -> None:
    """Release lock on POSIX."""
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _release_lock_windows(handle) -> None:
    """Release lock on Windows."""
    import msvcrt

    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)  # type: ignore[attr-defined]


def _acquire_worker_lease_sync(path: str | None = None) -> str:
    """Synchronous worker lease acquisition (blocking). Run in thread pool.

    Always attempts the lock; the file is the source of truth. The in-process
    cache (_lease_files) is only used to track handles we own for release,
    not to skip acquisition (that would allow a crashed-and-restarted process
    to bypass the lock if it kept the same PID).

    On startup, if the lock file exists with a stale PID (process dead),
    we remove it before attempting to acquire.
    """
    resolved = path or _lease_path()

    if os.path.exists(resolved):
        try:
            with open(resolved, encoding="utf-8") as f:
                pid_str = f.read().strip()
            if pid_str:
                stale_pid = int(pid_str)

                try:
                    os.kill(stale_pid, 0)
                except OSError:
                    log.info("Removing stale worker lock file (PID %d dead)", stale_pid)
                    os.remove(resolved)
        except (OSError, ValueError):
            pass

    # The handle is kept open for the process lifetime to hold the flock; it is
    # closed in _release_worker_lease_sync, so a context manager here would drop
    # the lock immediately.
    handle = open(resolved, "a+", encoding="utf-8")  # noqa: SIM115
    try:
        if os.name == "nt":
            _acquire_lock_windows(handle)
        else:
            _acquire_lock_posix(handle)
    except (OSError, ImportError):
        handle.close()
        raise WorkerLeaseError(
            f"another Ishastra worker process already owns {resolved}; run one "
            "process per database (or remove a stale lock if no worker runs)"
        ) from None

    handle.seek(0)
    handle.truncate()
    handle.write(f"{os.getpid()}\n")
    handle.flush()
    _lease_files[resolved] = handle
    return resolved


def _release_worker_lease_sync(path: str | None = None) -> None:
    """Synchronous worker lease release (blocking). Run in thread pool."""
    resolved = path or _lease_path()
    handle = _lease_files.pop(resolved, None)
    if handle is None:
        return
    try:
        if os.name == "nt":
            _release_lock_windows(handle)
        else:
            _release_lock_posix(handle)
    except (OSError, ImportError):
        pass
    handle.close()

    with contextlib.suppress(OSError):
        os.remove(resolved)


async def acquire_worker_lease(path: str | None = None) -> str:
    """Take the per-database worker lease. Raises WorkerLeaseError if taken.

    Runs blocking file lock operations in a thread pool to avoid blocking the event loop.
    """
    return await asyncio.to_thread(_acquire_worker_lease_sync, path)


async def release_worker_lease(path: str | None = None) -> None:
    """Release the worker lease if this process holds it (idempotent).

    Runs blocking file lock operations in a thread pool to avoid blocking the event loop.
    """
    await asyncio.to_thread(_release_worker_lease_sync, path)


class AssessmentWorker:
    def __init__(self, *, concurrency: int | None = None, queue_max: int | None = None) -> None:
        self.concurrency = concurrency if concurrency is not None else _worker_settings().workers
        self._queue: queue.Queue[Job] = queue.Queue(
            maxsize=queue_max if queue_max is not None else _worker_settings().queue_max
        )
        self._active: dict[str, Job] = {}
        self._on_finish: dict[str, Callable[[Job], None]] = {}
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._started = False
        self._start_lock = threading.Lock()
        self._stopping = threading.Event()
        self.name = f"ishastra-worker-{os.getpid()}-{id(self) & 0xFFFF:x}"
        self._lease: str | None = None

    def _publish_occupancy(self) -> None:
        """Publish queue depth and worker occupancy for this process."""
        from ishastra import metrics

        with self._lock:
            active = len(self._active)
        depth = self._queue.qsize()
        metrics.record_queue_depth(depth, "inprocess")
        metrics.record_worker_occupancy(self.concurrency, max(0, active - depth), "inprocess")

    async def start(self) -> None:
        """Idempotent: sweep interrupted jobs, then spawn the workers."""
        with self._start_lock:
            if self._started:
                return

            self._lease = await acquire_worker_lease()
            self._started = True

            await store.fail_interrupted(created_before=PROCESS_STARTED_AT)
            for index in range(self.concurrency):
                thread = threading.Thread(
                    target=self._thread_entry, name=f"ishastra-worker-{index}", daemon=True
                )
                thread.start()
                self._threads.append(thread)
            self._publish_occupancy()

    async def submit(self, job: Job, on_finish: Callable[[Job], None]) -> None:
        """Queue a prepared job. Raises AssessmentQueueFull when at capacity."""
        await self.start()
        with self._lock:
            self._active[job.id] = job
            self._on_finish[job.id] = on_finish
        try:
            self._queue.put_nowait(job)
        except queue.Full:
            with self._lock:
                self._active.pop(job.id, None)
                self._on_finish.pop(job.id, None)
            raise AssessmentQueueFull(f"assessment queue is full ({self._queue.maxsize} waiting)") from None
        self._publish_occupancy()

    def cancel(self, job_id: str) -> bool:
        """Signal a queued or running job to stop. False if it is not ours."""
        with self._lock:
            job = self._active.get(job_id)
        if job is None:
            return False
        job.cancel()
        return True

    def cancel_for_policy(self, policy_id: str) -> int:
        """Cancel every queued/running job bound to ``policy_id``.

        Authorization withdrawn must stop work that is no longer authorized:
        revoking an engagement policy cancels its in-flight assessments. Jobs
        not yet dequeued fail at their execution-time re-validation instead.
        Returns how many jobs were signalled.
        """
        with self._lock:
            targets = [
                job for job in self._active.values() if (job.policy or {}).get("policy_id") == policy_id
            ]
        for job in targets:
            job.cancel()
        return len(targets)

    async def shutdown(self, timeout: float = 10.0) -> None:
        """Stop cleanly: cancel running jobs, wait for workers, fail what never ran.

        Safe to call more than once; ``start()`` may be called again afterwards.
        """
        with self._start_lock:
            if not self._started:
                return
            log.debug(
                "Shutting down worker, stopping=%s, threads=%d",
                self._stopping.is_set(),
                len(self._threads),
            )
            self._stopping.set()
            with self._lock:
                running = list(self._active.values())
            log.debug("Cancelling %d running jobs", len(running))
            for job in running:
                job.cancel()
            deadline = time.monotonic() + timeout
            for i, thread in enumerate(self._threads):
                remaining = max(0.0, deadline - time.monotonic())
                log.debug(
                    "Joining thread %d/%d (ident=%s), remaining=%.2fs",
                    i + 1,
                    len(self._threads),
                    thread.ident,
                    remaining,
                )
                thread.join(remaining)
                log.debug("Thread %d joined, alive=%s", i + 1, thread.is_alive())
            if any(thread.is_alive() for thread in self._threads):
                log.warning("worker threads still running after %.0fs shutdown", timeout)
            self._threads.clear()

            await asyncio.sleep(1.0)
            log.debug("Worker threads cleared, calling fail_interrupted")

            try:
                await store.fail_interrupted()
            except Exception as exc:
                log.debug("fail_interrupted skipped due to: %s", exc)
            while True:
                try:
                    self._queue.get_nowait()
                    self._queue.task_done()
                except queue.Empty:
                    break
            with self._lock:
                self._active.clear()
                self._on_finish.clear()
            self._publish_occupancy()
            self._stopping.clear()
            self._started = False
            if self._lease is not None:
                await release_worker_lease(self._lease)
                self._lease = None

    def _thread_entry(self) -> None:
        """Entry point for worker threads: create and run a dedicated event loop."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            self._loop(loop)
        finally:
            with contextlib.suppress(Exception):
                loop.close()
            asyncio.set_event_loop(None)

    def _maybe_check_memory(self) -> None:
        """Periodically check RSS and trigger GC if over limit."""
        global _jobs_since_mem_check
        _jobs_since_mem_check += 1
        if _jobs_since_mem_check < _MEMORY_CHECK_INTERVAL:
            return
        _jobs_since_mem_check = 0
        try:
            import resource
            import sys

            rusage = resource.getrusage(resource.RUSAGE_SELF)

            if sys.platform == "darwin":
                rss_mb = rusage.ru_maxrss / (1024 * 1024)
            else:
                rss_mb = rusage.ru_maxrss / 1024
            limit_mb = _worker_settings().worker_memory_mb
            if rss_mb > limit_mb:
                log.warning(
                    "Worker RSS %.1f MB exceeds limit %d MB; forcing GC",
                    rss_mb,
                    limit_mb,
                )
                gc.collect()
        except Exception:
            pass

    def _run_one(self, loop: asyncio.AbstractEventLoop, job: Job) -> None:
        with self._lock:
            on_finish = self._on_finish.get(job.id)

        claimed = loop.run_until_complete(store.claim_job(job.id, tenant=job.actor, worker=self.name))

        if not claimed:
            log.warning("job %s was already claimed; not executing it again", job.id)
            job.state = jobs_module.JobState.FAILED
            job.error = "job was already claimed by another execution"
            job.finished_at = time.time()
        else:
            job.attempts += 1
            job.worker_id = self.name
            from ishastra import metrics

            metrics.observe_job_queue(job.profile, time.time() - job.created_at)
            try:
                jobs_module.execute(job)
            except Exception as exc:
                log.exception("assessment %s crashed", job.id)
                job.state = jobs_module.JobState.FAILED
                job.error = f"internal error: {type(exc).__name__}"
                job.finished_at = time.time()
        if on_finish is not None:
            try:
                on_finish(job)
            except Exception:
                log.exception("final save failed for %s", job.id)

        self._maybe_check_memory()

    def _loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Synchronous main loop for the worker thread, using the thread's event loop."""
        log.debug("Worker thread %s starting loop", threading.get_ident())
        while not self._stopping.is_set():
            try:
                job = self._queue.get(timeout=0.25)
            except queue.Empty:
                continue
            log.debug("Worker thread %s got job %s", threading.get_ident(), job.id)
            try:
                self._run_one(loop, job)
            finally:
                with self._lock:
                    self._active.pop(job.id, None)
                    self._on_finish.pop(job.id, None)
                self._queue.task_done()
                self._publish_occupancy()
        log.debug(
            "Worker thread %s exiting loop (stopping=%s)",
            threading.get_ident(),
            self._stopping.is_set(),
        )
