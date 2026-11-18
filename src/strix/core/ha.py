"""High Availability utilities for multi-node deployments.

This module provides:
- Leader election using PostgreSQL advisory locks
- Health check coordination
- Graceful shutdown with job drain
- HA mode configuration for API and scheduler

Note: Actual multi-node testing requires real infrastructure (PostgreSQL, Redis).
These primitives provide the foundation for HA deployments.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import time
import uuid
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from strix.audit import AuditChain
from strix.config import Settings
from strix.core import store

log = logging.getLogger(__name__)


class HAState(str, Enum):
    """High Availability node state."""

    STARTING = "starting"
    STANDBY = "standby"
    LEADER = "leader"
    SHUTTING_DOWN = "shutting_down"
    STOPPED = "stopped"


@dataclass
class NodeInfo:
    """Information about a HA cluster node."""

    node_id: str
    hostname: str
    pid: int
    state: HAState
    started_at: float
    last_heartbeat: float
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "hostname": self.hostname,
            "pid": self.pid,
            "state": self.state.value,
            "started_at": self.started_at,
            "last_heartbeat": self.last_heartbeat,
            "metadata": self.metadata,
        }


@dataclass
class LeaderElectionConfig:
    """Configuration for leader election."""

    lock_name: str = "strix_leader_election"
    ttl_seconds: int = 30
    retry_interval: float = 5.0
    max_retries: int = 3


class LeaderElection:
    """PostgreSQL advisory lock-based leader election.

    Uses pg_try_advisory_lock / pg_advisory_unlock for leader election.
    This requires PostgreSQL - SQLite does not support advisory locks.

    Usage:
        election = LeaderElection(config, settings)
        async with election.campaign() as is_leader:
            if is_leader:
                # Run leader-only tasks (scheduler, monitor, etc.)
            else:
                # Run as standby
    """

    def __init__(
        self,
        config: LeaderElectionConfig,
        settings: Settings,
        audit_chain: AuditChain | None = None,
    ) -> None:
        self.config = config
        self.settings = settings
        self.audit_chain = audit_chain
        self._node_id = f"{os.uname().nodename}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        self._lock_held = False
        self._heartbeat_task: asyncio.Task | None = None

    @property
    def node_id(self) -> str:
        return self._node_id

    async def try_acquire_leadership(self) -> bool:
        """Attempt to acquire the leadership lock. Returns True if successful."""
        if self.settings.db_path.startswith(("sqlite:", "sqlite://")):
            log.warning("Leader election requires PostgreSQL; running in single-node mode")
            return True  # In SQLite mode, single node is always leader

        try:
            async with store.get_db_async() as db, db.transaction() as conn:
                # Try to acquire advisory lock
                # Use a hash of the lock name to get a 64-bit integer
                lock_id = hash(self.config.lock_name) & 0x7FFFFFFF
                result = await conn.fetchrow("SELECT pg_try_advisory_lock($1)", lock_id)
                acquired = result[0] if result else False
                if acquired:
                    self._lock_held = True
                    log.info("Acquired leadership lock: %s", self._node_id)
                    if self.audit_chain:
                        await self.audit_chain.append_async(
                            {
                                "type": "ha_leader_elected",
                                "node_id": self._node_id,
                                "lock_name": self.config.lock_name,
                            }
                        )
                return acquired
        except Exception as exc:
            log.exception("Failed to acquire leadership lock: %s", exc)
            return False

    async def release_leadership(self) -> None:
        """Release the leadership lock."""
        if not self._lock_held:
            return
        if self.settings.db_path.startswith(("sqlite:", "sqlite://")):
            return

        try:
            async with store.get_db_async() as db, db.transaction() as conn:
                lock_id = hash(self.config.lock_name) & 0x7FFFFFFF
                await conn.execute("SELECT pg_advisory_unlock($1)", lock_id)
                self._lock_held = False
                log.info("Released leadership lock: %s", self._node_id)
                if self.audit_chain:
                    await self.audit_chain.append_async(
                        {
                            "type": "ha_leader_released",
                            "node_id": self._node_id,
                            "lock_name": self.config.lock_name,
                        }
                    )
        except Exception as exc:
            log.exception("Failed to release leadership lock: %s", exc)

    async def start_heartbeat(self) -> None:
        """Start periodic heartbeat to maintain leadership."""
        if self._heartbeat_task is not None:
            return

        async def _heartbeat() -> None:
            while self._lock_held:
                try:
                    await asyncio.sleep(self.config.ttl_seconds / 3)
                    if self._lock_held:
                        # Refresh lock by re-acquiring (idempotent)
                        await self.try_acquire_leadership()
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    log.exception("Heartbeat error: %s", exc)

        self._heartbeat_task = asyncio.create_task(_heartbeat())

    async def stop_heartbeat(self) -> None:
        """Stop the heartbeat task."""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._heartbeat_task
            self._heartbeat_task = None

    @contextlib.asynccontextmanager
    async def campaign(self) -> AsyncGenerator[bool, None]:
        """Campaign for leadership. Yields True if this node is leader."""
        acquired = await self.try_acquire_leadership()
        if acquired:
            await self.start_heartbeat()
        try:
            yield acquired
        finally:
            if acquired:
                await self.stop_heartbeat()
                await self.release_leadership()


class HealthCheckCoordinator:
    """Coordinates health checks across HA nodes."""

    def __init__(self, settings: Settings, audit_chain: AuditChain | None = None) -> None:
        self.settings = settings
        self.audit_chain = audit_chain
        self._checks: dict[str, Callable[[], Any]] = {}
        self._node_info: NodeInfo | None = None

    def register_check(self, name: str, check: Callable[[], Any]) -> None:
        """Register a health check function."""
        self._checks[name] = check

    async def run_checks(self) -> dict[str, Any]:
        """Run all registered health checks."""
        results = {}
        for name, check in self._checks.items():
            try:
                if asyncio.iscoroutinefunction(check):
                    result = await check()
                else:
                    result = check()
                results[name] = {"status": "healthy", "details": result}
            except Exception as exc:
                results[name] = {"status": "unhealthy", "error": str(exc)}
        return results

    async def get_overall_health(self) -> dict[str, Any]:
        """Get overall health status."""
        checks = await self.run_checks()
        all_healthy = all(c.get("status") == "healthy" for c in checks.values())
        return {
            "status": "healthy" if all_healthy else "degraded",
            "checks": checks,
            "node_id": self._node_info.node_id if self._node_info else "unknown",
            "timestamp": time.time(),
        }

    def set_node_info(self, node_info: NodeInfo) -> None:
        self._node_info = node_info


class GracefulShutdown:
    """Handles graceful shutdown with job drain.

    Coordinates with the scheduler and worker to:
    1. Stop accepting new work
    2. Wait for in-flight jobs to complete (with timeout)
    3. Cancel queued jobs
    4. Release resources
    """

    def __init__(
        self,
        settings: Settings,
        audit_chain: AuditChain | None = None,
        drain_timeout: float = 30.0,
    ) -> None:
        self.settings = settings
        self.audit_chain = audit_chain
        self.drain_timeout = drain_timeout
        self._shutdown_event = asyncio.Event()
        self._callbacks: list[Callable[[], Any]] = []
        self._original_handlers: dict[int, Callable[[int, Any], Any] | int | None] = {}

    def register_shutdown_callback(self, callback: Callable[[], Any]) -> None:
        """Register a callback to run during shutdown."""
        self._callbacks.append(callback)

    async def shutdown(self, signal_name: str = "SIGTERM") -> None:
        """Execute graceful shutdown sequence."""
        log.info("Graceful shutdown initiated by %s", signal_name)
        if self.audit_chain:
            await self.audit_chain.append_async(
                {
                    "type": "ha_shutdown_started",
                    "signal": signal_name,
                    "drain_timeout": self.drain_timeout,
                }
            )

        # Signal shutdown to all components
        self._shutdown_event.set()

        # Run registered callbacks
        for callback in self._callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback()
                else:
                    callback()
            except Exception as exc:
                log.exception("Shutdown callback failed: %s", exc)

        # Wait for in-flight work to complete (with timeout)
        log.info("Waiting for in-flight work to complete (timeout: %.1fs)", self.drain_timeout)
        try:
            await asyncio.wait_for(self._wait_for_drain(), timeout=self.drain_timeout)
        except TimeoutError:
            log.warning("Drain timeout exceeded, forcing shutdown")

        if self.audit_chain:
            await self.audit_chain.append_async(
                {
                    "type": "ha_shutdown_completed",
                    "signal": signal_name,
                }
            )
        log.info("Graceful shutdown completed")

    async def _wait_for_drain(self) -> None:
        """Wait for in-flight jobs to complete. Override in subclasses."""
        # Default implementation: just wait a bit
        await asyncio.sleep(0.1)

    def install_signal_handlers(self) -> None:
        """Install signal handlers for graceful shutdown."""
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                self._original_handlers[sig] = signal.getsignal(sig)
                signal.signal(sig, self._signal_handler)
            except (OSError, ValueError):
                pass  # Not in main thread or signal not available

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Signal handler that triggers async shutdown."""
        # Schedule the async shutdown
        asyncio.create_task(self.shutdown(signal.Signals(signum).name))

    def remove_signal_handlers(self) -> None:
        """Restore original signal handlers."""
        for sig, handler in self._original_handlers.items():
            with contextlib.suppress(OSError, ValueError):
                signal.signal(sig, handler)


class HAManager:
    """High-level HA manager coordinating leader election, health checks, and shutdown."""

    def __init__(
        self,
        settings: Settings,
        audit_chain: AuditChain,
        election_config: LeaderElectionConfig | None = None,
        drain_timeout: float = 30.0,
    ) -> None:
        self.settings = settings
        self.audit_chain = audit_chain
        self.election_config = election_config or LeaderElectionConfig()
        self.drain_timeout = drain_timeout

        self.election = LeaderElection(self.election_config, settings, audit_chain)
        self.health = HealthCheckCoordinator(settings, audit_chain)
        self.shutdown = GracefulShutdown(settings, audit_chain, drain_timeout)
        self._state = HAState.STARTING
        self._node_info = NodeInfo(
            node_id=self.election.node_id,
            hostname=os.uname().nodename,
            pid=os.getpid(),
            state=HAState.STARTING,
            started_at=time.time(),
            last_heartbeat=time.time(),
        )
        self.health.set_node_info(self._node_info)
        self._ha_mode = os.environ.get("STRIX_HA_MODE", "false").lower() == "true"

    @property
    def node_id(self) -> str:
        return self._node_info.node_id

    @property
    def state(self) -> HAState:
        return self._state

    @property
    def is_ha_mode(self) -> bool:
        return self._ha_mode

    @property
    def is_leader(self) -> bool:
        return self._state == HAState.LEADER

    async def start(self) -> bool:
        """Start HA manager. Returns True if this node is leader."""
        if not self.is_ha_mode:
            log.info("HA mode not enabled, running in single-node mode")
            self._state = HAState.LEADER
            return True

        log.info("Starting HA manager in HA mode: %s", self.node_id)
        self._state = HAState.STANDBY

        # Register default health checks
        self.health.register_check("database", self._check_database)
        self.health.register_check("redis", self._check_redis)

        # Campaign for leadership
        async with self.election.campaign() as is_leader:
            if is_leader:
                self._state = HAState.LEADER
                log.info("Node became leader: %s", self.node_id)
            else:
                self._state = HAState.STANDBY
                log.info("Node is standby: %s", self.node_id)

            # Install signal handlers for graceful shutdown
            self.shutdown.install_signal_handlers()

            # Register shutdown callback for leader election release
            self.shutdown.register_shutdown_callback(self.election.release_leadership)

            return is_leader

    async def stop(self) -> None:
        """Stop HA manager."""
        log.info("Stopping HA manager: %s", self.node_id)
        self._state = HAState.SHUTTING_DOWN
        self.shutdown.remove_signal_handlers()
        await self.shutdown.shutdown("STOP")
        self._state = HAState.STOPPED

    async def _check_database(self) -> dict[str, Any]:
        """Check database connectivity."""
        async with store.get_db_async() as db, db.transaction() as conn:
            await conn.execute("SELECT 1")
        return {"connected": True}

    async def _check_redis(self) -> dict[str, Any]:
        """Check Redis connectivity."""
        try:
            from strix.api.dependencies import get_redis

            redis = await get_redis()
            await redis.ping()
            return {"connected": True}
        except Exception as exc:
            return {"connected": False, "error": str(exc)}

    async def get_status(self) -> dict[str, Any]:
        """Get HA status."""
        health = await self.health.get_overall_health()
        return {
            "node_id": self.node_id,
            "state": self._state.value,
            "ha_mode": self.is_ha_mode,
            "is_leader": self.is_leader,
            "health": health,
            "uptime_seconds": time.time() - self._node_info.started_at,
        }


# Convenience functions for integration with app.py


async def create_ha_manager(
    settings: Settings,
    audit_chain: AuditChain,
    election_config: LeaderElectionConfig | None = None,
    drain_timeout: float = 30.0,
) -> HAManager:
    """Factory function to create and initialize HA manager."""
    manager = HAManager(
        settings=settings,
        audit_chain=audit_chain,
        election_config=election_config,
        drain_timeout=drain_timeout,
    )
    await manager.start()
    return manager
