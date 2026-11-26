"""Database optimization utilities for IshAstra.

Provides:
- SQLite WAL configuration
- PostgreSQL connection pool tuning
- Pagination helpers
- Query optimization utilities
- Database maintenance procedures
- Backup and restore helpers
"""

from __future__ import annotations

import logging
import shutil
import time
from collections.abc import Generator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiosqlite

try:
    import asyncpg
except ImportError:
    asyncpg = None

from ishastra.config import Settings

log = logging.getLogger(__name__)


@dataclass
class DbOptimizationConfig:
    """Configuration for database optimization."""

    # SQLite WAL settings
    sqlite_wal_mode: bool = True
    sqlite_wal_autocheckpoint: int = 1000  # Pages
    sqlite_synchronous: str = "NORMAL"  # NORMAL or FULL
    sqlite_cache_size: int = -2000  # KB, negative = KB, positive = pages
    sqlite_temp_store: str = "MEMORY"

    # Connection pooling
    connection_pool_size: int = 5
    connection_timeout: float = 30.0
    max_connections: int = 20

    # Query settings
    statement_timeout: float = 60.0  # Seconds
    idle_in_transaction_timeout: float = 300.0  # Seconds

    # Maintenance
    auto_vacuum: str = "INCREMENTAL"  # NONE, FULL, INCREMENTAL
    vacuum_threshold: int = 1000  # Rows deleted before auto-vacuum
    analyze_after_write: bool = True

    # Pagination defaults
    default_page_size: int = 100
    max_page_size: int = 1000

    # Backup
    backup_retention_days: int = 30
    backup_compress: bool = True


class DatabaseOptimizer:
    """Manages database optimization settings and maintenance."""

    def __init__(self, config: DbOptimizationConfig | None = None, settings: Settings | None = None):
        self.config = config or self._defaults(settings)
        self._db_path: str | None = None

    @staticmethod
    def _defaults(settings: Settings | None = None) -> DbOptimizationConfig:
        if settings:
            return DbOptimizationConfig(
                sqlite_wal_mode=settings.environment != "test",
                sqlite_wal_autocheckpoint=min(
                    5000,
                    1000 + (settings.worker_memory_mb // 200 if settings.worker_memory_mb else 0),
                ),
                connection_pool_size=min(20, max(1, settings.workers * 2)),
                max_connections=min(
                    50,
                    settings.worker_memory_mb // 256 if settings.worker_memory_mb else 20,
                ),
                default_page_size=100,
                max_page_size=1000,
                backup_retention_days=30,
            )
        return DbOptimizationConfig()

    def configure_sqlite(self, db_path: str | Path, optimize: bool = True) -> None:
        """Configure SQLite database for optimal performance.

        Should be called after opening a new database connection.
        """
        db_path = Path(db_path)
        self._db_path = str(db_path)

        if not db_path.exists():
            log.warning("Database path does not exist: %s", db_path)
            return

        try:
            # Use sync connection for configuration
            import aiosqlite

            async def _configure():
                async with aiosqlite.connect(str(db_path)) as conn:
                    if self.config.sqlite_wal_mode:
                        await conn.execute("PRAGMA journal_mode=WAL")
                        log.debug("Enabled WAL mode for %s", db_path)

                    await conn.execute(f"PRAGMA synchronous={self.config.sqlite_synchronous}")
                    await conn.execute(f"PRAGMA cache_size={self.config.sqlite_cache_size}")
                    await conn.execute(f"PRAGMA temp_store={self.config.sqlite_temp_store}")

                    if self.config.auto_vacuum != "NONE":
                        await conn.execute(f"PRAGMA auto_vacuum={self.config.auto_vacuum}")

                    # Create optimization indices
                    await self._create_optimization_indexes(conn)

            import asyncio
            asyncio.run(_configure())
            log.info("Database optimization configured for %s", db_path)

        except Exception as e:
            log.error("Failed to configure database optimization: %s", e)

    async def configure_sqlite_async(self, db_path: str | Path) -> None:
        """Configure SQLite database for optimal performance (async version)."""
        db_path = Path(db_path)
        self._db_path = str(db_path)

        if not db_path.exists():
            log.warning("Database path does not exist: %s", db_path)
            return

        try:
            async with aiosqlite.connect(str(db_path)) as conn:
                if self.config.sqlite_wal_mode:
                    await conn.execute("PRAGMA journal_mode=WAL")
                    log.debug("Enabled WAL mode for %s", db_path)

                await conn.execute(f"PRAGMA synchronous={self.config.sqlite_synchronous}")
                await conn.execute(f"PRAGMA cache_size={self.config.sqlite_cache_size}")
                await conn.execute(f"PRAGMA temp_store={self.config.sqlite_temp_store}")

                if self.config.auto_vacuum != "NONE":
                    await conn.execute(f"PRAGMA auto_vacuum={self.config.auto_vacuum}")

                await self._create_optimization_indexes(conn)

            log.info("Database optimization configured for %s", db_path)

        except Exception as e:
            log.error("Failed to configure database optimization: %s", e)

    async def _create_optimization_indexes(self, conn: aiosqlite.Connection) -> None:
        """Create optimization indices if they don't exist."""
        indexes = [
            # Findings optimization: common query patterns
            "CREATE INDEX IF NOT EXISTS idx_findings_tenant_severity "
            "ON findings (tenant, severity) WHERE tenant IS NOT NULL",

            "CREATE INDEX IF NOT EXISTS idx_findings_job_status "
            "ON findings (job_id, status) WHERE job_id IS NOT NULL",

            "CREATE INDEX IF NOT EXISTS idx_findings_category_severity "
            "ON findings (category, severity) WHERE category IS NOT NULL",

            # Jobs optimization
            "CREATE INDEX IF NOT EXISTS idx_jobs_tenant_state_created "
            "ON jobs (tenant, state, created_at) WHERE tenant IS NOT NULL",

            "CREATE INDEX IF NOT EXISTS idx_jobs_state_created "
            "ON jobs (state, created_at)",

            # Evidence packs optimization
            "CREATE INDEX IF NOT EXISTS idx_evidence_packs_tenant_created "
            "ON evidence_packs (tenant, created_at DESC) WHERE tenant IS NOT NULL",

            # Audit log optimization (if table exists)
            "CREATE INDEX IF NOT EXISTS idx_audit_log_tenant_ts "
            "ON audit_log (tenant, ts DESC) WHERE tenant IS NOT NULL",

            # Tenant users optimization
            "CREATE INDEX IF NOT EXISTS idx_tenant_users_tenant_active "
            "ON tenant_users (tenant_id, active) WHERE tenant_id IS NOT NULL",
        ]

        for index_sql in indexes:
            try:
                await conn.execute(index_sql)
            except Exception as e:
                log.debug("Could not create index: %s: %s", index_sql[:50], e)

    def configure_postgresql(self, pool: asyncpg.Pool) -> None:
        """Configure PostgreSQL connection pool for optimal performance."""
        if asyncpg is None:
            log.warning("asyncpg not available, skipping PostgreSQL optimization")
            return

        try:
            async def _configure():
                async with pool.acquire() as conn:
                    # Set per-connection settings
                    await conn.execute(
                        "SET statement_timeout = $1",
                        self.config.statement_timeout * 1000,
                    )
                    await conn.execute(
                        "SET idle_in_transaction_session_timeout = $1",
                        self.config.idle_in_transaction_timeout * 1000,
                    )

                    # Enable JIT if available
                    await conn.execute("SET jit = on")

                    # Optimize for bulk operations
                    await conn.execute("SET synchronous_commit = off")

                # Configure pool
                pool._timeout = self.config.connection_timeout

            import asyncio
            asyncio.run(_configure())
            log.info("PostgreSQL optimization configured")

        except Exception as e:
            log.error("Failed to configure PostgreSQL optimization: %s", e)

    async def vacuum_sqlite(self, db_path: str | Path, threshold: int | None = None) -> dict[str, Any]:
        """Run VACUUM on SQLite database if needed.

        Returns stats about the operation.
        """
        db_path = Path(db_path)
        if not db_path.exists():
            return {"error": f"Database not found: {db_path}"}

        threshold = threshold or self.config.vacuum_threshold

        # Get current stats
        async def _get_stats():
            async with aiosqlite.connect(str(db_path)) as conn:
                cursor = await conn.execute(
                    "SELECT page_count, page_size "
                    "FROM pragma_page_count(), pragma_page_size()",
                )
                row = await cursor.fetchone()
                if row:
                    return {"pages": row[0], "page_size": row[1], "size_bytes": row[0] * row[1]}
                return {}

        stats_before = await _get_stats()

        # Run VACUUM
        async def _vacuum():
            async with aiosqlite.connect(str(db_path)) as conn:
                await conn.execute("VACUUM")
                await conn.execute("ANALYZE")

        await _vacuum()

        stats_after = await _get_stats()

        return {
            "before": stats_before,
            "after": stats_after,
            "reclaimed_bytes": stats_before.get("size_bytes", 0) - stats_after.get("size_bytes", 0),
            "timestamp": time.time(),
        }

    async def backup_database(self, source_path: str | Path, backup_dir: str | Path,
                              compress: bool | None = None) -> Path:
        """Create a backup of the database.

        Args:
            source_path: Path to the database file
            backup_dir: Directory to store backup
            compress: Whether to compress (default: config value)

        Returns:
            Path to the backup file
        """
        source = Path(source_path)
        backup_dir = Path(backup_dir)
        backup_dir.mkdir(parents=True, exist_ok=True)

        compress = compress if compress is not None else self.config.backup_compress

        timestamp = time.strftime("%Y%m%d_%H%M%S")
        base_name = f"{source.stem}_{timestamp}"
        backup_path = backup_dir / f"{base_name}.db"

        if compress:
            backup_path = backup_path.with_suffix(".db.gz")

        # Copy database file
        shutil.copy2(str(source), str(backup_path))

        if compress:
            # Compress the backup
            import gzip
            compressed_path = backup_path.with_suffix(".gz")
            with open(backup_path, "rb") as f_in, gzip.open(compressed_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            backup_path.unlink()
            backup_path = compressed_path

        log.info("Database backup created: %s (size: %d bytes)", backup_path, backup_path.stat().st_size)

        # Clean old backups
        self._cleanup_old_backups(backup_dir)

        return backup_path

    def _cleanup_old_backups(self, backup_dir: Path) -> None:
        """Remove backups older than retention period."""
        if not backup_dir.exists():
            return

        cutoff = time.time() - (self.config.backup_retention_days * 86400)
        for f in backup_dir.iterdir():
            if f.is_file() and f.stat().st_mtime < cutoff:
                try:
                    f.unlink()
                    log.debug("Removed old backup: %s", f)
                except Exception as e:
                    log.warning("Failed to remove old backup %s: %s", f, e)

    async def verify_backup(self, backup_path: str | Path, original_path: str | Path) -> bool:
        """Verify a database backup can be restored.

        Args:
            backup_path: Path to the backup file
            original_path: Path to original database (for comparison)

        Returns:
            True if backup is valid
        """
        backup = Path(backup_path)
        if not backup.exists():
            log.error("Backup file not found: %s", backup)
            return False

        # Decompress if needed
        temp_path = Path(f"/tmp/verify_backup_{time.time()}.db")

        try:
            if backup.suffix == ".gz":
                import gzip
                with gzip.open(backup, "rb") as f_in, open(temp_path, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            else:
                shutil.copy2(backup, temp_path)

            # Verify it's a valid SQLite database
            async def _verify():
                async with aiosqlite.connect(str(temp_path)) as conn:
                    # Try to read schema
                    cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
                    row = await cursor.fetchone()
                    return row is not None

            valid = await _verify()

            if valid:
                log.info("Backup verified successfully: %s", backup)
            else:
                log.error("Backup verification failed: %s (invalid database)", backup)

            return valid

        except Exception as e:
            log.error("Backup verification failed: %s: %s", backup, e)
            return False

        finally:
            if temp_path.exists():
                temp_path.unlink()

    def paginate_query(
        self,
        query: str,
        params: tuple,
        page: int,
        page_size: int | None = None,
    ) -> tuple[str, tuple]:
        """Add pagination to a query.

        Args:
            query: SQL query (should return rows, not have LIMIT)
            params: Query parameters
            page: Page number (1-based)
            page_size: Items per page (default: config)

        Returns:
            (paginated_query, new_params)
        """
        page_size = page_size or self.config.default_page_size
        page_size = min(page_size, self.config.max_page_size)
        offset = (page - 1) * page_size

        # Remove any existing LIMIT
        query = query.replace("LIMIT ?", "").replace("LIMIT " + str(page_size), "")

        paginated = f"{query} LIMIT {page_size} OFFSET {offset}"
        return paginated, params

    def get_pagination_info(self, total_rows: int, page: int, page_size: int | None = None) -> dict[str, Any]:
        """Calculate pagination info.

        Args:
            total_rows: Total number of rows
            page: Current page (1-based)
            page_size: Items per page

        Returns:
            Dict with pagination metadata
        """
        page_size = page_size or self.config.default_page_size
        total_pages = (total_rows + page_size - 1) // page_size if total_rows > 0 else 0

        return {
            "page": page,
            "page_size": page_size,
            "total_rows": total_rows,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1,
            "next_page": page + 1 if page < total_pages else None,
            "prev_page": page - 1 if page > 1 else None,
        }


def stream_large_query_results(
    conn: Any,
    query: str,
    params: tuple = (),
    batch_size: int = 1000,
) -> Generator[list, None, None]:
    """Stream query results in batches to avoid loading all rows into memory.

    Use this for queries that may return large result sets.

    Args:
        conn: Database connection (asyncpg or aiosqlite)
        query: SQL query
        params: Query parameters
        batch_size: Number of rows per batch

    Yields:
        Lists of rows, each of size batch_size (or less for the last batch)
    """
    batch: list = []

    async def _stream():
        nonlocal batch
        cursor = await conn.execute(query, *params)

        while True:
            rows = await cursor.fetchmany(batch_size)
            if not rows:
                break
            yield rows

        await cursor.close()

    # For now, this is a sync placeholder - actual implementation
    # would depend on connection type
    yield batch


def create_optimized_connection_settings(profile: str = "standard") -> dict[str, Any]:
    """Get optimized connection settings for a resource profile.

    Args:
        profile: Profile name (lightweight, standard, high-capacity)

    Returns:
        Dict of connection settings
    """
    from ishastra.core.resource_profiles import PROFILES, get_profile

    if profile not in PROFILES:
        profile = "standard"

    p = get_profile(profile)

    settings = {
        "pool_size": p.worker_concurrency * 2,
        "max_overflow": p.worker_concurrency,
        "pool_timeout": 30,
        "pool_recycle": 3600,
        "pool_pre_ping": True,
    }

    # Profile-specific tuning
    if profile == "lightweight":
        settings.update({
            "pool_size": 1,
            "max_overflow": 0,
            "sqlite_wal": True,
        })
    elif profile == "standard":
        settings.update({
            "pool_size": 5,
            "max_overflow": 5,
        })
    elif profile == "high-capacity":
        settings.update({
            "pool_size": 20,
            "max_overflow": 30,
            "pool_timeout": 60,
        })

    return settings
