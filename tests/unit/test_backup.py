"""Backup and restore: one verified artifact per backend.

The disaster-recovery story is only real if the artifact is written and then
verified with the same checks a restore relies on, and if the database password
never reaches the command line.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ishastra.audit import AuditChain
from ishastra.core import standby, store
from ishastra.core.standby import StandbyError

pytestmark = pytest.mark.asyncio


async def test_sqlite_backup_is_written_and_verifies(store_with_scope, tmp_path: Path):
    chain = AuditChain(persistent=True, hmac_key="k" * 32)
    await chain.append_async({"event": "backup-source"})

    source = store.current_path()
    assert source != ":memory:"

    result = standby.create_backup(source, tmp_path / "backups")

    assert result["backend"] == "sqlite"
    artifact = Path(result["path"])
    assert artifact.exists() and artifact.stat().st_size > 0
    assert artifact.stat().st_mode & 0o077 == 0, "backup is readable by other users"

    assert not Path(f"{artifact}-wal").exists()
    assert not Path(f"{artifact}-shm").exists()
    assert [p.name for p in artifact.parent.iterdir()] == [artifact.name]

    info = await standby.verify_backup(artifact)
    assert info["backend"] == "sqlite"
    assert "audit_chain" in info["tables"]
    assert info["audit_chain_entries"] >= 1


async def test_unrecognised_backup_is_rejected(tmp_path: Path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"definitely not a database")
    with pytest.raises(StandbyError, match="unrecognised backup format"):
        await standby.verify_backup(junk)


async def test_empty_backup_is_rejected(tmp_path: Path):
    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    with pytest.raises(StandbyError, match="empty"):
        await standby.verify_backup(empty)


async def test_missing_database_is_reported(tmp_path: Path):
    with pytest.raises(StandbyError, match="database not found or empty"):
        standby.create_backup(str(tmp_path / "absent.db"), tmp_path / "backups")


async def test_postgres_password_never_reaches_argv():
    args, env, database = standby._pg_connection_args(
        "postgresql://ishastra:s3cret@db.internal:6543/ishastra?sslmode=require"
    )

    assert "s3cret" not in " ".join(args), "the password would be visible in /proc/<pid>/cmdline"
    assert env["PGPASSWORD"] == "s3cret"
    assert env["PGSSLMODE"] == "require"
    assert database == "ishastra"
    assert args[:4] == ["--host", "db.internal", "--port", "6543"]
