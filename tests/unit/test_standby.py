"""Tests for ishastra.core.standby module - Warm standby promotion."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from ishastra.audit import AuditChain
from ishastra.config import Settings
from ishastra.core import store
from ishastra.core.standby import (
    StandbyError,
    acquire_standby_lease,
    promote_standby,
    restore_database,
    run_readiness_checks,
    verify_backup,
)


@pytest_asyncio.fixture
async def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    store.configure(path)
    db = await store.get_database()
    await db.migrate()
    yield path
    await store.close_database()
    Path(path).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(path + suffix).unlink(missing_ok=True)


@pytest_asyncio.fixture
async def backup_db(temp_db):
    """Create a valid backup database with all required tables."""

    backup_path = temp_db.replace(".db", "_backup.db")
    store.configure(backup_path)
    db = await store.get_database()
    await db.migrate()

    chain = AuditChain(persistent=True, hmac_key="test-hmac-key")
    await chain.append_async({"event": "test_event", "data": "test"})

    db_conn = await db._get_conn()
    await db_conn.execute("PRAGMA user_version = 1")
    await db_conn.commit()
    await db._put_conn(db_conn)

    yield backup_path

    await store.close_database()
    Path(backup_path).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(backup_path + suffix).unlink(missing_ok=True)


@pytest.fixture
def mock_settings():
    """Create mock settings."""
    settings = MagicMock(spec=Settings)
    settings.audit_hmac_key = "test-hmac-key"
    settings.scope_mode = "global"
    settings.scope_file = "/tmp/scope.json"
    return settings


@pytest_asyncio.fixture
async def audit_chain(temp_db):
    """Create a test audit chain."""
    chain = AuditChain(persistent=True, hmac_key="test-hmac-key")
    yield chain


class TestStandbyError:
    """Test StandbyError exception."""

    def test_standby_error_inheritance(self):
        """Test StandbyError is a RuntimeError."""
        assert issubclass(StandbyError, RuntimeError)

    def test_standby_error_message(self):
        """Test StandbyError message."""
        exc = StandbyError("test error message")
        assert str(exc) == "test error message"


class TestVerifyBackup:
    """Tests for verify_backup function."""

    @pytest.mark.asyncio
    async def test_verify_backup_not_found(self):
        """Test verify_backup raises error for non-existent file."""
        with pytest.raises(StandbyError, match="backup file not found"):
            await verify_backup(Path("/nonexistent/backup.db"))

    @pytest.mark.asyncio
    async def test_verify_backup_not_a_file(self, tmp_path):
        """Test verify_backup raises error for directory."""
        with pytest.raises(StandbyError, match="backup path is not a file"):
            await verify_backup(tmp_path)

    @pytest.mark.asyncio
    async def test_verify_backup_empty_file(self, tmp_path):
        """Test verify_backup raises error for empty file."""
        empty_file = tmp_path / "empty.db"
        empty_file.write_bytes(b"")
        with pytest.raises(StandbyError, match="backup file is empty"):
            await verify_backup(empty_file)

    @pytest.mark.asyncio
    async def test_verify_backup_invalid_sqlite(self, tmp_path):
        """A file that is neither a SQLite snapshot nor a pg_dump archive is refused."""
        invalid_file = tmp_path / "invalid.db"
        invalid_file.write_bytes(b"not a sqlite database")
        with pytest.raises(StandbyError, match="unrecognised backup format"):
            await verify_backup(invalid_file)

    @pytest.mark.asyncio
    async def test_verify_backup_missing_tables(self, tmp_path):
        """Test verify_backup raises error for missing required tables."""

        db_path = tmp_path / "incomplete.db"
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE findings (id TEXT PRIMARY KEY)")
        conn.commit()
        conn.close()

        with pytest.raises(StandbyError, match="backup missing required tables"):
            await verify_backup(db_path)

    @pytest.mark.asyncio
    async def test_verify_backup_empty_audit_chain(self, tmp_path):
        """Test verify_backup raises error for empty audit_chain."""
        db_path = tmp_path / "empty_chain.db"
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE findings (id TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE audit_log (id TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE audit_chain (id INTEGER PRIMARY KEY, data TEXT)")
        conn.execute("CREATE TABLE api_keys (id TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("CREATE TABLE finding_records (tenant TEXT, fingerprint TEXT)")
        conn.execute("CREATE TABLE engagement_policies (id TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO settings (key, value) VALUES ('schema_version', '1')")
        conn.commit()
        conn.close()

        with pytest.raises(StandbyError, match="backup has empty audit_chain"):
            await verify_backup(db_path)

    @pytest.mark.asyncio
    async def test_verify_backup_success(self, backup_db):
        """Test successful backup verification."""
        result = await verify_backup(Path(backup_db))

        assert result["path"] == backup_db
        assert result["size_bytes"] > 0
        assert result["schema_version"] == 1
        assert result["audit_chain_entries"] > 0
        assert "jobs" in result["tables"]
        assert "findings" in result["tables"]
        assert "audit_chain" in result["tables"]
        assert "api_keys" in result["tables"]
        assert "settings" in result["tables"]

    @pytest.mark.asyncio
    async def test_verify_backup_schema_version_zero(self, tmp_path):
        """Test verify_backup handles missing schema_version."""
        db_path = tmp_path / "no_version.db"
        conn = sqlite3.connect(db_path)
        conn.execute("CREATE TABLE jobs (id TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE findings (id TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE audit_log (id TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE audit_chain (id INTEGER PRIMARY KEY, data TEXT)")
        conn.execute("CREATE TABLE api_keys (id TEXT PRIMARY KEY)")
        conn.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)")
        conn.execute("CREATE TABLE finding_records (tenant TEXT, fingerprint TEXT)")
        conn.execute("CREATE TABLE engagement_policies (id TEXT PRIMARY KEY)")
        conn.execute("INSERT INTO audit_chain (data) VALUES ('test')")
        conn.commit()
        conn.close()

        result = await verify_backup(db_path)
        assert result["schema_version"] == 0


class TestRestoreDatabase:
    """Tests for restore_database function."""

    @pytest.mark.asyncio
    async def test_restore_database_success(self, backup_db, tmp_path):
        """Test successful database restore."""
        target_path = tmp_path / "restored.db"

        restore_database(Path(backup_db), target_path)

        assert target_path.exists()
        assert target_path.stat().st_mode & 0o777 == 0o600

        conn = sqlite3.connect(target_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM audit_chain")
        count = cursor.fetchone()[0]
        assert count > 0
        conn.close()

    @pytest.mark.asyncio
    async def test_restore_database_creates_parent_dir(self, backup_db, tmp_path):
        """Test restore_database creates parent directories."""
        target_path = tmp_path / "subdir" / "restored.db"

        restore_database(Path(backup_db), target_path)

        assert target_path.exists()

    @pytest.mark.asyncio
    async def test_restore_database_removes_wal_shm(self, tmp_path):
        """Test restore_database removes existing WAL/SHM files."""

        backup_path = tmp_path / "backup.db"
        from ishastra.core import store

        store.configure(str(backup_path))
        db = await store.get_database()
        await db.migrate()

        from ishastra.audit import AuditChain

        chain = AuditChain(persistent=True, hmac_key="test-hmac-key")
        await chain.append_async({"event": "test_event", "data": "test"})

        db_conn = await db._get_conn()
        await db_conn.execute("PRAGMA user_version = 1")
        await db_conn.commit()
        await db._put_conn(db_conn)

        await store.close_database()

        target_path = tmp_path / "restored.db"

        target_path.write_bytes(b"existing")
        wal_path = Path(str(target_path) + "-wal")
        shm_path = Path(str(target_path) + "-shm")
        wal_path.write_bytes(b"wal")
        shm_path.write_bytes(b"shm")

        restore_database(backup_path, target_path)

        assert not wal_path.exists()
        assert not shm_path.exists()

    @pytest.mark.asyncio
    async def test_restore_database_invalid_source(self, tmp_path):
        """Test restore_database fails with invalid source."""
        invalid_source = tmp_path / "invalid.db"
        invalid_source.write_bytes(b"not sqlite")
        target_path = tmp_path / "target.db"

        with pytest.raises(StandbyError, match="database restore failed"):
            restore_database(invalid_source, target_path)


class TestAcquireStandbyLease:
    """Tests for acquire_standby_lease function."""

    @pytest.mark.asyncio
    async def test_acquire_standby_lease_success(self, temp_db, mock_settings):
        """Test successful lease acquisition."""
        with patch("ishastra.core.standby.store") as mock_store:
            mock_store.configure = MagicMock()
            mock_store.reset_database = AsyncMock()

            with patch("ishastra.core.worker.acquire_worker_lease", return_value="/tmp/lease.lock"):
                lease_path = await acquire_standby_lease(temp_db)

                assert lease_path == "/tmp/lease.lock"
                mock_store.configure.assert_called_once_with(temp_db)
                mock_store.reset_database.assert_called_once()

    @pytest.mark.asyncio
    async def test_acquire_standby_lease_failure(self, temp_db):
        """Test lease acquisition failure raises StandbyError."""
        from ishastra.core.worker import WorkerLeaseError

        with (
            patch("ishastra.core.standby.store") as mock_store,
            patch(
                "ishastra.core.worker.acquire_worker_lease",
                side_effect=WorkerLeaseError("Lease held by another process"),
            ),
            pytest.raises(StandbyError, match="Lease held by another process"),
        ):
            mock_store.configure = MagicMock()
            mock_store.reset_database = AsyncMock()
            await acquire_standby_lease(temp_db)


class TestRunReadinessChecks:
    """Tests for run_readiness_checks function."""

    @pytest.mark.asyncio
    async def test_run_readiness_checks_success(self, temp_db, mock_settings, audit_chain):
        """Test successful readiness checks."""

        scope_content = """{
  "program": "Test Program",
  "authorized_by": "Test Authorizer",
  "authorization_ref": "TEST-001",
  "include": ["example.com"],
  "exclude": [],
  "authorized_networks": [],
  "allowed_ports": [80, 443],
  "allow_broad_networks": false
}"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(scope_content)
            scope_path = f.name

        mock_settings.scope_file = scope_path

        with patch("ishastra.core.standby.store") as mock_store:
            mock_store.configure = MagicMock()
            mock_store.reset_database = AsyncMock()
            mock_store.schema_version = AsyncMock(return_value=1)
            mock_store.chain_count = AsyncMock(return_value=10)

            mock_db = AsyncMock()
            mock_store.get_database = AsyncMock(return_value=mock_db)
            mock_conn = AsyncMock()
            mock_transaction = MagicMock()
            mock_transaction.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_transaction.__aexit__ = AsyncMock()
            mock_db.transaction = MagicMock(return_value=mock_transaction)
            mock_store._fetchone = AsyncMock(return_value=(1,))

            with (
                patch("ishastra.core.standby.AuditChain", return_value=audit_chain),
                patch("ishastra.core.standby.get_settings", return_value=mock_settings),
                patch.object(audit_chain, "verify_async", return_value=(True, "ok")),
                patch("ishastra.core.scope.load", return_value=MagicMock(program="Test Program")),
            ):
                results = await run_readiness_checks(temp_db)

                assert results["audit_chain"]["ok"] is True
                assert results["schema_version"] == 1
                assert results["scope"]["ok"] is True
                assert results["api_keys"]["admin_count"] == 1
                assert results["api_keys"]["ok"] is True
                assert results["audit_chain_entries"] == 10

    @pytest.mark.asyncio
    async def test_run_readiness_checks_audit_chain_fails(self, temp_db, mock_settings):
        """Test readiness checks fail on audit chain verification."""
        with patch("ishastra.core.standby.store") as mock_store:
            mock_store.configure = MagicMock()
            mock_store.reset_database = AsyncMock()
            mock_store.schema_version = AsyncMock(return_value=1)
            mock_store.chain_count = AsyncMock(return_value=10)

            mock_audit_chain = AsyncMock()
            mock_audit_chain.verify_async = AsyncMock(return_value=(False, "chain broken"))

            with (
                patch("ishastra.core.standby.AuditChain", return_value=mock_audit_chain),
                patch("ishastra.core.standby.get_settings", return_value=mock_settings),
                pytest.raises(StandbyError, match="audit chain verification failed"),
            ):
                await run_readiness_checks(temp_db)

    @pytest.mark.asyncio
    async def test_run_readiness_checks_no_admin_keys(self, temp_db):
        """Test readiness checks fail when no admin keys (managed mode)."""
        mock_settings = MagicMock(spec=Settings)
        mock_settings.audit_hmac_key = "test-hmac-key"
        mock_settings.scope_mode = "managed"

        with patch("ishastra.core.standby.store") as mock_store:
            mock_store.configure = MagicMock()
            mock_store.reset_database = AsyncMock()
            mock_store.schema_version = AsyncMock(return_value=1)
            mock_store.chain_count = AsyncMock(return_value=10)
            mock_store.load_policies = AsyncMock(return_value=[{"status": "active"}])

            mock_db = AsyncMock()
            mock_store.get_database = AsyncMock(return_value=mock_db)

            mock_conn = AsyncMock()
            mock_transaction = MagicMock()
            mock_transaction.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_transaction.__aexit__ = AsyncMock()
            mock_db.transaction = MagicMock(return_value=mock_transaction)

            mock_store._fetchone = AsyncMock(return_value=(0,))

            mock_audit_chain = AsyncMock()
            mock_audit_chain.verify_async = AsyncMock(return_value=(True, "ok"))

            with (
                patch("ishastra.core.standby.AuditChain", return_value=mock_audit_chain),
                patch("ishastra.core.standby.get_settings", return_value=mock_settings),
                pytest.raises(StandbyError, match="no active admin API keys found"),
            ):
                await run_readiness_checks(temp_db)

    @pytest.mark.asyncio
    async def test_run_readiness_checks_no_admin_keys_managed(self, temp_db):
        """Test readiness checks fail when no admin API keys exist (managed mode)."""
        mock_settings = MagicMock(spec=Settings)
        mock_settings.audit_hmac_key = "test-hmac-key"
        mock_settings.scope_mode = "managed"

        with patch("ishastra.core.standby.store") as mock_store:
            mock_store.configure = MagicMock()
            mock_store.reset_database = AsyncMock()
            mock_store.schema_version = AsyncMock(return_value=1)
            mock_store.chain_count = AsyncMock(return_value=10)
            mock_store.load_policies = AsyncMock(return_value=[{"status": "active"}])

            mock_db = AsyncMock()
            mock_store.get_database = AsyncMock(return_value=mock_db)

            mock_conn = AsyncMock()
            mock_transaction = MagicMock()
            mock_transaction.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_transaction.__aexit__ = AsyncMock()
            mock_db.transaction = MagicMock(return_value=mock_transaction)

            mock_store._fetchone = AsyncMock(return_value=(0,))

            mock_audit_chain = AsyncMock()
            mock_audit_chain.verify_async = AsyncMock(return_value=(True, "ok"))

            with (
                patch("ishastra.core.standby.AuditChain", return_value=mock_audit_chain),
                patch("ishastra.core.standby.get_settings", return_value=mock_settings),
                pytest.raises(StandbyError, match="no active admin API keys found"),
            ):
                await run_readiness_checks(temp_db)

    @pytest.mark.asyncio
    async def test_run_readiness_checks_managed_mode_no_policies(self, temp_db):
        """Test readiness checks fail in managed mode with no active policies."""
        mock_settings = MagicMock(spec=Settings)
        mock_settings.audit_hmac_key = "test-hmac-key"
        mock_settings.scope_mode = "managed"

        with patch("ishastra.core.standby.store") as mock_store:
            mock_store.configure = MagicMock()
            mock_store.reset_database = AsyncMock()
            mock_store.schema_version = AsyncMock(return_value=1)
            mock_store.chain_count = AsyncMock(return_value=10)
            mock_store.load_policies = AsyncMock(return_value=[])

            mock_db = AsyncMock()
            mock_store.get_database = AsyncMock(return_value=mock_db)
            mock_conn = AsyncMock()
            mock_db.transaction.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_db.transaction.return_value.__aexit__ = AsyncMock()
            mock_store._fetchone = AsyncMock(return_value=(1,))

            mock_audit_chain = AsyncMock()
            mock_audit_chain.verify_async = AsyncMock(return_value=(True, "ok"))

            with (
                patch("ishastra.core.standby.AuditChain", return_value=mock_audit_chain),
                patch("ishastra.core.standby.get_settings", return_value=mock_settings),
                pytest.raises(StandbyError, match="no active engagement policies found"),
            ):
                await run_readiness_checks(temp_db)

    @pytest.mark.asyncio
    async def test_run_readiness_checks_global_mode_scope_not_found(self, temp_db):
        """Test readiness checks fail in global mode when scope file missing."""
        mock_settings = MagicMock(spec=Settings)
        mock_settings.audit_hmac_key = "test-hmac-key"
        mock_settings.scope_mode = "global"
        mock_settings.scope_file = "/nonexistent/scope.json"

        with patch("ishastra.core.standby.store") as mock_store:
            mock_store.configure = MagicMock()
            mock_store.reset_database = AsyncMock()
            mock_store.schema_version = AsyncMock(return_value=1)
            mock_store.chain_count = AsyncMock(return_value=10)

            mock_db = AsyncMock()
            mock_store.get_database = AsyncMock(return_value=mock_db)
            mock_conn = AsyncMock()
            mock_db.transaction.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_db.transaction.return_value.__aexit__ = AsyncMock()
            mock_store._fetchone = AsyncMock(return_value=(1,))

            mock_audit_chain = AsyncMock()
            mock_audit_chain.verify_async = AsyncMock(return_value=(True, "ok"))

            with (
                patch("ishastra.core.standby.AuditChain", return_value=mock_audit_chain),
                patch("ishastra.core.standby.get_settings", return_value=mock_settings),
                pytest.raises(StandbyError, match="scope file not found"),
            ):
                await run_readiness_checks(temp_db)

    @pytest.mark.asyncio
    async def test_run_readiness_checks_global_mode_scope_load_fails(self, temp_db):
        """Test readiness checks fail when scope file exists but fails to load."""
        mock_settings = MagicMock(spec=Settings)
        mock_settings.audit_hmac_key = "test-hmac-key"
        mock_settings.scope_mode = "global"
        mock_settings.scope_file = "/tmp/scope.json"

        with patch("ishastra.core.standby.store") as mock_store:
            mock_store.configure = MagicMock()
            mock_store.reset_database = AsyncMock()
            mock_store.schema_version = AsyncMock(return_value=1)
            mock_store.chain_count = AsyncMock(return_value=10)

            mock_db = AsyncMock()
            mock_store.get_database = AsyncMock(return_value=mock_db)
            mock_conn = AsyncMock()
            mock_db.transaction.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_db.transaction.return_value.__aexit__ = AsyncMock()
            mock_store._fetchone = AsyncMock(return_value=(1,))

            mock_audit_chain = AsyncMock()
            mock_audit_chain.verify_async = AsyncMock(return_value=(True, "ok"))

            with (
                patch("ishastra.core.standby.AuditChain", return_value=mock_audit_chain),
                patch("ishastra.core.standby.get_settings", return_value=mock_settings),
                patch("pathlib.Path.exists", return_value=True),
                patch("ishastra.core.scope.load", return_value=None),
                pytest.raises(StandbyError, match="scope file exists but failed to load"),
            ):
                await run_readiness_checks(temp_db)


class TestPromoteStandby:
    """Tests for promote_standby function."""

    @pytest.mark.asyncio
    async def test_promote_standby_no_backups(self, tmp_path):
        """Test promotion fails when no backup files found."""
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        db_path = tmp_path / "restored.db"

        with pytest.raises(StandbyError, match="no backup files found"):
            await promote_standby(backup_dir, db_path)

    @pytest.mark.asyncio
    async def test_promote_standby_success(self, tmp_path, mock_settings, audit_chain):
        """Test successful standby promotion."""

        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        backup_path = backup_dir / "ishastra-backup.db"

        from ishastra.core import store

        store.configure(str(backup_path))
        db = await store.get_database()
        await db.migrate()

        from ishastra.audit import AuditChain

        chain = AuditChain(persistent=True, hmac_key="test-hmac-key")
        await chain.append_async({"event": "test_event", "data": "test"})

        db_conn = await db._get_conn()
        await db_conn.execute("PRAGMA user_version = 1")
        await db_conn.commit()
        await db._put_conn(db_conn)

        await store.close_database()

        db_path = tmp_path / "promoted.db"

        with patch("ishastra.core.standby.verify_backup") as mock_verify:
            mock_verify.return_value = {
                "path": str(backup_path),
                "size_bytes": 1024,
                "schema_version": 1,
                "audit_chain_entries": 5,
                "tables": ["jobs", "findings"],
            }

            with (
                patch("ishastra.core.standby.restore_database") as mock_restore,
                patch(
                    "ishastra.core.standby.acquire_standby_lease",
                    return_value="/tmp/lease.lock",
                ) as mock_lease,
                patch("ishastra.core.standby.run_readiness_checks") as mock_readiness,
            ):
                mock_readiness.return_value = {
                    "audit_chain": {"ok": True, "reason": "ok"},
                    "schema_version": 1,
                    "scope": {"mode": "global", "ok": True},
                    "api_keys": {"admin_count": 1, "ok": True},
                    "audit_chain_entries": 5,
                }

                result = await promote_standby(backup_dir, db_path)

                assert result["ok"] is True
                assert result["backup_used"] == str(backup_path)
                assert result["db_restored_to"] == str(db_path)
                assert result["lease_path"] == "/tmp/lease.lock"
                assert "timings_ms" in result
                assert "rto_ms" in result

                mock_verify.assert_called_once()
                mock_restore.assert_called_once()
                mock_lease.assert_called_once()
                mock_readiness.assert_called_once()


class TestStandbyIntegration:
    """Integration tests for standby promotion workflow."""

    @pytest.mark.asyncio
    async def test_full_promotion_workflow(self, tmp_path, mock_settings):
        """Test complete promotion workflow with real databases."""

        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()

        backup_path = backup_dir / "ishastra-backup.db"
        store.configure(str(backup_path))
        db = await store.get_database()
        await db.migrate()

        chain = AuditChain(persistent=True, hmac_key="test-hmac-key")
        await chain.append_async({"event": "test", "data": "test"})

        db_conn = await db._get_conn()
        await db_conn.execute("UPDATE settings SET value = '1' WHERE key = 'schema_version'")
        await db_conn.commit()
        await db._put_conn(db_conn)

        await store.close_database()

        db_path = tmp_path / "promoted.db"

        mock_settings_managed = MagicMock(spec=Settings)
        mock_settings_managed.audit_hmac_key = "test-hmac-key"
        mock_settings_managed.scope_mode = "managed"
        mock_settings_managed.scope_file = "/tmp/scope.json"

        with (
            patch("ishastra.core.standby.get_settings", return_value=mock_settings_managed),
            patch("ishastra.core.standby.AuditChain") as mock_chain_class,
            patch("ishastra.core.worker.acquire_worker_lease", return_value="/tmp/lease.lock"),
            patch("ishastra.core.standby.store") as mock_store,
        ):
            mock_chain = AsyncMock()
            mock_chain.verify_async = AsyncMock(return_value=(True, "ok"))
            mock_chain_class.return_value = mock_chain

            mock_store.configure = MagicMock()
            mock_store.reset_database = AsyncMock()
            mock_store.schema_version = AsyncMock(return_value=1)
            mock_store.chain_count = AsyncMock(return_value=1)
            mock_store.load_policies = AsyncMock(return_value=[{"status": "active"}])

            mock_db = AsyncMock()
            mock_store.get_database = AsyncMock(return_value=mock_db)
            mock_conn = AsyncMock()
            mock_transaction = MagicMock()
            mock_transaction.__aenter__ = AsyncMock(return_value=mock_conn)
            mock_transaction.__aexit__ = AsyncMock()
            mock_db.transaction = MagicMock(return_value=mock_transaction)
            mock_store._fetchone = AsyncMock(return_value=(1,))

            result = await promote_standby(backup_dir, db_path)

            assert result["ok"] is True
            assert result["backup_used"] == str(backup_path)
            assert result["db_restored_to"] == str(db_path)
