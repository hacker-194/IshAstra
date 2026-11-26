"""Failure-injection tests for lease fencing and automated failover.

These tests verify that:
1. Fencing tokens prevent stale holders from operating after losing lease
2. Automated failover works when lease expires
3. Token increments monotonically on acquisition and renewal
"""

import time
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ishastra.core import store


class MockRow(dict):
    """Mock row that supports both dict access and attribute access."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__dict__ = self


def make_mock_pg_db():
    """Create a mock PostgreSQL database with proper advisory_lock context manager."""
    db = MagicMock()
    db.is_postgresql.return_value = True

    # Advisory lock connection (used by try_acquire_lease)
    advisory_conn = AsyncMock()
    advisory_conn.fetchrow = AsyncMock()  # For _fetchone on PostgreSQL
    advisory_conn.execute = AsyncMock(return_value="INSERT 0 1")  # For _execute

    @asynccontextmanager
    async def advisory_lock_ctx(lock_id):
        yield advisory_conn

    db.advisory_lock = advisory_lock_ctx

    # Transaction connection (used by renew_lease, get_lease_holder, release_lease, list_active_leases)
    txn_conn = AsyncMock()
    txn_conn.fetchrow = AsyncMock()  # For _fetchone on PostgreSQL
    txn_conn.fetch = AsyncMock()     # For _fetchall on PostgreSQL
    txn_conn.execute = AsyncMock(return_value="DELETE 1")  # For _execute

    @asynccontextmanager
    async def transaction_ctx():
        yield txn_conn

    db.transaction = transaction_ctx

    return db, advisory_conn, txn_conn


def mock_is_pg_connection(conn):
    """Mock _is_postgresql_connection to return True for our mock connections."""
    # Check if it's one of our mock connections
    return hasattr(conn, 'fetchrow') and callable(conn.fetchrow)


class TestLeaseFencing:
    """Tests for lease fencing token mechanism."""

    @pytest.fixture
    def mock_pg_db(self):
        return make_mock_pg_db()

    @pytest.fixture(autouse=True)
    async def setup_db(self, mock_pg_db):
        """Setup mock database for each test."""
        db, advisory_conn, txn_conn = mock_pg_db
        with (
            patch("ishastra.core.store.get_database", return_value=db),
            patch("ishastra.core.store._is_postgresql_connection", side_effect=mock_is_pg_connection),
        ):
            yield db, advisory_conn, txn_conn

    async def test_try_acquire_lease_sets_fencing_token(self, setup_db):
        """Test that acquiring a lease sets fencing_token to 1."""
        db, advisory_conn, txn_conn = setup_db
        advisory_conn.fetchrow.return_value = None  # No existing lease

        lease = await store.try_acquire_lease("test-lease", "holder-1", ttl_seconds=30.0)

        assert lease is not None
        assert lease.acquired
        assert lease.fencing_token == 1
        assert lease.name == "test-lease"
        assert lease.holder == "holder-1"

    async def test_try_acquire_lease_renews_and_increments_token(self, setup_db):
        """Test that re-acquiring same lease increments fencing token."""
        db, advisory_conn, txn_conn = setup_db

        # First acquisition
        advisory_conn.fetchrow.return_value = None
        lease1 = await store.try_acquire_lease("test-lease", "holder-1", ttl_seconds=30.0)
        assert lease1.fencing_token == 1

        # Second acquisition by same holder (renewal)
        advisory_conn.fetchrow.return_value = MockRow({
            "holder": "holder-1",
            "expires_at": time.time() + 10,
            "fencing_token": 1
        })
        lease2 = await store.try_acquire_lease("test-lease", "holder-1", ttl_seconds=30.0)
        assert lease2.fencing_token == 2

    async def test_try_acquire_lease_new_holder_after_expiry_resets_token(self, setup_db):
        """Test that new holder after expiry gets token=1."""
        db, advisory_conn, txn_conn = setup_db

        # Old lease expired
        advisory_conn.fetchrow.return_value = MockRow({
            "holder": "holder-1",
            "expires_at": time.time() - 10,
            "fencing_token": 5
        })
        lease = await store.try_acquire_lease("test-lease", "holder-2", ttl_seconds=30.0)
        assert lease.fencing_token == 1
        assert lease.holder == "holder-2"

    async def test_try_acquire_lease_denied_when_held_by_other(self, setup_db):
        """Test that acquisition fails when lease held by another holder."""
        db, advisory_conn, txn_conn = setup_db
        advisory_conn.fetchrow.return_value = MockRow({
            "holder": "holder-1",
            "expires_at": time.time() + 10,
            "fencing_token": 1
        })

        lease = await store.try_acquire_lease("test-lease", "holder-2", ttl_seconds=30.0)
        assert lease is None

    async def test_renew_lease_increments_fencing_token(self, setup_db):
        """Test that renew_lease increments fencing token."""
        db, advisory_conn, txn_conn = setup_db
        txn_conn.fetchrow.return_value = MockRow({"fencing_token": 4})

        renewed, new_token = await store.renew_lease("test-lease", "holder-1", ttl_seconds=30.0)

        assert renewed is True
        assert new_token == 4

    async def test_renew_lease_fails_with_stale_token(self, setup_db):
        """Test that renew with stale token fails (simulated by rowcount=0)."""
        db, advisory_conn, txn_conn = setup_db
        txn_conn.fetchrow.return_value = None  # No row updated

        renewed, new_token = await store.renew_lease("test-lease", "holder-1", ttl_seconds=30.0)

        assert renewed is False
        assert new_token == 0

    async def test_release_lease_requires_matching_token(self, setup_db):
        """Test that release_lease only succeeds with matching fencing token."""
        db, advisory_conn, txn_conn = setup_db

        # Release with correct token
        txn_conn.execute.return_value = "DELETE 1"
        released = await store.release_lease("test-lease", "holder-1", fencing_token=5)
        assert released is True

        # Release with stale token
        txn_conn.execute.return_value = "DELETE 0"
        released = await store.release_lease("test-lease", "holder-1", fencing_token=3)
        assert released is False

    async def test_release_lease_without_token_works(self, setup_db):
        """Test that release without token still works (backward compat)."""
        db, advisory_conn, txn_conn = setup_db
        txn_conn.execute.return_value = "DELETE 1"

        released = await store.release_lease("test-lease", "holder-1")
        assert released is True

    async def test_get_lease_holder_returns_token(self, setup_db):
        """Test that get_lease_holder returns fencing token."""
        db, advisory_conn, txn_conn = setup_db
        txn_conn.fetchrow.return_value = MockRow({"holder": "holder-1", "fencing_token": 7})

        holder, token = await store.get_lease_holder("test-lease")

        assert holder == "holder-1"
        assert token == 7

    async def test_get_lease_holder_returns_none_for_missing(self, setup_db):
        """Test that get_lease_holder returns None for non-existent lease."""
        db, advisory_conn, txn_conn = setup_db
        txn_conn.fetchrow.return_value = None

        holder, token = await store.get_lease_holder("nonexistent")

        assert holder is None
        assert token == 0

    async def test_list_active_leases_includes_token(self, setup_db):
        """Test that list_active_leases includes fencing token."""
        db, advisory_conn, txn_conn = setup_db
        txn_conn.fetch.return_value = [
            MockRow({
                "name": "lease1", "holder": "holder-1", "category": "scheduler",
                "lock_id": 123, "acquired_at": time.time(), "expires_at": time.time() + 30,
                "ttl_seconds": 30.0, "fencing_token": 3
            })
        ]

        leases = await store.list_active_leases()

        assert len(leases) == 1
        assert leases[0]["fencing_token"] == 3


class TestLeaseFencingFailover:
    """Failure-injection tests for automated failover scenarios."""

    @pytest.fixture
    def mock_pg_db(self):
        return make_mock_pg_db()

    async def test_failover_after_expiry_allows_new_holder(self, mock_pg_db):
        """Test that after lease expires, new holder can acquire with token=1."""
        db, advisory_conn, txn_conn = mock_pg_db
        with (
            patch("ishastra.core.store.get_database", return_value=db),
            patch("ishastra.core.store._is_postgresql_connection", side_effect=mock_is_pg_connection),
        ):
            # Old lease expired
            advisory_conn.fetchrow.return_value = MockRow({
                "holder": "holder-1",
                "expires_at": time.time() - 5,
                "fencing_token": 10
            })

            lease = await store.try_acquire_lease("scheduler", "holder-2", ttl_seconds=30.0)

            assert lease is not None
            assert lease.holder == "holder-2"
            assert lease.fencing_token == 1  # Reset for new holder

    async def test_stale_holder_cannot_renew_after_failover(self, mock_pg_db):
        """Test that old holder cannot renew after new holder acquired."""
        db, advisory_conn, txn_conn = mock_pg_db
        with (
            patch("ishastra.core.store.get_database", return_value=db),
            patch("ishastra.core.store._is_postgresql_connection", side_effect=mock_is_pg_connection),
        ):
            # New holder acquired, old lease expired
            advisory_conn.fetchrow.return_value = MockRow({
                "holder": "holder-2",
                "expires_at": time.time() + 20,
                "fencing_token": 1
            })

            # Old holder tries to acquire (should fail - held by other)
            lease = await store.try_acquire_lease("scheduler", "holder-1", ttl_seconds=30.0)
            assert lease is None

    async def test_stale_holder_cannot_release_after_failover(self, mock_pg_db):
        """Test that old holder cannot release after new holder acquired."""
        db, advisory_conn, txn_conn = mock_pg_db
        with (
            patch("ishastra.core.store.get_database", return_value=db),
            patch("ishastra.core.store._is_postgresql_connection", side_effect=mock_is_pg_connection),
        ):
            # New holder has lease with token=1
            txn_conn.execute.return_value = "DELETE 0"  # No rows deleted (token mismatch)

            released = await store.release_lease("scheduler", "holder-1", fencing_token=5)
            assert released is False  # Failed due to token mismatch

    async def test_new_holder_can_release_with_correct_token(self, mock_pg_db):
        """Test that new holder can release with their token."""
        db, advisory_conn, txn_conn = mock_pg_db
        with (
            patch("ishastra.core.store.get_database", return_value=db),
            patch("ishastra.core.store._is_postgresql_connection", side_effect=mock_is_pg_connection),
        ):
            txn_conn.execute.return_value = "DELETE 1"

            released = await store.release_lease("scheduler", "holder-2", fencing_token=1)
            assert released is True


class TestLeaseFencingConcurrency:
    """Concurrency tests for lease fencing."""

    @pytest.fixture
    def mock_pg_db(self):
        return make_mock_pg_db()

    async def test_concurrent_acquire_only_one_succeeds(self, mock_pg_db):
        """Test that concurrent acquire attempts only allow one winner."""
        db, advisory_conn, txn_conn = mock_pg_db
        with (
            patch("ishastra.core.store.get_database", return_value=db),
            patch("ishastra.core.store._is_postgresql_connection", side_effect=mock_is_pg_connection),
        ):
            # First call returns None (no lease), second returns held by first holder
            call_count = 0

            async def mock_fetchrow(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return None  # First acquire - no existing lease
                return MockRow({
                    "holder": "holder-1",
                    "expires_at": time.time() + 30,
                    "fencing_token": 1
                })

            advisory_conn.fetchrow.side_effect = mock_fetchrow

            # Simulate concurrent acquires
            lease1 = await store.try_acquire_lease("test", "holder-1", ttl_seconds=30.0)
            lease2 = await store.try_acquire_lease("test", "holder-2", ttl_seconds=30.0)

            assert lease1 is not None
            assert lease1.acquired
            assert lease1.fencing_token == 1
            assert lease2 is None  # Second holder denied

    async def test_token_monotonic_increments(self, mock_pg_db):
        """Test that fencing token monotonically increases."""
        db, advisory_conn, txn_conn = mock_pg_db
        with (
            patch("ishastra.core.store.get_database", return_value=db),
            patch("ishastra.core.store._is_postgresql_connection", side_effect=mock_is_pg_connection),
        ):
            # Tokens returned by fetchrow for each call (first call returns None = no lease)
            # After first acquisition (token=1), renewals should see token=1, then 2, etc.
            call_count = 0

            async def mock_fetchrow(*args, **kwargs):
                nonlocal call_count
                if call_count == 0:
                    call_count += 1
                    return None  # First call - no existing lease
                # Subsequent calls return current token (1, then 2)
                current_token = call_count
                call_count += 1
                return MockRow({
                    "holder": "holder-1",
                    "expires_at": time.time() + 10,
                    "fencing_token": current_token
                })

            advisory_conn.fetchrow.side_effect = mock_fetchrow

            lease1 = await store.try_acquire_lease("test", "holder-1", ttl_seconds=30.0)
            assert lease1.fencing_token == 1

            lease2 = await store.try_acquire_lease("test", "holder-1", ttl_seconds=30.0)
            assert lease2.fencing_token == 2

            lease3 = await store.try_acquire_lease("test", "holder-1", ttl_seconds=30.0)
            assert lease3.fencing_token == 3


class TestLeaseFencingSQLite:
    """Tests for SQLite (non-PostgreSQL) fallback behavior."""

    async def test_sqlite_returns_lease_without_token(self):
        """Test that SQLite fallback returns lease with token=0."""
        db = MagicMock()
        db.is_postgresql.return_value = False

        with patch("ishastra.core.store.get_database", return_value=db):
            lease = await store.try_acquire_lease("test-lease", "holder-1", ttl_seconds=30.0)

            assert lease is not None
            assert lease.acquired
            assert lease.fencing_token == 0  # No fencing in SQLite mode

    async def test_sqlite_renew_returns_true(self):
        """Test that SQLite renew returns True."""
        db = MagicMock()
        db.is_postgresql.return_value = False

        with patch("ishastra.core.store.get_database", return_value=db):
            renewed, token = await store.renew_lease("test-lease", "holder-1", ttl_seconds=30.0)
            assert renewed is True
            assert token == 0

    async def test_sqlite_release_returns_true(self):
        """Test that SQLite release returns True."""
        db = MagicMock()
        db.is_postgresql.return_value = False

        with patch("ishastra.core.store.get_database", return_value=db):
            released = await store.release_lease("test-lease", "holder-1", fencing_token=5)
            assert released is True

    async def test_sqlite_get_lease_holder_returns_none(self):
        """Test that SQLite get_lease_holder returns None."""
        db = MagicMock()
        db.is_postgresql.return_value = False

        with patch("ishastra.core.store.get_database", return_value=db):
            holder, token = await store.get_lease_holder("test-lease")
            assert holder is None
            assert token == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
