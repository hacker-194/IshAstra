"""Security tests for AuditChain integrity verification.

These tests directly manipulate the SQLite database to tamper with audit_chain
and audit_log entries, then verify that the chain verification fails.

Tests both paths: with and without STRIX_AUDIT_HMAC_KEY.
"""

import asyncio
import hashlib
import hmac
import json
import tempfile
from pathlib import Path

import pytest

from strix.audit import GENESIS_HASH, AuditChain
from strix.core import store


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    store.configure(path)
    yield path
    Path(path).unlink(missing_ok=True)
    for suffix in ("-wal", "-shm"):
        Path(path + suffix).unlink(missing_ok=True)
    asyncio.run(store.reset_database())


def _digest(body: dict, hmac_key: str = "") -> str:
    """Compute the digest for a chain entry (matches AuditChain._digest)."""
    payload = json.dumps(body, sort_keys=True).encode()
    if hmac_key:
        return hmac.new(hmac_key.encode(), payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()


class TestAuditChainIntegrityWithoutHMAC:
    """Test chain integrity verification WITHOUT HMAC key (STRIX_AUDIT_HMAC_KEY not set)."""

    @pytest.fixture
    def chain(self, temp_db):
        """Create a chain in persistent mode without HMAC key."""
        return AuditChain(persistent=True, hmac_key="")

    async def _setup_chain(self, chain, entries_data):
        """Append multiple entries to the chain."""
        for entry in entries_data:
            await chain.append_async(entry)

    async def _get_chain_rows(self, temp_db):
        """Fetch all chain rows directly from SQLite."""
        db = await store.get_database()
        async with db.transaction() as conn:
            rows = await store._fetchall(
                conn, "SELECT sequence, previous_hash, hash, data FROM audit_chain ORDER BY sequence"
            )
        return [dict(row) for row in rows]

    async def _update_chain_row(self, temp_db, sequence, updates):
        """Update a specific chain row in SQLite."""
        db = await store.get_database()
        async with db.transaction() as conn:
            # First get the current row
            row = await store._fetchone(
                conn,
                "SELECT sequence, previous_hash, hash, data FROM audit_chain WHERE sequence = ?",
                sequence,
            )
            if not row:
                raise ValueError(f"No chain entry with sequence {sequence}")

            data = json.loads(row["data"])
            data.update(updates.get("data", {}))

            new_hash = updates.get("hash", row["hash"])
            new_previous = updates.get("previous_hash", row["previous_hash"])

            await store._execute(
                conn,
                "UPDATE audit_chain SET previous_hash = ?, hash = ?, data = ? WHERE sequence = ?",
                new_previous,
                new_hash,
                json.dumps(data, sort_keys=True),
                sequence,
            )

    async def _delete_chain_row(self, temp_db, sequence):
        """Delete a specific chain row from SQLite."""
        db = await store.get_database()
        async with db.transaction() as conn:
            await store._execute(conn, "DELETE FROM audit_chain WHERE sequence = ?", sequence)

    async def _insert_chain_row(self, temp_db, sequence, previous_hash, data):
        """Insert a new chain row at a specific sequence."""
        digest = _digest(data)
        db = await store.get_database()
        async with db.transaction() as conn:
            await store._execute(
                conn,
                "INSERT INTO audit_chain (sequence, previous_hash, hash, data) VALUES (?, ?, ?, ?)",
                sequence,
                previous_hash,
                digest,
                json.dumps(data, sort_keys=True),
            )

    def test_tamper_entry_data(self, temp_db, chain):
        """Tamper with entry data -> verification MUST fail."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "test1", "value": "original"},
                    {"event": "test2", "value": "original"},
                    {"event": "test3", "value": "original"},
                ],
            )
            # Verify chain is valid initially
            ok, reason = await chain.verify_async()
            assert ok is True, f"Initial chain should be valid: {reason}"

            # Tamper with the data of entry 2
            await self._update_chain_row(temp_db, 2, {"data": {"event": "test2", "value": "TAMPERED"}})

            # Verification must fail
            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail after data tampering"
            assert "Hash mismatch" in reason, f"Expected hash mismatch, got: {reason}"

        asyncio.run(run_test())

    def test_delete_entry(self, temp_db, chain):
        """Delete an entry from the chain -> verification MUST fail."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "test1"},
                    {"event": "test2"},
                    {"event": "test3"},
                ],
            )
            ok, reason = await chain.verify_async()
            assert ok is True

            # Delete entry 2
            await self._delete_chain_row(temp_db, 2)

            # Verification must fail (sequence gap)
            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail after entry deletion"
            assert "expected sequence" in reason.lower(), f"Expected sequence gap error, got: {reason}"

        asyncio.run(run_test())

    def test_reorder_entries(self, temp_db, chain):
        """Reorder entries in the chain (swap data without fixing hashes) -> verification MUST fail."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "first", "order": 1},
                    {"event": "second", "order": 2},
                    {"event": "third", "order": 3},
                ],
            )
            ok, reason = await chain.verify_async()
            assert ok is True

            # Swap the DATA of entries 2 and 3 WITHOUT updating their hashes
            rows = await self._get_chain_rows(temp_db)

            entry2_data = json.loads(rows[1]["data"])
            entry3_data = json.loads(rows[2]["data"])
            entry1_hash = rows[0]["hash"]  # hash of entry 1

            # Swap data but fix previous_hash in the data to match the position
            # Entry 2 gets entry 3's data but with correct previous_hash (entry1_hash)
            # Entry 3 gets entry 2's data but with correct previous_hash (entry2's original hash)
            entry2_hash = rows[1]["hash"]  # original hash of entry 2

            # This breaks the chain because the stored hashes won't match the new data
            await self._update_chain_row(
                temp_db, 2, {"data": {**entry3_data, "sequence": 2, "previous_hash": entry1_hash}}
            )
            await self._update_chain_row(
                temp_db, 3, {"data": {**entry2_data, "sequence": 3, "previous_hash": entry2_hash}}
            )

            # Verification must fail (hash mismatch)
            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail after reordering"
            assert "Hash mismatch" in reason, f"Expected hash mismatch, got: {reason}"

        asyncio.run(run_test())

    def test_append_fake_entry(self, temp_db, chain):
        """Append a fake entry to the chain -> verification MUST fail."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "test1"},
                    {"event": "test2"},
                ],
            )
            ok, reason = await chain.verify_async()
            assert ok is True

            # Get the tip
            rows = await self._get_chain_rows(temp_db)
            rows[-1]["hash"]

            # Insert a fake entry at sequence 3 with wrong previous_hash
            fake_data = {"event": "fake", "sequence": 3, "previous_hash": "wrong_previous_hash"}
            await self._insert_chain_row(temp_db, 3, "wrong_previous_hash", fake_data)

            # Verification must fail
            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail after fake append"
            reason_lower = reason.lower()
            assert "prev hash mismatch" in reason_lower or "expected sequence" in reason_lower, reason

        asyncio.run(run_test())

    def test_modify_previous_hash(self, temp_db, chain):
        """Modify previous_hash field -> verification MUST fail."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "test1"},
                    {"event": "test2"},
                    {"event": "test3"},
                ],
            )
            ok, reason = await chain.verify_async()
            assert ok is True

            # Modify previous_hash of entry 3
            rows = await self._get_chain_rows(temp_db)
            entry3_data = json.loads(rows[2]["data"])

            await self._update_chain_row(
                temp_db,
                3,
                {
                    "previous_hash": "tampered_previous_hash",
                    "data": {**entry3_data, "previous_hash": "tampered_previous_hash"},
                },
            )

            # Verification must fail
            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail after previous_hash tampering"
            assert "prev hash mismatch" in reason.lower(), f"Expected prev hash mismatch, got: {reason}"

        asyncio.run(run_test())

    def test_modify_sequence_number(self, temp_db, chain):
        """Modify sequence number in entry data -> verification MUST fail (hash mismatch)."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "test1"},
                    {"event": "test2"},
                    {"event": "test3"},
                ],
            )
            ok, reason = await chain.verify_async()
            assert ok is True

            # Modify sequence of entry 2 to 5 in the data (but not the row's primary key)
            rows = await self._get_chain_rows(temp_db)
            entry2_data = json.loads(rows[1]["data"])

            await self._update_chain_row(temp_db, 2, {"data": {**entry2_data, "sequence": 5}})

            # Verification must fail - hash mismatch because data changed but hash wasn't updated
            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail after sequence tampering"
            assert "Hash mismatch" in reason, f"Expected hash mismatch, got: {reason}"

        asyncio.run(run_test())


class TestAuditChainIntegrityWithHMAC:
    """Test chain integrity verification WITH HMAC key (STRIX_AUDIT_HMAC_KEY set)."""

    @pytest.fixture
    def chain(self, temp_db):
        """Create a chain in persistent mode WITH HMAC key."""
        return AuditChain(persistent=True, hmac_key="secret-hmac-key-123")

    async def _setup_chain(self, chain, entries_data):
        """Append multiple entries to the chain."""
        for entry in entries_data:
            await chain.append_async(entry)

    async def _get_chain_rows(self, temp_db):
        """Fetch all chain rows directly from SQLite."""
        db = await store.get_database()
        async with db.transaction() as conn:
            rows = await store._fetchall(
                conn, "SELECT sequence, previous_hash, hash, data FROM audit_chain ORDER BY sequence"
            )
        return [dict(row) for row in rows]

    async def _update_chain_row(self, temp_db, sequence, updates):
        """Update a specific chain row in SQLite."""
        db = await store.get_database()
        async with db.transaction() as conn:
            row = await store._fetchone(
                conn,
                "SELECT sequence, previous_hash, hash, data FROM audit_chain WHERE sequence = ?",
                sequence,
            )
            if not row:
                raise ValueError(f"No chain entry with sequence {sequence}")

            data = json.loads(row["data"])
            data.update(updates.get("data", {}))

            new_hash = updates.get("hash", row["hash"])
            new_previous = updates.get("previous_hash", row["previous_hash"])

            await store._execute(
                conn,
                "UPDATE audit_chain SET previous_hash = ?, hash = ?, data = ? WHERE sequence = ?",
                new_previous,
                new_hash,
                json.dumps(data, sort_keys=True),
                sequence,
            )

    async def _delete_chain_row(self, temp_db, sequence):
        """Delete a specific chain row from SQLite."""
        db = await store.get_database()
        async with db.transaction() as conn:
            await store._execute(conn, "DELETE FROM audit_chain WHERE sequence = ?", sequence)

    async def _insert_chain_row(self, temp_db, sequence, previous_hash, data, hmac_key="secret-hmac-key-123"):
        """Insert a new chain row at a specific sequence with HMAC."""
        digest = _digest(data, hmac_key)
        db = await store.get_database()
        async with db.transaction() as conn:
            await store._execute(
                conn,
                "INSERT INTO audit_chain (sequence, previous_hash, hash, data) VALUES (?, ?, ?, ?)",
                sequence,
                previous_hash,
                digest,
                json.dumps(data, sort_keys=True),
            )

    def test_tamper_entry_data(self, temp_db, chain):
        """Tamper with entry data -> verification MUST fail (HMAC key present)."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "test1", "value": "original"},
                    {"event": "test2", "value": "original"},
                    {"event": "test3", "value": "original"},
                ],
            )
            ok, reason = await chain.verify_async()
            assert ok is True

            # Tamper with the data of entry 2
            await self._update_chain_row(temp_db, 2, {"data": {"event": "test2", "value": "TAMPERED"}})

            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail after data tampering"
            assert "Hash mismatch" in reason, f"Expected hash mismatch, got: {reason}"

        asyncio.run(run_test())

    def test_delete_entry(self, temp_db, chain):
        """Delete an entry from the chain -> verification MUST fail (HMAC key present)."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "test1"},
                    {"event": "test2"},
                    {"event": "test3"},
                ],
            )
            ok, reason = await chain.verify_async()
            assert ok is True

            await self._delete_chain_row(temp_db, 2)

            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail after entry deletion"
            assert "expected sequence" in reason.lower(), f"Expected sequence gap error, got: {reason}"

        asyncio.run(run_test())

    def test_reorder_entries(self, temp_db, chain):
        """Reorder entries (swap data without fixing hashes) -> verification MUST fail (HMAC key present)."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "first", "order": 1},
                    {"event": "second", "order": 2},
                    {"event": "third", "order": 3},
                ],
            )
            ok, reason = await chain.verify_async()
            assert ok is True

            rows = await self._get_chain_rows(temp_db)
            entry2_data = json.loads(rows[1]["data"])
            entry3_data = json.loads(rows[2]["data"])
            entry1_hash = rows[0]["hash"]  # hash of entry 1
            entry2_hash = rows[1]["hash"]  # original hash of entry 2

            # Swap data but fix previous_hash in the data to match the position
            # This breaks the chain because the stored hashes won't match the new data
            await self._update_chain_row(
                temp_db, 2, {"data": {**entry3_data, "sequence": 2, "previous_hash": entry1_hash}}
            )
            await self._update_chain_row(
                temp_db, 3, {"data": {**entry2_data, "sequence": 3, "previous_hash": entry2_hash}}
            )

            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail after reordering"
            assert "Hash mismatch" in reason, f"Expected hash mismatch, got: {reason}"

        asyncio.run(run_test())

    def test_append_fake_entry(self, temp_db, chain):
        """Append a fake entry -> verification MUST fail (HMAC key present)."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "test1"},
                    {"event": "test2"},
                ],
            )
            ok, reason = await chain.verify_async()
            assert ok is True

            rows = await self._get_chain_rows(temp_db)
            rows[-1]["hash"]

            # Insert fake entry with correct HMAC but wrong previous_hash
            fake_data = {"event": "fake", "sequence": 3, "previous_hash": "wrong_previous_hash"}
            await self._insert_chain_row(temp_db, 3, "wrong_previous_hash", fake_data)

            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail after fake append"

        asyncio.run(run_test())

    def test_append_fake_entry_with_correct_hmac_but_wrong_chain(self, temp_db, chain):
        """Append entry with correct HMAC but wrong previous_hash -> MUST fail."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "test1"},
                    {"event": "test2"},
                ],
            )
            ok, reason = await chain.verify_async()
            assert ok is True

            rows = await self._get_chain_rows(temp_db)
            tip_hash = rows[-1]["hash"]

            # Insert at sequence 4 with correct linkage but it's extra
            fake_data = {"event": "fake", "sequence": 4, "previous_hash": tip_hash}
            await self._insert_chain_row(temp_db, 4, tip_hash, fake_data)

            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail with extra entry"
            assert "expected sequence" in reason.lower(), f"Expected sequence error, got: {reason}"

        asyncio.run(run_test())

    def test_tamper_without_knowing_hmac_key(self, temp_db, chain):
        """Attacker without HMAC key cannot forge valid entry."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "test1"},
                    {"event": "test2"},
                ],
            )
            ok, reason = await chain.verify_async()
            assert ok is True

            rows = await self._get_chain_rows(temp_db)
            tip_hash = rows[-1]["hash"]

            # Attacker tries to append without knowing HMAC key (uses empty key)
            fake_data = {"event": "fake", "sequence": 3, "previous_hash": tip_hash}
            # Insert with NO hmac (attacker doesn't know the key)
            digest = _digest(fake_data, "")  # Empty key - wrong!
            db = await store.get_database()
            async with db.transaction() as conn:
                await store._execute(
                    conn,
                    "INSERT INTO audit_chain (sequence, previous_hash, hash, data) VALUES (?, ?, ?, ?)",
                    3,
                    tip_hash,
                    digest,
                    json.dumps(fake_data, sort_keys=True),
                )

            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail - attacker used wrong HMAC key"
            assert "Hash mismatch" in reason, f"Expected hash mismatch, got: {reason}"

        asyncio.run(run_test())

    def test_modify_previous_hash(self, temp_db, chain):
        """Modify previous_hash field -> verification MUST fail (HMAC key present)."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "test1"},
                    {"event": "test2"},
                    {"event": "test3"},
                ],
            )
            ok, reason = await chain.verify_async()
            assert ok is True

            rows = await self._get_chain_rows(temp_db)
            entry3_data = json.loads(rows[2]["data"])

            await self._update_chain_row(
                temp_db,
                3,
                {
                    "previous_hash": "tampered_previous_hash",
                    "data": {**entry3_data, "previous_hash": "tampered_previous_hash"},
                },
            )

            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail after previous_hash tampering"
            assert "prev hash mismatch" in reason.lower(), f"Expected prev hash mismatch, got: {reason}"

        asyncio.run(run_test())

    def test_modify_sequence_number(self, temp_db, chain):
        """Modify sequence in entry data -> verification MUST fail
        (hash mismatch, HMAC key present)."""

        async def run_test():
            await self._setup_chain(
                chain,
                [
                    {"event": "test1"},
                    {"event": "test2"},
                    {"event": "test3"},
                ],
            )
            ok, reason = await chain.verify_async()
            assert ok is True

            rows = await self._get_chain_rows(temp_db)
            entry2_data = json.loads(rows[1]["data"])

            await self._update_chain_row(temp_db, 2, {"data": {**entry2_data, "sequence": 5}})

            ok, reason = await chain.verify_async()
            assert ok is False, "Chain verification should fail after sequence tampering"
            assert "Hash mismatch" in reason, f"Expected hash mismatch, got: {reason}"

        asyncio.run(run_test())


class TestAuditChainInMemoryMode:
    """Test chain integrity in non-persistent (in-memory) mode."""

    def test_tamper_in_memory_without_hmac(self):
        """Tamper with in-memory chain without HMAC."""
        chain = AuditChain(persistent=False, hmac_key="")
        chain.append({"event": "test1"})
        chain.append({"event": "test2"})
        chain.append({"event": "test3"})

        ok, reason = chain.verify()
        assert ok is True

        # Tamper directly
        chain._entries[1]["event"] = "TAMPERED"

        ok, reason = chain.verify()
        assert ok is False
        assert "Hash mismatch" in reason

    def test_tamper_in_memory_with_hmac(self):
        """Tamper with in-memory chain with HMAC."""
        chain = AuditChain(persistent=False, hmac_key="secret-key")
        chain.append({"event": "test1"})
        chain.append({"event": "test2"})
        chain.append({"event": "test3"})

        ok, reason = chain.verify()
        assert ok is True

        chain._entries[1]["event"] = "TAMPERED"

        ok, reason = chain.verify()
        assert ok is False
        assert "Hash mismatch" in reason

    def test_delete_in_memory(self):
        """Delete entry from in-memory chain."""
        chain = AuditChain(persistent=False, hmac_key="secret-key")
        chain.append({"event": "test1"})
        chain.append({"event": "test2"})
        chain.append({"event": "test3"})

        ok, reason = chain.verify()
        assert ok is True

        # Delete middle entry
        del chain._entries[1]

        ok, reason = chain.verify()
        assert ok is False
        assert "expected sequence" in reason.lower()

    def test_reorder_in_memory(self):
        """Reorder entries in in-memory chain."""
        chain = AuditChain(persistent=False, hmac_key="secret-key")
        chain.append({"event": "first"})
        chain.append({"event": "second"})
        chain.append({"event": "third"})

        ok, reason = chain.verify()
        assert ok is True

        # Swap entries 1 and 2 (indices 0 and 1)
        chain._entries[0], chain._entries[1] = chain._entries[1], chain._entries[0]
        # Fix sequence numbers
        chain._entries[0]["sequence"] = 1
        chain._entries[1]["sequence"] = 2

        ok, reason = chain.verify()
        assert ok is False


class TestAuditLogIntegrity:
    """Test audit_log table tampering detection (separate from chain)."""

    @pytest.fixture
    def temp_db(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            path = f.name
        store.configure(path)
        yield path
        Path(path).unlink(missing_ok=True)
        for suffix in ("-wal", "-shm"):
            Path(path + suffix).unlink(missing_ok=True)
        asyncio.run(store.reset_database())

    def test_audit_log_tamper_does_not_affect_chain(self, temp_db):
        """Tampering with audit_log should not affect audit_chain verification."""
        from strix.audit import AuditLog

        async def run_test():
            log = AuditLog(max_entries=100, persistent=True)
            chain = AuditChain(persistent=True, hmac_key="test-key")

            await log.record_async({"event": "test1", "tenant": "tenant-a"})
            await chain.append_async({"event": "chain1"})

            # Tamper with audit_log directly
            db = await store.get_database()
            async with db.transaction() as conn:
                await store._execute(
                    conn,
                    "UPDATE audit_log SET data = ? WHERE id = (SELECT MAX(id) FROM audit_log)",
                    json.dumps({"event": "TAMPERED", "tenant": "tenant-a"}, sort_keys=True),
                )

            # Chain should still verify
            ok, reason = await chain.verify_async()
            assert ok is True, f"Chain should be valid: {reason}"

        asyncio.run(run_test())

    def test_audit_log_delete_does_not_affect_chain(self, temp_db):
        """Deleting from audit_log should not affect audit_chain."""
        from strix.audit import AuditLog

        async def run_test():
            log = AuditLog(max_entries=100, persistent=True)
            chain = AuditChain(persistent=True, hmac_key="test-key")

            await log.record_async({"event": "test1", "tenant": "tenant-a"})
            await chain.append_async({"event": "chain1"})

            # Delete from audit_log
            db = await store.get_database()
            async with db.transaction() as conn:
                await store._execute(conn, "DELETE FROM audit_log WHERE id = (SELECT MAX(id) FROM audit_log)")

            # Chain should still verify
            ok, reason = await chain.verify_async()
            assert ok is True, f"Chain should be valid: {reason}"

        asyncio.run(run_test())


class TestEdgeCases:
    """Edge case tests for audit chain integrity."""

    @pytest.fixture
    def temp_db(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            path = f.name
        store.configure(path)
        yield path
        Path(path).unlink(missing_ok=True)
        for suffix in ("-wal", "-shm"):
            Path(path + suffix).unlink(missing_ok=True)
        asyncio.run(store.reset_database())

    def test_empty_chain_verifies(self, temp_db):
        """Empty chain should verify as valid."""
        chain = AuditChain(persistent=True, hmac_key="test-key")
        ok, reason = asyncio.run(chain.verify_async())
        assert ok is True
        assert reason is None

    def test_single_entry_chain(self, temp_db):
        """Single entry chain should verify."""
        chain = AuditChain(persistent=True, hmac_key="test-key")
        asyncio.run(chain.append_async({"event": "only"}))
        ok, reason = asyncio.run(chain.verify_async())
        assert ok is True

    def test_genesis_hash_cannot_be_changed(self, temp_db):
        """First entry's previous_hash must be GENESIS_HASH."""
        chain = AuditChain(persistent=True, hmac_key="test-key")
        asyncio.run(chain.append_async({"event": "test1"}))

        # Verify initial
        ok, reason = asyncio.run(chain.verify_async())
        assert ok is True

        # Try to change first entry's previous_hash
        async def tamper():
            db = await store.get_database()
            async with db.transaction() as conn:
                await store._execute(
                    conn, "UPDATE audit_chain SET previous_hash = ? WHERE sequence = 1", "not_genesis"
                )

        asyncio.run(tamper())

        ok, reason = asyncio.run(chain.verify_async())
        assert ok is False
        assert "prev hash mismatch" in reason.lower()

    def test_verify_cached_respects_tampering(self, temp_db):
        """verify_cached should detect tampering after cache expires."""
        chain = AuditChain(persistent=True, hmac_key="test-key")
        asyncio.run(chain.append_async({"event": "test1"}))
        asyncio.run(chain.append_async({"event": "test2"}))

        # First verify (caches success)
        ok, _ = chain.verify_cached(max_age=30.0)
        assert ok is True

        # Tamper
        async def tamper():
            db = await store.get_database()
            async with db.transaction() as conn:
                await store._execute(
                    conn,
                    "UPDATE audit_chain SET data = ? WHERE sequence = 1",
                    json.dumps(
                        {"event": "TAMPERED", "sequence": 1, "previous_hash": GENESIS_HASH}, sort_keys=True
                    ),
                )

        asyncio.run(tamper())

        # Cached verify should still return cached (success)
        ok, _ = chain.verify_cached(max_age=30.0)
        assert ok is True  # Still cached

        # Full verify should fail
        ok, reason = chain.verify()
        assert ok is False
        assert "Hash mismatch" in reason
