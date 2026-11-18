"""Unit tests for Strix Audit (AuditLog, AuditChain)."""

import asyncio
import tempfile
from pathlib import Path

import pytest

from strix.audit import GENESIS_HASH, AuditChain, AuditLog
from strix.core import store


@pytest.fixture
def temp_db():
    """Create a temporary database for testing."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    store.configure(path)
    yield path
    Path(path).unlink(missing_ok=True)
    # Clean up WAL/SHM files
    for suffix in ("-wal", "-shm"):
        Path(path + suffix).unlink(missing_ok=True)
    # Reset store
    asyncio.run(store.reset_database())


class TestAuditLog:
    """Test AuditLog in-memory and persistent modes."""

    def test_audit_log_creation(self):
        """Create audit log."""
        log = AuditLog(max_entries=100)
        assert log._max == 100
        assert log._persistent is False

    def test_audit_log_record_and_entries(self):
        """Record entries and retrieve them."""
        log = AuditLog(max_entries=100)
        log.record({"event": "test", "data": "value"})
        log.record({"event": "test2", "data": "value2"})
        entries = log.entries()
        assert len(entries) == 2
        assert entries[0]["event"] == "test"
        assert entries[1]["event"] == "test2"

    def test_audit_log_max_entries_limit(self):
        """Audit log respects max_entries limit."""
        log = AuditLog(max_entries=3)
        for i in range(5):
            log.record({"event": f"test{i}"})
        entries = log.entries()
        assert len(entries) == 3
        assert entries[0]["event"] == "test2"  # Oldest dropped
        assert entries[2]["event"] == "test4"  # Newest kept

    def test_audit_log_redacts_credentials(self):
        """Recorded entries have credentials redacted."""
        log = AuditLog(max_entries=100)
        log.record(
            {
                "event": "api_call",
                "api_key": "secret123",
                "password": "pass123",
                "token": "token123",
            }
        )
        entries = log.entries()
        assert "secret123" not in str(entries)
        assert "pass123" not in str(entries)
        assert "token123" not in str(entries)

    def test_audit_log_tenant_filtering(self):
        """Entries can be filtered by tenant."""
        log = AuditLog(max_entries=100)
        log.record({"event": "test", "tenant": "tenant-a"})
        log.record({"event": "test", "tenant": "tenant-b"})
        log.record({"event": "test", "tenant": "tenant-a"})
        all_entries = log.entries(tenant=None)
        tenant_a = log.entries(tenant="tenant-a")
        tenant_b = log.entries(tenant="tenant-b")
        assert len(all_entries) == 3
        assert len(tenant_a) == 2
        assert len(tenant_b) == 1

    def test_audit_log_persistent_mode_load(self, temp_db):
        """Persistent mode loads from database on load()."""
        log = AuditLog(max_entries=100, persistent=True)
        log.load()
        assert list(log._entries) == []


class TestAuditLogAsync:
    """Test AuditLog async API."""

    @pytest.mark.asyncio
    async def test_audit_log_async_record_and_load(self):
        """Async record and load."""
        log = AuditLog(max_entries=100, persistent=False)
        await log.record_async({"event": "async_test", "value": 42})
        entries = log.entries()
        assert len(entries) == 1
        assert entries[0]["event"] == "async_test"
        assert entries[0]["value"] == 42

    @pytest.mark.asyncio
    async def test_audit_log_load_async(self, temp_db):
        """Async load (no-op for non-persistent)."""
        log = AuditLog(max_entries=100, persistent=True)
        await log.load_async()
        assert list(log._entries) == []


class TestAuditChain:
    """Test AuditChain hash chaining."""

    def test_audit_chain_creation(self):
        """Create audit chain."""
        chain = AuditChain(persistent=False)
        assert chain._persistent is False
        assert chain._entries == []

    def test_audit_chain_append(self):
        """Append entries to chain."""
        chain = AuditChain(persistent=False, hmac_key="test-key")
        digest1 = chain.append({"event": "test1"})
        digest2 = chain.append({"event": "test2"})
        assert len(chain._entries) == 2
        assert digest1 != digest2
        # Second entry commits to first
        assert chain._entries[1]["previous_hash"] == digest1

    def test_audit_chain_genesis_hash(self):
        """First entry uses GENESIS_HASH as previous."""
        chain = AuditChain(persistent=False)
        _ = chain.append({"event": "first"})
        assert chain._entries[0]["previous_hash"] == GENESIS_HASH
        assert chain._entries[0]["sequence"] == 1

    def test_audit_chain_verify_valid(self):
        """Verify valid chain."""
        chain = AuditChain(persistent=False, hmac_key="test-key")
        chain.append({"event": "test1"})
        chain.append({"event": "test2"})
        chain.append({"event": "test3"})
        ok, reason = chain.verify()
        assert ok is True
        assert reason is None

    def test_audit_chain_verify_detects_tampering(self):
        """Verify detects tampered entry."""
        chain = AuditChain(persistent=False, hmac_key="test-key")
        chain.append({"event": "test1"})
        chain.append({"event": "test2"})
        # Tamper with first entry
        chain._entries[0]["event"] = "tampered"
        ok, reason = chain.verify()
        assert ok is False
        assert "Hash mismatch" in reason

    def test_audit_chain_verify_detects_sequence_gap(self):
        """Verify detects sequence number gap."""
        chain = AuditChain(persistent=False, hmac_key="test-key")
        chain.append({"event": "test1"})
        chain.append({"event": "test2"})
        # Manually insert entry with wrong sequence
        chain._entries[1]["sequence"] = 5
        ok, reason = chain.verify()
        assert ok is False
        assert "expected sequence" in reason

    def test_audit_chain_verify_detects_prev_hash_mismatch(self):
        """Verify detects previous hash mismatch."""
        chain = AuditChain(persistent=False, hmac_key="test-key")
        chain.append({"event": "test1"})
        chain.append({"event": "test2"})
        # Break the chain
        chain._entries[1]["previous_hash"] = "wrong_hash"
        ok, reason = chain.verify()
        assert ok is False
        assert "prev hash mismatch" in reason

    def test_audit_chain_without_hmac(self):
        """Chain works without HMAC key (SHA256 only)."""
        chain = AuditChain(persistent=False)  # No hmac_key
        digest1 = chain.append({"event": "test1"})
        digest2 = chain.append({"event": "test2"})
        ok, reason = chain.verify()
        assert ok is True
        # Digests should be different
        assert digest1 != digest2

    def test_audit_chain_len(self):
        """Chain length."""
        chain = AuditChain(persistent=False)
        assert len(chain) == 0
        chain.append({"event": "test1"})
        assert len(chain) == 1
        chain.append({"event": "test2"})
        assert len(chain) == 2

    @pytest.mark.asyncio
    async def test_audit_chain_append_async(self):
        """Async append."""
        chain = AuditChain(persistent=False, hmac_key="test-key")
        await chain.append_async({"event": "async_test"})
        assert len(chain._entries) == 1
        assert chain._entries[0]["event"] == "async_test"

    @pytest.mark.asyncio
    async def test_audit_chain_verify_async(self):
        """Async verify."""
        chain = AuditChain(persistent=False, hmac_key="test-key")
        await chain.append_async({"event": "test1"})
        await chain.append_async({"event": "test2"})
        ok, reason = await chain.verify_async()
        assert ok is True
        assert reason is None

    @pytest.mark.asyncio
    async def test_audit_chain_len_async(self):
        """Async len."""
        chain = AuditChain(persistent=False)
        assert await chain.len_async() == 0
        await chain.append_async({"event": "test1"})
        assert await chain.len_async() == 1


class TestAuditChainCachedVerify:
    """Test cached verification."""

    def test_verify_cached_first_call(self):
        """First verify call runs full verification."""
        chain = AuditChain(persistent=False, hmac_key="test-key")
        chain.append({"event": "test1"})
        chain.append({"event": "test2"})
        ok, reason = chain.verify_cached(max_age=30.0)
        assert ok is True

    def test_verify_cached_subsequent_calls(self):
        """Subsequent calls within max_age return cached result."""
        chain = AuditChain(persistent=False, hmac_key="test-key")
        chain.append({"event": "test1"})
        ok1, _ = chain.verify_cached(max_age=30.0)
        ok2, _ = chain.verify_cached(max_age=30.0)
        ok3, _ = chain.verify_cached(max_age=30.0)
        assert ok1 is True
        assert ok2 is True
        assert ok3 is True

    def test_verify_cached_failed_not_cached(self):
        """Failed verification is never cached."""
        chain = AuditChain(persistent=False, hmac_key="test-key")
        chain.append({"event": "test1"})
        chain.append({"event": "test2"})
        # Tamper
        chain._entries[0]["event"] = "tampered"
        ok1, _ = chain.verify_cached(max_age=30.0)
        assert ok1 is False
        # Fix it
        chain._entries[0]["event"] = "test1"
        ok2, _ = chain.verify_cached(max_age=30.0)
        assert ok2 is True  # Should re-verify and pass

    @pytest.mark.asyncio
    async def test_verify_cached_async(self):
        """Async cached verify."""
        chain = AuditChain(persistent=False, hmac_key="test-key")
        await chain.append_async({"event": "test1"})
        ok1, _ = await chain.verify_cached_async(max_age=30.0)
        ok2, _ = await chain.verify_cached_async(max_age=30.0)
        assert ok1 is True
        assert ok2 is True


class TestAuditChainSerialization:
    """Test chain entry access and serialization."""

    def test_chain_entries_property(self):
        """Entries property returns copy of in-memory chain."""
        chain = AuditChain(persistent=False)
        chain.append({"event": "test1"})
        entries = chain.entries
        assert len(entries) == 1
        assert entries[0]["event"] == "test1"
        # Modifying returned list doesn't affect chain
        entries.append({"event": "fake"})
        assert len(chain._entries) == 1

    def test_chain_iter_entries(self):
        """Iterate chain entries for verification."""
        chain = AuditChain(persistent=False, hmac_key="test-key")
        chain.append({"event": "test1"})
        chain.append({"event": "test2"})
        entries = list(chain._iter_entries())
        assert len(entries) == 2
        seq, prev, digest, body = entries[0]
        assert seq == 1
        assert prev == GENESIS_HASH
        assert body["event"] == "test1"


class TestAuditRedaction:
    """Test that redaction works in audit chain."""

    def test_chain_redacts_on_append(self):
        """Chain redacts credentials on append."""
        chain = AuditChain(persistent=False)
        chain.append(
            {
                "event": "api_call",
                "api_key": "secret123",
                "password": "pass123",
            }
        )
        # The sealed entry should be redacted
        entry = chain._entries[0]
        assert "secret123" not in str(entry)
        assert "pass123" not in str(entry)
        # But the hash should still verify
        ok, _ = chain.verify()
        assert ok is True
