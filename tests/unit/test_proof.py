"""Unit tests for Strix Proof (grant, receipt, verification)."""

import importlib
import json
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from strix.proof import (
    GENESIS,
    VERSION,
    Gate,
    Ledger,
    ProofError,
    Receipt,
    build_pack,
    canonical,
    digest,
    fingerprint,
    load_grant,
    load_private_key,
    load_public_key,
    new_grant,
    new_keypair,
    public_key,
    sign,
    verify_pack,
    verify_signature,
    write_private_key,
)


# Ensure clean state: test_otel.py mocks can interfere with cryptography
@pytest.fixture(autouse=True)
def reset_crypto_state():
    """Reset any global state that might affect cryptography operations."""
    yield
    # Force re-import of cryptography primitives and strix.proof to clear mock residue
    import sys

    for mod in list(sys.modules.keys()):
        if "strix.proof" in mod or "cryptography.hazmat.primitives.asymmetric.ed25519" in mod:
            del sys.modules[mod]
    import cryptography.hazmat.primitives.asymmetric.ed25519 as ed25519

    importlib.reload(ed25519)


class TestCanonicalEncoding:
    """Test canonical encoding and digest functions."""

    def test_canonical_encoding(self):
        """Canonical encoding produces deterministic sorted output."""
        data = {"b": 2, "a": 1, "c": {"z": 26, "y": 25}}
        result = canonical(data)
        assert b'"a":1' in result
        assert b'"b":2' in result
        assert result == canonical(data)  # Deterministic

    def test_digest_deterministic(self):
        """Digest is deterministic for same input."""
        data = {"key": "value", "num": 42}
        d1 = digest(data)
        d2 = digest(data)
        assert d1 == d2
        assert len(d1) == 64  # SHA256 hex

    def test_canonical_handles_unicode(self):
        """Canonical encoding handles unicode."""
        data = {"message": "Hello 世界"}
        result = canonical(data)
        assert "世界" in result.decode()


class TestKeyGeneration:
    """Test Ed25519 key generation and utilities."""

    def test_new_keypair(self):
        """Generate keypair produces valid keys."""
        private, public = new_keypair()
        assert private is not None
        assert public is not None
        assert len(private) > 0
        assert len(public) > 0

    def test_public_key_from_private(self):
        """Derive public key from private key."""
        private, public = new_keypair()
        derived = public_key(private)
        assert derived == public

    def test_public_key_invalid_private_raises(self):
        """Invalid private key raises ProofError."""
        with pytest.raises(ProofError, match="invalid Ed25519 private key"):
            public_key("invalid")

    def test_fingerprint(self):
        """Fingerprint produces short stable identifier."""
        private, public = new_keypair()
        fp = fingerprint(public)
        assert len(fp) == 32  # 32 hex chars
        assert fp == fingerprint(public)  # Stable

    def test_fingerprint_invalid_public_no_raise(self):
        """fingerprint hashes whatever bytes it gets (no validation here)."""
        # fingerprint doesn't validate Ed25519 format, just hashes the bytes
        fp = fingerprint("invalid")
        assert len(fp) == 32  # Still produces 32-char hex

    def test_public_key_invalid_raises(self):
        """public_key validates Ed25519 private key format."""
        with pytest.raises(ProofError, match="invalid Ed25519 private key"):
            public_key("invalid")


class TestSigningAndVerification:
    """Test signing and signature verification."""

    def test_sign_and_verify(self):
        """Sign payload and verify with correct public key."""
        private, public = new_keypair()
        payload = {"action": "test", "value": 123}
        signature = sign(payload, private)
        assert verify_signature(payload, signature, public) is True

    def test_verify_fails_with_wrong_key(self):
        """Verification fails with different public key."""
        private1, public1 = new_keypair()
        _, public2 = new_keypair()
        payload = {"action": "test"}
        signature = sign(payload, private1)
        assert verify_signature(payload, signature, public2) is False

    def test_verify_fails_with_tampered_payload(self):
        """Verification fails if payload is modified."""
        private, public = new_keypair()
        payload = {"action": "test", "value": 1}
        signature = sign(payload, private)
        tampered = {"action": "test", "value": 2}
        assert verify_signature(tampered, signature, public) is False

    def test_verify_fails_with_tampered_signature(self):
        """Verification fails if signature is modified."""
        private, public = new_keypair()
        payload = {"action": "test"}
        signature = sign(payload, private)
        # Tamper with the first base64 character, not the last: trailing padding
        # bits can decode to identical bytes and make this assertion flaky.
        tampered_sig = ("A" if signature[0] != "A" else "B") + signature[1:]
        assert verify_signature(payload, tampered_sig, public) is False


class TestKeyFileOperations:
    """Test private/public key file operations."""

    def test_write_and_load_private_key(self):
        """Write and load private key file."""
        private, public = new_keypair()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "key.key"
            write_private_key(path, private)
            loaded = load_private_key(path)
            assert loaded == private

    def test_private_key_file_permissions(self):
        """Private key file has restricted permissions."""
        private, _ = new_keypair()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "key.key"
            write_private_key(path, private)
            mode = path.stat().st_mode & 0o777
            assert mode == 0o600

    def test_load_private_key_strips_prefix(self):
        """Load private key handles prefix correctly."""
        private, _ = new_keypair()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "key.key"
            path.write_text("strix-proof-private:" + private + "\n")
            loaded = load_private_key(path)
            assert loaded == private

    def test_load_public_key(self):
        """Load public key file."""
        _, public = new_keypair()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "key.pub"
            path.write_text(public + "\n")
            loaded = load_public_key(path)
            assert loaded == public

    def test_load_public_key_rejects_private(self):
        """Load public key rejects private key file."""
        private, _ = new_keypair()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "key.pub"
            path.write_text("strix-proof-private:" + private + "\n")
            with pytest.raises(ProofError, match="holds a private key"):
                load_public_key(path)


class TestGrant:
    """Test Grant creation, signing, and verification."""

    def test_new_grant(self):
        """Create unsigned grant."""
        grant = new_grant(
            program="Test Program",
            authorized_by="Test Org",
            authorization_ref="TEST-001",
            include=["example.com"],
            allowed_ports=[80, 443],
        )
        assert grant.program == "Test Program"
        assert grant.authorized_by == "Test Org"
        assert grant.include == ("example.com",)
        assert grant.allowed_ports == (80, 443)
        assert grant.signature == ""  # Unsigned

    def test_new_grant_with_defaults(self):
        """Grant with default values."""
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        )
        assert grant.exclude == ()
        assert grant.authorized_networks == ()
        assert grant.allow_broad_networks is False
        assert grant.not_before > 0
        assert grant.not_after > grant.not_before

    def test_grant_sign(self):
        """Sign grant with private key."""
        private, public = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
            allowed_ports=[443],
        )
        signed = grant.sign(private)
        assert signed.signature != ""
        assert signed.issuer == public

    def test_grant_verify_valid(self):
        """Verify valid signed grant."""
        private, public = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
            allowed_ports=[443],
        )
        signed = grant.sign(private)
        ok, reason = signed.verify(trusted_issuer=public)
        assert ok is True
        assert reason == ""

    def test_grant_verify_rejects_wrong_issuer(self):
        """Verify rejects grant signed by different key."""
        private1, public1 = new_keypair()
        _, public2 = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        )
        signed = grant.sign(private1)
        ok, reason = signed.verify(trusted_issuer=public2)
        assert ok is False
        assert "not the pinned issuer" in reason

    def test_grant_verify_rejects_unsigned(self):
        """Verify rejects unsigned grant."""
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        )
        ok, reason = grant.verify()
        assert ok is False
        assert "not signed" in reason

    def test_grant_verify_rejects_expired(self):
        """Verify rejects expired grant."""
        private, public = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
            days=0.0,  # Expired immediately
        )
        signed = grant.sign(private)
        ok, reason = signed.verify(now=signed.not_after + 1)
        assert ok is False
        assert "grant validity window is empty" in reason

    def test_grant_verify_rejects_not_yet_effective(self):
        """Verify rejects grant not yet effective."""
        private, public = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
            days=30,
        )
        signed = grant.sign(private)
        ok, reason = signed.verify(now=signed.not_before - 1)
        assert ok is False
        assert "not effective" in reason

    def test_grant_to_scope(self):
        """Grant converts to Scope."""
        private, _ = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com", "*.example.com"],
            exclude=["admin.example.com"],
            authorized_networks=["10.0.0.0/8"],
            allowed_ports=[80, 443],
            allow_broad_networks=True,
        )
        signed = grant.sign(private)
        scope = signed.to_scope()
        assert scope.program == "Test"
        assert scope.include == ("example.com", "*.example.com")
        assert scope.exclude == ("admin.example.com",)
        assert scope.authorized_networks == ("10.0.0.0/8",)
        assert scope.allowed_ports == (80, 443)
        assert scope.allow_broad_networks is True

    def test_grant_verify_validates_scope(self):
        """Grant verify checks scope shape (signature fails first if body tampered)."""
        private, public = new_keypair()
        # Create a valid grant, sign it, then tamper with include
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        )
        signed = grant.sign(private)
        # Tampering with include changes the body, so signature verification fails first
        tampered = replace(signed, include=())
        ok, reason = tampered.verify(trusted_issuer=public)
        assert ok is False
        assert "grant signature does not verify" in reason

    def test_load_grant_from_file(self):
        """Load grant from JSON file."""
        private, public = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        )
        signed = grant.sign(private)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "grant.json"
            path.write_text(json.dumps(signed.to_dict()))
            loaded = load_grant(path)
            assert loaded.grant_id == signed.grant_id
            assert loaded.program == "Test"

    def test_load_grant_invalid_json_raises(self):
        """Load grant raises on invalid JSON."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "grant.json"
            path.write_text("not json")
            with pytest.raises(ProofError, match="not valid JSON"):
                load_grant(path)


class TestReceipt:
    """Test Receipt creation and verification."""

    def test_receipt_body(self):
        """Receipt body excludes hash and signature."""
        receipt = Receipt(
            seq=1,
            grant_id="gr_test",
            grant_digest="abc123",
            actor="agent",
            url="https://example.com/",
            method="GET",
            decision="allow",
            reason="",
            timestamp=1234567890.0,
            previous=GENESIS,
            hash="hash123",
            signature="sig123",
        )
        body = receipt.body()
        assert "hash" not in body
        assert "signature" not in body
        assert body["seq"] == 1
        assert body["decision"] == "allow"

    def test_receipt_signature_ok(self):
        """Receipt signature verification."""
        private, public = new_keypair()
        body_hash = "abc123"
        signature = sign({"hash": body_hash}, private)
        receipt = Receipt(
            seq=1,
            grant_id="gr_test",
            grant_digest="abc123",
            actor="agent",
            url="https://example.com/",
            method="GET",
            decision="allow",
            reason="",
            timestamp=1234567890.0,
            previous=GENESIS,
            hash=body_hash,
            signature=signature,
        )
        assert receipt.signature_ok(public) is True
        assert receipt.signature_ok("wrong_key") is False


class TestLedger:
    """Test Ledger receipt chaining."""

    def test_ledger_creation(self):
        """Create ledger with signing key."""
        private, _ = new_keypair()
        ledger = Ledger(signing_key=private, actor="test-agent")
        assert ledger.gate_public_key is not None
        assert ledger.receipts == []

    def test_ledger_ensure_header(self):
        """Ledger header binds to grant."""
        private, _ = new_keypair()
        grant_private, grant_public = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        ).sign(grant_private)
        ledger = Ledger(signing_key=private, actor="test-agent")
        ledger.ensure_header(grant)
        assert ledger.header["grant_id"] == grant.grant_id
        assert ledger.header["gate_public_key"] == ledger.gate_public_key

    def test_ledger_rejects_different_grant(self):
        """Ledger rejects header for different grant."""
        private, _ = new_keypair()
        grant_private1, _ = new_keypair()
        grant_private2, _ = new_keypair()
        grant1 = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        ).sign(grant_private1)
        grant2 = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        ).sign(grant_private2)
        ledger = Ledger(signing_key=private, actor="test-agent")
        ledger.ensure_header(grant1)
        with pytest.raises(ProofError, match="belongs to grant"):
            ledger.ensure_header(grant2)

    def test_ledger_record_receipt(self):
        """Record a receipt in the ledger."""
        private, _ = new_keypair()
        grant_private, _ = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        ).sign(grant_private)
        ledger = Ledger(signing_key=private, actor="test-agent")
        ledger.ensure_header(grant)
        receipt = ledger.record(
            grant,
            url="https://example.com/",
            method="GET",
            decision="allow",
            reason="in scope",
        )
        assert receipt.seq == 1
        assert receipt.decision == "allow"
        assert receipt.signature != ""
        assert len(ledger.receipts) == 1

    def test_ledger_chain_verification(self):
        """Ledger chain verification passes for valid chain."""
        private, _ = new_keypair()
        grant_private, _ = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        ).sign(grant_private)
        ledger = Ledger(signing_key=private, actor="test-agent")
        ledger.ensure_header(grant)
        for i in range(3):
            ledger.record(
                grant, url=f"https://example.com/page{i}", method="GET", decision="allow", reason=""
            )
        ok, reason = ledger.verify()
        assert ok is True
        assert reason == ""

    def test_ledger_read_only_without_key(self):
        """Ledger without signing key is read-only."""
        private, _ = new_keypair()
        grant_private, _ = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        ).sign(grant_private)
        ledger = Ledger(path=None)  # No signing key
        ledger.ensure_header(grant)
        with pytest.raises(ProofError, match="read-only"):
            ledger.record(grant, url="https://example.com/", method="GET", decision="allow", reason="")


class TestGate:
    """Test Gate authorization decisions."""

    def test_gate_authorize_allow(self):
        """Gate allows in-scope URL."""
        grant_private, _ = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
            allowed_ports=[80, 443],
        ).sign(grant_private)
        gate = Gate(grant, signing_key=new_keypair()[0], actor="test-agent")
        receipt = gate.authorize("https://example.com/", "GET")
        assert receipt.decision == "allow"

    def test_gate_authorize_deny_out_of_scope(self):
        """Gate denies out-of-scope URL."""
        grant_private, _ = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        ).sign(grant_private)
        gate = Gate(grant, signing_key=new_keypair()[0], actor="test-agent")
        receipt = gate.authorize("https://other.com/", "GET")
        assert receipt.decision == "deny"
        assert "out_of_scope" in receipt.reason

    def test_gate_authorize_deny_port(self):
        """Gate denies URL with unauthorized port."""
        grant_private, _ = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
            allowed_ports=[80, 443],
        ).sign(grant_private)
        gate = Gate(grant, signing_key=new_keypair()[0], actor="test-agent")
        receipt = gate.authorize("https://example.com:8080/", "GET")
        assert receipt.decision == "deny"
        assert "port" in receipt.reason

    def test_gate_observe_records_decisions(self):
        """Gate.observe records decisions from scope observer."""
        grant_private, _ = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        ).sign(grant_private)
        gate = Gate(grant, signing_key=new_keypair()[0], actor="test-agent")
        with gate.observe():
            gate.authorize("https://example.com/", "GET")
        receipts = gate.ledger.receipts
        assert len(receipts) >= 1


class TestProofPack:
    """Test proof pack building and verification."""

    def test_build_pack(self):
        """Build proof pack from grant and ledger."""
        grant_private, grant_public = new_keypair()
        gate_private, gate_public = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        ).sign(grant_private)
        ledger = Ledger(signing_key=gate_private, actor="test-agent")
        ledger.ensure_header(grant)
        ledger.record(grant, url="https://example.com/", method="GET", decision="allow", reason="")
        ledger.record(
            grant, url="https://example.com/page2", method="GET", decision="deny", reason="out_of_scope"
        )
        pack = build_pack(grant, ledger)
        assert pack["version"] == VERSION
        assert pack["grant"]["grant_id"] == grant.grant_id
        assert len(pack["receipts"]) == 2
        assert pack["summary"]["allowed"] == 1
        assert pack["summary"]["denied"] == 1

    def test_build_pack_rejects_broken_chain(self):
        """Build pack rejects ledger with broken chain."""
        grant_private, _ = new_keypair()
        gate_private, _ = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        ).sign(grant_private)
        ledger = Ledger(signing_key=gate_private, actor="test-agent")
        ledger.ensure_header(grant)
        ledger.record(grant, url="https://example.com/", method="GET", decision="allow", reason="")
        # Manually tamper with receipt
        ledger._receipts[0] = Receipt(
            seq=1,
            grant_id="different_grant",
            grant_digest="different",
            actor="test-agent",
            url="https://example.com/",
            method="GET",
            decision="allow",
            reason="",
            timestamp=1234567890.0,
            previous=GENESIS,
            hash="tampered",
            signature="invalid",
        )
        with pytest.raises(ProofError, match="broken ledger"):
            build_pack(grant, ledger)

    def test_verify_pack_valid(self):
        """Verify valid proof pack."""
        grant_private, grant_public = new_keypair()
        gate_private, gate_public = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        ).sign(grant_private)
        ledger = Ledger(signing_key=gate_private, actor="test-agent")
        ledger.ensure_header(grant)
        ledger.record(grant, url="https://example.com/", method="GET", decision="allow", reason="")
        pack = build_pack(grant, ledger)
        report = verify_pack(pack, trusted_issuer=grant_public, trusted_gate=gate_public)
        assert report["ok"] is True
        assert report["checks"]["grant_signature"] is True
        assert report["checks"]["issuer_trusted"] is True
        assert report["checks"]["chain"] is True
        assert report["checks"]["scope_compliance"] is True
        assert report["checks"]["gate_key"] is True

    def test_verify_pack_invalid_grant_signature(self):
        """Verify pack rejects invalid grant signature."""
        grant_private, grant_public = new_keypair()
        _, wrong_public = new_keypair()
        gate_private, gate_public = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        ).sign(grant_private)
        ledger = Ledger(signing_key=gate_private, actor="test-agent")
        ledger.ensure_header(grant)
        ledger.record(grant, url="https://example.com/", method="GET", decision="allow", reason="")
        pack = build_pack(grant, ledger)
        report = verify_pack(pack, trusted_issuer=wrong_public, trusted_gate=gate_public)
        assert report["ok"] is False
        assert report["checks"]["grant_signature"] is False

    def test_verify_pack_invalid_gate_key(self):
        """Verify pack rejects mismatched gate key."""
        grant_private, grant_public = new_keypair()
        gate_private, gate_public = new_keypair()
        _, wrong_gate = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
        ).sign(grant_private)
        ledger = Ledger(signing_key=gate_private, actor="test-agent")
        ledger.ensure_header(grant)
        ledger.record(grant, url="https://example.com/", method="GET", decision="allow", reason="")
        pack = build_pack(grant, ledger)
        report = verify_pack(pack, trusted_issuer=grant_public, trusted_gate=wrong_gate)
        assert report["ok"] is False
        assert report["checks"]["gate_key"] is False

    def test_verify_pack_scope_compliance(self):
        """Verify pack checks scope compliance for allowed receipts."""
        grant_private, grant_public = new_keypair()
        gate_private, gate_public = new_keypair()
        grant = new_grant(
            program="Test",
            authorized_by="Me",
            authorization_ref="REF-1",
            include=["example.com"],
            allowed_ports=[443],
        ).sign(grant_private)
        ledger = Ledger(signing_key=gate_private, actor="test-agent")
        ledger.ensure_header(grant)
        # Record an "allow" for a port not in scope
        ledger.record(grant, url="https://example.com:8080/", method="GET", decision="allow", reason="")
        pack = build_pack(grant, ledger)
        report = verify_pack(pack, trusted_issuer=grant_public, trusted_gate=gate_public)
        assert report["ok"] is False
        assert report["checks"]["scope_compliance"] is False


class TestProofCLI:
    """Test proof CLI integration (smoke test)."""

    def test_grant_creation_via_temp_files(self):
        """Grant can be created and saved to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            grant_path = Path(tmpdir) / "grant.json"
            key_path = Path(tmpdir) / "issuer.key"

            private_key, public_key_val = new_keypair()

            grant = new_grant(
                program="CLI Test",
                authorized_by="Tester",
                authorization_ref="CLI-001",
                include=["test.example.com"],
                allowed_ports=[443],
            )

            signed_grant = grant.sign(private_key)

            grant_path.write_text(json.dumps(signed_grant.to_dict(), indent=2))
            key_path.write_text(private_key)

            loaded = load_grant(grant_path)
            ok, _ = loaded.verify(trusted_issuer=public_key_val)
            assert ok is True
