"""Tests for the dual-approval break-glass workflow."""

from __future__ import annotations

import json
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from ishastra.core import scope_breakglass, scope_signing


def _create_test_jwks(temp_dir: Path) -> tuple[Path, Path, Path]:
    """Create a JWKS with two test keys and return (jwks_path, key1_path, key2_path)."""

    pem1, jwk1 = scope_signing.generate_keypair("approver1")
    pem2, jwk2 = scope_signing.generate_keypair("approver2")

    key1_path = temp_dir / "approver1.pem"
    key2_path = temp_dir / "approver2.pem"
    jwks_path = temp_dir / "jwks.json"

    key1_path.write_bytes(pem1)
    key1_path.chmod(0o600)
    key2_path.write_bytes(pem2)
    key2_path.chmod(0o600)

    jwks_data = {"keys": [jwk1, jwk2]}
    jwks_path.write_text(json.dumps(jwks_data, indent=2))

    return jwks_path, key1_path, key2_path


def _create_base_scope() -> dict[str, Any]:
    """Create a minimal valid scope document."""
    return {
        "program": "test-program",
        "authorized_by": "test-authorizer",
        "authorization_ref": "test-ref-123",
        "include": ["*.example.com", "api.example.com"],
        "exclude": ["internal.example.com"],
        "authorized_networks": ["10.0.0.0/8"],
        "allowed_ports": [80, 443, 8443],
        "allow_broad_networks": False,
        "version": 2,
    }


class TestBreakGlassCreation:
    """Tests for creating break-glass scope documents."""

    def test_create_break_glass_scope_success(self) -> None:
        """Test successful creation of a break-glass scope."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_dir = Path(tmpdir)
            jwks_path, key1_path, key2_path = _create_test_jwks(temp_dir)
            base_scope = _create_base_scope()

            result = scope_breakglass.create_break_glass_scope(
                scope_document=base_scope,
                approver1_key_path=str(key1_path),
                approver1_kid="approver1",
                approver2_key_path=str(key2_path),
                approver2_kid="approver2",
                jwks_path=str(jwks_path),
                tenant_id="tenant-123",
                reason="Emergency production incident",
                duration="4h",
            )

            assert "signatures" in result
            assert len(result["signatures"]) == 2
            assert result["metadata"]["break_glass"] == "true"
            assert result["metadata"]["break_glass_reason"] == "Emergency production incident"
            assert result["metadata"]["break_glass_tenant"] == "tenant-123"
            assert "break_glass_approvers" in result["metadata"]
            assert "approver1,approver2" in result["metadata"]["break_glass_approvers"]
            assert "expires_at" in result
            assert result["include"] == base_scope["include"]

    def test_create_break_glass_scope_invalid_duration(self) -> None:
        """Test that duration exceeding 4h is rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_dir = Path(tmpdir)
            jwks_path, key1_path, key2_path = _create_test_jwks(temp_dir)
            base_scope = _create_base_scope()

            with pytest.raises(scope_breakglass.BreakGlassError) as exc_info:
                scope_breakglass.create_break_glass_scope(
                    scope_document=base_scope,
                    approver1_key_path=str(key1_path),
                    approver1_kid="approver1",
                    approver2_key_path=str(key2_path),
                    approver2_kid="approver2",
                    jwks_path=str(jwks_path),
                    tenant_id="tenant-123",
                    reason="Emergency",
                    duration="5h",
                )

            assert "exceeds maximum" in str(exc_info.value)

    def test_create_break_glass_scope_same_approver_rejected(self) -> None:
        """Test that using the same approver twice is rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_dir = Path(tmpdir)
            jwks_path, key1_path, key2_path = _create_test_jwks(temp_dir)
            base_scope = _create_base_scope()

            with pytest.raises(scope_breakglass.BreakGlassError) as exc_info:
                scope_breakglass.create_break_glass_scope(
                    scope_document=base_scope,
                    approver1_key_path=str(key1_path),
                    approver1_kid="approver1",
                    approver2_key_path=str(key1_path),
                    approver2_kid="approver1",
                    jwks_path=str(jwks_path),
                    tenant_id="tenant-123",
                    reason="Emergency",
                    duration="4h",
                )

            assert "different keys" in str(exc_info.value)

    def test_create_break_glass_scope_missing_approver_in_jwks(self) -> None:
        """Test that approver not in JWKS is rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_dir = Path(tmpdir)
            jwks_path, key1_path, key2_path = _create_test_jwks(temp_dir)
            base_scope = _create_base_scope()

            with pytest.raises(scope_breakglass.BreakGlassError) as exc_info:
                scope_breakglass.create_break_glass_scope(
                    scope_document=base_scope,
                    approver1_key_path=str(key1_path),
                    approver1_kid="approver1",
                    approver2_key_path=str(key2_path),
                    approver2_kid="nonexistent",
                    jwks_path=str(jwks_path),
                    tenant_id="tenant-123",
                    reason="Emergency",
                    duration="4h",
                )

            assert "not found in JWKS" in str(exc_info.value)


class TestBreakGlassVerification:
    """Tests for verifying break-glass scope documents."""

    def test_verify_valid_break_glass_scope(self) -> None:
        """Test verification of a valid break-glass scope."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_dir = Path(tmpdir)
            jwks_path, key1_path, key2_path = _create_test_jwks(temp_dir)
            base_scope = _create_base_scope()

            signed = scope_breakglass.create_break_glass_scope(
                scope_document=base_scope,
                approver1_key_path=str(key1_path),
                approver1_kid="approver1",
                approver2_key_path=str(key2_path),
                approver2_kid="approver2",
                jwks_path=str(jwks_path),
                tenant_id="tenant-123",
                reason="Emergency",
                duration="4h",
            )

            valid, msg, meta = scope_breakglass.verify_break_glass_scope(signed, str(jwks_path))

            assert valid is True
            assert msg == "valid"
            assert meta is not None
            assert meta["tenant_id"] == "tenant-123"
            assert meta["reason"] == "Emergency"
            assert set(meta["approvers"]) == {"approver1", "approver2"}
            assert "scope_hash" in meta

    def test_verify_non_break_glass_document(self) -> None:
        """Test that non-break-glass documents are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_dir = Path(tmpdir)
            jwks_path, key1_path, key2_path = _create_test_jwks(temp_dir)
            base_scope = _create_base_scope()

            key = scope_signing.load_private_key_file(key1_path)
            signed = scope_signing.sign_document(base_scope, key, "approver1")

            valid, msg, meta = scope_breakglass.verify_break_glass_scope(signed, str(jwks_path))

            assert valid is False
            assert "not a break-glass document" in msg
            assert meta is None

    def test_verify_expired_break_glass_scope(self) -> None:
        """Test that expired break-glass scopes are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_dir = Path(tmpdir)
            jwks_path, key1_path, key2_path = _create_test_jwks(temp_dir)
            base_scope = _create_base_scope()

            signed = scope_breakglass.create_break_glass_scope(
                scope_document=base_scope,
                approver1_key_path=str(key1_path),
                approver1_kid="approver1",
                approver2_key_path=str(key2_path),
                approver2_kid="approver2",
                jwks_path=str(jwks_path),
                tenant_id="tenant-123",
                reason="Emergency",
                duration="4h",
            )

            signed["expires_at"] = "2020-01-01T00:00:00+00:00"
            signed["metadata"]["break_glass_expires_at"] = "2020-01-01T00:00:00+00:00"

            valid, msg, meta = scope_breakglass.verify_break_glass_scope(signed, str(jwks_path))

            assert valid is False
            assert "expired" in msg.lower()

    def test_verify_wrong_number_of_signatures(self) -> None:
        """Test that documents with wrong number of signatures are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_dir = Path(tmpdir)
            jwks_path, key1_path, key2_path = _create_test_jwks(temp_dir)
            base_scope = _create_base_scope()

            signed = scope_breakglass.create_break_glass_scope(
                scope_document=base_scope,
                approver1_key_path=str(key1_path),
                approver1_kid="approver1",
                approver2_key_path=str(key2_path),
                approver2_kid="approver2",
                jwks_path=str(jwks_path),
                tenant_id="tenant-123",
                reason="Emergency",
                duration="4h",
            )

            signed["signatures"] = [signed["signatures"][0]]

            valid, msg, meta = scope_breakglass.verify_break_glass_scope(signed, str(jwks_path))

            assert valid is False
            assert "exactly 2 signatures" in msg

    def test_verify_tampered_document(self) -> None:
        """Test that tampered documents are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_dir = Path(tmpdir)
            jwks_path, key1_path, key2_path = _create_test_jwks(temp_dir)
            base_scope = _create_base_scope()

            signed = scope_breakglass.create_break_glass_scope(
                scope_document=base_scope,
                approver1_key_path=str(key1_path),
                approver1_kid="approver1",
                approver2_key_path=str(key2_path),
                approver2_kid="approver2",
                jwks_path=str(jwks_path),
                tenant_id="tenant-123",
                reason="Emergency",
                duration="4h",
            )

            signed["include"] = ["evil.com"]

            valid, msg, meta = scope_breakglass.verify_break_glass_scope(signed, str(jwks_path))

            assert valid is False
            assert "verification failed" in msg.lower() or "signature" in msg.lower()


class TestBreakGlassRevocation:
    """Tests for revoking break-glass scope documents."""

    def test_revoke_break_glass_scope(self) -> None:
        """Test revoking a break-glass scope."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_dir = Path(tmpdir)
            jwks_path, key1_path, key2_path = _create_test_jwks(temp_dir)
            base_scope = _create_base_scope()

            signed = scope_breakglass.create_break_glass_scope(
                scope_document=base_scope,
                approver1_key_path=str(key1_path),
                approver1_kid="approver1",
                approver2_key_path=str(key2_path),
                approver2_kid="approver2",
                jwks_path=str(jwks_path),
                tenant_id="tenant-123",
                reason="Emergency",
                duration="4h",
            )

            revoked = scope_breakglass.revoke_break_glass_scope(
                document=signed,
                jwks=str(jwks_path),
                revoked_by="admin",
                reason="Incident resolved",
            )

            assert revoked["metadata"]["revoked"] == "true"
            assert revoked["metadata"]["revoked_by"] == "admin"
            assert revoked["metadata"]["revocation_reason"] == "Incident resolved"
            assert "revoked_at" in revoked["metadata"]
            assert revoked["revoked"] is True

            assert "signatures" not in revoked

    def test_revoke_invalid_document_fails(self) -> None:
        """Test that revoking an invalid document fails."""
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_dir = Path(tmpdir)
            jwks_path, key1_path, key2_path = _create_test_jwks(temp_dir)
            base_scope = _create_base_scope()

            key = scope_signing.load_private_key_file(key1_path)
            signed = scope_signing.sign_document(base_scope, key, "approver1")

            with pytest.raises(scope_breakglass.BreakGlassError) as exc_info:
                scope_breakglass.revoke_break_glass_scope(
                    document=signed,
                    jwks=str(jwks_path),
                    revoked_by="admin",
                    reason="Test",
                )

            assert "not a break-glass document" in str(exc_info.value)


class TestBreakGlassCLI:
    """Tests for the CLI command."""

    def test_cli_help(self) -> None:
        """Test that CLI help works."""
        import sys
        from io import StringIO

        from ishastra.cli import main

        old_argv = sys.argv
        old_stdout = sys.stdout
        try:
            sys.argv = ["ishastra", "scope-breakglass", "--help"]
            sys.stdout = StringIO()
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 0
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout

    def test_cli_missing_required_args(self) -> None:
        """Test that CLI fails with missing required args."""
        import sys
        from io import StringIO

        from ishastra.cli import main

        old_argv = sys.argv
        old_stderr = sys.stderr
        try:
            sys.argv = ["ishastra", "scope-breakglass"]
            sys.stderr = StringIO()
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code != 0
        finally:
            sys.argv = old_argv
            sys.stderr = old_stderr


class TestScopeHash:
    """Tests for scope hash computation."""

    def test_scope_hash_consistency(self) -> None:
        """Test that scope hash is consistent for same document."""
        doc = _create_base_scope()

        hash1 = scope_breakglass._compute_scope_hash(doc)
        hash2 = scope_breakglass._compute_scope_hash(doc)

        assert hash1 == hash2
        assert len(hash1) == 64

    def test_scope_hash_changes_with_content(self) -> None:
        """Test that scope hash changes when content changes."""
        doc1 = _create_base_scope()
        doc2 = {**doc1, "include": ["*.different.com"]}

        hash1 = scope_breakglass._compute_scope_hash(doc1)
        hash2 = scope_breakglass._compute_scope_hash(doc2)

        assert hash1 != hash2

    def test_scope_hash_ignores_signatures(self) -> None:
        """Test that signatures field doesn't affect hash."""
        doc1 = _create_base_scope()
        doc2 = {**doc1, "signatures": [{"alg": "Ed25519", "kid": "test", "sig": "abc"}]}

        hash1 = scope_breakglass._compute_scope_hash(doc1)
        hash2 = scope_breakglass._compute_scope_hash(doc2)

        assert hash1 == hash2


class TestBreakGlassDurationParsing:
    """Tests for duration parsing."""

    def test_parse_seconds(self) -> None:
        td = scope_breakglass._parse_duration("3600")
        assert td == timedelta(seconds=3600)

    def test_parse_minutes(self) -> None:
        td = scope_breakglass._parse_duration("90m")
        assert td == timedelta(minutes=90)

    def test_parse_hours(self) -> None:
        td = scope_breakglass._parse_duration("4h")
        assert td == timedelta(hours=4)

    def test_parse_days(self) -> None:
        td = scope_breakglass._parse_duration("7d")
        assert td == timedelta(days=7)

    def test_parse_invalid(self) -> None:
        with pytest.raises(ValueError):
            scope_breakglass._parse_duration("invalid")
        with pytest.raises(ValueError):
            scope_breakglass._parse_duration("-1h")
        with pytest.raises(ValueError):
            scope_breakglass._parse_duration("0m")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
