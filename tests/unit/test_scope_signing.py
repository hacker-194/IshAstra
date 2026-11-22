"""Ed25519 scope document signing: tamper detection and key rotation."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

import pytest

from ishastra.core import scope_signing
from ishastra.security.authorization.scope import (
    configure,
    configure_signing,
    extend_scope_expiry,
    parse_scope_document,
    revoke_scope,
)

KID = "kid-2026-11"

DOC = {
    "version": 2,
    "program": "Signed engagement",
    "authorized_by": "CISO",
    "authorization_ref": "SIG-001",
    "include": ["example.com"],
    "allowed_ports": [443],
}


def _pem_file(tmp_path, name, pem):
    path = tmp_path / name
    path.write_bytes(pem)
    return path


@pytest.fixture
def keypair(tmp_path):
    pem, jwk = scope_signing.generate_keypair(KID)
    return _pem_file(tmp_path, "scope-signing-key.pem", pem), jwk


@pytest.fixture(autouse=True)
def signing_isolation():
    configure_signing(None)
    yield
    configure_signing(None)
    configure(
        program="Cleanup",
        authorized_by="Test",
        authorization_ref="CLEANUP",
        include=["cleanup.local"],
    )


def _signed(document, key_path, kid=KID, **kwargs):
    return scope_signing.sign_document(document, scope_signing.load_private_key_file(key_path), kid, **kwargs)


def test_signed_document_loads_with_its_key(keypair):
    key_path, jwk = keypair
    configure_signing({"keys": [jwk]})
    installed = parse_scope_document(_signed(DOC, key_path))
    assert installed.program == "Signed engagement"
    assert installed.include == ("example.com",)


def test_tampered_include_is_refused(keypair):
    key_path, jwk = keypair
    configure_signing({"keys": [jwk]})
    document = _signed(DOC, key_path)
    document["include"].append("attacker.example")
    with pytest.raises(ValueError, match="does not verify"):
        parse_scope_document(document)


def test_signature_covers_revocation_fields(keypair):
    key_path, jwk = keypair
    configure_signing({"keys": [jwk]})
    revoked = {
        **DOC,
        "revoked": True,
        "revoked_at": "2026-01-01T00:00:00+00:00",
        "revoked_by": "sec-lead",
        "revocation_reason": "containment",
    }
    document = _signed(revoked, key_path)
    document["revoked"] = False
    with pytest.raises(ValueError, match="does not verify"):
        parse_scope_document(document)


def test_configured_signing_refuses_an_unsigned_document(keypair):
    _, jwk = keypair
    configure_signing({"keys": [jwk]})
    with pytest.raises(ValueError, match="is not signed"):
        parse_scope_document(DOC)


def test_signed_document_without_a_key_set_is_refused(keypair, monkeypatch):
    key_path, _ = keypair
    monkeypatch.delenv("ISHASTRA_SCOPE_JWKS", raising=False)
    configure_signing(None)
    with pytest.raises(ValueError, match="no verification key set"):
        parse_scope_document(_signed(DOC, key_path))


def test_signature_from_a_different_key_is_refused(tmp_path, keypair):
    _, jwk = keypair
    other_pem, _ = scope_signing.generate_keypair("kid-other")
    other_path = _pem_file(tmp_path, "other.pem", other_pem)
    configure_signing({"keys": [jwk]})
    with pytest.raises(ValueError, match="does not verify"):
        parse_scope_document(_signed(DOC, other_path, KID))


def test_unpublished_kid_is_refused(keypair):
    key_path, jwk = keypair
    configure_signing({"keys": [{**jwk, "kid": "other"}]})
    with pytest.raises(ValueError, match="not in the configured key set"):
        parse_scope_document(_signed(DOC, key_path))


def test_rotation_accepts_both_keys_then_retires_the_old_one(tmp_path):
    old_pem, old_jwk = scope_signing.generate_keypair("kid-1")
    new_pem, new_jwk = scope_signing.generate_keypair("kid-2")
    old_path = _pem_file(tmp_path, "old.pem", old_pem)
    new_path = _pem_file(tmp_path, "new.pem", new_pem)

    configure_signing({"keys": [old_jwk, new_jwk]})
    assert parse_scope_document(_signed(DOC, old_path, "kid-1")).program == "Signed engagement"
    assert parse_scope_document(_signed(DOC, new_path, "kid-2")).program == "Signed engagement"

    configure_signing({"keys": [new_jwk]})
    with pytest.raises(ValueError, match="not in the configured key set"):
        parse_scope_document(_signed(DOC, old_path, "kid-1"))


def test_jwks_file_named_by_environment_is_used(keypair, tmp_path, monkeypatch):
    key_path, jwk = keypair
    jwks_path = tmp_path / "jwks.json"
    jwks_path.write_text(json.dumps({"keys": [jwk]}))
    monkeypatch.setenv("ISHASTRA_SCOPE_JWKS", str(jwks_path))
    configure_signing(None)
    assert parse_scope_document(_signed(DOC, key_path)).program == "Signed engagement"


def test_key_rotation_keeps_old_keys_and_refreshes_file_backed_verification(tmp_path, monkeypatch):
    old_pem, old_jwk = scope_signing.generate_keypair("kid-old")
    old_path = _pem_file(tmp_path, "old.pem", old_pem)
    jwks_path = tmp_path / "jwks.json"
    jwks_path.write_text(json.dumps({"keys": [old_jwk]}))
    monkeypatch.setenv("ISHASTRA_SCOPE_JWKS", str(jwks_path))
    configure_signing(None)
    assert parse_scope_document(_signed(DOC, old_path, "kid-old")).program == "Signed engagement"

    new_path = tmp_path / "new.pem"
    new_jwk = scope_signing.rotate_keypair("kid-new", new_path, jwks_path)
    assert new_path.stat().st_mode & 0o777 == 0o600
    assert len(json.loads(jwks_path.read_text())["keys"]) == 2
    assert parse_scope_document(_signed(DOC, new_path, "kid-new")).program == "Signed engagement"
    assert parse_scope_document(_signed(DOC, old_path, "kid-old")).program == "Signed engagement"

    with pytest.raises(ValueError, match="already contains kid"):
        scope_signing.rotate_keypair("kid-new", tmp_path / "duplicate.pem", jwks_path)
    assert not (tmp_path / "duplicate.pem").exists()
    assert new_jwk["kid"] == "kid-new"


def test_scope_key_rotate_cli(tmp_path):
    from ishastra.cli import main

    _, old_jwk = scope_signing.generate_keypair("kid-old")
    jwks_path = tmp_path / "jwks.json"
    jwks_path.write_text(json.dumps({"keys": [old_jwk]}))
    new_path = tmp_path / "new.pem"

    with pytest.raises(SystemExit) as result:
        main(
            [
                "scope-key-rotate",
                "--kid",
                "kid-new",
                "--key",
                str(new_path),
                "--jwks",
                str(jwks_path),
            ]
        )

    assert result.value.code == 0
    assert new_path.stat().st_mode & 0o777 == 0o600
    assert [entry["kid"] for entry in json.loads(jwks_path.read_text())["keys"]] == ["kid-old", "kid-new"]


def test_field_order_does_not_matter(keypair):
    key_path, jwk = keypair
    configure_signing({"keys": [jwk]})
    signed = _signed(DOC, key_path)
    reordered = dict(reversed(list(signed.items())))
    assert parse_scope_document(reordered).program == "Signed engagement"


@pytest.mark.parametrize(
    ("jwks", "message"),
    [
        ({}, "must be an object with a 'keys' list"),
        ({"keys": []}, "contains no keys"),
        ({"keys": [{"kty": "RSA", "crv": "Ed25519", "kid": "k", "x": "AA"}]}, "kty=OKP"),
        ({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "AA"}]}, "non-empty 'kid'"),
        ({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k", "x": "AA"}]}, "32-byte"),
    ],
)
def test_malformed_key_sets_are_refused(jwks, message):
    with pytest.raises(ValueError, match=message):
        scope_signing.parse_jwks(jwks)


def test_revoking_a_signed_document_requires_the_key(tmp_path, keypair):
    key_path, jwk = keypair
    configure_signing({"keys": [jwk]})
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(_signed(DOC, key_path)))

    with pytest.raises(ValueError, match="requires the signing key"):
        revoke_scope(path, revoked_by="sec-lead", reason="engagement ended")

    revoked = revoke_scope(
        path,
        revoked_by="sec-lead",
        reason="engagement ended",
        private_key=key_path,
        kid=KID,
    )
    assert revoked.is_revoked()


def test_extending_a_signed_expiry_requires_the_key(tmp_path, keypair):
    key_path, jwk = keypair
    configure_signing({"keys": [jwk]})
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(_signed(DOC, key_path)))

    with pytest.raises(ValueError, match="requires the signing key"):
        extend_scope_expiry(path, "2030-01-01T00:00:00+00:00")

    extended = extend_scope_expiry(
        path,
        "2030-01-01T00:00:00+00:00",
        private_key=key_path,
        kid=KID,
    )
    assert extended.expires_at == "2030-01-01T00:00:00+00:00"


def test_keygen_and_sign_cli_round_trip(tmp_path):
    from ishastra.cli import main

    key_path = tmp_path / "signing.pem"
    jwks_path = tmp_path / "jwks.json"
    doc_path = tmp_path / "scope.json"
    doc_path.write_text(json.dumps(DOC))

    with pytest.raises(SystemExit) as keygen:
        main(["scope-keygen", "--kid", KID, "--key", str(key_path), "--jwks", str(jwks_path)])
    assert keygen.value.code == 0
    assert key_path.stat().st_mode & 0o777 == 0o600

    with pytest.raises(SystemExit) as sign:
        main(["scope-sign", "--scope", str(doc_path), "--key", str(key_path), "--kid", KID])
    assert sign.value.code == 0

    configure_signing(json.loads(jwks_path.read_text()))
    assert parse_scope_document(json.loads(doc_path.read_text())).program == "Signed engagement"


class TestFreshness:
    """A correctly signed but old document must not be replayable."""

    def test_stale_document_is_refused(self, keypair):
        key_path, jwk = keypair
        configure_signing({"keys": [jwk]}, max_age=3600)
        old = _signed(DOC, key_path, issued_at=datetime.now(UTC) - timedelta(days=2))
        with pytest.raises(ValueError, match="is stale"):
            parse_scope_document(old)

    def test_fresh_document_passes(self, keypair):
        key_path, jwk = keypair
        configure_signing({"keys": [jwk]}, max_age=3600)
        assert parse_scope_document(_signed(DOC, key_path)).program == "Signed engagement"

    def test_document_without_issued_at_is_refused(self, keypair):
        key_path, jwk = keypair
        configure_signing({"keys": [jwk]})
        key = scope_signing.load_private_key_file(key_path)
        payload = scope_signing.canonical_payload(DOC)
        document = {
            **DOC,
            "signature": {
                "alg": "Ed25519",
                "kid": KID,
                "sig": base64.urlsafe_b64encode(key.sign(payload)).decode().rstrip("="),
            },
        }
        with pytest.raises(ValueError, match="no issued_at"):
            parse_scope_document(document)

    def test_future_issued_at_is_refused(self, keypair):
        key_path, jwk = keypair
        configure_signing({"keys": [jwk]})
        future = _signed(DOC, key_path, issued_at=datetime.now(UTC) + timedelta(hours=1))
        with pytest.raises(ValueError, match="in the future"):
            parse_scope_document(future)

    def test_issued_at_without_timezone_is_refused(self, keypair):
        key_path, jwk = keypair
        configure_signing({"keys": [jwk]})
        naive = _signed(DOC, key_path, issued_at="2026-01-01T00:00:00")
        with pytest.raises(ValueError, match="must carry a timezone"):
            parse_scope_document(naive)

    def test_max_age_none_allows_a_stale_document(self, keypair):
        key_path, jwk = keypair
        configure_signing({"keys": [jwk]}, max_age=None)
        old = _signed(DOC, key_path, issued_at=datetime.now(UTC) - timedelta(days=2))
        assert parse_scope_document(old).program == "Signed engagement"


def test_scope_sign_stamps_a_default_expiry(tmp_path, keypair):
    from ishastra.cli import main

    key_path, _jwk = keypair
    doc = tmp_path / "mint.json"
    doc.write_text(json.dumps({k: v for k, v in DOC.items() if k != "expires_at"}))

    with pytest.raises(SystemExit) as sign:
        main(["scope-sign", "--scope", str(doc), "--key", str(key_path), "--kid", KID])
    assert sign.value.code == 0

    signed = json.loads(doc.read_text())
    stamped = datetime.fromisoformat(signed["expires_at"])
    assert timedelta(0) < stamped - datetime.now(UTC) <= timedelta(hours=24, seconds=5)


def test_scope_sign_no_expiry_leaves_the_document_open_ended(tmp_path, keypair):
    from ishastra.cli import main

    key_path, _jwk = keypair
    doc = tmp_path / "mint.json"
    doc.write_text(json.dumps({k: v for k, v in DOC.items() if k != "expires_at"}))

    with pytest.raises(SystemExit) as sign:
        main(
            [
                "scope-sign",
                "--scope",
                str(doc),
                "--key",
                str(key_path),
                "--kid",
                KID,
                "--no-expiry",
            ]
        )
    assert sign.value.code == 0
    assert "expires_at" not in json.loads(doc.read_text())


class TestBreakGlassIssuance:
    """Emergency issuance is capped by the tool, not by the operator's judgement."""

    @staticmethod
    def _args(path, key, **overrides):
        import argparse

        fields = {
            "scope": str(path),
            "key": str(key),
            "kid": KID,
            "output": None,
            "expires_in": "1h",
            "no_expiry": False,
            "break_glass": True,
        }
        fields.update(overrides)
        return argparse.Namespace(**fields)

    def _document(self, tmp_path):
        document = dict(DOC)
        document["metadata"] = {"incident": "INC-42"}
        path = tmp_path / "scope.json"
        path.write_text(json.dumps(document))
        return path

    def test_a_break_glass_document_is_bounded_and_marked(self, tmp_path, keypair):
        from ishastra.cli import _run_scope_sign

        key_path, jwk = keypair
        path = self._document(tmp_path)

        assert _run_scope_sign(self._args(path, key_path)) == 0

        signed = json.loads(path.read_text())
        assert signed["metadata"]["break_glass"] == "true"
        assert signed["expires_at"]
        scope_signing.verify_document(
            signed, {KID: scope_signing.load_private_key_file(key_path).public_key()}
        )
        assert jwk["kid"] == KID

    def test_a_window_longer_than_the_cap_is_refused(self, tmp_path, keypair):
        from ishastra.cli import _run_scope_sign

        key_path, _jwk = keypair
        path = self._document(tmp_path)
        before = path.read_text()

        assert _run_scope_sign(self._args(path, key_path, expires_in="6h")) == 2
        assert path.read_text() == before

    def test_an_unbounded_break_glass_is_refused(self, tmp_path, keypair):
        from ishastra.cli import _run_scope_sign

        key_path, _jwk = keypair
        path = self._document(tmp_path)

        assert _run_scope_sign(self._args(path, key_path, no_expiry=True)) == 2
