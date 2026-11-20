"""Evidence bundles must be verifiable offline and must reject tampering."""

from __future__ import annotations

import argparse
import io
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from ishastra import cli
from ishastra.core import bundle, scope_signing

JOB = {"id": "job_test", "state": "completed", "verdict": "1 finding(s)"}
AUDIT = [{"sequence": 1, "hash": "a" * 64, "event": "job_completed"}]
SCOPE = {"version": 2, "program": "Bundle test", "include": ["example.com"]}


def _keypair(tmp_path: Path, kid: str = "bundle-test"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    pem, jwk = scope_signing.generate_keypair(kid)
    key_path = tmp_path / "key.pem"
    key_path.write_bytes(pem)
    key_path.chmod(0o600)
    return scope_signing.load_private_key_file(key_path), jwk


def _rewrite(data: bytes, name: str, payload: bytes) -> bytes:
    source = zipfile.ZipFile(io.BytesIO(data))
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as target:
        for entry in source.namelist():
            target.writestr(entry, payload if entry == name else source.read(entry))
    return buffer.getvalue()


def test_bundle_verifies(tmp_path: Path) -> None:
    key, jwk = _keypair(tmp_path)
    data = bundle.build_bundle(job=JOB, audit=AUDIT, scope_document=SCOPE, private_key=key, kid=jwk["kid"])
    manifest = bundle.verify_bundle(data, {jwk["kid"]: key.public_key()})
    assert manifest["job_id"] == "job_test"
    assert set(manifest["files"]) == {"job.json", "audit.json", "scope.json"}


def test_tampered_member_is_rejected(tmp_path: Path) -> None:
    key, jwk = _keypair(tmp_path)
    data = bundle.build_bundle(job=JOB, audit=AUDIT, scope_document=SCOPE, private_key=key, kid=jwk["kid"])
    tampered = _rewrite(data, "scope.json", json.dumps({**SCOPE, "include": ["*"]}).encode())
    with pytest.raises(bundle.BundleError, match="scope.json"):
        bundle.verify_bundle(tampered, {jwk["kid"]: key.public_key()})


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    key, jwk = _keypair(tmp_path)
    other_key, other_jwk = _keypair(tmp_path / "other", kid="other-key")
    data = bundle.build_bundle(job=JOB, audit=AUDIT, scope_document=SCOPE, private_key=key, kid=jwk["kid"])
    with pytest.raises(bundle.BundleError, match="not in the configured key set"):
        bundle.verify_bundle(data, {other_jwk["kid"]: other_key.public_key()})


def test_cli_creates_then_verifies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    key, jwk = _keypair(tmp_path)
    jwks = tmp_path / "jwks.json"
    jwks.write_text(json.dumps({"keys": [jwk]}))
    scope_path = tmp_path / "scope.json"
    scope_path.write_text(json.dumps(SCOPE))

    async def fake_get_database():
        return None

    async def fake_get_job(job_id: str, *, tenant: str | None = None):
        return JOB if job_id == JOB["id"] else None

    async def fake_get_findings(job_id: str, *, tenant: str | None = None):
        return []

    async def fake_chain_rows():
        for row in AUDIT:
            yield row

    monkeypatch.setattr(cli.store, "get_database", fake_get_database)
    monkeypatch.setattr(cli.store, "get_job", fake_get_job)
    monkeypatch.setattr(cli.store, "get_findings", fake_get_findings)
    monkeypatch.setattr(cli.store, "chain_rows", fake_chain_rows)
    monkeypatch.setattr(cli.store, "configure", lambda path: None)
    monkeypatch.setattr(cli, "get_settings", lambda: SimpleNamespace(db_path="unused"))

    out = tmp_path / "evidence.zip"
    created = cli._run_bundle(
        argparse.Namespace(
            job=JOB["id"],
            tenant=None,
            scope=str(scope_path),
            key=str(tmp_path / "key.pem"),
            kid=jwk["kid"],
            out=str(out),
            verify="",
            jwks="",
        )
    )
    assert created == 0 and out.exists()

    manifest = bundle.verify_bundle(out.read_bytes(), {jwk["kid"]: key.public_key()})
    assert {"sarif.json", "report.html"} <= set(manifest["files"])

    verified = cli._run_bundle(argparse.Namespace(verify=str(out), jwks=str(jwks)))
    assert verified == 0


def test_extra_member_is_rejected(tmp_path: Path) -> None:
    key, jwk = _keypair(tmp_path)
    data = bundle.build_bundle(job=JOB, audit=AUDIT, scope_document=SCOPE, private_key=key, kid=jwk["kid"])
    buffer = io.BytesIO(data)
    with zipfile.ZipFile(buffer, "a") as archive:
        archive.writestr("smuggled.txt", b"extra")
    with pytest.raises(bundle.BundleError, match="unlisted entries"):
        bundle.verify_bundle(buffer.getvalue(), {jwk["kid"]: key.public_key()})
