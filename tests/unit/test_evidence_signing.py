"""Evidence signing tests: sign, verify, and reject tampering offline."""

from __future__ import annotations

import dataclasses
import json

import pytest

from ishastra.security.signing.service import (
    EvidenceSigningService,
    new_keypair,
    verify_evidence_file,
)


@pytest.fixture
def workspace(tmp_path):
    """A workspace with two scanner output files."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "results.json").write_text('{"findings": []}')
    (ws / "report.sarif").write_text('{"version": "2.1.0"}')
    return ws


def _service() -> EvidenceSigningService:
    private_key, _ = new_keypair()
    return EvidenceSigningService(signing_key_private=private_key)


async def test_signed_manifest_verifies(workspace) -> None:
    service = _service()
    manifest = await service.create_evidence_from_workspace(
        tenant_id="t1", job_id="j1", engagement_id="e1", workspace_path=str(workspace)
    )
    ok, reason = service.verify_evidence(manifest)
    assert ok, reason
    assert len(manifest.artifacts) == 2
    assert manifest.key_id


async def test_edited_manifest_fails_verification(workspace) -> None:
    service = _service()
    manifest = await service.create_evidence_from_workspace(
        tenant_id="t1", job_id="j1", engagement_id="e1", workspace_path=str(workspace)
    )
    tampered = dataclasses.replace(manifest, metadata={"findings": "none"})
    ok, reason = service.verify_evidence(tampered)
    assert not ok
    assert "signature" in reason


async def test_unsigned_manifest_fails_verification(workspace) -> None:
    service = _service()
    manifest = await service.create_evidence_from_workspace(
        tenant_id="t1", job_id="j1", engagement_id="e1", workspace_path=str(workspace)
    )
    unsigned = dataclasses.replace(manifest, signature="")
    ok, reason = service.verify_evidence(unsigned)
    assert not ok
    assert "not signed" in reason


async def test_unknown_key_id_fails_verification(workspace) -> None:
    service = _service()
    manifest = await service.create_evidence_from_workspace(
        tenant_id="t1", job_id="j1", engagement_id="e1", workspace_path=str(workspace)
    )
    ok, reason = service.verify_evidence(manifest, key_id="0" * 32)
    assert not ok
    assert "unknown key_id" in reason


async def test_offline_verification_rejects_tampered_artifact(workspace, tmp_path) -> None:
    service = _service()
    manifest = await service.create_evidence_from_workspace(
        tenant_id="t1", job_id="j1", engagement_id="e1", workspace_path=str(workspace)
    )
    manifest_path = tmp_path / "evidence.json"
    manifest_path.write_text(json.dumps(manifest.to_dict()))
    public_path = tmp_path / "evidence.pub"
    public_path.write_text(service.get_verification_keys()[service.key_id])

    ok, reason = verify_evidence_file(manifest_path, public_path, artifacts_dir=workspace)
    assert ok, reason

    (workspace / "results.json").write_text('{"findings": ["injected"]}')
    ok, reason = verify_evidence_file(manifest_path, public_path, artifacts_dir=workspace)
    assert not ok
    assert "hash mismatch" in reason


async def test_offline_verification_rejects_tampered_manifest(workspace, tmp_path) -> None:
    service = _service()
    manifest = await service.create_evidence_from_workspace(
        tenant_id="t1", job_id="j1", engagement_id="e1", workspace_path=str(workspace)
    )
    data = manifest.to_dict()
    data["job_id"] = "another-job"
    manifest_path = tmp_path / "evidence.json"
    manifest_path.write_text(json.dumps(data))
    public_path = tmp_path / "evidence.pub"
    public_path.write_text(service.get_verification_keys()[service.key_id])

    ok, reason = verify_evidence_file(manifest_path, public_path)
    assert not ok
    assert "signature" in reason


async def test_cli_evidence_verify(workspace, tmp_path) -> None:
    from argparse import Namespace

    from ishastra.cli import _run_evidence_verify

    service = _service()
    manifest = await service.create_evidence_from_workspace(
        tenant_id="t1", job_id="j1", engagement_id="e1", workspace_path=str(workspace)
    )
    manifest_path = tmp_path / "evidence.json"
    manifest_path.write_text(json.dumps(manifest.to_dict()))
    public_path = tmp_path / "evidence.pub"
    public_path.write_text(service.get_verification_keys()[service.key_id])

    args = Namespace(
        manifest=str(manifest_path),
        key=str(public_path),
        artifacts_dir=str(workspace),
        json=True,
    )
    assert _run_evidence_verify(args) == 0

    (workspace / "results.json").write_text("tampered")
    assert _run_evidence_verify(args) == 1


async def test_missing_artifact_is_rejected(workspace, tmp_path) -> None:
    service = _service()
    manifest = await service.create_evidence_from_workspace(
        tenant_id="t1", job_id="j1", engagement_id="e1", workspace_path=str(workspace)
    )
    manifest_path = tmp_path / "evidence.json"
    manifest_path.write_text(json.dumps(manifest.to_dict()))
    public_path = tmp_path / "evidence.pub"
    public_path.write_text(service.get_verification_keys()[service.key_id])

    (workspace / "report.sarif").unlink()
    ok, reason = verify_evidence_file(manifest_path, public_path, artifacts_dir=workspace)
    assert not ok
    assert "missing artifact" in reason
