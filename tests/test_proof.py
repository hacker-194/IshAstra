"""Strix Proof: signed grants, the receipt chain, and proof-pack verification."""

import json

import pytest

from strix import proof

BASE = {
    "program": "proof tests",
    "authorized_by": "pytest",
    "authorization_ref": "local-proof",
    "include": ["example.com", "*.example.com"],
}


def _signed(**overrides):
    private, _public = proof.new_keypair()
    return proof.new_grant(**{**BASE, **overrides}).sign(private)


def _gate(tmp_path, grant, **kwargs):
    return proof.Gate(grant, ledger_path=tmp_path / "ledger.jsonl", **kwargs)


def test_grant_round_trip_and_pinned_issuer(tmp_path):
    grant = _signed()
    restored = proof.Grant.from_dict(json.loads(json.dumps(grant.to_dict())))
    assert restored.verify(now=grant.not_before) == (True, "")
    assert restored.verify(trusted_issuer=grant.issuer)[0]

    other, _ = proof.new_keypair()
    other_public = proof.public_key(other)
    ok, reason = restored.verify(trusted_issuer=other_public)
    assert not ok and "not the pinned issuer" in reason


def test_tampered_grant_is_refused():
    data = _signed().to_dict()
    data["include"] = [*data["include"], "victim.example.net"]
    ok, reason = proof.Grant.from_dict(data).verify()
    assert not ok and "signature does not verify" in reason


def test_gate_allows_scope_and_receipts_denials(tmp_path):
    grant = _signed()
    gate = _gate(tmp_path, grant, actor="scanner")

    allowed = gate.authorize("https://example.com/login")
    denied = gate.authorize("https://evil.com/login")

    assert allowed.decision == "allow"
    assert denied.decision == "deny"
    assert "not in the authorized scope" in denied.reason
    assert [r.seq for r in gate.ledger.receipts] == [1, 2]
    assert gate.ledger.verify() == (True, "")

    rows = [
        json.loads(line)
        for line in (tmp_path / "ledger.jsonl").read_text().splitlines()
    ]
    assert rows[0]["type"] == proof.LEDGER_TYPE
    assert [row["decision"] for row in rows[1:]] == ["allow", "deny"]


def test_gate_refuses_expired_or_foreign_grant(tmp_path):
    import time

    expired = _signed(now=time.time() - 10 * 86400, days=1)
    with pytest.raises(proof.ProofError, match="expired"):
        _gate(tmp_path, expired)

    grant = _signed()
    other, _ = proof.new_keypair()
    with pytest.raises(proof.ProofError, match="not the pinned issuer"):
        _gate(tmp_path, grant, trusted_issuer=proof.public_key(other))


def test_proof_pack_verifies(tmp_path):
    grant = _signed()
    gate = _gate(tmp_path, grant)
    gate.authorize("https://example.com/")
    gate.authorize("https://api.example.com/v1")
    gate.authorize("https://evil.com/")

    pack = proof.build_pack(grant, gate.ledger)
    report = proof.verify_pack(pack, trusted_issuer=grant.issuer)
    assert report["ok"], report["errors"]
    assert report["checks"]["chain"] and report["checks"]["scope_compliance"]
    assert report["checks"]["issuer_trusted"]
    assert (report["summary"]["allowed"], report["summary"]["denied"]) == (2, 1)
    assert report["summary"]["grant_id"] == grant.grant_id


def test_proof_pack_detects_tampering(tmp_path):
    grant = _signed()
    gate = _gate(tmp_path, grant)
    gate.authorize("https://example.com/")
    gate.authorize("https://api.example.com/")
    pack = proof.build_pack(grant, gate.ledger)

    altered = json.loads(json.dumps(pack))
    altered["receipts"][0]["url"] = "https://evil.com/"
    assert not proof.verify_pack(altered)["ok"]

    reordered = json.loads(json.dumps(pack))
    reordered["receipts"].reverse()
    assert not proof.verify_pack(reordered)["ok"]

    dropped = json.loads(json.dumps(pack))
    dropped["receipts"].pop(0)
    assert not proof.verify_pack(dropped)["ok"]

    claimed = json.loads(json.dumps(pack))
    claimed["summary"]["allowed"] = 99
    assert not proof.verify_pack(claimed)["ok"]


def test_receipt_outside_grant_window_fails_verification(tmp_path):
    grant = _signed()
    gate = _gate(tmp_path, grant)
    gate.ledger.record(
        grant,
        url="https://example.com/",
        method="GET",
        decision="allow",
        reason="",
        now=grant.not_after + 60,
    )
    report = proof.verify_pack(proof.build_pack(grant, gate.ledger))
    assert not report["ok"]
    assert any("outside the grant window" in error for error in report["errors"])


def test_ledger_resumes_across_gate_restarts(tmp_path):
    grant = _signed()
    private, _public = proof.new_keypair()
    ledger_path = tmp_path / "ledger.jsonl"
    first = proof.Gate(grant, signing_key=private, ledger_path=ledger_path)
    first.authorize("https://example.com/a")

    second = proof.Gate(grant, signing_key=private, ledger_path=ledger_path)
    assert second.authorize("https://example.com/b").seq == 2
    assert proof.verify_pack(proof.build_pack(grant, second.ledger))["ok"]

    stranger, _ = proof.new_keypair()
    with pytest.raises(proof.ProofError, match="written by"):
        proof.Gate(grant, signing_key=stranger, ledger_path=ledger_path)


def test_api_verifies_and_reports_tampering(client, tmp_path):
    grant = _signed()
    gate = _gate(tmp_path, grant)
    gate.authorize("https://example.com/")
    pack = proof.build_pack(grant, gate.ledger)

    response = client.post(
        "/api/proof/verify",
        json={"proof": pack, "trusted_issuer": grant.issuer},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True, body["errors"]
    assert body["checks"]["chain"] and body["checks"]["issuer_trusted"]
    assert body["verified_at"] > 0

    pack["receipts"][0]["url"] = "https://evil.com/"
    tampered = client.post("/api/proof/verify", json={"proof": pack}).json()
    assert tampered["ok"] is False
    assert tampered["checks"]["chain"] is False

    assert (
        client.post("/api/proof/verify", json={"proof": "not-a-pack"}).status_code
        == 422
    )


def test_cli_grant_then_verify(tmp_path, capsys):
    grant_path = tmp_path / "grant.json"
    key_path = tmp_path / "issuer.key"
    from strix.cli import main

    with pytest.raises(SystemExit) as created:
        main(
            [
                "grant",
                "--program",
                "cli proof",
                "--authorized-by",
                "pytest",
                "--ref",
                "cli-test",
                "--include",
                "example.com",
                "--key-out",
                str(key_path),
                "--out",
                str(grant_path),
            ]
        )
    assert created.value.code == 0

    grant = proof.load_grant(grant_path)
    gate = _gate(tmp_path, grant)
    gate.authorize("https://example.com/")
    pack_path = tmp_path / "proof.json"
    pack_path.write_text(json.dumps(proof.build_pack(grant, gate.ledger)))

    with pytest.raises(SystemExit) as verified:
        main(
            [
                "verify",
                str(pack_path),
                "--issuer-key",
                str(key_path),
                "--json",
            ]
        )
    assert verified.value.code == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
