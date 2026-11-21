"""`ishastra demo` must produce a signed scope and a working key set on its own."""

from __future__ import annotations

import json
import stat
from pathlib import Path

from ishastra.cli import _prepare_demo_environment
from ishastra.core import scope_signing


def test_demo_environment_is_self_contained(tmp_path: Path) -> None:
    env = _prepare_demo_environment(tmp_path)

    scope_path = Path(env["ISHASTRA_SCOPE_FILE"])
    jwks_path = Path(env["ISHASTRA_SCOPE_JWKS"])
    assert scope_path.is_file() and jwks_path.is_file()
    assert env["ISHASTRA_DB"].startswith(str(tmp_path))
    assert len(env["ISHASTRA_API_KEY"]) >= 32
    assert env["ISHASTRA_ENCRYPTION_KEY"] and env["ISHASTRA_AUDIT_HMAC_KEY"]

    document = json.loads(scope_path.read_text())
    assert scope_signing.is_signed(document)
    assert document["include"] == ["localhost", "127.0.0.1"]
    assert document["allow_broad_networks"] is False

    kid = scope_signing.verify_document(document, scope_signing.load_jwks(jwks_path))
    assert kid == document["signature"]["kid"]


def test_demo_private_key_is_owner_only(tmp_path: Path) -> None:
    env = _prepare_demo_environment(tmp_path)
    key_path = tmp_path / "scope-signing-key.pem"
    assert key_path.is_file()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600
    assert env["ISHASTRA_SCOPE_JWKS"].endswith("jwks.json")
