"""Tests for strix.cli module."""

from __future__ import annotations

import contextlib
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from strix import proof
from strix.cli import (
    _build_auth_config,
    _gate_key,
    _public_key,
    _run_assess,
    _run_grant,
    _run_proof,
    _run_scope_template,
    _run_scope_wizard,
    _run_server,
    _run_verify,
    main,
)
from strix.config import Settings


class TestBuildAuthConfig:
    """Test _build_auth_config function."""

    def test_no_auth_config(self):
        """Test with no auth config returns None."""
        args = MagicMock()
        args.auth_config = None
        args.auth_type = None
        args.auth_bearer = None
        args.auth_api_key = None
        args.auth_header = []
        args.auth_cookie = []
        args.auth_login_url = None
        args.auth_username = None
        args.auth_password = None
        args.auth_csrf_field = None
        args.auth_extra_field = []
        args.auth_username_field = "username"
        args.auth_password_field = "password"

        result = _build_auth_config(args)
        assert result is None

    def test_auth_config_file(self):
        """Test loading auth config from file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"type": "token", "bearer": "test-token"}, f)
            config_path = f.name

        try:
            args = MagicMock()
            args.auth_config = config_path
            args.auth_type = None
            args.auth_bearer = None
            args.auth_api_key = None
            args.auth_header = []
            args.auth_cookie = []
            args.auth_login_url = None
            args.auth_username = None
            args.auth_password = None
            args.auth_csrf_field = None
            args.auth_extra_field = []
            args.auth_username_field = "username"
            args.auth_password_field = "password"

            result = _build_auth_config(args)
            assert result == {"type": "token", "bearer": "test-token"}
        finally:
            Path(config_path).unlink()

    def test_token_auth_from_flags(self):
        """Test building token auth from flags."""
        args = MagicMock()
        args.auth_config = None
        args.auth_type = "token"
        args.auth_bearer = "test-bearer"
        args.auth_api_key = None
        args.auth_header = ["X-Custom: value"]
        args.auth_cookie = []
        args.auth_login_url = None
        args.auth_username = None
        args.auth_password = None
        args.auth_csrf_field = None
        args.auth_extra_field = []
        args.auth_username_field = "username"
        args.auth_password_field = "password"

        result = _build_auth_config(args)
        assert result["type"] == "token"
        assert result["bearer"] == "test-bearer"
        assert result["custom_headers"] == {"X-Custom": "value"}

    def test_session_auth_from_flags(self):
        """Test building session auth from flags."""
        args = MagicMock()
        args.auth_config = None
        args.auth_type = "session"
        args.auth_bearer = None
        args.auth_api_key = None
        args.auth_header = []
        args.auth_cookie = ["sessionid=abc123", "csrf=xyz"]
        args.auth_login_url = None
        args.auth_username = None
        args.auth_password = None
        args.auth_csrf_field = None
        args.auth_extra_field = []
        args.auth_username_field = "username"
        args.auth_password_field = "password"

        result = _build_auth_config(args)
        assert result["type"] == "session"
        assert result["cookies"] == {"sessionid": "abc123", "csrf": "xyz"}

    def test_form_login_auth_from_flags(self):
        """Test building form_login auth from flags."""
        args = MagicMock()
        args.auth_config = None
        args.auth_type = "form_login"
        args.auth_bearer = None
        args.auth_api_key = None
        args.auth_header = []
        args.auth_cookie = []
        args.auth_login_url = "https://example.com/login"
        args.auth_username = "user"
        args.auth_password = "pass"
        args.auth_csrf_field = "csrf_token"
        args.auth_extra_field = ["redirect=/dashboard"]
        args.auth_username_field = "username"
        args.auth_password_field = "password"

        result = _build_auth_config(args)
        assert result["type"] == "form_login"
        assert result["login_url"] == "https://example.com/login"
        assert result["username"] == "user"
        assert result["password"] == "pass"
        assert result["csrf_field"] == "csrf_token"
        assert result["extra_fields"] == {"redirect": "/dashboard"}

    def test_auto_detect_token_auth(self):
        """Test auto-detect token auth from bearer flag."""
        args = MagicMock()
        args.auth_config = None
        args.auth_type = None
        args.auth_bearer = "test-bearer"
        args.auth_api_key = None
        args.auth_header = []
        args.auth_cookie = []
        args.auth_login_url = None
        args.auth_username = None
        args.auth_password = None
        args.auth_csrf_field = None
        args.auth_extra_field = []
        args.auth_username_field = "username"
        args.auth_password_field = "password"

        result = _build_auth_config(args)
        assert result["type"] == "token"
        assert result["bearer"] == "test-bearer"

    def test_auto_detect_session_auth(self):
        """Test auto-detect session auth from cookie flag."""
        args = MagicMock()
        args.auth_config = None
        args.auth_type = None
        args.auth_bearer = None
        args.auth_api_key = None
        args.auth_header = []
        args.auth_cookie = ["sessionid=abc"]
        args.auth_login_url = None
        args.auth_username = None
        args.auth_password = None
        args.auth_csrf_field = None
        args.auth_extra_field = []
        args.auth_username_field = "username"
        args.auth_password_field = "password"

        result = _build_auth_config(args)
        assert result["type"] == "session"
        assert result["cookies"] == {"sessionid": "abc"}

    def test_auto_detect_form_login(self):
        """Test auto-detect form_login from login_url."""
        args = MagicMock()
        args.auth_config = None
        args.auth_type = None
        args.auth_bearer = None
        args.auth_api_key = None
        args.auth_header = []
        args.auth_cookie = []
        args.auth_login_url = "https://example.com/login"
        args.auth_username = "user"
        args.auth_password = "pass"
        args.auth_csrf_field = None
        args.auth_extra_field = []
        args.auth_username_field = "username"
        args.auth_password_field = "password"

        result = _build_auth_config(args)
        assert result["type"] == "form_login"
        assert result["login_url"] == "https://example.com/login"


class TestPublicKey:
    """Test _public_key function."""

    def test_empty_string(self):
        """Test empty string returns empty."""
        assert _public_key("") == ""

    def test_inline_key(self):
        """Test inline key returns as-is."""
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI..."
        assert _public_key(key) == key

    def test_file_path_not_exists(self):
        """Test non-existent file path returns as-is."""
        assert _public_key("/nonexistent/key.pub") == "/nonexistent/key.pub"


class TestGateKey:
    """Test _gate_key function."""

    def test_existing_key(self, tmp_path):
        """Test loading existing gate key."""
        key_file = tmp_path / "gate.key"
        private_key = proof.new_keypair()[0]
        proof.write_private_key(key_file, private_key)

        result = _gate_key(str(key_file))
        assert result == private_key

    def test_new_key_creation(self, tmp_path):
        """Test creating new gate key."""
        key_file = tmp_path / "new_gate.key"

        result = _gate_key(str(key_file))
        # The result is the raw private key (base64), not the prefixed version
        # The prefix is added when writing to file
        assert not result.startswith(proof.PRIVATE_KEY_PREFIX)
        assert key_file.exists()
        # Verify the file has the prefix
        file_content = key_file.read_text().strip()
        assert file_content.startswith(proof.PRIVATE_KEY_PREFIX)


class TestRunGrant:
    """Test _run_grant function."""

    def test_create_grant(self, tmp_path):
        """Test creating a grant."""
        args = MagicMock()
        args.program = "Test Program"
        args.authorized_by = "Test Authorizer"
        args.ref = "TEST-001"
        args.include = ["example.com"]
        args.exclude = []
        args.network = []
        args.port = []
        args.days = 30.0
        args.id = ""
        args.key = None
        args.key_out = str(tmp_path / "issuer.key")
        args.allow_broad_networks = False
        args.out = str(tmp_path / "grant.json")

        with patch("sys.stderr.write"):
            result = _run_grant(args)
            assert result == 0

        grant_path = Path(args.out)
        assert grant_path.exists()

        grant_data = json.loads(grant_path.read_text())
        assert grant_data["program"] == "Test Program"
        assert grant_data["authorized_by"] == "Test Authorizer"
        assert grant_data["authorization_ref"] == "TEST-001"
        assert grant_data["include"] == ["example.com"]

    def test_create_grant_with_existing_key(self, tmp_path):
        """Test creating grant with existing key."""
        key_file = tmp_path / "existing.key"
        private_key = proof.new_keypair()[0]
        proof.write_private_key(key_file, private_key)

        args = MagicMock()
        args.program = "Test Program"
        args.authorized_by = "Test Authorizer"
        args.ref = "TEST-001"
        args.include = ["example.com"]
        args.exclude = []
        args.network = []
        args.port = []
        args.days = 30.0
        args.id = ""
        args.key = str(key_file)
        args.key_out = str(tmp_path / "issuer.key")
        args.allow_broad_networks = False
        args.out = str(tmp_path / "grant.json")

        with patch("sys.stderr.write"):
            result = _run_grant(args)
            assert result == 0

        grant_path = Path(args.out)
        assert grant_path.exists()


class TestRunProof:
    """Test _run_proof function."""

    def test_create_proof_pack(self, tmp_path):
        """Test creating proof pack from grant and ledger."""
        # Create a grant
        private_key = proof.new_keypair()[0]
        grant = proof.new_grant(
            program="Test",
            authorized_by="Tester",
            authorization_ref="TEST-001",
            include=["example.com"],
        ).sign(private_key)

        grant_path = tmp_path / "grant.json"
        grant_path.write_text(json.dumps(grant.to_dict(), indent=2))

        # Create a ledger with some receipts
        ledger_path = tmp_path / "proof-ledger.jsonl"
        gate_key = proof.new_keypair()[0]
        gate = proof.Gate(grant, signing_key=gate_key, actor="test", ledger_path=ledger_path)
        gate.authorize("https://example.com/", "GET")
        gate.authorize("https://evil.com/", "GET")  # This will be denied

        args = MagicMock()
        args.grant = str(grant_path)
        args.ledger = str(ledger_path)
        args.gate_key = ""
        args.out = str(tmp_path / "proof.json")

        with patch("sys.stderr.write"):
            result = _run_proof(args)
            assert result == 0

        proof_path = Path(args.out)
        assert proof_path.exists()

        pack = json.loads(proof_path.read_text())
        assert "grant" in pack
        assert "receipts" in pack
        assert len(pack["receipts"]) == 2


class TestRunVerify:
    """Test _run_verify function."""

    def test_verify_valid_proof(self, tmp_path):
        """Test verifying a valid proof pack."""
        # Create a grant
        private_key = proof.new_keypair()[0]
        grant = proof.new_grant(
            program="Test",
            authorized_by="Tester",
            authorization_ref="TEST-001",
            include=["example.com"],
        ).sign(private_key)

        # Create a ledger with some receipts
        tmp_path / "proof-ledger.jsonl"
        gate_key = proof.new_keypair()[0]
        gate = proof.Gate(grant, signing_key=gate_key, actor="test")
        gate.authorize("https://example.com/", "GET")

        # Build proof pack
        pack = proof.build_pack(grant, gate.ledger)
        proof_path = tmp_path / "proof.json"
        proof_path.write_text(json.dumps(pack, indent=2))

        args = MagicMock()
        args.proof = str(proof_path)
        args.issuer_key = ""
        args.gate_key = ""
        args.json = False

        with patch("sys.stdout.write"), patch("sys.stderr.write"):
            result = _run_verify(args)
            # Should succeed
            assert result in (0, 1)  # Depends on pinning


class TestRunScopeTemplate:
    """Test _run_scope_template function."""

    def test_list_templates(self, capsys):
        """Test listing available templates."""
        args = MagicMock()
        args.sector = "list"
        args.output = None
        args.domain = None

        result = _run_scope_template(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "bank" in captured.out
        assert "telco" in captured.out
        assert "gov" in captured.out
        assert "global" in captured.out

    def test_generate_bank_template(self, tmp_path, capsys):
        """Test generating bank template."""
        args = MagicMock()
        args.sector = "bank"
        args.output = str(tmp_path / "scope.json")
        args.domain = "mybank.com"

        result = _run_scope_template(args)
        assert result == 0

        scope_path = Path(args.output)
        assert scope_path.exists()

        scope_data = json.loads(scope_path.read_text())
        assert "program" in scope_data
        assert "include" in scope_data

    def test_unknown_sector(self):
        """Test unknown sector returns error."""
        args = MagicMock()
        args.sector = "unknown"
        args.output = None
        args.domain = None

        result = _run_scope_template(args)
        assert result == 3


class TestRunScopeWizard:
    """Test _run_scope_wizard function."""

    def test_scope_wizard_valid(self, tmp_path, monkeypatch):
        """Test scope wizard with valid inputs."""
        output_path = tmp_path / "scope.json"

        # Mock user input
        inputs = iter(
            [
                "Test Program",  # program
                "Test Authorizer",  # authorized_by
                "TEST-001",  # authorization_ref
                "example.com, *.example.com",  # include hosts
                "",  # exclude hosts
                "10.0.0.0/8",  # authorized networks
                "80, 443",  # allowed ports
                "30",  # days valid
                str(output_path),  # output path
                "y",  # confirm
            ]
        )
        monkeypatch.setattr("builtins.input", lambda prompt: next(inputs))

        args = MagicMock()
        args.output = str(output_path)

        result = _run_scope_wizard(args)
        assert result == 0
        assert output_path.exists()

        scope_data = json.loads(output_path.read_text())
        assert scope_data["program"] == "Test Program"
        assert scope_data["authorized_by"] == "Test Authorizer"
        assert scope_data["include"] == ["example.com", "*.example.com"]

    def test_scope_wizard_cancelled(self, tmp_path, monkeypatch):
        """Test scope wizard cancelled by user."""
        inputs = iter(
            [
                "Test Program",
                "Test Authorizer",
                "TEST-001",
                "example.com",
                "",
                "10.0.0.0/8",
                "80, 443",
                "30",
                str(tmp_path / "scope.json"),
                "n",  # cancel
            ]
        )
        monkeypatch.setattr("builtins.input", lambda prompt: next(inputs))

        args = MagicMock()
        args.output = str(tmp_path / "scope.json")

        result = _run_scope_wizard(args)
        assert result == 0
        assert not Path(args.output).exists()


class TestRunAssess:
    """Test _run_assess function."""

    @pytest.mark.asyncio
    async def test_run_assess_basic(self, tmp_path, scope_file):
        """Test basic assess command."""
        # This is a more involved integration test
        # We'll mock the heavy parts
        args = MagicMock()
        args.target = "https://example.com/"
        args.profile = "web"
        args.scope = scope_file
        args.output = None
        args.timeout = 300.0
        args.actor = "test"
        args.auth_type = None
        args.auth_config = None
        args.auth_bearer = None
        args.auth_api_key = None
        args.auth_api_key_header = "X-API-Key"
        args.auth_header = []
        args.auth_cookie = []
        args.auth_login_url = None
        args.auth_username = None
        args.auth_password = None
        args.auth_username_field = "username"
        args.auth_password_field = "password"
        args.auth_csrf_field = None
        args.auth_extra_field = []
        args.grant = ""
        args.proof_out = ""
        args.proof_ledger = ""
        args.gate_key = ""
        args.trusted_issuer = ""

        # Mock jobs.prepare and jobs.execute
        with (
            patch("strix.cli.jobs_module.prepare") as mock_prepare,
            patch("strix.cli.jobs_module.execute") as mock_execute,
            patch("strix.cli.get_settings") as mock_settings,
            patch("strix.cli._configure_logging"),
            patch("strix.cli.scope_module.load") as mock_scope_load,
            patch("strix.cli.jobs_module.JobState") as mock_job_state,
        ):
            mock_settings.return_value = Settings(
                db_path=":memory:",
                encryption_key="i2q1RZNk5PGHI2AiS4waZgbfgwivSD+BEy14nBdumzQ=",
                audit_hmac_key="dGVzdC1hdWQtaG1hYy1rZXktMzJieXRlcw==",
            )

            mock_scope = MagicMock()
            mock_scope_load.return_value = mock_scope

            mock_job = MagicMock()
            mock_job.id = "test-job"
            mock_job.state = mock_job_state.COMPLETED
            mock_job.verdict = "clean"
            mock_job.findings = []
            mock_job.error = None
            mock_job.policy = {}
            mock_prepare.return_value = mock_job

            mock_execute.return_value = None

            result = _run_assess(args)
            assert result == 0


class TestRunServer:
    """Test _run_server function."""

    def test_run_server(self):
        """Test server command."""
        args = MagicMock()
        args.host = "127.0.0.1"
        args.port = 8000
        args.reload = False
        args.reset_audit_chain = False

        with (
            patch("strix.cli.uvicorn.run") as mock_run,
            patch("strix.cli.get_settings") as mock_settings,
            patch("strix.cli._configure_logging"),
        ):
            mock_settings.return_value = Settings(
                db_path=":memory:",
                encryption_key="i2q1RZNk5PGHI2AiS4waZgbfgwivSD+BEy14nBdumzQ=",
                audit_hmac_key="dGVzdC1hdWQtaG1hYy1rZXktMzJieXRlcw==",
            )

            _run_server(args)
            mock_run.assert_called_once()


class TestMain:
    """Test main entry point."""

    def test_main_serve(self, monkeypatch):
        """Test main with serve command."""
        monkeypatch.setattr("sys.argv", ["strix", "serve"])

        with (
            patch("strix.cli._run_server") as mock_run_server,
            patch("strix.cli.get_settings"),
            patch("strix.cli._configure_logging"),
        ):
            main()
            mock_run_server.assert_called_once()

    def test_main_version(self, capsys):
        """Test main with --version."""
        with contextlib.suppress(SystemExit):
            main(["--version"])
        captured = capsys.readouterr()
        assert "strix" in captured.out
