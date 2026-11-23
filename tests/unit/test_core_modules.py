"""Unit tests for Ishastra core modules.

Tests cover: scope, jobs, findings, authz, crypto modules.
All tests are self-contained with no external dependencies.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from ishastra.core.authz import (
    AuthConfig,
    DifferentialResult,
    Principal,
    body_digest,
    candidate_endpoints,
    classify,
)
from ishastra.core.findings import (
    CONFIDENCES,
    SEVERITIES,
    VERIFICATIONS,
    Finding,
    dedupe,
    to_sarif,
    validate_transition,
)
from ishastra.core.jobs import (
    AdapterRun,
    Job,
    JobState,
    RunState,
    prepare,
)
from ishastra.crypto import EncryptionError, decrypt, encrypt, generate_key
from ishastra.security.authorization.scope import Scope, load


class TestScopeUnit:
    """Unit tests for scope loading and validation."""

    def create_scope_file(self, content: str) -> str:
        """Create a temporary scope file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            return f.name

    def test_load_valid_scope(self):
        """Test loading a valid scope document."""
        content = """{
  "program": "Test Program",
  "authorized_by": "Test Authorizer",
  "authorization_ref": "TEST-001",
  "include": ["example.com", "*.example.com"],
  "exclude": ["admin.example.com"],
  "authorized_networks": ["10.0.0.0/8", "172.16.0.0/12"],
  "allowed_ports": [80, 443, 8080],
  "allow_broad_networks": false
}"""
        path = self.create_scope_file(content)
        try:
            scope = load(path)
            assert isinstance(scope, Scope)
            assert scope.program == "Test Program"
            assert scope.authorized_by == "Test Authorizer"
            assert scope.authorization_ref == "TEST-001"
            assert scope.include == ("example.com", "*.example.com")
            assert scope.exclude == ("admin.example.com",)
            assert scope.authorized_networks == ("10.0.0.0/8", "172.16.0.0/12")
            assert scope.allowed_ports == (80, 443, 8080)
            assert scope.allow_broad_networks is False
        finally:
            Path(path).unlink()

    def test_load_minimal_scope(self):
        """Test loading minimal valid scope."""
        content = """{
  "program": "Minimal",
  "authorized_by": "Me",
  "authorization_ref": "REF-1",
  "include": ["example.com"],
  "exclude": [],
  "authorized_networks": [],
  "allowed_ports": [],
  "allow_broad_networks": false
}"""
        path = self.create_scope_file(content)
        try:
            scope = load(path)
            assert scope.program == "Minimal"
            assert scope.include == ("example.com",)
        finally:
            Path(path).unlink()

    def test_load_missing_program_raises(self):
        """Test missing program field raises error."""
        content = """{
  "authorized_by": "Me",
  "authorization_ref": "REF-1",
  "include": ["example.com"],
  "exclude": [],
  "authorized_networks": [],
  "allowed_ports": [],
  "allow_broad_networks": false
}"""
        path = self.create_scope_file(content)
        try:
            with pytest.raises(ValueError, match="program"):
                load(path)
        finally:
            Path(path).unlink()

    def test_load_empty_include_raises(self):
        """Test empty include list raises error."""
        content = """{
  "program": "Test",
  "authorized_by": "Me",
  "authorization_ref": "REF-1",
  "include": [],
  "exclude": [],
  "authorized_networks": [],
  "allowed_ports": [],
  "allow_broad_networks": false
}"""
        path = self.create_scope_file(content)
        try:
            with pytest.raises(ValueError, match="include"):
                load(path)
        finally:
            Path(path).unlink()

    def test_load_broad_network_rejected_by_default(self):
        """Test networks broader than /8 are rejected by default."""
        content = """{
  "program": "Test",
  "authorized_by": "Me",
  "authorization_ref": "REF-1",
  "include": ["example.com"],
  "exclude": [],
  "authorized_networks": ["0.0.0.0/0"],
  "allowed_ports": [],
  "allow_broad_networks": false
}"""
        path = self.create_scope_file(content)
        try:
            with pytest.raises(ValueError, match="covers more than a /8"):
                load(path)
        finally:
            Path(path).unlink()

    def test_load_broad_network_allowed_when_flag_true(self):
        """Test broad network allowed when flag is true."""
        content = """{
  "program": "Test",
  "authorized_by": "Me",
  "authorization_ref": "REF-1",
  "include": ["example.com"],
  "exclude": [],
  "authorized_networks": ["0.0.0.0/0"],
  "allowed_ports": [],
  "allow_broad_networks": true
}"""
        path = self.create_scope_file(content)
        try:
            scope = load(path)
            assert scope.authorized_networks == ("0.0.0.0/0",)
            assert scope.allow_broad_networks is True
        finally:
            Path(path).unlink()

    def test_check_host_match_exact(self, scope_file):
        """Test check function with exact host match."""
        scope = load(scope_file)
        denial, reason = scope.check("https://example.com/")
        assert denial == ""
        assert reason == ""

    def test_check_host_match_wildcard(self, scope_file):
        """Test check function with wildcard subdomain match."""
        scope = load(scope_file)
        denial, reason = scope.check("https://api.example.com/")
        assert denial == ""
        denial, reason = scope.check("https://www.example.com/")
        assert denial == ""

    def test_check_host_excluded(self, scope_file):
        """Test check function with excluded host."""
        scope = load(scope_file)
        denial, reason = scope.check("https://admin.example.com/")
        assert denial == "out_of_scope"

    def test_check_host_not_in_scope(self, scope_file):
        """Test check function with host not in scope."""
        scope = load(scope_file)
        denial, reason = scope.check("https://other.com/")
        assert denial == "out_of_scope"

    def test_check_port_restriction(self, scope_file):
        """Test check with port checking."""
        scope = load(scope_file)
        denial, reason = scope.check("https://example.com:443/")
        assert denial == ""
        denial, reason = scope.check("http://example.com:80/")
        assert denial == ""
        denial, reason = scope.check("https://example.com:8080/")
        assert denial == ""
        denial, reason = scope.check("https://example.com:8443/")
        assert denial == "out_of_scope"

    def test_check_no_port_restriction_allows_all(self, scope_file_no_auth):
        """Test check with empty allowed_ports allows all ports."""
        scope = load(scope_file_no_auth)
        denial, reason = scope.check("https://example.com:443/")
        assert denial == ""
        denial, reason = scope.check("https://example.com:8080/")
        assert denial == ""
        denial, reason = scope.check("https://example.com:9999/")
        assert denial == ""


class TestCryptoUnit:
    """Unit tests for AES-GCM encryption/decryption."""

    def test_generate_key_produces_valid_base64_32_bytes(self):
        """Test key generation produces valid base64 32-byte key."""
        key = generate_key()
        assert isinstance(key, str)
        import base64

        decoded = base64.b64decode(key)
        assert len(decoded) == 32

    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt/decrypt roundtrip works."""
        key = generate_key()
        plaintext = "secret-api-key-12345"
        encrypted = encrypt(plaintext, key)
        assert isinstance(encrypted, str)
        assert len(encrypted) > 0
        decrypted = decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_empty_string_encryption(self):
        """Test empty string encryption (28-byte edge case fix)."""
        key = generate_key()
        encrypted = encrypt("", key)
        assert encrypted == ""
        decrypted = decrypt(encrypted, key)
        assert decrypted == ""

    def test_encrypt_decrypt_special_chars(self):
        """Test encryption with special characters."""
        key = generate_key()
        plaintext = "p@$$w0rd!@#$%^&*()_+-=[]{}|;':\",./<>?"
        encrypted = encrypt(plaintext, key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_encrypt_decrypt_unicode(self):
        """Test encryption with unicode characters."""
        key = generate_key()
        plaintext = "सेवा पासवर्ड 🔐 パスワード"
        encrypted = encrypt(plaintext, key)
        decrypted = decrypt(encrypted, key)
        assert decrypted == plaintext

    def test_different_keys_fail(self):
        """Test that different keys cannot decrypt."""
        key1 = generate_key()
        key2 = generate_key()
        plaintext = "secret"
        encrypted = encrypt(plaintext, key1)
        with pytest.raises(EncryptionError, match="invalid key or corrupted data"):
            decrypt(encrypted, key2)

    def test_corrupted_ciphertext_fail(self):
        """Test that corrupted ciphertext fails."""
        key = generate_key()
        plaintext = "secret"
        encrypted = encrypt(plaintext, key)
        import base64

        decoded = base64.b64decode(encrypted)

        corrupted = decoded[:-1] + bytes([decoded[-1] ^ 0xFF])
        corrupted_b64 = base64.b64encode(corrupted).decode()
        with pytest.raises(EncryptionError, match="invalid key or corrupted data"):
            decrypt(corrupted_b64, key)

    def test_invalid_base64_key_raises(self):
        """Test invalid base64 key raises error."""
        with pytest.raises(EncryptionError, match="Invalid base64 key"):
            encrypt("test", "not-base64!")

    def test_wrong_key_length_raises(self):
        """Test wrong key length raises error."""
        import base64

        short_key = base64.b64encode(b"short").decode()
        with pytest.raises(EncryptionError, match="Key must be 32 bytes"):
            encrypt("test", short_key)

    def test_invalid_base64_ciphertext_raises(self):
        """Test invalid base64 ciphertext raises error."""
        key = generate_key()
        with pytest.raises(EncryptionError, match="Invalid base64 ciphertext"):
            decrypt("not-base64!", key)

    def test_ciphertext_too_short_raises(self):
        """Test too short ciphertext raises error (28-byte edge case)."""
        key = generate_key()
        import base64

        short_ciphertext = base64.b64encode(b"x" * 28).decode()
        with pytest.raises(EncryptionError, match="Ciphertext too short"):
            decrypt(short_ciphertext, key)


class TestFindingsUnit:
    """Unit tests for findings model, dedupe, SARIF, and state transitions."""

    def test_finding_creation_valid(self):
        """Test creating a valid Finding."""
        finding = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing Content-Security-Policy header",
            severity="low",
            confidence="medium",
            detector="ishastra-http",
            detector_version="1.0.0",
            evidence="HTTP 200 response carries no Content-Security-Policy header",
            location="https://example.com/",
            cwe="CWE-693",
            verification="observed",
        )
        assert finding.asset == "https://example.com/"
        assert finding.category == "missing_csp"
        assert finding.severity == "low"
        assert finding.confidence == "medium"
        assert finding.verification == "observed"

    def test_finding_invalid_severity_raises(self):
        """Test invalid severity raises ValueError."""
        with pytest.raises(ValueError, match="severity"):
            Finding(
                asset="https://example.com/",
                category="test",
                title="Test",
                severity="invalid",
                confidence="medium",
                detector="test",
                detector_version="1.0",
                evidence="test",
            )

    def test_finding_invalid_confidence_raises(self):
        """Test invalid confidence raises ValueError."""
        with pytest.raises(ValueError, match="confidence"):
            Finding(
                asset="https://example.com/",
                category="test",
                title="Test",
                severity="low",
                confidence="invalid",
                detector="test",
                detector_version="1.0",
                evidence="test",
            )

    def test_finding_invalid_verification_raises(self):
        """Test invalid verification raises ValueError."""
        with pytest.raises(ValueError, match="verification"):
            Finding(
                asset="https://example.com/",
                category="test",
                title="Test",
                severity="low",
                confidence="medium",
                detector="test",
                detector_version="1.0",
                evidence="test",
                verification="invalid",
            )

    def test_finding_fingerprint_stable(self):
        """Test fingerprint is stable for same asset/category/location."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="test",
            detector_version="1.0",
            evidence="evidence 1",
            location="https://example.com/",
        )
        f2 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP (different title)",
            severity="high",
            confidence="high",
            detector="test",
            detector_version="1.0",
            evidence="evidence 2",
            location="https://example.com/",
        )
        assert f1.fingerprint == f2.fingerprint

    def test_finding_fingerprint_different_for_different_location(self):
        """Test fingerprint differs for different location."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="test",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
        )
        f2 = Finding(
            asset="https://example.com/page",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="test",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/page",
        )
        assert f1.fingerprint != f2.fingerprint

    def test_finding_to_dict_includes_all_fields(self):
        """Test to_dict includes all fields."""
        finding = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="test",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
            cwe="CWE-693",
            verification="observed",
        )
        d = finding.to_dict()
        assert d["asset"] == "https://example.com/"
        assert d["category"] == "missing_csp"
        assert d["severity"] == "low"
        assert d["confidence"] == "medium"
        assert d["cwe"] == "CWE-693"
        assert d["fingerprint"] == finding.fingerprint

    def test_dedupe_merges_same_fingerprint_keeps_more_severe(self):
        """Test dedupe merges same fingerprint keeping more severe."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="test",
            detector_version="1.0",
            evidence="evidence 1",
            location="https://example.com/",
        )
        f2 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="high",
            confidence="high",
            detector="other",
            detector_version="1.0",
            evidence="evidence 2",
            location="https://example.com/",
        )
        merged = dedupe([f1, f2])
        assert len(merged) == 1
        assert merged[0].severity == "high"
        assert "test" in merged[0].sources
        assert "other" in merged[0].sources

    def test_dedupe_different_locations_not_merged(self):
        """Test dedupe does not merge different locations."""
        f1 = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="test",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
        )
        f2 = Finding(
            asset="https://example.com/page",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="test",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/page",
        )
        merged = dedupe([f1, f2])
        assert len(merged) == 2

    def test_to_sarif_generates_valid_structure(self):
        """Test SARIF generation produces valid structure."""
        finding = Finding(
            asset="https://example.com/",
            category="missing_csp",
            title="Missing CSP",
            severity="low",
            confidence="medium",
            detector="test",
            detector_version="1.0",
            evidence="evidence",
            location="https://example.com/",
            cwe="CWE-693",
            verification="observed",
        )
        sarif = to_sarif([finding])
        assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "ishastra"
        assert len(sarif["runs"][0]["results"]) == 1
        result = sarif["runs"][0]["results"][0]
        assert result["ruleId"] == "missing_csp"
        assert result["level"] == "note"
        assert "partialFingerprints" in result

    def test_validate_transition_valid(self):
        """Test validate_transition allows valid transitions."""
        validate_transition("new", "triaged")
        validate_transition("triaged", "in_progress")
        validate_transition("in_progress", "fix_verified")
        validate_transition("fix_verified", "closed")

    def test_validate_transition_invalid_raises(self):
        """Test validate_transition raises for invalid transitions."""
        with pytest.raises(ValueError, match="Invalid transition"):
            validate_transition("new", "closed")
        with pytest.raises(ValueError, match="Invalid transition"):
            validate_transition("closed", "new")
        with pytest.raises(ValueError, match="Invalid transition"):
            validate_transition("triaged", "new")


class TestAuthzUnit:
    """Unit tests for authorization diff logic."""

    def test_principal_creation_with_cookies(self):
        """Test Principal creation with cookies."""
        principal = Principal(
            id="test-user",
            cookies=(("sessionid", "abc123"),),
            headers=(("X-Custom", "value"),),
            bearer="token123",
        )
        assert principal.id == "test-user"
        assert dict(principal.cookies) == {"sessionid": "abc123"}
        assert dict(principal.headers) == {"X-Custom": "value"}
        assert principal.bearer == "token123"
        assert principal.has_credentials is True

    def test_principal_from_dict(self):
        """Test Principal.from_dict factory."""
        data = {
            "id": "test-user",
            "cookies": [{"name": "sessionid", "value": "abc123"}],
            "headers": {"X-Custom": "value"},
            "bearer": "token123",
        }
        principal = Principal.from_dict(data)
        assert principal.id == "test-user"
        assert dict(principal.cookies) == {"sessionid": "abc123"}
        assert dict(principal.headers) == {"X-Custom": "value"}
        assert principal.bearer == "token123"

    def test_principal_invalid_id_raises(self):
        """Test invalid principal id raises."""
        with pytest.raises(ValueError, match="principal id"):
            Principal(id="invalid id!")

    def test_auth_config_creation(self):
        """Test AuthConfig creation."""
        principal1 = Principal(id="user1", cookies=(("sessionid", "abc"),))
        principal2 = Principal(id="user2", cookies=(("sessionid", "def"),))
        config = AuthConfig(users=(principal1, principal2))
        assert config.ids == ("user1", "user2")

    def test_auth_config_duplicate_ids_raises(self):
        """Test duplicate principal ids raises."""
        principal1 = Principal(id="user1", cookies=(("sessionid", "abc"),))
        principal2 = Principal(id="user1", cookies=(("sessionid", "def"),))
        with pytest.raises(ValueError, match="principal ids must be unique"):
            AuthConfig(users=(principal1, principal2))

    def test_auth_config_no_credentials_raises(self):
        """Test principal without credentials raises."""
        principal = Principal(id="user1")
        with pytest.raises(ValueError, match="every principal needs at least one credential"):
            AuthConfig(users=(principal,))

    def test_candidate_endpoints_numeric_path(self):
        """Test candidate_endpoints finds numeric path segments."""
        urls = [
            "https://example.com/api/orders/1001",
            "https://example.com/api/users/42/profile",
            "https://example.com/dashboard",
        ]
        candidates = candidate_endpoints(urls)
        assert "https://example.com/api/orders/1001" in candidates
        assert "https://example.com/api/users/42/profile" in candidates
        assert "https://example.com/dashboard" not in candidates

    def test_candidate_endpoints_id_query_param(self):
        """Test candidate_endpoints finds id-shaped query params."""
        urls = [
            "https://example.com/api/order?id=123",
            "https://example.com/api/order?order_id=456",
            "https://example.com/search?q=test&page=1",
        ]
        candidates = candidate_endpoints(urls)
        assert "https://example.com/api/order?id=123" in candidates
        assert "https://example.com/api/order?order_id=456" in candidates
        assert "https://example.com/search?q=test&page=1" not in candidates

    def test_candidate_endpoints_excludes_non_object_params(self):
        """Test candidate_endpoints excludes pagination/search params."""
        urls = [
            "https://example.com/api/orders?page=1",
            "https://example.com/api/orders?limit=10&offset=0",
            "https://example.com/api/orders?sort=name&order=asc",
        ]
        candidates = candidate_endpoints(urls)
        assert len(candidates) == 0

    def test_candidate_endpoints_max_limit(self):
        """Test candidate_endpoints respects max_endpoints limit."""
        urls = [f"https://example.com/api/item/{i}" for i in range(20)]
        candidates = candidate_endpoints(urls, max_endpoints=5)
        assert len(candidates) == 5

    def test_body_digest_consistent(self):
        """Test body_digest produces consistent output."""
        body = "test response body"
        digest1 = body_digest(body)
        digest2 = body_digest(body)
        assert digest1 == digest2
        assert len(digest1) == 16

    def test_body_digest_different_bodies(self):
        """Test body_digest differs for different bodies."""
        assert body_digest("body1") != body_digest("body2")

    def test_classify_authorization_missing(self):
        """Test classify returns authorization_missing when anonymous matches."""
        diff = DifferentialResult(
            endpoint="https://example.com/api/order/123",
            responses=(
                ("user1", 200, "abc123"),
                ("anonymous", 200, "abc123"),
            ),
            anonymous_matches_first=True,
            principals_identical=False,
        )
        categories = classify(diff)
        assert "authorization_missing" in categories

    def test_classify_object_access_unscoped(self):
        """Test classify returns object_access_unscoped when principals identical."""
        diff = DifferentialResult(
            endpoint="https://example.com/api/order/123",
            responses=(
                ("user1", 200, "abc123"),
                ("user2", 200, "abc123"),
                ("anonymous", 401, ""),
            ),
            anonymous_matches_first=False,
            principals_identical=True,
        )
        categories = classify(diff)
        assert "object_access_unscoped" in categories

    def test_classify_both(self):
        """Test classify returns both when both conditions met."""
        diff = DifferentialResult(
            endpoint="https://example.com/api/order/123",
            responses=(
                ("user1", 200, "abc123"),
                ("user2", 200, "abc123"),
                ("anonymous", 200, "abc123"),
            ),
            anonymous_matches_first=True,
            principals_identical=True,
        )
        categories = classify(diff)
        assert "authorization_missing" in categories
        assert "object_access_unscoped" in categories


class TestJobsUnit:
    """Unit tests for job lifecycle and orchestration."""

    def test_job_creation_defaults(self):
        """Test Job creation with defaults."""
        job = Job(
            target="https://example.com/",
            profile="web",
            actor="analyst",
            policy={},
        )
        assert job.id.startswith("job_")
        assert job.target == "https://example.com/"
        assert job.profile == "web"
        assert job.actor == "analyst"
        assert job.state == JobState.QUEUED
        assert job.runs == []
        assert job.findings == []
        assert job.attempts == 0

    def test_job_coverage_counts_states(self):
        """Test coverage property counts run states."""
        job = Job(
            target="https://example.com/",
            profile="web",
            actor="analyst",
            policy={},
        )
        job.runs = [
            AdapterRun(adapter="a1", state=RunState.OK, findings=2),
            AdapterRun(adapter="a2", state=RunState.PARTIAL, findings=1),
            AdapterRun(adapter="a3", state=RunState.FAILED, detail="error"),
        ]
        coverage = job.coverage()
        assert coverage["total"] == 3
        assert coverage["ok"] == 1
        assert coverage["partial"] == 1
        assert coverage["failed"] == 1
        assert len(coverage["adapters"]) == 3

    def test_job_verdict_completed_no_findings(self):
        """Test verdict for completed job with no findings."""
        job = Job(
            target="https://example.com/",
            profile="web",
            actor="analyst",
            policy={},
            state=JobState.COMPLETED,
            runs=[AdapterRun(adapter="a1", state=RunState.OK, findings=0)],
        )
        assert job.verdict == "no findings (complete coverage)"

    def test_job_verdict_completed_with_findings(self):
        """Test verdict for completed job with findings."""
        from ishastra.core.findings import Finding

        job = Job(
            target="https://example.com/",
            profile="web",
            actor="analyst",
            policy={},
            state=JobState.COMPLETED,
            runs=[AdapterRun(adapter="a1", state=RunState.OK, findings=3)],
            findings=[
                Finding(
                    asset="https://example.com/",
                    category="test",
                    title="Test",
                    severity="low",
                    confidence="medium",
                    detector="test",
                    detector_version="1.0",
                    evidence="evidence",
                )
            ]
            * 3,
        )
        assert job.verdict == "3 finding(s)"

    def test_job_verdict_partial_no_findings(self):
        """Test verdict for partial job with no findings."""
        job = Job(
            target="https://example.com/",
            profile="web",
            actor="analyst",
            policy={},
            state=JobState.PARTIAL,
            runs=[AdapterRun(adapter="a1", state=RunState.PARTIAL, findings=0)],
        )
        assert job.verdict == "inconclusive: no findings (partial coverage)"

    def test_job_verdict_failed_no_usable_coverage(self):
        """Test verdict for failed job with no usable coverage."""
        job = Job(
            target="https://example.com/",
            profile="web",
            actor="analyst",
            policy={},
            state=JobState.FAILED,
            runs=[
                AdapterRun(adapter="a1", state=RunState.UNAVAILABLE, detail="not installed"),
                AdapterRun(adapter="a2", state=RunState.REJECTED, detail="not applicable"),
            ],
        )
        assert job.verdict == "no usable coverage"

    def test_job_verdict_cancelled(self):
        """Test verdict for cancelled job."""
        job = Job(
            target="https://example.com/",
            profile="web",
            actor="analyst",
            policy={},
            state=JobState.CANCELLED,
        )
        assert job.verdict == "cancelled; do not treat as clean"

    def test_job_is_clean_true(self):
        """Test is_clean returns True only for complete coverage with zero findings."""
        job = Job(
            target="https://example.com/",
            profile="web",
            actor="analyst",
            policy={},
            state=JobState.COMPLETED,
            runs=[AdapterRun(adapter="a1", state=RunState.OK, findings=0)],
            findings=[],
        )
        assert job.is_clean() is True

    def test_job_is_clean_false_findings(self):
        """Test is_clean returns False when findings exist."""
        from ishastra.core.findings import Finding

        job = Job(
            target="https://example.com/",
            profile="web",
            actor="analyst",
            policy={},
            state=JobState.COMPLETED,
            runs=[AdapterRun(adapter="a1", state=RunState.OK, findings=1)],
            findings=[
                Finding(
                    asset="https://example.com/",
                    category="test",
                    title="Test",
                    severity="low",
                    confidence="medium",
                    detector="test",
                    detector_version="1.0",
                    evidence="evidence",
                )
            ],
        )
        assert job.is_clean() is False

    def test_job_is_clean_false_partial(self):
        """Test is_clean returns False for partial coverage."""
        job = Job(
            target="https://example.com/",
            profile="web",
            actor="analyst",
            policy={},
            state=JobState.PARTIAL,
            runs=[AdapterRun(adapter="a1", state=RunState.PARTIAL, findings=0)],
            findings=[],
        )
        assert job.is_clean() is False

    def test_prepare_creates_job_with_policy(self, scope_file):
        """Test prepare creates job with scope-bound policy."""
        from ishastra.core import scope

        scope.load(scope_file)
        job = prepare(
            target="https://example.com/",
            profile="web",
            actor="analyst",
            policy={"custom": "value"},
            timeout=300.0,
        )
        assert job.target == "https://example.com/"
        assert job.profile == "web"
        assert job.policy["custom"] == "value"
        assert job.policy["timeout"] == 300.0
        assert "authorization_ref" in job.policy
        assert "policy_id" in job.policy
        assert job.scope_snapshot is not None

    def test_prepare_fails_without_scope(self):
        """Test prepare fails when no scope is configured."""
        from ishastra.security.authorization import scope as scope_module

        scope_module._active = None
        with pytest.raises(ValueError, match="no authorized scope configured"):
            prepare(
                target="https://example.com/",
                profile="web",
                actor="analyst",
                policy={},
            )


class TestConstants:
    """Test that constants are correctly defined."""

    def test_severities_order(self):
        """Test SEVERITIES tuple has correct order (most severe first)."""
        assert SEVERITIES == ("critical", "high", "medium", "low", "info")

    def test_confidences_order(self):
        """Test CONFIDENCES tuple has correct order."""
        assert CONFIDENCES == ("high", "medium", "low")

    def test_verifications_order(self):
        """Test VERIFICATIONS tuple has correct order."""
        assert VERIFICATIONS == ("observed", "inferred", "unverified")

    def test_run_states_exist(self):
        """Test all RunState values exist."""
        assert RunState.OK.value == "ok"
        assert RunState.PARTIAL.value == "partial"
        assert RunState.REJECTED.value == "rejected"
        assert RunState.UNAVAILABLE.value == "unavailable"
        assert RunState.FAILED.value == "failed"
        assert RunState.TIMEOUT.value == "timeout"
        assert RunState.CANCELLED.value == "cancelled"

    def test_job_states_exist(self):
        """Test all JobState values exist."""
        assert JobState.QUEUED.value == "queued"
        assert JobState.RUNNING.value == "running"
        assert JobState.COMPLETED.value == "completed"
        assert JobState.PARTIAL.value == "partial"
        assert JobState.FAILED.value == "failed"
        assert JobState.CANCELLED.value == "cancelled"
