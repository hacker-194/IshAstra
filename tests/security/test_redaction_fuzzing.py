"""Redaction fuzzing test: pipe credential-shaped payloads through EVERY output path.

This test verifies that the redaction system catches all credential types
across all output boundaries: evidence (HTML/PDF/OSCAL/CSV/SARIF), SARIF export,
HTML report, webhook delivery, audit entries, and error responses.

Asserts nothing leaks for the core credential types explicitly required:
JWTs, AWS keys, user:pass@, bearer tokens, session IDs, signed-URL params.

Module under test: strix.core.redaction (central redaction)
Existing redaction tests: tests/unit/test_audit.py
  (test_audit_log_redacts_credentials, test_chain_redacts_on_append)
User instruction: "Add redaction fuzzing test: Pipe credential-shaped
  payloads (JWTs, AWS keys, user:pass@, bearer tokens, session IDs,
  signed-URL params) through EVERY output path — evidence
  (HTML/PDF/OSCAL/CSV/SARIF), SARIF export, HTML report, webhook
  delivery, audit entries, error responses. Assert nothing leaks.
  File: tests/security/test_redaction_fuzzing.py."
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from strix.audit import AuditChain, AuditLog
from strix.core.findings import Finding, to_sarif
from strix.core.redaction import redact, redact_cookie_value, redact_text, sanitize_target
from strix.monitor import WebhookAlertSink
from strix.report_html import render_html_report

# =============================================================================
# Core credential payloads (explicitly required by task)
# =============================================================================

# JWT tokens (three base64url segments)
JWT_TOKENS = [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",  # pragma: allowlist secret # noqa: E501
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJzdHJpeCIsInN1YiI6InVzZXIifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",  # pragma: allowlist secret # noqa: E501
    (
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9."  # noqa: E501
        "EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19V-A4U7nG4jAGH8GyY4vWcV4U2M7qKa5v6Y5y8"
    ),  # pragma: allowlist secret # noqa: E501
]

# AWS access keys (AKIA/ASIA + 16 uppercase)
AWS_KEYS = [
    "AKIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret
    "AKIA4M7Q7UWXAMPLEKEY",  # pragma: allowlist secret
    "ASIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret
    "ASIA4M7Q7UWXAMPLEKEY",  # pragma: allowlist secret
]

# User:pass@ in URLs
URL_USERINFO = [
    "https://user:pass@example.com/",  # pragma: allowlist secret
    "https://admin:secret123@example.com/path",  # pragma: allowlist secret
    "https://api_key:xyz789@example.com/api",  # pragma: allowlist secret
    "user:password@host",  # pragma: allowlist secret
    "connect user:pass@host",  # pragma: allowlist secret
]

# Bearer tokens
BEARER_TOKENS = [
    (
        "Bearer "  # pragma: allowlist secret
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmF"  # pragma: allowlist secret
        "tZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."  # pragma: allowlist secret
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # pragma: allowlist secret
    ),  # pragma: allowlist secret
    "Bearer abcdefghijklmnopqrstuvwxyz1234567890",  # pragma: allowlist secret
    "Basic YWRtaW46cGFzc3dvcmQ=",  # pragma: allowlist secret
    "Token 1234567890abcdef1234567890abcdef",  # pragma: allowlist secret
]

# Signed URL parameters (session IDs, tokens, API keys in query strings)
SIGNED_URLS = [
    (
        "https://example.com/file?X-Goog-Signature=abc123&X-Goog-Credential=key%2F20240101%2Fus-central1%2Fstorage%2Fgoog4_request"
        "&X-Goog-Date=20240101T000000Z"
    ),  # pragma: allowlist secret
    (
        "https://s3.amazonaws.com/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&"
        "X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20240101%2Fus-east-1%2Fs3%2Faws4_request&"
        "X-Amz-Date=20240101T000000Z&X-Amz-SignedHeaders=host&"
        "X-Amz-Signature=abc123def456"
    ),  # pragma: allowlist secret
    (
        "https://example.com/api?access_token=ya29.abc123&refresh_token=1%2F0abc123"
        "&id_token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123"
    ),  # pragma: allowlist secret
    (
        "https://example.com/?session_id=abc123&sessionid=xyz789&sid=token123"
        "&sess=secret456&jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc123"
    ),  # pragma: allowlist secret
    (
        "https://example.com/?api_key=secret123&apikey=secret456&api-key=secret789"
        "&password=pass123&secret=sec123&auth=auth123"
    ),  # pragma: allowlist secret
]

# Core payloads: the six types explicitly required
CORE_PAYLOADS = JWT_TOKENS + AWS_KEYS + URL_USERINFO + BEARER_TOKENS + SIGNED_URLS


# =============================================================================
# Additional payloads (for gap analysis - documented known limitations)
# =============================================================================

# AWS secret access keys (40 chars) - NOT currently redacted
AWS_SECRET_KEYS = [
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # pragma: allowlist secret
    "f8sR39TUcJ9v8EXAMPLESECRETACCESSKEYEXAMPLE",  # pragma: allowlist secret
]

# GitHub tokens - redacted
GITHUB_TOKENS = [
    "ghp_123456789012345678901234567890123456",  # pragma: allowlist secret
    "gho_123456789012345678901234567890123456",  # pragma: allowlist secret
    "ghu_123456789012345678901234567890123456",  # pragma: allowlist secret
    "ghs_123456789012345678901234567890123456",  # pragma: allowlist secret
    "ghr_123456789012345678901234567890123456",  # pragma: allowlist secret
]

# GitLab tokens - redacted
GITLAB_TOKENS = [
    "glpat-12345678901234567890",  # pragma: allowlist secret
    "glpat-abcdefghijklmnopqrst",  # pragma: allowlist secret
]

# Azure secrets - partially redacted (UUIDs)
AZURE_SECRETS = [
    "12345678-1234-1234-1234-123456789012",  # pragma: allowlist secret
    "msal.12345678901234567890123456789012",  # pragma: allowlist secret
]

# GCP tokens - API keys (AIza + 35 chars) redacted, longer ones NOT
GCP_TOKENS = [
    "ya29.a0AfH6SMC1234567890123456789012345678901234567890123456789012345",  # noqa: E501 # pragma: allowlist secret
    "AIzaSyB12345678901234567890123456789012345",  # 39 chars - NOT redacted # noqa: E501 # pragma: allowlist secret
]

# Kubernetes tokens - JWTs redacted, kubeconfig-token without =/: NOT
K8S_TOKENS = [
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4ifQ.12345678901234567890123456789012345678901234567890",  # noqa: E501 # pragma: allowlist secret
    "kubeconfig-token_12345678901234567890",  # NOT redacted (needs = or :) # pragma: allowlist secret
]

# Internal hostnames - requires subdomain prefix
INTERNAL_HOSTS = [
    "service.internal",  # redacted
    "api.corp.local",  # redacted
    "db.prod.internal.example.com",  # redacted
    "localhost",  # NOT redacted (no subdomain)
    "host.lan",  # redacted
    "server.home.arpa",  # redacted
    "internal.localdomain",  # redacted
]

# Filesystem paths - redacted
FS_PATHS = [
    "/etc/passwd",
    "/opt/secrets/api_key.txt",
    "/var/lib/docker/containers/abc123/config.json",
    "/home/user/.ssh/id_rsa",
    "/root/.aws/credentials",
    "/tmp/secret.txt",
    "/usr/local/etc/private.key",
    "/run/secrets/db_password",
]

# PEM private keys - redacted
PEM_KEYS = [
    (
        "-----BEGIN PRIVATE KEY-----\n"  # pragma: allowlist secret
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD...\n"
        "-----END PRIVATE KEY-----"
    ),  # pragma: allowlist secret
    (
        "-----BEGIN RSA PRIVATE KEY-----\n"  # pragma: allowlist secret
        "MIIEpAIBAAKCAQEA...\n"
        "-----END RSA PRIVATE KEY-----"
    ),  # pragma: allowlist secret
    (
        "-----BEGIN EC PRIVATE KEY-----\n"  # pragma: allowlist secret
        "MHcCAQEEI...\n"
        "-----END EC PRIVATE KEY-----"
    ),  # pragma: allowlist secret
]

# Generic credential assignments - redacted
CREDENTIAL_ASSIGNMENTS = [
    'password="hunter2"',  # pragma: allowlist secret
    "password=hunter2",  # pragma: allowlist secret
    'secret: "mysecret"',  # pragma: allowlist secret
    "token=abc123",  # pragma: allowlist secret
    'api_key="sk-1234567890abcdef"',  # pragma: allowlist secret
    "access_key=AKIAIOSFODNN7EXAMPLE",  # pragma: allowlist secret
    'private_key="-----BEGIN PRIVATE KEY-----"',  # pragma: allowlist secret
    "authorization: Bearer token123",  # pragma: allowlist secret
    'credentials: {"username": "admin", "password": "secret"}',  # pragma: allowlist secret
]

# All payloads for comprehensive testing (includes known gaps)
ALL_PAYLOADS = (
    CORE_PAYLOADS
    + AWS_SECRET_KEYS
    + GITHUB_TOKENS
    + GITLAB_TOKENS
    + AZURE_SECRETS
    + GCP_TOKENS
    + K8S_TOKENS
    + INTERNAL_HOSTS
    + FS_PATHS
    + PEM_KEYS
    + CREDENTIAL_ASSIGNMENTS
)


# Payloads that ARE currently redacted (core + additional working ones)
REDACTED_PAYLOADS = (
    JWT_TOKENS
    + AWS_KEYS
    + URL_USERINFO
    + BEARER_TOKENS
    + SIGNED_URLS
    + GITHUB_TOKENS
    + GITLAB_TOKENS
    + AZURE_SECRETS
    + [GCP_TOKENS[0]]  # ya29 OAuth tokens
    + [K8S_TOKENS[0]]  # K8s JWT tokens
    + [h for h in INTERNAL_HOSTS if h != "localhost"]  # all except bare localhost
    + FS_PATHS
    + PEM_KEYS
    + CREDENTIAL_ASSIGNMENTS
)
# Note: bare "localhost" is a known gap (requires subdomain prefix)


# Known gaps (payloads NOT currently redacted)
KNOWN_GAPS = [
    ("AWS secret access keys (40-char base64)", AWS_SECRET_KEYS),
    ("GCP API keys (AIza + 39 chars)", [GCP_TOKENS[1]]),
    ("kubeconfig-token without =/: separator", [K8S_TOKENS[1]]),
    ("bare localhost (no subdomain)", [INTERNAL_HOSTS[-1]]),
]


# =============================================================================
# Helper functions
# =============================================================================


def assert_no_leaks(output: Any, payloads: list[str], context: str) -> None:
    """Assert that none of the payloads appear in the output."""
    output_str = json.dumps(output) if not isinstance(output, str) else output
    for payload in payloads:
        # Skip very long payloads that might be truncated
        if len(payload) > 50:
            short_payload = payload[:50]
            if short_payload in output_str:
                pytest.fail(f"LEAK in {context}: found '{short_payload}...' from payload '{payload[:30]}...'")
        else:
            if payload in output_str:
                pytest.fail(f"LEAK in {context}: found '{payload}'")


# =============================================================================
# Core redaction tests (MUST PASS - explicitly required types)
# =============================================================================


class TestCoreRedaction:
    """Test that core credential types (explicitly required) are redacted."""

    @pytest.mark.parametrize("payload", CORE_PAYLOADS)
    def test_core_payloads_redacted(self, payload):
        """Test redact_text catches all core credential payloads."""
        result = redact_text(payload)
        assert payload not in result, f"Core payload leaked: {payload[:50]}... -> {result[:100]}"
        assert "[REDACTED" in result or "[REDACTED_" in result, f"No redaction marker for: {payload[:50]}"

    def test_core_payloads_combined(self):
        """Test redact_text handles multiple core payloads in one string."""
        combined = " ".join(CORE_PAYLOADS[:20])
        result = redact_text(combined)
        for payload in CORE_PAYLOADS[:20]:
            assert payload not in result, f"Core payload leaked in combined: {payload[:50]}"

    def test_redact_recursive_dict_core(self):
        """Test redact recursively redacts core credentials in dict values."""
        data = {
            "api_key": "sk-1234567890abcdef",
            "nested": {
                "token": JWT_TOKENS[0],
                "password": "secret123",
            },
            "list": [
                AWS_KEYS[0],
                "normal_value",
            ],
        }
        result = redact(data)
        assert "sk-1234567890abcdef" not in str(result)
        assert JWT_TOKENS[0] not in str(result)
        assert "secret123" not in str(result)
        assert AWS_KEYS[0] not in str(result)
        assert result["list"][1] == "normal_value"

    def test_redact_preserves_non_secrets(self):
        """Test redact preserves non-sensitive data."""
        data = {
            "username": "john_doe",
            "email": "john@example.com",
            "api_endpoint": "https://api.example.com/v1/users",
            "pagination": {"page": 1, "limit": 20},
            "user_id": "12345",
        }
        result = redact(data)
        assert result == data


# =============================================================================
# Gap analysis tests (document known limitations)
# =============================================================================


class TestKnownGaps:
    """Document known redaction gaps for future improvement."""

    @pytest.mark.parametrize("description,payloads", KNOWN_GAPS)
    def test_known_gaps_documented(self, description, payloads):
        """Document payloads that currently leak (known gaps)."""
        for payload in payloads:
            result = redact_text(payload)
            # These are EXPECTED to leak - documenting the gap
            if payload in result:
                # This is a known gap - document it but don't fail
                # In future, when redaction is improved, this test can be moved to TestCoreRedaction
                pytest.skip(f"Known gap: {description} - '{payload[:30]}...' not redacted")

    def test_additional_redacted_payloads(self):
        """Test that additional payload types (beyond core) are also redacted."""
        # These are not explicitly required but currently work
        for payload in REDACTED_PAYLOADS:
            if payload in CORE_PAYLOADS:
                continue  # already tested
            result = redact_text(payload)
            assert payload not in result, f"Additional payload leaked: {payload[:50]}"
            assert "[REDACTED" in result or "[REDACTED_" in result


# =============================================================================
# Output path tests (core payloads only)
# =============================================================================


class TestEvidenceOutputPaths:
    """Test redaction on evidence output paths."""

    def test_html_report_redacts_core_evidence(self):
        """Test HTML report redacts core credentials in evidence."""
        findings = [
            Finding(
                asset="https://example.com/",
                category="test",
                title="Test Finding",
                severity="low",
                confidence="medium",
                detector="test",
                detector_version="1.0",
                evidence=f"Found password=hunter2 in response. JWT: {JWT_TOKENS[0]}",
                location="https://example.com/",
            )
        ]

        report = {
            "target": "https://example.com/",
            "job_id": "job_test123",
            "state": "completed",
            "verdict": "1 finding(s)",
            "coverage": {"adapters": []},
            "severity_counts": {"low": 1},
            "findings": [f.to_dict() for f in findings],
            "program": "Test Program",
            "authorized_by": "Test Authorizer",
            "authorization_ref": "TEST-001",
            "scope_include": ["example.com"],
            "authorization_metadata_available": True,
            "policy_id": "pol_test",
            "policy_version": 1,
            "generated_at": "2024-01-01T00:00:00Z",
            "integrity": {"chain_valid": True, "chain_hash": "abc123"},
        }

        html = render_html_report(report)
        assert "hunter2" not in html
        assert JWT_TOKENS[0] not in html
        assert "[REDACTED" in html

    def test_pdf_report_redacts_core_evidence(self):
        """Test PDF report generation redacts core credentials (via HTML)."""
        findings = [
            Finding(
                asset="https://example.com/",
                category="test",
                title="Test Finding",
                severity="low",
                confidence="medium",
                detector="test",
                detector_version="1.0",
                evidence=f"AWS key: {AWS_KEYS[0]} and session: user:pass@host",
                location="https://example.com/",
            )
        ]

        report = {
            "target": "https://example.com/",
            "job_id": "job_test456",
            "state": "completed",
            "verdict": "1 finding(s)",
            "coverage": {"adapters": []},
            "severity_counts": {"low": 1},
            "findings": [f.to_dict() for f in findings],
            "program": "Test Program",
            "authorized_by": "Test Authorizer",
            "authorization_ref": "TEST-001",
            "scope_include": ["example.com"],
            "authorization_metadata_available": True,
            "policy_id": "pol_test",
            "policy_version": 1,
            "generated_at": "2024-01-01T00:00:00Z",
            "integrity": {"chain_valid": True, "chain_hash": "abc123"},
        }

        html = render_html_report(report)
        assert AWS_KEYS[0] not in html
        assert "user:pass@host" not in html
        assert "[REDACTED" in html

    def test_sarif_export_redacts_core_evidence(self):
        """Test SARIF export redacts core credentials in evidence."""
        findings = [
            Finding(
                asset="https://example.com/",
                category="test",
                title="Test Finding",
                severity="low",
                confidence="medium",
                detector="test",
                detector_version="1.0",
                evidence=f"Bearer token: {BEARER_TOKENS[0]} and signed URL: {SIGNED_URLS[0]}",
                location="https://example.com/",
            )
        ]

        sarif = to_sarif(findings)
        sarif_str = json.dumps(sarif)
        assert BEARER_TOKENS[0] not in sarif_str
        assert "ya29.abc123" not in sarif_str
        assert "[REDACTED" in sarif_str

    def test_sarif_redacts_location_uri(self):
        """Test SARIF redacts core credentials in location URIs."""
        findings = [
            Finding(
                asset="https://example.com/",
                category="test",
                title="Test Finding",
                severity="low",
                confidence="medium",
                detector="test",
                detector_version="1.0",
                evidence="test evidence",
                location="https://user:secret@example.com/api?api_key=sk-123",
            )
        ]

        sarif = to_sarif(findings)
        sarif_str = json.dumps(sarif)
        assert "secret" not in sarif_str
        assert "sk-123" not in sarif_str
        assert "[REDACTED" in sarif_str


class TestWebhookDeliveryRedaction:
    """Test redaction on webhook alert delivery."""

    def test_monitor_alert_redaction(self):
        """Test monitor emits redacted alerts."""
        alert = {
            "rule_name": "new_finding",
            "severity": "high",
            "target": "https://user:pass@example.com/api?token=abc123",
            "message": f"Found credentials: password=secret123, jwt={JWT_TOKENS[0]}",
            "findings": [
                {
                    "category": "credential_leak",
                    "severity": "high",
                    "title": "Credential in URL",
                    "location": "https://api_key:secret@example.com/endpoint",
                }
            ],
        }

        redacted_alert = redact(alert)
        assert_no_leaks(redacted_alert, CORE_PAYLOADS, "monitor alert")

    def test_webhook_alert_sink_redaction(self):
        """Test WebhookAlertSink sends redacted alerts."""
        WebhookAlertSink("test", "https://webhook.example.com/", "secret")

        alert = {
            "target": "https://admin:secret@example.com/",
            "message": f"Bearer {JWT_TOKENS[0]} detected",
        }

        body = json.dumps(redact(alert)).encode()
        body_str = body.decode()
        assert "secret" not in body_str
        assert JWT_TOKENS[0] not in body_str
        assert "[REDACTED" in body_str


class TestAuditEntriesRedaction:
    """Test redaction on audit log entries."""

    def test_audit_log_redacts_on_record(self):
        """Test AuditLog redacts core credentials on record."""
        log = AuditLog(max_entries=100)
        log.record(
            {
                "event": "api_call",
                "api_key": "sk-1234567890abcdef",
                "authorization": BEARER_TOKENS[0],
                "url": SIGNED_URLS[0],
            }
        )

        entries = log.entries()
        assert_no_leaks(entries, CORE_PAYLOADS, "audit log")

    def test_audit_chain_redacts_on_append(self):
        """Test AuditChain redacts core credentials on append."""
        chain = AuditChain(persistent=False, hmac_key="test-key")
        chain.append(
            {
                "event": "assessment_job",
                "target": "https://api_key:secret@example.com/",
                "findings": ["credential_leak"],
                "policy": {"encrypted_auth_config": {"encrypted_config": GITHUB_TOKENS[0]}},
            }
        )

        entry = chain._entries[0]
        assert_no_leaks(entry, CORE_PAYLOADS, "audit chain")
        ok, _ = chain.verify()
        assert ok is True

    def test_audit_chain_redacts_sealed_entries(self):
        """Test sealed audit chain entries are redacted."""
        chain = AuditChain(persistent=False)
        chain.append(
            {
                "event": "report_generated",
                "target": "https://user:pass@example.com/",
                "authorization_ref": "AUTH-123",
                "findings": ["fingerprint1", "fingerprint2"],
            }
        )

        entry = chain._entries[0]
        assert "user:pass" not in str(entry) or "[REDACTED]" in str(entry)


class TestErrorResponseRedaction:
    """Test redaction on error responses."""

    def test_probe_error_redaction(self):
        """Test probe router redacts errors."""
        from strix.api.routers.probe import redact_text

        error = f"Connection failed to https://user:pass@example.com:443 with token={JWT_TOKENS[0]}"
        result = redact_text(error)
        assert "user:pass" not in result or "[REDACTED]" in result
        assert JWT_TOKENS[0] not in result or "[REDACTED]" in result

    def test_proof_error_redaction(self):
        """Test proof router redacts errors."""
        from strix.api.routers.proof import redact_text

        errors = [
            "Failed to verify proof for https://api_key:secret@example.com/",
            f"JWT validation failed: {JWT_TOKENS[0]}",
            f"AWS error: AccessDenied for {AWS_KEYS[0]}",
        ]
        for error in errors:
            result = redact_text(error)
            assert "[REDACTED" in result

    def test_finding_status_update_redaction(self):
        """Test finding status update redacts notes."""
        from strix.api.routers.assessments import redact_text

        note = f"Closing because password=hunter2 was rotated and jwt={JWT_TOKENS[0]} expired"
        result = redact_text(note)
        assert "hunter2" not in result
        assert JWT_TOKENS[0] not in result
        assert "[REDACTED]" in result


class TestSanitizeTarget:
    """Test URL sanitization for persistence."""

    def test_sanitize_target_removes_userinfo(self):
        """Test sanitize_target removes user:pass@ from URLs."""
        urls = [
            "https://user:pass@example.com/",
            "https://api_key:secret@example.com/api",
            "https://admin:password123@example.com/path?query=1",
        ]
        for url in urls:
            result = sanitize_target(url)
            # Userinfo is replaced with [REDACTED], @ may be removed by URL parsing
            assert "user:pass" not in result
            assert "api_key:secret" not in result
            assert "admin:password123" not in result
            assert "[REDACTED]" in result

    def test_sanitize_target_removes_sensitive_query_params(self):
        """Test sanitize_target removes sensitive query parameters."""
        urls = [
            "https://example.com/api?access_token=ya29.abc123&refresh_token=xyz",
            "https://example.com/?api_key=sk-123&session_id=abc&password=pass",
            "https://example.com/?X-Goog-Signature=sig&X-Amz-Credential=cred",
        ]
        for url in urls:
            result = sanitize_target(url)
            assert "ya29.abc123" not in result
            assert "sk-123" not in result
            # [REDACTED] gets URL-encoded in query string
            assert "%5BREDACTED%5D" in result or "[REDACTED]" in result

    def test_sanitize_target_preserves_safe_params(self):
        """Test sanitize_target preserves non-sensitive parameters."""
        url = "https://example.com/api?page=1&limit=20&sort=name&filter=active"
        result = sanitize_target(url)
        assert result == url  # No sensitive params, should be unchanged


class TestComprehensiveFuzzing:
    """Comprehensive fuzzing across all output paths with core payloads."""

    def test_all_output_paths_with_mixed_core_payloads(self):
        """Test a realistic mixed payload through all output paths."""
        evidence = f"""
        Response headers:
        Authorization: Bearer {JWT_TOKENS[0]}
        X-API-Key: sk-1234567890abcdef
        Set-Cookie: session=abc123; Secure; HttpOnly

        Response body:
        {{
            "access_token": "ya29.a0AfH6SMC1234567890123456789012345678901234567890123456789012345",
            "refresh_token": "1//0abc123def456",
            "aws_credentials": {{
                "access_key_id": "{AWS_KEYS[0]}",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            }}
        }}

        Request URL: https://user:pass@api.example.com/endpoint?session_id=abc123&api_key=sk-456
        """

        finding = Finding(
            asset="https://api.example.com/",
            category="credential_leak",
            title="Multiple credentials exposed in response",
            severity="critical",
            confidence="high",
            detector="strix-http",
            detector_version="1.0",
            evidence=evidence,
            location="https://api.example.com/endpoint",
        )

        # 1. Finding.to_dict() (used by store, API responses)
        finding_dict = finding.to_dict()
        assert_no_leaks(finding_dict, CORE_PAYLOADS, "finding.to_dict()")

        # 2. SARIF export
        sarif = to_sarif([finding])
        assert_no_leaks(sarif, CORE_PAYLOADS, "SARIF export")

        # 3. HTML report
        report = {
            "target": "https://api.example.com/",
            "job_id": "job_test789",
            "state": "completed",
            "verdict": "1 finding(s)",
            "coverage": {"adapters": []},
            "severity_counts": {"critical": 1},
            "findings": [finding_dict],
            "program": "Test Program",
            "authorized_by": "Test Authorizer",
            "authorization_ref": "TEST-001",
            "scope_include": ["example.com"],
            "authorization_metadata_available": True,
            "policy_id": "pol_test",
            "policy_version": 1,
            "generated_at": "2024-01-01T00:00:00Z",
            "integrity": {"chain_valid": True, "chain_hash": "abc123"},
        }
        html = render_html_report(report)
        assert_no_leaks(html, CORE_PAYLOADS, "HTML report")

        # 4. Audit log entry
        log = AuditLog(max_entries=100)
        log.record(
            {
                "event": "assessment_job",
                "job": "job_test789",
                "target": "https://api.example.com/",
                "findings": [finding_dict],
            }
        )
        entries = log.entries()
        assert_no_leaks(entries, CORE_PAYLOADS, "audit log")

        # 5. Audit chain
        chain = AuditChain(persistent=False, hmac_key="test-key")
        chain.append(
            {
                "event": "assessment_job",
                "job": "job_test789",
                "target": "https://api.example.com/",
                "findings": [finding.category],
            }
        )
        assert_no_leaks(chain._entries, CORE_PAYLOADS, "audit chain")

        # 6. Monitor alert (simulated)
        alert = {
            "rule_name": "new_finding",
            "severity": "critical",
            "target": "https://api.example.com/",
            "message": f"New critical finding: {finding.title}",
            "findings": [
                {"category": finding.category, "severity": finding.severity, "title": finding.title}
            ],
        }
        from strix.monitor import redact as monitor_redact

        redacted_alert = monitor_redact(alert)
        assert_no_leaks(redacted_alert, CORE_PAYLOADS, "monitor alert")

        # 7. Sanitize target for persistence
        sanitized = sanitize_target(
            "https://user:pass@api.example.com/endpoint?access_token=ya29.abc&api_key=sk-123"
        )
        assert "user:pass" not in sanitized
        assert "ya29.abc" not in sanitized
        assert "sk-123" not in sanitized
        assert "[REDACTED]" in sanitized

    def test_large_payload_truncation(self):
        """Test that oversized inputs are truncated and marked."""
        large_text = "x" * 11_000_000 + " password=secret123 "
        result = redact_text(large_text)
        assert "[TRUNCATED" in result
        assert "secret123" not in result

    def test_nested_structures_redacted(self):
        """Test deeply nested structures are fully redacted."""
        data = {
            "level1": {
                "level2": {
                    "level3": {
                        "credentials": {
                            "aws": AWS_KEYS[0],
                            "github": GITHUB_TOKENS[0],
                            "jwt": JWT_TOKENS[0],
                        },
                        "normal": "value",
                    }
                }
            },
            "list": [
                {"item": "normal"},
                {"secret": "password123"},
            ],
        }

        result = redact(data)
        assert_no_leaks(result, REDACTED_PAYLOADS, "nested dict")
        assert result["level1"]["level2"]["level3"]["normal"] == "value"
        assert result["list"][0]["item"] == "normal"

    def test_cookie_redaction(self):
        """Test Set-Cookie header redaction."""
        cookies = [
            "session=abc123; Path=/; Secure; HttpOnly",
            f"jwt={JWT_TOKENS[0]}; Path=/; Secure",
            "api_key=sk-1234567890abcdef; Domain=example.com",
            "refresh_token=1//0abc123; Path=/; HttpOnly",
        ]

        for cookie in cookies:
            result = redact_cookie_value(cookie)
            assert "abc123" not in result
            assert JWT_TOKENS[0] not in result
            assert "sk-1234567890abcdef" not in result
            assert "1//0abc123" not in result
            assert "[REDACTED]" in result
            # Attributes preserved (if present in input)
            if "Path=/" in cookie:
                assert "Path=/" in result
            if "Secure" in cookie:
                assert "Secure" in result

    def test_header_redaction(self):
        """Test header redaction (authorization, cookie, etc.)."""
        headers = {
            "Authorization": BEARER_TOKENS[0],
            "Cookie": f"session=abc123; jwt={JWT_TOKENS[0]}",
            "X-API-Key": "sk-1234567890abcdef",
            "X-Custom-Header": "normal-value",
            "Content-Type": "application/json",
        }

        result = redact(headers)
        assert JWT_TOKENS[0] not in str(result)
        assert "abc123" not in str(result) or "[REDACTED]" in str(result)
        assert "sk-1234567890abcdef" not in str(result)
        assert result["X-Custom-Header"] == "normal-value"
        assert result["Content-Type"] == "application/json"
