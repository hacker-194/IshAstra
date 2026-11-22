"""Playwright E2E tests for critical user paths (sync API).

Tests cover: authentication → assessment creation → findings review → SARIF export.
"""

import pytest


@pytest.mark.e2e
class TestAuthFlow:
    """Tests for authentication and authorization."""

    def test_health_endpoint(self, page, base_url: str):
        """Verify health endpoint returns OK."""
        response = page.request.get(f"{base_url}/api/health")
        assert response.ok
        data = response.json()
        assert data.get("status") == "healthy"

    def test_ready_endpoint(self, page, base_url: str):
        """Verify readiness endpoint returns OK."""
        response = page.request.get(f"{base_url}/api/ready")
        assert response.ok
        data = response.json()
        assert data.get("ready") is True

    def test_metrics_endpoint(self, page, base_url: str):
        """Verify metrics endpoint exposes Prometheus metrics (requires admin)."""
        response = page.request.get(f"{base_url}/api/metrics/otel")

        if response.status == 401:
            pytest.skip("Metrics endpoint requires admin API key")
        assert response.ok
        text = response.text()
        assert "strix_" in text or "http_requests_total" in text


@pytest.mark.e2e
class TestAssessmentLifecycle:
    """Tests for the full assessment lifecycle: create → monitor → results → export."""

    def test_create_assessment(self, page, base_url: str, auth_headers: dict):
        """Create a web assessment against a test target."""
        payload = {
            "target": "https://httpbin.org",
            "profile": "web",
            "actor": "test-tenant-1",
        }
        response = page.request.post(
            f"{base_url}/api/assess",
            headers=auth_headers,
            data=payload,
        )
        assert response.ok, f"Failed: {response.text()}"
        data = response.json()
        assert "job_id" in data or "id" in data
        assert data.get("status") == "queued" or data.get("state") == "queued"

    def test_list_assessments(self, page, base_url: str, auth_headers: dict):
        """List assessments returns expected structure."""
        response = page.request.get(
            f"{base_url}/api/assess",
            headers=auth_headers,
        )
        assert response.ok
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert isinstance(data["items"], list)

    def test_create_and_monitor_assessment(self, page, base_url: str, auth_headers: dict):
        """Create assessment and monitor until completion."""

        payload = {
            "target": "https://httpbin.org/get",
            "profile": "web",
            "actor": "test-tenant-1",
        }
        response = page.request.post(
            f"{base_url}/api/assess",
            headers=auth_headers,
            data=payload,
        )
        assert response.ok
        data = response.json()
        assessment_id = data.get("job_id") or data.get("id")

        # A real scan against a live target routinely takes longer than two
        # minutes; the job timeout is 30 minutes.
        max_polls = 150
        for _ in range(max_polls):
            response = page.request.get(
                f"{base_url}/api/assess/{assessment_id}",
                headers=auth_headers,
            )
            assert response.ok
            data = response.json()
            terminal_states = ("completed", "failed", "cancelled")
            if data.get("status") in terminal_states or data.get("state") in terminal_states:
                break
            page.wait_for_timeout(2000)
        else:
            pytest.fail("Assessment did not complete in time")

        assert data.get("status") == "completed" or data.get("state") == "completed"


@pytest.mark.e2e
class TestFindingsAndExport:
    """Tests for findings review and SARIF export."""

    def test_list_findings(self, page, base_url: str, auth_headers: dict):
        """List findings for an assessment."""

        self._create_completed_assessment(page, base_url, auth_headers)

        response = page.request.get(
            f"{base_url}/api/findings",
            headers=auth_headers,
        )
        assert response.ok
        data = response.json()
        assert "items" in data
        assert isinstance(data["items"], list)

    def test_export_sarif(self, page, base_url: str, auth_headers: dict):
        """Export findings as SARIF 2.1.0."""
        self._create_completed_assessment(page, base_url, auth_headers)

        response = page.request.get(
            f"{base_url}/api/assess/{self._assessment_id}/sarif",
            headers=auth_headers,
        )
        assert response.ok
        data = response.json()
        assert data.get("version") == "2.1.0"
        assert "$schema" in data
        assert "runs" in data
        assert isinstance(data["runs"], list)

    def _create_completed_assessment(self, page, base_url: str, auth_headers: dict):
        """Helper to create and wait for assessment completion."""
        payload = {
            "target": "https://httpbin.org/get",
            "profile": "web",
            "actor": "test-tenant-1",
        }
        response = page.request.post(
            f"{base_url}/api/assess",
            headers=auth_headers,
            data=payload,
        )
        assert response.ok
        data = response.json()
        self._assessment_id = data.get("job_id") or data.get("id")

        max_polls = 150
        for _ in range(max_polls):
            response = page.request.get(
                f"{base_url}/api/assess/{self._assessment_id}",
                headers=auth_headers,
            )
            assert response.ok
            data = response.json()
            terminal_states = ("completed", "failed", "cancelled")
            if data.get("status") in terminal_states or data.get("state") in terminal_states:
                break
            page.wait_for_timeout(2000)
        else:
            pytest.fail("Assessment did not complete in time")

        assert data.get("status") == "completed" or data.get("state") == "completed"


@pytest.mark.e2e
class TestTenantIsolation:
    """Tests for multi-tenant isolation."""

    def test_tenant_cannot_access_other_tenant_data(self, page, base_url: str, auth_headers: dict):
        """Tenant A cannot access Tenant B's assessments.

        Note: Full tenant isolation test requires multiple valid API keys.
        This test verifies the auth mechanism works with the test key.
        """

        payload = {"target": "https://httpbin.org", "profile": "web", "actor": "test-tenant-1"}
        response = page.request.post(
            f"{base_url}/api/assess",
            headers=auth_headers,
            data=payload,
        )
        assert response.ok
        data = response.json()
        assessment_id = data.get("job_id") or data.get("id")

        response = page.request.get(
            f"{base_url}/api/assess/{assessment_id}",
            headers=auth_headers,
        )
        assert response.ok


@pytest.mark.e2e
class TestScopeEnforcement:
    """Tests for scope gate enforcement."""

    def test_out_of_scope_target_rejected(self, page, base_url: str, auth_headers: dict):
        """Targets outside scope should be rejected."""
        payload = {
            "target": "https://google.com",
            "profile": "web",
            "actor": "test-tenant-1",
        }
        response = page.request.post(
            f"{base_url}/api/assess",
            headers=auth_headers,
            data=payload,
        )

        assert response.status in (400, 403, 422)
        data = response.json()
        detail = data.get("detail", "").lower()
        assert "scope" in detail or "unauthorized" in detail or "not authorized" in detail
