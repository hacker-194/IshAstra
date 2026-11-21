# Testing Guide

# Testing Guide

Comprehensive testing strategy for Ishastra.

## Test Pyramid

```
                    ┌─────────────┐
                    │   E2E       │  ← Few, high confidence
                    │   (Playwright, API)    
                    ├─────────────┤
                    │ Integration │  ← Medium, real dependencies
                    │   (PostgreSQL, Redis, adapters) 
                    ├─────────────┤
                    │  Contract   │  ← API schema validation
                    ├─────────────┤
                    │    Unit     │  ← Many, fast, isolated
                    │   (pytest, cargo test)     
                    └─────────────┘
```

## Test Categories

| Category | Tools | Speed | Scope | When |
|----------|-------|-------|-------|------|
| Unit | pytest, cargo test | <1s | Single function/class | Every commit |
| Contract | schemathesis, pytest | <5s | API schemas | Every commit |
| Integration | pytest, testcontainers | <30s | Real DB, Redis, adapters | PR merge |
| E2E | Playwright, API client | <5min | Full system | Release, nightly |

## Running Tests

```bash
# All tests (CI equivalent)
make test

# Unit tests only (fast)
make test-unit

# Integration tests (requires Docker)
make test-integration

# Contract tests
make test-contract

# E2E tests (requires deployed env)
make test-e2e

# With coverage
make test-coverage

# Specific test file
pytest tests/unit/core/test_scope_gate.py -v

# Specific test
pytest tests/unit/core/test_scope_gate.py::test_layer1_cidr_match -v
```

## Unit Tests (Python)

### Structure

```python
# tests/unit/core/test_scope_gate.py
import pytest
from ishastra.core.scope_gate import ScopeGate, ScopeDocument
from ishastra.core.exceptions import ScopeGateError

class TestScopeGateLayer1:
    """Tests for Layer 1: URL/Host/Port validation."""
    
    @pytest.fixture
    def scope(self) -> ScopeDocument:
        return ScopeDocument(
            authorized_networks=["10.0.0.0/8"],
            include_hosts=["api.example.com"],
            allowed_ports=[80, 443],
        )
    
    @pytest.fixture
    def gate(self, scope: ScopeDocument) -> ScopeGate:
        return ScopeGate(scope)
    
    async def test_allows_matching_host(self, gate: ScopeGate):
        result = await gate.validate("https://api.example.com/endpoint")
        assert result.host == "api.example.com"
    
    async def test_denies_non_matching_host(self, gate: ScopeGate):
        with pytest.raises(ScopeGateError) as exc:
            await gate.validate("https://evil.com/endpoint")
        assert exc.value.layer == 1
    
    @pytest.mark.parametrize("url,expected_port", [
        ("https://api.example.com", 443),
        ("http://api.example.com", 80),
        ("https://api.example.com:8443", 8443),
    ])
    async def test_port_validation(self, gate: ScopeGate, url: str, expected_port: int):
        result = await gate.validate(url)
        assert result.port == expected_port
```

### Async Fixtures

```python
# conftest.py
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

@pytest_asyncio.fixture
async def db_session() -> AsyncSession:
    engine = create_async_engine("postgresql+asyncpg://test:test@localhost/test")
    async with AsyncSession(engine) as session:
        yield session
        await session.rollback()
```

### Mocking

```python
from unittest.mock import AsyncMock, patch

async def test_adapter_with_mock():
    with patch("ishastra.adapters.nuclei.NucleiAdapter.run", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = AdapterResult(findings=[...])
        result = await adapter.run("https://example.com", {})
        assert len(result.findings) == 1
```

## Unit Tests (Rust)

### Structure

```rust
// src/ishastra-rust/src/scope_gate/tests.rs
#[cfg(test)]
mod tests {
    use super::*;
    use strix_rust::{ScopeGate, ScopeDocument, Destination};
    
    fn test_scope() -> ScopeDocument {
        ScopeDocument {
            authorized_networks: vec!["10.0.0.0/8".parse().unwrap()],
            include_hosts: vec!["api.example.com".to_string()],
            allowed_ports: vec![80, 443],
            ..Default::default()
        }
    }
    
    #[tokio::test]
    async fn test_layer1_allows_matching_host() {
        let gate = ScopeGate::new(test_scope());
        let dest = gate.validate(&"https://api.example.com/endpoint".parse().unwrap()).await.unwrap();
        assert_eq!(dest.host, "api.example.com");
    }
    
    #[tokio::test]
    async fn test_layer1_denies_non_matching_host() {
        let gate = ScopeGate::new(test_scope());
        let err = gate.validate(&"https://evil.com/endpoint".parse().unwrap()).await.unwrap_err();
        assert_eq!(err.layer(), 1);
    }
}
```

## Integration Tests

### Database Integration

```python
# tests/integration/test_assessment_flow.py
import pytest
from ishastra.api.main import app
from httpx import AsyncClient

@pytest_asyncio.fixture
async def client() -> AsyncClient:
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

class TestAssessmentFlow:
    async def test_create_and_run_assessment(self, client: AsyncClient, db_session, scope):
        # Create assessment
        response = await client.post(
            "/api/v1/assessments",
            json={
                "scope_id": scope.id,
                "targets": ["https://api.example.com"],
                "adapters": ["http_probe"],
            },
            headers={"Authorization": "Bearer test_key"}
        )
        assert response.status_code == 202
        assessment_id = response.json()["id"]
        
        # Wait for completion (in test, worker runs inline)
        await wait_for_completion(assessment_id)
        
        # Verify findings
        response = await client.get(f"/api/v1/assessments/{assessment_id}/findings")
        assert response.status_code == 200
```

### Adapter Integration

```python
# tests/integration/adapters/test_nuclei.py
import pytest
from ishastra.adapters.nuclei import NucleiAdapter

class TestNucleiIntegration:
    @pytest.mark.integration
    async def test_nuclei_finds_cve(self):
        adapter = NucleiAdapter()
        result = await adapter.run(
            "https://httpbin.org",
            {"severity": ["critical", "high"], "templates": ["cves/"]}
        )
        # Should not crash, may or may not find vulns
        assert isinstance(result.findings, list)
```

### Testcontainers for Real Dependencies

```python
# tests/integration/conftest.py
import pytest
from testcontainers.postgres import PostgresContainer
from testcontainers.redis import RedisContainer

@pytest.fixture(scope="session")
def postgres():
    with PostgresContainer("pgvector/pgvector:pg16") as pg:
        yield pg.get_connection_url()

@pytest.fixture(scope="session")
def redis():
    with RedisContainer("redis:7-alpine") as r:
        yield f"redis://{r.get_container_host_ip()}:{r.get_exposed_port(6379)}"
```

## Contract Tests

### OpenAPI Schema Validation

```python
# tests/contract/test_api_schema.py
import schemathesis
from ishastra.api.main import app

schema = schemathesis.from_pytest_fixture("openapi_schema")

@schema.parametrize()
def test_api_conforms_to_schema(case, openapi_schema):
    case.call_and_validate()
```

### Generate Test Cases

```bash
# Generate contract tests from OpenAPI
schemathesis generate pytest app.openapi.json -o tests/contract/generated/
```

## E2E Tests

### Playwright Setup

```typescript
// tests/e2e/playwright.config.ts
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  retries: 2,
  workers: 4,
  use: {
    baseURL: process.env.ISHASTRA_E2E_URL || 'http://localhost:8000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
  ],
  webServer: {
    command: 'docker compose -f docker-compose.e2e.yml up',
    url: 'http://localhost:8000/health',
    reuseExistingServer: !process.env.CI,
  },
});
```

### E2E Test Example

```typescript
// tests/e2e/assessment.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Assessment Flow', () => {
  test('create assessment and view findings', async ({ page, request }) => {
    // Create scope via API
    const scope = await request.post('/api/v1/scopes', {
      data: { name: "E2E Test", authorized_networks: ["10.0.0.0/8"] }
    });
    expect(scope.ok()).toBeTruthy();
    
    // Create assessment
    const assessment = await request.post('/api/v1/assessments', {
      data: { scope_id: scope.id, targets: ["https://httpbin.org"], adapters: ["http_probe"] }
    });
    expect(assessment.ok()).toBeTruthy();
    
    // Poll for completion
    await waitForAssessment(assessment.id, 'completed');
    
    // View findings in UI
    await page.goto(`/assessments/${assessment.id}`);
    await expect(page.locator('[data-testid="findings-table"]')).toBeVisible();
  });
});
```

## Test Data

### Fixtures

```python
# tests/fixtures/scopes.py
from ishastra.models.scope import ScopeDocument

SCOPE_MINIMAL = ScopeDocument(
    name="Minimal Scope",
    authorized_networks=["10.0.0.0/8"],
)

SCOPE_FULL = ScopeDocument(
    name="Full Scope",
    authorized_networks=["10.0.0.0/8", "172.16.0.0/12"],
    include_hosts=["api.example.com", "app.example.com"],
    exclude_hosts=["internal.example.com"],
    allowed_ports=[80, 443, 8080, 8443],
    dns_resolver="cloudflare",
    break_glass={...},
)
```

### Factories

```python
# tests/factories.py
import factory
from ishastra.models.assessment import Assessment
from ishastra.models.finding import Finding

class AssessmentFactory(factory.Factory):
    class Meta:
        model = Assessment
    
    id = factory.Sequence(lambda n: f"asm_{n:06d}")
    scope_id = "scope_test_001"
    status = "pending"
    targets = ["https://example.com"]
    adapters = ["http_probe"]
```

## Coverage Requirements

| Component | Minimum | Target |
|-----------|---------|--------|
| Core (Scope Gate, Ishastra Proof) | 90% | 95% |
| API | 80% | 90% |
| Adapters | 70% | 85% |
| Workers | 75% | 85% |
| Overall | 80% | 90% |

```bash
# Check coverage
make test-coverage

# View HTML report
open htmlcov/index.html
```

## CI Pipeline

```yaml
# .github/workflows/test.yml
name: Test
on: [push, pull_request]
jobs:
  unit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run unit tests
        run: make test-unit
  
  integration:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: pgvector/pgvector:pg16
      redis:
        image: redis:7-alpine
    steps:
      - uses: actions/checkout@v4
      - name: Run integration tests
        run: make test-integration
  
  contract:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run contract tests
        run: make test-contract
  
  e2e:
    runs-on: ubuntu-latest
    if: github.event_name == 'release' || github.event_name == 'schedule'
    steps:
      - uses: actions/checkout@v4
      - name: Deploy to staging
        run: make deploy-staging
      - name: Run E2E tests
        run: make test-e2e
```

## Troubleshooting

### Flaky Tests

```python
# Mark flaky tests for quarantine
@pytest.mark.flaky(reruns=3, reruns_delay=1)
async def test_sometimes_flaky():
    ...
```

### Slow Tests

```python
# Mark slow tests
@pytest.mark.slow
async def test_large_assessment():
    ...

# Run without slow tests
pytest -m "not slow"
```

### Test Debugging

```bash
# Debug with pdb
pytest tests/unit/test_xyz.py -v --pdb

# Debug with VS Code
# Add to launch.json:
{
  "type": "python",
  "request": "launch",
  "module": "pytest",
  "args": ["tests/unit/test_xyz.py", "-v", "-s"],
  "justMyCode": false
}
```

## Related

- [Development Guide](development.md)
- [Code Style Guide](code-style.md)
- [Release Process](releasing.md)
- [Architecture Overview](../architecture/overview.md)