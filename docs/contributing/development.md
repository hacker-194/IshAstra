# Development Guide

# Development Guide

Complete guide for contributing to IshAstra.

## Quick Start

```bash
# 1. Fork and clone
git clone https://github.com/hacker-194/IshAstra.git
cd ishastra

# 2. Start dev environment
docker compose -f docker-compose.dev.yml up -d

# 3. Run tests
make test

# 4. Run the API
make run-api

# 5. Run a worker
make run-worker
```

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Docker | 24+ | Container runtime |
| Docker Compose | 2.20+ | Multi-container dev |
| Python | 3.11+ | API, workers, adapters |
| Rust | 1.75+ | Core engine, Scope Gate |
| Node.js | 20+ | Web UI (if applicable) |
| k0s | 1.28+ | Local Kubernetes (optional) |
| helm | 3.13+ | Helm charts (optional) |

## Project Structure

```
ishastra/
├── src/
│   ├── ishastra/
│   │   ├── api/           # FastAPI REST API
│   │   ├── core/          # Scope Gate, IshAstra Proof, auth
│   │   ├── workers/       # worker processes
│   │   ├── adapters/      # Built-in & external adapters
│   │   ├── models/        # SQLAlchemy + Pydantic
│   │   ├── db/            # Database, migrations, RLS
│   │   └── utils/         # Shared utilities
│   └── ishastra-rust/        # Rust core (Scope Gate, crypto)
├── kubernetes/            # k0s, Helm, manifests
├── docker/                # Dockerfiles
├── docs/                  # This documentation
├── tests/
│   ├── unit/              # Unit tests
│   ├── integration/       # Integration tests
│   ├── contract/          # API contract tests
│   └── e2e/               # End-to-end tests
├── scripts/               # Operational scripts
├── .github/               # CI/CD workflows
└── Makefile               # Common commands
```

## Development Workflow

### 1. Create Feature Branch

```bash
git checkout main
git pull origin main
git checkout -b feat/your-feature-name
```

### 2. Make Changes

Follow the [Code Style Guide](code-style.md).

### 3. Run Tests

```bash
# All tests
make test

# Specific test suites
make test-unit
make test-integration
make test-contract
make test-e2e

# With coverage
make test-coverage
```

### 4. Run Linters

```bash
# Python
make lint-python

# Rust
make lint-rust

# All
make lint
```

### 5. Commit & Push

```bash
git add .
git commit -m "feat(scope): add new adapter for XYZ"
git push origin feat/your-feature-name
```

### 6. Create Pull Request

Use the PR template. Ensure:
- [ ] Tests pass
- [ ] Linting passes
- [ ] Documentation updated
- [ ] Changelog entry added

## Running Locally

### Docker Compose (Recommended)

```yaml
# docker-compose.dev.yml
version: '3.8'
services:
  postgres:
    image: pgvector/pgvector:pg16
    environment:
      POSTGRES_DB: ishastra
      POSTGRES_USER: ishastra
      POSTGRES_PASSWORD: dev
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  api:
    build:
      context: .
      dockerfile: docker/Dockerfile.api.dev
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgresql://ishastra:dev@postgres/ishastra
      REDIS_URL: redis://redis:6379
      ISHASTRA_ENV: development
    volumes:
      - ./src:/app/src
    depends_on:
      - postgres
      - redis

  worker:
    build:
      context: .
      dockerfile: docker/Dockerfile.worker.dev
    environment:
      DATABASE_URL: postgresql://ishastra:dev@postgres/ishastra
      REDIS_URL: redis://redis:6379
      ISHASTRA_ENV: development
    volumes:
      - ./src:/app/src
    depends_on:
      - postgres
      - redis

volumes:
  pgdata:
```

```bash
# The repository ships one compose stack; there is no docker-compose.dev.yml.
docker compose up -d
curl http://localhost:8000/api/health
```

### Native Python (Alternative)

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Install Rust core
cd src/ishastra-rust && cargo build --release && cd ../..

# Schema upgrades run automatically at startup; no separate migration command exists.

# Run API
ishastra serve --reload --port 8000

# Run worker (separate terminal)
```bash
# IshAstra worker uses the durable Redis Streams queue (configured via ISHASTRA_QUEUE_MODE=redis-streams)
ishastra worker --worker-count 3
```

## Database Migrations

```bash
# Create new migration
# Edit src/ishastra/core/store.py (MIGRATIONS / MIGRATIONS_PG) and bump schema_version.

# Apply migrations
# The store applies the schema chain at startup.

# Rollback
# Forward-only schema: restore a backup to roll back.

# Show history
# See the ordered statement lists in src/ishastra/core/store.py.
```

## Adding a New Adapter

### 1. Create Adapter Module

```python
# src/ishastra/adapters/my_adapter/__init__.py
from ishastra.adapters.base import BaseAdapter, AdapterResult, Finding

class MyAdapter(BaseAdapter):
    name = "my_adapter"
    version = "1.0.0"
    description = "My custom adapter"
    
    async def run(self, target: str, options: dict) -> AdapterResult:
        # Your logic here
        findings = []
        # ...
        return AdapterResult(findings=findings)
```

### 2. Register Adapter

```python
# src/ishastra/adapters/registry.py
from ishastra.adapters.my_adapter import MyAdapter

ADAPTERS = {
    "http_probe": HTTPProbeAdapter,
    "crawler": CrawlerAdapter,
    "my_adapter": MyAdapter,  # Add here
}
```

### 3. Add Tests

```python
# tests/unit/adapters/test_my_adapter.py
import pytest
from ishastra.adapters.my_adapter import MyAdapter

@pytest.mark.asyncio
async def test_my_adapter():
    adapter = MyAdapter()
    result = await adapter.run("https://example.com", {})
    assert isinstance(result.findings, list)
```

### 4. Update Documentation

Add to [Adapters Reference](../adapters/external.md) and [Custom Adapter SDK](../adapters/sdk.md).

## Running Adapters in Development

```bash
# Adapters are exercised through an assessment profile
ishastra assess run --target https://example.com --profile web

# The scope document is always enforced by the gate
ishastra assess run --target https://example.com --profile web --scope scope.json
```

## Debugging

### API Debugging

```bash
# Enable debug logging
export ISHASTRA_LOG_LEVEL=DEBUG

# Attach debugger (VS Code)
# launch.json:
{
  "type": "python",
  "request": "attach",
  "connect": {"host": "localhost", "port": 5678},
  "justMyCode": false
}
```

### Worker Debugging

```bash
# Run worker with debug
# Run worker with debug (uses Redis Streams queue when ISHASTRA_QUEUE_MODE=redis-streams)
# IshAstra worker now uses the durable Redis Streams queue (configured via ISHASTRA_QUEUE_MODE=redis-streams)
ishastra worker --worker-count 3
# or with celery pool (Redis required):
# celery -A ishastra.workers.celery_app worker -l info
```
```

### Database Debugging

```bash
# Connect to PostgreSQL
docker compose exec postgres psql -U ishastra -d ishastra

# Common queries
SELECT * FROM assessments ORDER BY created_at DESC LIMIT 10;
SELECT * FROM findings WHERE severity = 'critical';
SELECT * FROM scope_documents WHERE status = 'active';
```

## Common Commands

```bash
# Make targets
make help              # Show all targets
make test              # Run all tests
make test-unit         # Unit tests only
make test-coverage     # With coverage report
make lint              # All linters
make format            # Auto-format code
make build             # Build all containers
make run-api           # Run API server
make run-worker        # Run Celery worker
make migrate           # Run migrations
make clean             # Clean build artifacts

# Database
make db-shell          # PostgreSQL shell
make db-reset          # Drop and recreate

# Documentation
make docs-serve        # Serve MkDocs locally
make docs-build        # Build static site
```

## Pre-commit Hooks

```bash
# Install
pre-commit install

# Run manually
pre-commit run --all-files

# Hooks include:
# - black (Python formatting)
# - isort (import sorting)
# - ruff (Python linting)
# - rustfmt (Rust formatting)
# - clippy (Rust linting)
# - markdownlint (Markdown)
# - yamllint (YAML)
# - shellcheck (Shell scripts)
# - detect-secrets (Secret scanning)
```

## Getting Help

- **GitHub Discussions**: Architecture questions, proposals
- **GitHub Issues**: Bug reports, feature requests
- **Discord**: Real-time chat, #development channel
- **Code Review**: All PRs reviewed by maintainers

## Related

- [Code Style Guide](code-style.md)
- [Testing Guide](testing.md)
- [Release Process](releasing.md)
- [Architecture Overview](../architecture/overview.md)
- [Custom Adapter SDK](../adapters/sdk.md)