# Local Development

# Local Development with Docker Compose

## Quick Start

```bash
git clone https://github.com/strix/strix
cd strix
docker-compose up -d
```

## Services

| Service | URL | Credentials |
|---------|-----|-------------|
| Strix API | http://localhost:8000 | API key from `.env` |
| Grafana | http://localhost:3000 | admin / admin |
| Prometheus | http://localhost:9090 | — |
| PostgreSQL | localhost:5432 | strix / strix |
| Redis | localhost:6379 | — |

## Environment Variables

Copy and customize:
```bash
cp .env.example .env
```

Key variables:
```env
# API
STRIX_API_KEY=dev-key-change-in-production
STRIX_SECRET_KEY=dev-secret-change-in-production

# Database
DATABASE_URL=postgresql://strix:strix@localhost:5432/strix
REDIS_URL=redis://localhost:6379/0

# Scope Gate
STRIX_SCOPE_DOC_PATH=scope.example.json

# Logging
LOG_LEVEL=DEBUG
```

## Development Workflow

### Run Tests
```bash
# Unit tests
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# With coverage
pytest tests/ --cov=src/strix --cov-report=html
```

### Code Quality
```bash
# Lint
ruff check src/ tests/

# Type check
mypy src/

# Format
ruff format src/ tests/
```

### Pre-commit Hooks
```bash
pre-commit install
pre-commit run --all-files
```

## Hot Reload

The Docker Compose setup mounts source code for hot reload:
```yaml
volumes:
  - ./src:/app/src
```

Changes to Python files auto-reload the API.

## Debugging

### VS Code Debug Config
```json
{
  "name": "Strix API",
  "type": "python",
  "request": "attach",
  "connect": {"host": "localhost", "port": 5678},
  "pathMappings": [{"localRoot": "${workspaceFolder}/src", "remoteRoot": "/app/src"}]
}
```

### Add Breakpoint in Code
```python
import debugpy
debugpy.listen(("0.0.0.0", 5678))
debugpy.wait_for_client()  # Blocks until debugger attaches
```

## Database Migrations

```bash
# Create migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

## Custom Scope Document

```bash
# Use your own scope
cp scope.example.json scope.json
# Edit scope.json
docker-compose restart api
```

## Troubleshooting

### Port Conflicts
```bash
# Check what's using ports
lsof -i :8000 -i :3000 -i :5432 -i :6379

# Change ports in docker-compose.yml
```

### Database Connection Issues
```bash
# Check PostgreSQL logs
docker-compose logs postgres

# Reset database
docker-compose down -v
docker-compose up -d
```

### Permission Errors
```bash
# Fix file permissions
sudo chown -R $USER:$USER .
```