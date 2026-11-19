# Docker Compose Deployment

# Docker Compose Deployment

Local development and single-host production deployment with Docker Compose.

## Quick Start

```bash
# Clone repository
git clone https://github.com/strix/strix.git
cd strix

# Copy environment template
cp .env.example .env

# Edit .env with your configuration
vim .env

# Start all services
docker compose up -d

# Run migrations
docker compose exec api alembic upgrade head

# Verify
curl http://localhost:8000/health
```

## Service Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Docker Compose Stack                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │   API       │    │  Worker     │    │  Scheduler  │    │  Nginx      │  │
│  │  :8000      │    │  (queue)    │    │  (cron)     │    │  :80/:443   │  │
│  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘    └──────┬──────┘  │
│         │                  │                  │                  │          │
│         └──────────────────┼──────────────────┼──────────────────┘          │
│                            ▼                  ▼                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                    │
│  │ PostgreSQL  │    │   Redis     │    │  MinIO      │                    │
│  │  :5432      │    │  :6379      │    │  :9000      │                    │
│  └─────────────┘    └─────────────┘    └─────────────┘                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## docker-compose.yml

```yaml
# docker-compose.yml
version: "3.9"

services:
  # Reverse proxy with TLS termination
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
      - nginx-logs:/var/log/nginx
    depends_on:
      - api
    networks:
      - strix-network
    restart: unless-stopped

  # API Server
  api:
    build:
      context: .
      dockerfile: Dockerfile.api
    image: strix/api:latest
    environment:
      - DATABASE_URL=postgresql://strix:strix@postgres:5432/strix
      - REDIS_URL=redis://redis:6379/0
      - STRIX_SCOPE_DOC_PATH=/config/scope.json
      - STRIX_JWKS_URL=https://api.strix.dev/.well-known/jwks.json
      - LOG_LEVEL=DEBUG
      - ENVIRONMENT=development
    volumes:
      - ./scope.json:/config/scope.json:ro
      - ./src:/app/src:ro  # For hot reload in dev
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - strix-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: "2"
          memory: 4G
        reservations:
          cpus: "0.5"
          memory: 1G

  # Worker (assessment execution)
  worker:
    build:
      context: .
      dockerfile: Dockerfile.worker
    image: strix/worker:latest
    environment:
      - DATABASE_URL=postgresql://strix:strix@postgres:5432/strix
      - REDIS_URL=redis://redis:6379/0
      - STRIX_SCOPE_DOC_PATH=/config/scope.json
      - LOG_LEVEL=INFO
      - ENVIRONMENT=development
    volumes:
      - ./scope.json:/config/scope.json:ro
      - /var/run/docker.sock:/var/run/docker.sock  # For containerized adapters
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - strix-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: "4"
          memory: 8G
        reservations:
          cpus: "1"
          memory: 2G

  # Scheduler (cron jobs, recurring assessments)
  scheduler:
    build:
      context: .
      dockerfile: Dockerfile.scheduler
    image: strix/scheduler:latest
    environment:
      - DATABASE_URL=postgresql://strix:strix@postgres:5432/strix
      - REDIS_URL=redis://redis:6379/0
      - STRIX_SCOPE_DOC_PATH=/config/scope.json
      - LOG_LEVEL=INFO
      - ENVIRONMENT=development
    volumes:
      - ./scope.json:/config/scope.json:ro
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - strix-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 512M
        reservations:
          cpus: "0.1"
          memory: 128M

  # PostgreSQL Database
  postgres:
    image: pgvector/pgvector:pg16
    environment:
      - POSTGRES_DB=strix
      - POSTGRES_USER=strix
      - POSTGRES_PASSWORD=strix
      - POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./init-scripts:/docker-entrypoint-initdb.d:ro
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U strix -d strix"]
      interval: 5s
      timeout: 5s
      retries: 10
    networks:
      - strix-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: "2"
          memory: 4G
        reservations:
          cpus: "0.5"
          memory: 1G

  # Redis (Queue + Cache)
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes --maxmemory 512mb --maxmemory-policy allkeys-lru
    volumes:
      - redis-data:/data
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 10
    networks:
      - strix-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: "1"
          memory: 1G
        reservations:
          cpus: "0.1"
          memory: 256M

  # MinIO (Object Storage for reports, artifacts)
  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      - MINIO_ROOT_USER=strix
      - MINIO_ROOT_PASSWORD=strix123
    volumes:
      - minio-data:/data
    ports:
      - "9000:9000"
      - "9001:9001"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 30s
      timeout: 20s
      retries: 3
    networks:
      - strix-network
    restart: unless-stopped

volumes:
  postgres-data:
  redis-data:
  minio-data:
  nginx-logs:

networks:
  strix-network:
    driver: bridge
```

## Production docker-compose.prod.yml

```yaml
# docker-compose.prod.yml
version: "3.9"

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.prod.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
      - nginx-logs:/var/log/nginx
    networks:
      - strix-network
    restart: always
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 512M

  api:
    image: ghcr.io/strix/api:3.5.0
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - STRIX_SCOPE_DOC_PATH=/config/scope.json
      - STRIX_JWKS_URL=${JWKS_URL}
      - LOG_LEVEL=INFO
      - ENVIRONMENT=production
    volumes:
      - ./scope.json:/config/scope.json:ro
    networks:
      - strix-network
    restart: always
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: "2"
          memory: 4G
        reservations:
          cpus: "0.5"
          memory: 1G
      update_config:
        parallelism: 1
        delay: 10s
        order: start-first

  worker:
    image: ghcr.io/strix/worker:3.5.0
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - STRIX_SCOPE_DOC_PATH=/config/scope.json
      - LOG_LEVEL=INFO
      - ENVIRONMENT=production
    volumes:
      - ./scope.json:/config/scope.json:ro
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - strix-network
    restart: always
    deploy:
      replicas: 5
      resources:
        limits:
          cpus: "4"
          memory: 8G
        reservations:
          cpus: "1"
          memory: 2G

  scheduler:
    image: ghcr.io/strix/scheduler:3.5.0
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - REDIS_URL=${REDIS_URL}
      - STRIX_SCOPE_DOC_PATH=/config/scope.json
      - LOG_LEVEL=INFO
      - ENVIRONMENT=production
    volumes:
      - ./scope.json:/config/scope.json:ro
    networks:
      - strix-network
    restart: always
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: "0.5"
          memory: 512M

volumes:
  nginx-logs:

networks:
  strix-network:
    driver: bridge
    attachable: true
```

## Environment Configuration

### .env.example

```bash
# .env.example

# Database
DATABASE_URL=postgresql://strix:strix@postgres:5432/strix

# Redis
REDIS_URL=redis://redis:6379/0

# JWT Secret (generate with: openssl rand -base64 32)
JWT_SECRET=your-super-secret-jwt-key-change-in-production

# API Key for authentication
API_KEY=strix-dev-key-change-in-production

# JWKS URL for token validation
JWKS_URL=https://api.strix.dev/.well-known/jwks.json

# Scope document path
STRIX_SCOPE_DOC_PATH=/config/scope.json

# Log level
LOG_LEVEL=INFO

# Environment
ENVIRONMENT=development

# MinIO
MINIO_ROOT_USER=strix
MINIO_ROOT_PASSWORD=strix123
MINIO_ENDPOINT=http://minio:9000

# External services (for production)
# EXTERNAL_DATABASE_URL=postgresql://user:pass@host:5432/strix?sslmode=require
# EXTERNAL_REDIS_URL=redis://:pass@host:6379/0
```

### .env.production

```bash
# .env.production

DATABASE_URL=postgresql://strix:strong-password@postgres:5432/strix
REDIS_URL=redis://:strong-password@redis:6379/0
JWT_SECRET=production-jwt-secret-from-vault
API_KEY=strix-production-api-key-from-vault
JWKS_URL=https://api.yourdomain.com/.well-known/jwks.json
STRIX_SCOPE_DOC_PATH=/config/scope.json
LOG_LEVEL=INFO
ENVIRONMENT=production
MINIO_ROOT_USER=strix
MINIO_ROOT_PASSWORD=strong-minio-password
MINIO_ENDPOINT=https://minio.yourdomain.com
```

## Nginx Configuration

### nginx.conf (Development)

```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream api {
        server api:8000;
    }

    server {
        listen 80;
        server_name localhost;

        location / {
            proxy_pass http://api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 300s;
            proxy_send_timeout 300s;
        }

        location /health {
            proxy_pass http://api/health;
            access_log off;
        }
    }
}
```

### nginx.prod.conf (Production)

```nginx
# nginx.prod.conf
events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    server_tokens off;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/s;

    upstream api {
        least_conn;
        server api:8000 max_fails=3 fail_timeout=30s;
        keepalive 32;
    }

    # HTTP -> HTTPS redirect
    server {
        listen 80;
        server_name api.yourdomain.com;
        return 301 https://$server_name$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name api.yourdomain.com;

        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;

        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

        # Rate limiting
        limit_req zone=api burst=200 nodelay;

        location / {
            proxy_pass http://api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_read_timeout 300s;
            proxy_send_timeout 300s;
            proxy_buffering off;
        }

        location /api/v1/auth/ {
            limit_req zone=auth burst=20 nodelay;
            proxy_pass http://api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /health {
            proxy_pass http://api/health;
            access_log off;
            limit_req off;
        }
    }
}
```

## Database Initialization

### init-scripts/01-extensions.sql

```sql
-- init-scripts/01-extensions.sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";
CREATE EXTENSION IF NOT EXISTS "vector";  -- pgvector for embeddings
```

### init-scripts/02-init.sql

```sql
-- init-scripts/02-init.sql
-- Create additional schemas if needed
CREATE SCHEMA IF NOT EXISTS strix_audit;
CREATE SCHEMA IF NOT EXISTS strix_compliance;

-- Set default privileges
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO strix;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO strix;
```

## Commands

### Development

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f api
docker compose logs -f worker

# Run migrations
docker compose exec api alembic upgrade head

# Create migration
docker compose exec api alembic revision --autogenerate -m "description"

# Shell into container
docker compose exec api bash
docker compose exec worker bash

# Run tests
docker compose exec api pytest

# Stop all
docker compose down

# Stop and remove volumes
docker compose down -v
```

### Production

```bash
# Deploy
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Scale workers
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --scale worker=10

# Rolling update
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --no-deps api

# View logs
docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f --tail=100

# Backup database
docker compose exec postgres pg_dump -U strix strix | gzip > backup-$(date +%F).sql.gz

# Restore database
gunzip -c backup-2024-01-15.sql.gz | docker compose exec -T postgres psql -U strix strix
```

## Health Checks

```bash
# API health
curl http://localhost:8000/health

# Detailed health
curl http://localhost:8000/health/detailed

# Database connectivity
docker compose exec api python -c "
import asyncpg, os, asyncio
async def check():
    conn = await asyncpg.connect(os.getenv('DATABASE_URL'))
    print(await conn.fetchval('SELECT 1'))
    await conn.close()
asyncio.run(check())
"

# Redis connectivity
docker compose exec redis redis-cli ping

# Queue status
curl http://localhost:8000/api/v1/queue/status \
  -H "Authorization: Bearer $API_KEY"
```

## Resource Requirements

| Environment | CPU | Memory | Disk |
|-------------|-----|--------|------|
| Development | 4 cores | 8 GB | 20 GB |
| Production (small) | 8 cores | 16 GB | 50 GB |
| Production (medium) | 16 cores | 32 GB | 100 GB |
| Production (large) | 32 cores | 64 GB | 200 GB |

## Troubleshooting

### Common Issues

| Issue | Fix |
|-------|-----|
| Port 80/443 in use | Stop local nginx/apache, or change ports |
| Database connection refused | Wait for healthcheck, check DATABASE_URL |
| Redis connection refused | Wait for healthcheck, check REDIS_URL |
| Worker OOM | Increase memory limit, reduce concurrency |
| Migrations fail | Check DATABASE_URL, run manually |
| Scope Gate DENY | Verify scope.json, check CIDR ranges |

### Debug Commands

```bash
# Check container status
docker compose ps

# Check resource usage
docker stats

# Inspect network
docker network inspect strix_strix-network

# Check volumes
docker volume ls

# Execute in running container
docker compose exec api python -c "from strix.core.scope import ScopeGate; print('OK')"
```

## Related

- [Kubernetes Deployment](../deployment/kubernetes.md)
- [Helm Deployment](../deployment/helm.md)
- [Local Development](../quickstart/local-dev.md)
- [Free Tier Deployment](../deployment/free-tier.md)