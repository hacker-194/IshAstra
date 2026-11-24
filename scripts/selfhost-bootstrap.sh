#!/usr/bin/env bash
# selfhost-bootstrap.sh — One-command local IshAstra for evaluation
# Creates ~/.ishastra-selfhost/ with SQLite, scope, keys, starts API + worker
# Safe defaults: localhost-only scope, no external dependencies, no cloud

set -euo pipefail

SELFHOST_DIR="${HOME}/.ishastra-selfhost"
SCOPE_FILE="${SELFHOST_DIR}/scope.json"
ENV_FILE="${SELFHOST_DIR}/.env"
COMPOSE_FILE="${SELFHOST_DIR}/docker-compose.yml"

echo "🛡️  IshAstra Self-Host Bootstrap"
echo "================================="
echo ""

# Check prerequisites
for cmd in docker docker-compose git; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "❌ Missing: $cmd — install it first"
        exit 1
    fi
done

# Create directory
mkdir -p "${SELFHOST_DIR}"
cd "${SELFHOST_DIR}"

# Generate secrets
API_KEY=$(openssl rand -base64 32 | tr -d '\n')
AUDIT_HMAC_KEY=$(openssl rand -base64 32 | tr -d '\n')
ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d '\n')

# Create scope.json (localhost only — safe default)
cat > "${SCOPE_FILE}" <<'EOF'
{
  "program": "IshAstra Self-Host Evaluation",
  "authorized_by": "Self-Host User",
  "authorization_ref": "SELF-HOST-EVAL",
  "include": ["localhost", "127.0.0.1", "::1"],
  "exclude": [],
  "authorized_networks": ["127.0.0.0/8", "::1/128"],
  "allowed_ports": [80, 443, 8000, 8080],
  "allow_broad_networks": false
}
EOF

# Create .env
cat > "${ENV_FILE}" <<EOF
ISHASTRA_ENV=production
ISHASTRA_API_KEY=${API_KEY}
ISHASTRA_AUDIT_HMAC_KEY=${AUDIT_HMAC_KEY}
ISHASTRA_ENCRYPTION_KEY=${ENCRYPTION_KEY}
ISHASTRA_SCOPE_FILE=/etc/ishastra/scope.json
ISHASTRA_DATABASE_URL=sqlite:///var/lib/ishastra/ishastra.db
ISHASTRA_SCOPE_MODE=auto
ISHASTRA_RETENTION_DAYS=90
ISHASTRA_LOG_FORMAT=json
ISHASTRA_LOG_LEVEL=INFO
ISHASTRA_WORKERS=2
ISHASTRA_QUEUE_MODE=in-process
ISHASTRA_DISABLE_DOCS=false
EOF

# Create docker-compose.yml (SQLite only, no postgres/redis)
cat > "${COMPOSE_FILE}" <<'EOF'
version: "3.9"

services:
  ishastra:
    image: ghcr.io/hacker-194/ishastra:latest
    pull_policy: always
    container_name: ishastra-selfhost
    restart: unless-stopped
    environment:
      - ISHASTRA_ENV=production
    env_file:
      - .env
    volumes:
      - ./scope.json:/etc/ishastra/scope.json:ro
      - ishastra-data:/var/lib/ishastra
    ports:
      - "8000:8000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/ready"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 20s
    # Hardening
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
      - /var/run

volumes:
  ishastra-data:
EOF

# Pull image
echo "📦 Pulling IshAstra image..."
docker compose -f "${COMPOSE_FILE}" pull

# Start
echo "🚀 Starting IshAstra..."
docker compose -f "${COMPOSE_FILE}" up -d

# Wait for ready
echo "⏳ Waiting for API to be ready..."
for i in {1..30}; do
    if curl -sf "http://localhost:8000/api/ready" >/dev/null 2>&1; then
        echo ""
        echo "✅ IshAstra is ready!"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🌐  UI:       http://localhost:8000"
        echo "🔑  API Key:  ${API_KEY}"
        echo "📁  Data:     ${SELFHOST_DIR}"
        echo "📄  Scope:    ${SCOPE_FILE}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "Next steps:"
        echo "  1. Open http://localhost:8000"
        echo "  2. Paste the API Key into the top bar"
        echo "  3. Create an assessment (target: http://localhost:8000 for demo)"
        echo ""
        echo "To stop:  docker compose -f ${COMPOSE_FILE} down"
        echo "To logs:  docker compose -f ${COMPOSE_FILE} logs -f"
        echo "To update: docker compose -f ${COMPOSE_FILE} pull && docker compose -f ${COMPOSE_FILE} up -d"
        exit 0
    fi
    sleep 2
    echo -n "."
done

echo ""
echo "❌ Timeout waiting for API. Check logs:"
echo "   docker compose -f ${COMPOSE_FILE} logs ishastra"
exit 1