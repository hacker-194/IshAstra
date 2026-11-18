#!/usr/bin/env bash
# Strix Secret Generation Script
# ===============================
# Generates cryptographically secure random secrets for all required environment variables.
# Usage: ./scripts/generate-secrets.sh [--output FILE] [--scope production|staging]
# Options:
#   --output FILE       Write to .env file instead of stdout (default: stdout)
#   --scope SCOPE       Generate for production or staging (default: production)
#   --integration       Include integration secrets (Slack, Jira, GitHub, etc.)
#   --force             Overwrite output file without confirmation
#   -h, --help          Show this help message
#
# Generated secrets are base64-encoded where required (32+ bytes = 44+ chars).
# All secrets use cryptographically secure random sources (/dev/urandom or openssl).

set -euo pipefail

# Default values
OUTPUT_FILE=""
SCOPE="production"
INCLUDE_INTEGRATIONS=false
FORCE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --scope)
            SCOPE="$2"
            shift 2
            ;;
        --integration)
            INCLUDE_INTEGRATIONS=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        -h|--help)
            cat <<'EOF'
Strix Secret Generation Script
==============================

Generates cryptographically secure random secrets for all required environment variables.

Usage: ./scripts/generate-secrets.sh [OPTIONS]

Options:
  --output FILE       Write to .env file instead of stdout (default: stdout)
  --scope SCOPE       Generate for production or staging (default: production)
  --integration       Include integration secrets (Slack, Jira, GitHub, etc.)
  --force             Overwrite output file without confirmation
  -h, --help          Show this help message

Examples:
  # Generate all secrets to stdout
  ./scripts/generate-secrets.sh

  # Generate production secrets to .env.production
  ./scripts/generate-secrets.sh --output .env.production --scope production

  # Generate staging secrets with integrations
  ./scripts/generate-secrets.sh --output .env.staging --scope staging --integration

  # Generate only core secrets (no integrations)
  ./scripts/generate-secrets.sh --output .env.production --scope production

Note: Integration secrets (Slack, Jira, GitHub, etc.) require manual configuration
with actual credentials from those services. This script generates placeholder
values that MUST be replaced with real credentials.
EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# Helper: generate base64-encoded random bytes
gen_base64() {
    local bytes="${1:-32}"
    openssl rand -base64 "$bytes" | tr -d '\n'
}

# Helper: generate hex-encoded random bytes
gen_hex() {
    local bytes="${1:-32}"
    openssl rand -hex "$bytes" | tr -d '\n'
}

# Helper: generate URL-safe base64 (no padding, no +/ characters)
gen_urlsafe_base64() {
    local bytes="${1:-32}"
    openssl rand -base64 "$bytes" | tr '+/' '-_' | tr -d '=' | tr -d '\n'
}

# Helper: generate a secure password
gen_password() {
    local length="${1:-24}"
    # Use alphanumeric + safe special chars
    openssl rand -base64 "$length" | tr -d '=+/' | cut -c1-"$length"
}

# Helper: append key=value to OUTPUT
append_var() {
    local key="$1"
    local value="$2"
    OUTPUT+="${key}=${value}\n"
}

# Helper: append comment to OUTPUT
append_comment() {
    OUTPUT+="# $1\n"
}

# Check if output file exists and confirm overwrite
if [[ -n "$OUTPUT_FILE" && -f "$OUTPUT_FILE" && "$FORCE" != "true" ]]; then
    read -rp "File $OUTPUT_FILE exists. Overwrite? [y/N] " -n 1
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

# Build output
OUTPUT=""

# Header
append_comment "Strix ${SCOPE^} Environment Configuration"
append_comment "============================================"
append_comment "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
append_comment "Generator: scripts/generate-secrets.sh"
if [[ "$INCLUDE_INTEGRATIONS" == "true" ]]; then
    append_comment "Includes: Core + Integration secrets"
else
    append_comment "Includes: Core secrets only (use --integration for integrations)"
fi
append_comment "NEVER COMMIT THIS FILE TO VERSION CONTROL!"
append_comment ""
OUTPUT+="\n"

# ============================================================
# CORE SECRETS (Always generated)
# ============================================================
append_comment "Core API authentication (base64, 32+ bytes / 44+ chars)"
append_var "STRIX_API_KEY" "$(gen_base64 32)"
append_comment "HMAC key for audit log integrity verification (base64, 32+ bytes)"
append_var "STRIX_AUDIT_HMAC_KEY" "$(gen_base64 32)"
append_comment "Webhook HMAC secret for verifying inbound webhook signatures (hex, 32 bytes)"
append_var "STRIX_WEBHOOK_SECRET" "$(gen_hex 32)"
append_comment "Encryption key for webhook secrets at rest (base64, 32 bytes, AES-GCM)"
append_var "STRIX_ENCRYPTION_KEY" "$(gen_base64 32)"
OUTPUT+="\n"

# Database & Scope Configuration
append_comment "Database & Scope Configuration"
append_var "STRIX_DB" "/var/lib/strix/strix.db"
append_var "STRIX_SCOPE_FILE" "/etc/strix/scope.json"
append_var "STRIX_SCOPE_MODE" "auto"
OUTPUT+="\n"

# Worker & Queue Configuration
append_comment "Worker & Queue Configuration"
if [[ "$SCOPE" == "production" ]]; then
    append_var "STRIX_WORKERS" "4"
    append_var "STRIX_QUEUE_MAX" "32"
    append_var "STRIX_RETENTION_DAYS" "90"
else
    append_var "STRIX_WORKERS" "2"
    append_var "STRIX_QUEUE_MAX" "16"
    append_var "STRIX_RETENTION_DAYS" "30"
fi
append_var "STRIX_QUEUE_MODE" "inprocess"
OUTPUT+="\n"

# Redis Configuration
append_comment "Redis Configuration"
append_var "STRIX_REDIS_URL" "redis://redis:6379/0"
append_var "STRIX_REDIS_PASSWORD" "$(gen_base64 24)"
append_var "STRIX_REDIS_REQUIRED" "1"
OUTPUT+="\n"

# Celery Configuration
append_comment "Celery Configuration (used when STRIX_QUEUE_MODE=celery)"
append_var "STRIX_CELERY_BROKER_URL" "redis://redis:6379/1"
append_var "STRIX_CELERY_RESULT_BACKEND" "redis://redis:6379/2"
append_var "STRIX_CELERY_MAX_TASKS_PER_CHILD" "50"
append_var "STRIX_CELERY_MAX_MEMORY_PER_CHILD" "1073741824"
append_var "STRIX_CELERY_TASK_TIME_LIMIT" "3600"
append_var "STRIX_CELERY_TASK_SOFT_TIME_LIMIT" "300"
OUTPUT+="\n"

# PostgreSQL (commented by default)
append_comment "PostgreSQL Configuration (uncomment if using PostgreSQL)"
append_comment "STRIX_DB=postgresql://strix:\${STRIX_DB_PASSWORD}@postgres:5432/strix"
append_comment "STRIX_DB_PASSWORD=$(gen_base64 24)"
OUTPUT+="\n"

# Logging Configuration
append_comment "Logging Configuration"
if [[ "$SCOPE" == "production" ]]; then
    append_var "STRIX_LOG_FORMAT" "json"
    append_var "STRIX_LOG_LEVEL" "INFO"
    append_var "STRIX_DEBUG" "0"
else
    append_var "STRIX_LOG_FORMAT" "json"
    append_var "STRIX_LOG_LEVEL" "DEBUG"
    append_var "STRIX_DEBUG" "0"
fi
OUTPUT+="\n"

# Networking
append_comment "Networking"
append_var "STRIX_TRUSTED_PROXIES" "172.28.0.0/24"
OUTPUT+="\n"

# Grafana
append_comment "Grafana Admin Password"
append_var "GRAFANA_PASSWORD" "$(gen_password 24)"
OUTPUT+="\n"

# ============================================================
# INTEGRATION SECRETS (Only if --integration flag)
# ============================================================
if [[ "$INCLUDE_INTEGRATIONS" == "true" ]]; then
    append_comment "============================================================================"
    append_comment "INTEGRATION SECRETS"
    append_comment "============================================================================"
    append_comment "IMPORTANT: These are PLACEHOLDERS. Replace with actual credentials from"
    append_comment "each service. This script cannot generate valid credentials for external"
    append_comment "services. You must obtain these from the respective service consoles."
    append_comment "============================================================================"
    OUTPUT+="\n"

    # Alertmanager / SMTP
    append_comment "Alertmanager / SMTP"
    append_var "SMTP_PASSWORD" "$(gen_password 24)"
    append_var "ALERTMANAGER_WEBHOOK_URL" "https://alertmanager.example.com/webhook"
    OUTPUT+="\n"

    # Slack Integration
    append_comment "Slack Integration (REPLACE with actual webhook URLs from Slack App)"
    append_var "SLACK_WEBHOOK_URL" "https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>"
    append_var "SLACK_WEBHOOK_URL_CRITICAL" "https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>"
    append_var "SLACK_WEBHOOK_URL_SECURITY" "https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>"
    append_var "SLACK_BOT_TOKEN" "xoxb-REPLACE_WITH_BOT_TOKEN"
    append_var "SLACK_APP_TOKEN" "xapp-REPLACE_WITH_APP_TOKEN"
    OUTPUT+="\n"

    # Jira Integration
    append_comment "Jira Integration (REPLACE with actual API token from Atlassian)"
    append_var "JIRA_API_TOKEN" "REPLACE_WITH_JIRA_API_TOKEN"
    append_var "JIRA_BASE_URL" "https://company.atlassian.net"
    append_var "JIRA_EMAIL" "security@company.com"
    OUTPUT+="\n"

    # GitHub Integration
    append_comment "GitHub Integration (REPLACE with actual PAT from GitHub Settings)"
    append_var "GITHUB_TOKEN" "ghp_REPLACE_WITH_GITHUB_PAT"
    append_var "GITHUB_ACTIONS_TOKEN" "ghp_REPLACE_WITH_ACTIONS_TOKEN"
    append_var "GITHUB_OWNER" "myorg"
    append_var "GITHUB_REPO" "security-tracking"
    OUTPUT+="\n"

    # GitLab Integration
    append_comment "GitLab Integration (REPLACE with actual PAT from GitLab Settings)"
    append_var "GITLAB_TOKEN" "glpat_REPLACE_WITH_GITLAB_TOKEN"
    append_var "GITLAB_CI_TOKEN" "glptt_REPLACE_WITH_CI_TOKEN"
    append_var "GITLAB_BASE_URL" "https://gitlab.com"
    OUTPUT+="\n"

    # Microsoft Teams
    append_comment "Microsoft Teams (REPLACE with actual webhook URL)"
    append_var "TEAMS_WEBHOOK_URL" "https://outlook.office.com/webhook/REPLACE_WITH_TEAMS_WEBHOOK"
    OUTPUT+="\n"

    # Mattermost
    append_comment "Mattermost (REPLACE with actual webhook URL)"
    append_var "MATTERMOST_WEBHOOK_URL" "https://mattermost.example.com/hooks/REPLACE_WITH_HOOK"
    OUTPUT+="\n"

    # Splunk HEC
    append_comment "Splunk HEC (REPLACE with actual HEC token)"
    append_var "SPLUNK_HEC_TOKEN" "REPLACE_WITH_SPLUNK_HEC_TOKEN"
    append_var "SPLUNK_HOST" "splunk.example.com"
    append_var "SPLUNK_PORT" "8088"
    OUTPUT+="\n"

    # Datadog
    append_comment "Datadog (REPLACE with actual API key)"
    append_var "DATADOG_API_KEY" "REPLACE_WITH_DATADOG_API_KEY"
    append_var "DATADOG_SITE" "datadoghq.com"
    OUTPUT+="\n"

    # Elasticsearch / Elastic Cloud
    append_comment "Elasticsearch / Elastic Cloud (REPLACE with actual credentials)"
    append_var "ELASTIC_API_KEY" "REPLACE_WITH_ELASTIC_API_KEY"
    append_var "ELASTIC_CLOUD_ID" "REPLACE_WITH_CLOUD_ID"
    append_var "ELASTIC_PASSWORD" "REPLACE_WITH_ELASTIC_PASSWORD"
    OUTPUT+="\n"

    # Azure Sentinel
    append_comment "Azure Sentinel (REPLACE with actual workspace credentials)"
    append_var "SENTINEL_WORKSPACE_ID" "REPLACE_WITH_WORKSPACE_ID"
    append_var "SENTINEL_SHARED_KEY" "REPLACE_WITH_BASE64_SHARED_KEY"
    append_var "AZURE_TENANT_ID" "REPLACE_WITH_TENANT_ID"
    append_var "AZURE_CLIENT_ID" "REPLACE_WITH_CLIENT_ID"
    append_var "AZURE_CLIENT_SECRET" "REPLACE_WITH_CLIENT_SECRET"
    OUTPUT+="\n"

    # ServiceNow
    append_comment "ServiceNow (REPLACE with actual credentials)"
    append_var "SERVICENOW_PASSWORD" "REPLACE_WITH_SERVICENOW_PASSWORD"
    append_var "SERVICENOW_CLIENT_ID" "REPLACE_WITH_CLIENT_ID"
    append_var "SERVICENOW_CLIENT_SECRET" "REPLACE_WITH_CLIENT_SECRET"
    append_var "SERVICENOW_INSTANCE_URL" "https://company.service-now.com"
    OUTPUT+="\n"

    # PagerDuty
    append_comment "PagerDuty (REPLACE with actual service key)"
    append_var "PAGERDUTY_SERVICE_KEY" "REPLACE_WITH_PAGERDUTY_KEY"
    OUTPUT+="\n"

    # OpenTelemetry / Distributed Tracing
    append_comment "OpenTelemetry / Distributed Tracing"
    append_var "OTEL_ENDPOINT" "http://otel-collector:4318/v1/traces"
    append_var "OTEL_EXPORTER_OTLP_ENDPOINT" "http://otel-collector:4318"
    OUTPUT+="\n"

    # Sentry Error Tracking
    append_comment "Sentry Error Tracking (REPLACE with actual DSN from Sentry)"
    append_var "SENTRY_DSN" "https://REPLACE_WITH_SENTRY_DSN@sentry.io/123456"
    append_var "SENTRY_ENVIRONMENT" "${SCOPE}"
    append_var "SENTRY_TRACES_SAMPLE_RATE" "0.1"
    OUTPUT+="\n"

    # HashiCorp Vault
    append_comment "HashiCorp Vault (REPLACE with actual credentials)"
    append_var "VAULT_TOKEN" "REPLACE_WITH_VAULT_TOKEN"
    append_var "VAULT_ADDR" "https://vault.example.com"
    append_var "VAULT_ROLE_ID" "REPLACE_WITH_ROLE_ID"
    append_var "VAULT_SECRET_ID" "REPLACE_WITH_SECRET_ID"
    append_var "VAULT_NAMESPACE" "security"
    OUTPUT+="\n"

    # AWS Secrets Manager
    append_comment "AWS Secrets Manager (REPLACE with actual credentials)"
    append_var "AWS_ACCESS_KEY_ID" "REPLACE_WITH_ACCESS_KEY"
    append_var "AWS_SECRET_ACCESS_KEY" "REPLACE_WITH_SECRET_KEY"
    append_var "AWS_REGION" "us-east-1"
    append_var "AWS_ROLE_ARN" "arn:aws:iam::123456789012:role/StrixSecretsRole"
    append_var "AWS_KMS_KEY_ID" "alias/strix-secrets"
    OUTPUT+="\n"

    # Azure Key Vault
    append_comment "Azure Key Vault (REPLACE with actual vault URL)"
    append_var "AZURE_KEYVAULT_URL" "https://strix-secrets.vault.azure.net"
    OUTPUT+="\n"

    # GCP Secret Manager
    append_comment "GCP Secret Manager (REPLACE with actual project)"
    append_var "GCP_PROJECT_ID" "my-gcp-project"
    append_var "GCP_CREDENTIALS_PATH" "/path/to/service-account.json"
    OUTPUT+="\n"

    # SMTP for Email Alerts
    append_comment "SMTP for Email Alerts"
    append_var "SMTP_HOST" "smtp.example.com"
    append_var "SMTP_PORT" "587"
    append_var "SMTP_USERNAME" "alertmanager"
    append_var "SMTP_FROM" "alertmanager@strix.example.com"
    OUTPUT+="\n"
fi

# ============================================================
# EXTERNAL SERVICE ENDPOINTS
# ============================================================
append_comment "============================================================================"
append_comment "EXTERNAL SERVICE ENDPOINTS"
append_comment "============================================================================"
OUTPUT+="\n"

append_comment "Prometheus / Alertmanager"
append_var "PROMETHEUS_URL" "http://prometheus:9090"
append_var "ALERTMANAGER_URL" "http://alertmanager:9093"
OUTPUT+="\n"

append_comment "Loki / Tempo"
append_var "LOKI_URL" "http://loki:3100"
append_var "TEMPO_URL" "http://tempo:3200"
OUTPUT+="\n"

append_comment "Grafana"
append_var "GRAFANA_URL" "http://grafana:3000"
OUTPUT+="\n"

# ============================================================
# SECURITY / HARDENING SETTINGS
# ============================================================
append_comment "============================================================================"
append_comment "SECURITY / HARDENING SETTINGS"
append_comment "============================================================================"
OUTPUT+="\n"

append_comment "TLS/SSL Configuration"
append_var "STRIX_TLS_ENABLED" "1"
if [[ "$SCOPE" == "production" ]]; then
    append_var "STRIX_TLS_CERT_PATH" "/etc/letsencrypt/live/strix.example.com/fullchain.pem"
    append_var "STRIX_TLS_KEY_PATH" "/etc/letsencrypt/live/strix.example.com/privkey.pem"
    append_var "STRIX_CERT_EMAIL" "security@example.com"
    append_var "STRIX_TLS_DOMAINS" "strix.example.com,api.strix.example.com"
else
    append_var "STRIX_TLS_CERT_PATH" "/etc/letsencrypt/live/strix-staging.example.com/fullchain.pem"
    append_var "STRIX_TLS_KEY_PATH" "/etc/letsencrypt/live/strix-staging.example.com/privkey.pem"
    append_var "STRIX_CERT_EMAIL" "security-staging@example.com"
    append_var "STRIX_TLS_DOMAINS" "strix-staging.example.com,api.strix-staging.example.com"
fi
OUTPUT+="\n"

# ============================================================
# PERFORMANCE TUNING
# ============================================================
append_comment "============================================================================"
append_comment "PERFORMANCE TUNING"
append_comment "============================================================================"
OUTPUT+="\n"

if [[ "$SCOPE" == "production" ]]; then
    append_var "STRIX_WORKER_MEMORY_MB" "2048"
    append_var "STRIX_REQUEST_TIMEOUT" "300"
    append_var "STRIX_MAX_CONCURRENT" "10"
else
    append_var "STRIX_WORKER_MEMORY_MB" "1024"
    append_var "STRIX_REQUEST_TIMEOUT" "300"
    append_var "STRIX_MAX_CONCURRENT" "5"
fi

# Write output
if [[ -n "$OUTPUT_FILE" ]]; then
    echo -e "$OUTPUT" > "$OUTPUT_FILE"
    chmod 600 "$OUTPUT_FILE"
    echo "Generated $OUTPUT_FILE with secure permissions (600)"
else
    echo -e "$OUTPUT"
fi

echo ""
echo "========================================="
echo "IMPORTANT NEXT STEPS:"
echo "========================================="
echo "1. Review the generated file and update domain names, emails, etc."
echo "2. Replace ALL integration placeholder values with actual credentials"
echo "3. Copy config/scope.${SCOPE}.json.example to config/scope.json and configure"
echo "4. Run ./scripts/validate-env.sh --env-file $OUTPUT_FILE --scope-file config/scope.json"
echo "5. For TLS: obtain certificates (Let's Encrypt or your CA) and update paths"
echo ""
echo "Integration secrets that MUST be manually configured:"
echo "  - Slack webhook URLs and bot/app tokens"
echo "  - Jira API token"
echo "  - GitHub/GitLab personal access tokens"
echo "  - Teams/Mattermost webhook URLs"
echo "  - Splunk HEC token"
echo "  - Datadog API key"
echo "  - Sentry DSN"
echo "  - Cloud provider credentials (AWS, Azure, GCP)"
echo "  - Vault credentials"
echo ""
echo "Security reminders:"
echo "  - NEVER commit .env.${SCOPE} to version control"
echo "  - Store backups in a password manager or secret manager"
echo "  - Rotate secrets periodically (recommended: every 90 days)"
echo "  - Use --integration flag to include integration placeholders"