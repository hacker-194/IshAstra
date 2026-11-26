#!/usr/bin/env bash














set -euo pipefail


OUTPUT_FILE=""
SCOPE="production"
INCLUDE_INTEGRATIONS=false
FORCE=false


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
Ishastra Secret Generation Script
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

  ./scripts/generate-secrets.sh


  ./scripts/generate-secrets.sh --output .env.production --scope production


  ./scripts/generate-secrets.sh --output .env.staging --scope staging --integration


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


gen_base64() {
    local bytes="${1:-32}"
    openssl rand -base64 "$bytes" | tr -d '\n'
}


gen_hex() {
    local bytes="${1:-32}"
    openssl rand -hex "$bytes" | tr -d '\n'
}


gen_urlsafe_base64() {
    local bytes="${1:-32}"
    openssl rand -base64 "$bytes" | tr '+/' '-_' | tr -d '=' | tr -d '\n'
}


gen_password() {
    local length="${1:-24}"

    openssl rand -base64 "$length" | tr -d '=+/' | cut -c1-"$length"
}


append_var() {
    local key="$1"
    local value="$2"
    OUTPUT+="${key}=${value}\n"
}


append_comment() {
    OUTPUT+="# $1\n"
}


if [[ -n "$OUTPUT_FILE" && -f "$OUTPUT_FILE" && "$FORCE" != "true" ]]; then
    read -rp "File $OUTPUT_FILE exists. Overwrite? [y/N] " -n 1
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi


OUTPUT=""


append_comment "Ishastra ${SCOPE^} Environment Configuration"
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




append_comment "Core API authentication (base64, 32+ bytes / 44+ chars)"
append_var "ISHASTRA_API_KEY" "$(gen_base64 32)"
append_comment "HMAC key for audit log integrity verification (base64, 32+ bytes)"
append_var "ISHASTRA_AUDIT_HMAC_KEY" "$(gen_base64 32)"
append_comment "Webhook HMAC secret for verifying inbound webhook signatures (hex, 32 bytes)"
append_var "ISHASTRA_WEBHOOK_SECRET" "$(gen_hex 32)"
append_comment "Encryption key for webhook secrets at rest (base64, 32 bytes, AES-GCM)"
append_var "ISHASTRA_ENCRYPTION_KEY" "$(gen_base64 32)"
OUTPUT+="\n"


append_comment "Database & Scope Configuration"
append_var "ISHASTRA_DB" "/var/lib/ishastra/ishastra.db"
append_var "ISHASTRA_SCOPE_FILE" "/etc/ishastra/scope.json"
append_var "ISHASTRA_SCOPE_MODE" "auto"
OUTPUT+="\n"


append_comment "Worker & Queue Configuration"
if [[ "$SCOPE" == "production" ]]; then
    append_var "ISHASTRA_WORKERS" "4"
    append_var "ISHASTRA_QUEUE_MAX" "32"
    append_var "ISHASTRA_RETENTION_DAYS" "90"
else
    append_var "ISHASTRA_WORKERS" "2"
    append_var "ISHASTRA_QUEUE_MAX" "16"
    append_var "ISHASTRA_RETENTION_DAYS" "30"
fi
append_var "ISHASTRA_QUEUE_MODE" "inprocess"
OUTPUT+="\n"


append_comment "Redis Configuration"
append_var "ISHASTRA_REDIS_URL" "redis://redis:6379/0"
append_var "ISHASTRA_REDIS_PASSWORD" "$(gen_base64 24)"
append_var "ISHASTRA_REDIS_REQUIRED" "1"
OUTPUT+="\n"



append_comment "PostgreSQL Configuration (Docker Compose)"
append_comment "Owner runs migrations; the app role is non-owner and has no CREATE"
append_var "POSTGRES_PASSWORD" "$(gen_hex 24)"
append_var "ISHASTRA_APP_PASSWORD" "$(gen_hex 24)"
OUTPUT+="\n"


append_comment "Logging Configuration"
if [[ "$SCOPE" == "production" ]]; then
    append_var "ISHASTRA_LOG_FORMAT" "json"
    append_var "ISHASTRA_LOG_LEVEL" "INFO"
    append_var "ISHASTRA_DEBUG" "0"
else
    append_var "ISHASTRA_LOG_FORMAT" "json"
    append_var "ISHASTRA_LOG_LEVEL" "DEBUG"
    append_var "ISHASTRA_DEBUG" "0"
fi
OUTPUT+="\n"


append_comment "Networking"
append_var "ISHASTRA_TRUSTED_PROXIES" "172.28.0.0/24"
OUTPUT+="\n"


append_comment "Grafana Admin Password"
append_var "GRAFANA_PASSWORD" "$(gen_password 24)"
append_var "KEYCLOAK_ADMIN_PASSWORD" "$(gen_password 24)"
OUTPUT+="\n"




if [[ "$INCLUDE_INTEGRATIONS" == "true" ]]; then
    append_comment "============================================================================"
    append_comment "INTEGRATION SECRETS"
    append_comment "============================================================================"
    append_comment "IMPORTANT: These are PLACEHOLDERS. Replace with actual credentials from"
    append_comment "each service. This script cannot generate valid credentials for external"
    append_comment "services. You must obtain these from the respective service consoles."
    append_comment "============================================================================"
    OUTPUT+="\n"


    append_comment "Alertmanager / SMTP"
    append_var "SMTP_PASSWORD" "$(gen_password 24)"
    append_var "ALERTMANAGER_WEBHOOK_URL" "https://alertmanager.example.com/webhook"
    OUTPUT+="\n"


    append_comment "Slack Integration (REPLACE with actual webhook URLs from Slack App)"
    append_var "SLACK_WEBHOOK_URL" "https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>"
    append_var "SLACK_WEBHOOK_URL_CRITICAL" "https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>"
    append_var "SLACK_WEBHOOK_URL_SECURITY" "https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>"
    append_var "SLACK_BOT_TOKEN" "xoxb-REPLACE_WITH_BOT_TOKEN"
    append_var "SLACK_APP_TOKEN" "xapp-REPLACE_WITH_APP_TOKEN"
    OUTPUT+="\n"


    append_comment "Jira Integration (REPLACE with actual API token from Atlassian)"
    append_var "JIRA_API_TOKEN" "REPLACE_WITH_JIRA_API_TOKEN"
    append_var "JIRA_BASE_URL" "https://company.atlassian.net"
    append_var "JIRA_EMAIL" "security@company.com"
    OUTPUT+="\n"


    append_comment "GitHub Integration (REPLACE with actual PAT from GitHub Settings)"
    append_var "GITHUB_TOKEN" "ghp_REPLACE_WITH_GITHUB_PAT"
    append_var "GITHUB_ACTIONS_TOKEN" "ghp_REPLACE_WITH_ACTIONS_TOKEN"
    append_var "GITHUB_OWNER" "myorg"
    append_var "GITHUB_REPO" "security-tracking"
    OUTPUT+="\n"


    append_comment "GitLab Integration (REPLACE with actual PAT from GitLab Settings)"
    append_var "GITLAB_TOKEN" "glpat_REPLACE_WITH_GITLAB_TOKEN"
    append_var "GITLAB_CI_TOKEN" "glptt_REPLACE_WITH_CI_TOKEN"
    append_var "GITLAB_BASE_URL" "https://gitlab.com"
    OUTPUT+="\n"


    append_comment "Microsoft Teams (REPLACE with actual webhook URL)"
    append_var "TEAMS_WEBHOOK_URL" "https://outlook.office.com/webhook/REPLACE_WITH_TEAMS_WEBHOOK"
    OUTPUT+="\n"


    append_comment "Mattermost (REPLACE with actual webhook URL)"
    append_var "MATTERMOST_WEBHOOK_URL" "https://mattermost.example.com/hooks/REPLACE_WITH_HOOK"
    OUTPUT+="\n"


    append_comment "Splunk HEC (REPLACE with actual HEC token)"
    append_var "SPLUNK_HEC_TOKEN" "REPLACE_WITH_SPLUNK_HEC_TOKEN"
    append_var "SPLUNK_HOST" "splunk.example.com"
    append_var "SPLUNK_PORT" "8088"
    OUTPUT+="\n"


    append_comment "Datadog (REPLACE with actual API key)"
    append_var "DATADOG_API_KEY" "REPLACE_WITH_DATADOG_API_KEY"
    append_var "DATADOG_SITE" "datadoghq.com"
    OUTPUT+="\n"


    append_comment "Elasticsearch / Elastic Cloud (REPLACE with actual credentials)"
    append_var "ELASTIC_API_KEY" "REPLACE_WITH_ELASTIC_API_KEY"
    append_var "ELASTIC_CLOUD_ID" "REPLACE_WITH_CLOUD_ID"
    append_var "ELASTIC_PASSWORD" "REPLACE_WITH_ELASTIC_PASSWORD"
    OUTPUT+="\n"


    append_comment "Azure Sentinel (REPLACE with actual workspace credentials)"
    append_var "SENTINEL_WORKSPACE_ID" "REPLACE_WITH_WORKSPACE_ID"
    append_var "SENTINEL_SHARED_KEY" "REPLACE_WITH_BASE64_SHARED_KEY"
    append_var "AZURE_TENANT_ID" "REPLACE_WITH_TENANT_ID"
    append_var "AZURE_CLIENT_ID" "REPLACE_WITH_CLIENT_ID"
    append_var "AZURE_CLIENT_SECRET" "REPLACE_WITH_CLIENT_SECRET"
    OUTPUT+="\n"


    append_comment "ServiceNow (REPLACE with actual credentials)"
    append_var "SERVICENOW_PASSWORD" "REPLACE_WITH_SERVICENOW_PASSWORD"
    append_var "SERVICENOW_CLIENT_ID" "REPLACE_WITH_CLIENT_ID"
    append_var "SERVICENOW_CLIENT_SECRET" "REPLACE_WITH_CLIENT_SECRET"
    append_var "SERVICENOW_INSTANCE_URL" "https://company.service-now.com"
    OUTPUT+="\n"


    append_comment "PagerDuty (REPLACE with actual service key)"
    append_var "PAGERDUTY_SERVICE_KEY" "REPLACE_WITH_PAGERDUTY_KEY"
    OUTPUT+="\n"


    append_comment "OpenTelemetry / Distributed Tracing"
    append_var "OTEL_ENDPOINT" "http://otel-collector:4318/v1/traces"
    append_var "OTEL_EXPORTER_OTLP_ENDPOINT" "http://otel-collector:4318"
    OUTPUT+="\n"


    append_comment "Sentry Error Tracking (REPLACE with actual DSN from Sentry)"
    append_var "SENTRY_DSN" "https://REPLACE_WITH_SENTRY_DSN@sentry.io/123456"
    append_var "SENTRY_ENVIRONMENT" "${SCOPE}"
    append_var "SENTRY_TRACES_SAMPLE_RATE" "0.1"
    OUTPUT+="\n"


    append_comment "HashiCorp Vault (REPLACE with actual credentials)"
    append_var "VAULT_TOKEN" "REPLACE_WITH_VAULT_TOKEN"
    append_var "VAULT_ADDR" "https://vault.example.com"
    append_var "VAULT_ROLE_ID" "REPLACE_WITH_ROLE_ID"
    append_var "VAULT_SECRET_ID" "REPLACE_WITH_SECRET_ID"
    append_var "VAULT_NAMESPACE" "security"
    OUTPUT+="\n"


    append_comment "AWS Secrets Manager (REPLACE with actual credentials)"
    append_var "AWS_ACCESS_KEY_ID" "REPLACE_WITH_ACCESS_KEY"
    append_var "AWS_SECRET_ACCESS_KEY" "REPLACE_WITH_SECRET_KEY"
    append_var "AWS_REGION" "us-east-1"
    append_var "AWS_ROLE_ARN" "arn:aws:iam::123456789012:role/IshastraSecretsRole"
    append_var "AWS_KMS_KEY_ID" "alias/ishastra-secrets"
    OUTPUT+="\n"


    append_comment "Azure Key Vault (REPLACE with actual vault URL)"
    append_var "AZURE_KEYVAULT_URL" "https://ishastra-secrets.vault.azure.net"
    OUTPUT+="\n"


    append_comment "GCP Secret Manager (REPLACE with actual project)"
    append_var "GCP_PROJECT_ID" "my-gcp-project"
    append_var "GCP_CREDENTIALS_PATH" "/path/to/service-account.json"
    OUTPUT+="\n"


    append_comment "SMTP for Email Alerts"
    append_var "SMTP_HOST" "smtp.example.com"
    append_var "SMTP_PORT" "587"
    append_var "SMTP_USERNAME" "alertmanager"
    append_var "SMTP_FROM" "alertmanager@ishastra.example.com"
    OUTPUT+="\n"
fi




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




append_comment "============================================================================"
append_comment "SECURITY / HARDENING SETTINGS"
append_comment "============================================================================"
OUTPUT+="\n"

append_comment "TLS/SSL Configuration"
append_var "ISHASTRA_TLS_ENABLED" "1"
if [[ "$SCOPE" == "production" ]]; then
    append_var "ISHASTRA_TLS_CERT_PATH" "/etc/letsencrypt/live/ishastra.example.com/fullchain.pem"
    append_var "ISHASTRA_TLS_KEY_PATH" "/etc/letsencrypt/live/ishastra.example.com/privkey.pem"
    append_var "ISHASTRA_CERT_EMAIL" "security@example.com"
    append_var "ISHASTRA_TLS_DOMAINS" "ishastra.example.com,api.ishastra.example.com"
else
    append_var "ISHASTRA_TLS_CERT_PATH" "/etc/letsencrypt/live/ishastra-staging.example.com/fullchain.pem"
    append_var "ISHASTRA_TLS_KEY_PATH" "/etc/letsencrypt/live/ishastra-staging.example.com/privkey.pem"
    append_var "ISHASTRA_CERT_EMAIL" "security-staging@example.com"
    append_var "ISHASTRA_TLS_DOMAINS" "ishastra-staging.example.com,api.ishastra-staging.example.com"
fi
OUTPUT+="\n"




append_comment "============================================================================"
append_comment "PERFORMANCE TUNING"
append_comment "============================================================================"
OUTPUT+="\n"

if [[ "$SCOPE" == "production" ]]; then
    append_var "ISHASTRA_WORKER_MEMORY_MB" "2048"
    append_var "ISHASTRA_REQUEST_TIMEOUT" "300"
    append_var "ISHASTRA_MAX_CONCURRENT" "10"
else
    append_var "ISHASTRA_WORKER_MEMORY_MB" "1024"
    append_var "ISHASTRA_REQUEST_TIMEOUT" "300"
    append_var "ISHASTRA_MAX_CONCURRENT" "5"
fi


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