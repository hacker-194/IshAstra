#!/usr/bin/env bash






set -euo pipefail


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'


ENV_FILE="${1:-.env.production}"
SCOPE_FILE="${2:-config/scope.json}"
TLS_ENABLED="${ISHASTRA_TLS_ENABLED:-0}"


while [[ $
    case $1 in
        --env-file)
            ENV_FILE="$2"
            shift 2
            ;;
        --scope-file)
            SCOPE_FILE="$2"
            shift 2
            ;;
        --tls-enabled)
            TLS_ENABLED=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--env-file FILE] [--scope-file FILE] [--tls-enabled]"
            echo "  --env-file     Path to .env file (default: .env.production)"
            echo "  --scope-file   Path to scope.json (default: config/scope.json)"
            echo "  --tls-enabled  Validate TLS certificates exist"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done


if [[ ! -f "$ENV_FILE" ]]; then
    echo -e "${RED}✗ Error: Environment file not found: $ENV_FILE${NC}"
    exit 1
fi


set -a
source "$ENV_FILE"
set +a

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           Ishastra Environment Validation                       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo "Env file: $ENV_FILE"
echo "Scope file: $SCOPE_FILE"
echo "TLS enabled: $TLS_ENABLED"
echo ""


ERRORS=0
WARNINGS=0


check_var() {
    local var_name="$1"
    local var_value="${!var_name:-}"
    local description="$2"
    local required="${3:-true}"
    local is_base64="${4:-false}"
    local min_length="${5:-1}"

    if [[ -z "$var_value" ]]; then
        if [[ "$required" == "true" ]]; then
            echo -e "${RED}✗ MISSING: $var_name${NC} - $description"
            ((ERRORS++))
        else
            echo -e "${YELLOW}⚠ OPTIONAL: $var_name${NC} - $description (not set)"
            ((WARNINGS++))
        fi
        return 1
    fi

    if [[ ${
        echo -e "${RED}✗ TOO SHORT: $var_name${NC} - $description (length: ${#var_value}, min: $min_length)"
        ((ERRORS++))
        return 1
    fi

    if [[ "$is_base64" == "true" ]]; then
        if ! echo "$var_value" | base64 -d >/dev/null 2>&1; then
            echo -e "${RED}✗ INVALID BASE64: $var_name${NC} - $description"
            ((ERRORS++))
            return 1
        fi

        local decoded_len
        decoded_len=$(echo -n "$var_value" | base64 -d | wc -c)
        if [[ $decoded_len -lt 32 ]]; then
            echo -e "${RED}✗ TOO SHORT (decoded): $var_name${NC} - $description (decoded: ${decoded_len} bytes, min: 32)"
            ((ERRORS++))
            return 1
        fi
    fi


    local masked="${var_value:0:4}****${var_value: -4}"
    if [[ ${
        masked="****"
    fi
    echo -e "${GREEN}✓ OK: $var_name${NC} = $masked"
    return 0
}

check_file() {
    local file_path="$1"
    local description="$2"
    local required="${3:-true}"

    if [[ ! -f "$file_path" ]]; then
        if [[ "$required" == "true" ]]; then
            echo -e "${RED}✗ MISSING FILE: $file_path${NC} - $description"
            ((ERRORS++))
        else
            echo -e "${YELLOW}⚠ OPTIONAL FILE: $file_path${NC} - $description (not found)"
            ((WARNINGS++))
        fi
        return 1
    fi

    echo -e "${GREEN}✓ FILE EXISTS: $file_path${NC} - $description"
    return 0
}

check_json() {
    local file_path="$1"
    local description="$2"

    if [[ ! -f "$file_path" ]]; then
        echo -e "${RED}✗ MISSING: $file_path${NC} - $description"
        ((ERRORS++))
        return 1
    fi

    if ! jq -e . "$file_path" >/dev/null 2>&1; then
        echo -e "${RED}✗ INVALID JSON: $file_path${NC} - $description"
        ((ERRORS++))
        return 1
    fi


    local program
    program=$(jq -r '.program // empty' "$file_path")
    local authorized_by
    authorized_by=$(jq -r '.authorized_by // empty' "$file_path")
    local include
    include=$(jq -r '.include // empty' "$file_path")

    if [[ -z "$program" || -z "$authorized_by" || -z "$include" ]]; then
        echo -e "${RED}✗ INVALID SCOPE: $file_path${NC} - Missing required fields (program, authorized_by, include)"
        ((ERRORS++))
        return 1
    fi

    echo -e "${GREEN}✓ VALID JSON: $file_path${NC} - $description (program: $program)"
    return 0
}

check_tls_certs() {
    local cert_path="$1"
    local key_path="$2"

    if [[ ! -f "$cert_path" ]]; then
        echo -e "${RED}✗ TLS CERT NOT FOUND: $cert_path${NC}"
        ((ERRORS++))
        return 1
    fi

    if [[ ! -f "$key_path" ]]; then
        echo -e "${RED}✗ TLS KEY NOT FOUND: $key_path${NC}"
        ((ERRORS++))
        return 1
    fi


    if ! openssl x509 -noout -modulus -in "$cert_path" 2>/dev/null | openssl md5 | grep -q "$(openssl rsa -noout -modulus -in "$key_path" 2>/dev/null | openssl md5)"; then
        echo -e "${YELLOW}⚠ TLS CERT/KEY MISMATCH: $cert_path / $key_path${NC}"
        ((WARNINGS++))
    else
        echo -e "${GREEN}✓ TLS CERT/KEY PAIR VALID${NC}"
    fi


    local expiry
    expiry=$(openssl x509 -noout -enddate -in "$cert_path" 2>/dev/null | cut -d= -f2)
    if [[ -n "$expiry" ]]; then
        local expiry_epoch
        expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry" +%s 2>/dev/null)
        local now_epoch
        now_epoch=$(date +%s)
        local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

        if [[ $days_left -lt 30 ]]; then
            echo -e "${RED}✗ TLS CERT EXPIRES SOON: $days_left days${NC} ($expiry)"
            ((ERRORS++))
        elif [[ $days_left -lt 60 ]]; then
            echo -e "${YELLOW}⚠ TLS CERT EXPIRES IN: $days_left days${NC} ($expiry)"
            ((WARNINGS++))
        else
            echo -e "${GREEN}✓ TLS CERT VALID: $days_left days remaining${NC} ($expiry)"
        fi
    fi

    return 0
}





echo -e "${BLUE}--- Core Required Variables ---${NC}"


check_var "ISHASTRA_API_KEY" "API authentication key (base64, 32+ bytes)" true true 44
check_var "ISHASTRA_AUDIT_HMAC_KEY" "Audit HMAC key (base64, 32+ bytes)" true true 44
check_var "ISHASTRA_WEBHOOK_SECRET" "Webhook HMAC secret (min 16 chars)" true false 16


check_var "ISHASTRA_DB" "Database path/URL" true false 1
check_var "ISHASTRA_SCOPE_FILE" "Scope file path" true false 1
check_var "ISHASTRA_SCOPE_MODE" "Scope mode (auto|strict|permissive)" true false 1


check_var "ISHASTRA_WORKERS" "Number of worker threads" true false 1
check_var "ISHASTRA_QUEUE_MAX" "Max queue size per worker" true false 1
check_var "ISHASTRA_RETENTION_DAYS" "Evidence retention days" true false 1
check_var "ISHASTRA_QUEUE_MODE" "Queue mode (inprocess|celery)" true false 1


check_var "ISHASTRA_REDIS_URL" "Redis connection URL" true false 1
check_var "ISHASTRA_REDIS_PASSWORD" "Redis password" false false 1
check_var "ISHASTRA_REDIS_REQUIRED" "Require Redis (1/0)" true false 1


check_var "ISHASTRA_CELERY_BROKER_URL" "Celery broker URL" false false 1
check_var "ISHASTRA_CELERY_RESULT_BACKEND" "Celery result backend" false false 1


check_var "ISHASTRA_LOG_FORMAT" "Log format (json|text)" true false 1
check_var "ISHASTRA_LOG_LEVEL" "Log level (DEBUG|INFO|WARN|ERROR)" true false 1


check_var "ISHASTRA_TRUSTED_PROXIES" "Trusted proxy CIDRs" true false 1


check_var "GRAFANA_PASSWORD" "Grafana admin password" true false 8

echo ""
echo -e "${BLUE}--- Integration Variables (optional but recommended) ---${NC}"


check_var "SMTP_PASSWORD" "SMTP password for alerts" false false 1
check_var "ALERTMANAGER_WEBHOOK_URL" "Alertmanager webhook URL" false false 1


check_var "SLACK_WEBHOOK_URL" "Slack webhook URL" false false 1


check_var "JIRA_API_TOKEN" "Jira API token" false false 1
check_var "JIRA_BASE_URL" "Jira base URL" false false 1


check_var "GITHUB_TOKEN" "GitHub PAT (ghp_...)" false false 1


check_var "GITLAB_TOKEN" "GitLab PAT (glpat_...)" false false 1


check_var "TEAMS_WEBHOOK_URL" "Teams webhook URL" false false 1


check_var "SPLUNK_HEC_TOKEN" "Splunk HEC token" false false 1


check_var "DATADOG_API_KEY" "Datadog API key" false false 1


check_var "ELASTIC_API_KEY" "Elastic API key (base64)" false true 1


check_var "SENTINEL_WORKSPACE_ID" "Sentinel workspace ID" false false 1
check_var "SENTINEL_SHARED_KEY" "Sentinel shared key (base64)" false true 1


check_var "SERVICENOW_PASSWORD" "ServiceNow password" false false 1


check_var "PAGERDUTY_SERVICE_KEY" "PagerDuty service key" false false 1


check_var "OTEL_ENDPOINT" "OTLP endpoint URL" false false 1


check_var "SENTRY_DSN" "Sentry DSN" false false 1


check_var "VAULT_TOKEN" "Vault token" false false 1
check_var "VAULT_ADDR" "Vault address" false false 1


check_var "AWS_ACCESS_KEY_ID" "AWS access key" false false 1
check_var "AWS_SECRET_ACCESS_KEY" "AWS secret key" false false 1


check_var "AZURE_KEYVAULT_URL" "Azure Key Vault URL" false false 1


check_var "GCP_PROJECT_ID" "GCP project ID" false false 1

echo ""
echo -e "${BLUE}--- Scope Configuration ---${NC}"
check_json "$SCOPE_FILE" "Scope configuration"

echo ""
echo -e "${BLUE}--- TLS Certificates ---${NC}"
if [[ "$TLS_ENABLED" == "1" || "$ISHASTRA_TLS_ENABLED" == "1" ]]; then
    check_tls_certs "${ISHASTRA_TLS_CERT_PATH:-/etc/letsencrypt/live/ishastra.example.com/fullchain.pem}" \
                    "${ISHASTRA_TLS_KEY_PATH:-/etc/letsencrypt/live/ishastra.example.com/privkey.pem}"
else
    echo -e "${YELLOW}⚠ TLS validation skipped (ISHASTRA_TLS_ENABLED not set)${NC}"
    ((WARNINGS++))
fi

echo ""
echo -e "${BLUE}--- Placeholder Detection ---${NC}"

PLACEHOLDER_VARS=(
    "ISHASTRA_API_KEY"
    "ISHASTRA_AUDIT_HMAC_KEY"
    "ISHASTRA_WEBHOOK_SECRET"
    "ISHASTRA_REDIS_PASSWORD"
    "GRAFANA_PASSWORD"
    "SLACK_WEBHOOK_URL"
    "JIRA_API_TOKEN"
    "GITHUB_TOKEN"
    "GITLAB_TOKEN"
    "TEAMS_WEBHOOK_URL"
    "SPLUNK_HEC_TOKEN"
    "DATADOG_API_KEY"
    "SENTRY_DSN"
)

for var in "${PLACEHOLDER_VARS[@]}"; do
    val="${!var:-}"
    if [[ "$val" == REPLACE_* ]] || [[ "$val" == "REPLACE_WITH_"* ]] || [[ "$val" == *"REPLACE"* ]]; then
        echo -e "${RED}✗ PLACEHOLDER DETECTED: $var${NC} = $val"
        ((ERRORS++))
    fi
done




echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                     Validation Summary                       ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"

if [[ $ERRORS -eq 0 && $WARNINGS -eq 0 ]]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    exit 0
elif [[ $ERRORS -eq 0 ]]; then
    echo -e "${YELLOW}⚠ Validation passed with $WARNINGS warning(s)${NC}"
    exit 0
else
    echo -e "${RED}✗ Validation failed with $ERRORS error(s) and $WARNINGS warning(s)${NC}"
    exit 1
fi