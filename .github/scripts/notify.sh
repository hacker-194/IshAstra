#!/bin/bash
# Notification script for CI/CD pipeline
# Supports Slack and Microsoft Teams webhooks

set -euo pipefail

# Inputs
EVENT="${1:-unknown}"       # start, success, failure, smoke-success, smoke-failure, rollback, rollback-start, rollback-success, rollback-failure
ENVIRONMENT="${2:-unknown}" # staging, production
APPS="${3:-unknown}"        # comma-separated list of ArgoCD apps
COMMIT_SHA="${4:-unknown}"  # git commit SHA
REF="${5:-unknown}"         # git ref (branch or tag)

# Configuration from environment
SLACK_WEBHOOK="${SLACK_WEBHOOK_URL:-}"
TEAMS_WEBHOOK="${TEAMS_WEBHOOK_URL:-}"
REPO="${GITHUB_REPOSITORY:-unknown}"
RUN_URL="${GITHUB_SERVER_URL:-https://github.com}/${REPO}/actions/runs/${GITHUB_RUN_ID:-unknown}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Colors for Slack
declare -A SLACK_COLORS=(
  ["start"]="good"
  ["success"]="good"
  ["failure"]="danger"
  ["smoke-success"]="good"
  ["smoke-failure"]="warning"
  ["rollback"]="warning"
  ["rollback-start"]="warning"
  ["rollback-success"]="good"
  ["rollback-failure"]="danger"
)

# Emoji for messages
declare -A EMOJIS=(
  ["start"]="🚀"
  ["success"]="✅"
  ["failure"]="❌"
  ["smoke-success"]="✅"
  ["smoke-failure"]="⚠️"
  ["rollback"]="🔄"
  ["rollback-start"]="🔄"
  ["rollback-success"]="✅"
  ["rollback-failure"]="❌"
)

# Human-readable event names
declare -A EVENT_NAMES=(
  ["start"]="Deployment Started"
  ["success"]="Deployment Successful"
  ["failure"]="Deployment Failed"
  ["smoke-success"]="Smoke Tests Passed"
  ["smoke-failure"]="Smoke Tests Failed"
  ["rollback"]="Automated Rollback Triggered"
  ["rollback-start"]="Manual Rollback Started"
  ["rollback-success"]="Rollback Successful"
  ["rollback-failure"]="Rollback Failed"
)

# Build message
SHORT_SHA="${COMMIT_SHA:0:8}"
EVENT_NAME="${EVENT_NAMES[$EVENT]:-$EVENT}"
EMOJI="${EMOJIS[$EVENT]:-ℹ️}"
COLOR="${SLACK_COLORS[$EVENT]:-#808080}"

# Build fields for Slack/Teams
FIELDS=(
  "Environment: ${ENVIRONMENT}"
  "Applications: ${APPS}"
  "Commit: ${SHORT_SHA}"
  "Ref: ${REF}"
  "Time: ${TIMESTAMP}"
  "Run: <${RUN_URL}|View Run>"
)

# Create JSON payload for Slack
slack_payload() {
  local fields_json=""
  for field in "${FIELDS[@]}"; do
    local title=$(echo "$field" | cut -d: -f1)
    local value=$(echo "$field" | cut -d: -f2-)
    fields_json+="{\"title\":\"${title}\",\"value\":\"${value}\",\"short\":true},"
  done
  fields_json="${fields_json%,}"

  cat <<EOF
{
  "username": "Strix CI/CD",
  "icon_emoji": ":robot_face:",
  "attachments": [
    {
      "color": "${COLOR}",
      "title": "${EMOJI} ${EVENT_NAME} - ${REPO}",
      "title_link": "${RUN_URL}",
      "fields": [${fields_json}],
      "footer": "Strix Security Platform",
      "ts": $(date +%s)
    }
  ]
}
EOF
}

# Create JSON payload for Teams
teams_payload() {
  local facts_json=""
  for field in "${FIELDS[@]}"; do
    local title=$(echo "$field" | cut -d: -f1)
    local value=$(echo "$field" | cut -d: -f2-)
    facts_json+="{\"name\":\"${title}\",\"value\":\"${value}\"},"
  done
  facts_json="${facts_json%,}"

  cat <<EOF
{
  "@type": "MessageCard",
  "@context": "http://schema.org/extensions",
  "themeColor": "${COLOR}",
  "summary": "${EVENT_NAME} - ${REPO}",
  "sections": [
    {
      "activityTitle": "${EMOJI} ${EVENT_NAME}",
      "activitySubtitle": "${REPO}",
      "facts": [${facts_json}],
      "markdown": true
    }
  ],
  "potentialAction": [
    {
      "@type": "OpenUri",
      "name": "View Run",
      "targets": [
        {
          "os": "default",
          "uri": "${RUN_URL}"
        }
      ]
    }
  ]
}
EOF
}

# Send to Slack
if [[ -n "${SLACK_WEBHOOK}" ]]; then
  echo "Sending notification to Slack..."
  PAYLOAD=$(slack_payload)
  curl -s -X POST -H 'Content-type: application/json' \
    --data "${PAYLOAD}" \
    "${SLACK_WEBHOOK}" || echo "Warning: Slack notification failed"
fi

# Send to Teams
if [[ -n "${TEAMS_WEBHOOK}" ]]; then
  echo "Sending notification to Microsoft Teams..."
  PAYLOAD=$(teams_payload)
  curl -s -X POST -H 'Content-type: application/json' \
    --data "${PAYLOAD}" \
    "${TEAMS_WEBHOOK}" || echo "Warning: Teams notification failed"
fi

# Log to console for debugging
echo "Notification sent: ${EVENT} for ${ENVIRONMENT} (${APPS})"