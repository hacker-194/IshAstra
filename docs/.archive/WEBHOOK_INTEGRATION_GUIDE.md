# Strix Webhook Integration Guide

## Overview

Strix supports **outbound webhooks** for real-time alerting on assessment results. Webhooks are configured by administrators and deliver JSON payloads to your HTTP endpoints.

---

## Quick Start

### 1. Configure Webhook (Admin Only)

```bash
curl -X POST https://strix.example.com/api/alerts/webhook \
  -H "Authorization: Bearer sk_admin_..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "slack-alerts",
    "url": "https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>"
  }'
```

### 2. Configure Monitor Targets (Admin Only)

```bash
curl -X POST https://strix.example.com/api/monitor/configure \
  -H "Authorization: Bearer sk_admin_..." \
  -H "Content-Type: application/json" \
  -d '{
    "interval_seconds": 300,
    "targets": ["https://example.com", "https://api.example.com"],
    "replace": true
  }'
```

### 3. Receive Alerts

Your endpoint receives POST requests with assessment results.

---

## Webhook Payload Format

Two different things are called a webhook here, and only one exists in this build:

1. **Monitor alerts (implemented).** `WebhookAlertSink` in `src/strix/monitor.py`
   POSTs `json.dumps(redact(alert))` to a pinned destination, signed with
   `STRIX_WEBHOOK_SECRET`, with bounded retries. The alert body carries `rule_name`, `severity`, `target`, `message`, `job`, `findings`, `category`, `title`, `location`.
2. **Assessment-completed events (not emitted).** Strix does not POST a
   job-completion event today. The JSON below is an *example schema for a sender
   you write yourself*; the receiver samples in this guide read fields with
   `.get()` so they also work when the body is the monitor alert above.

## Security

### Signature Verification

Each webhook includes a `X-Strix-Signature` header for verification:

```
X-Strix-Signature: sha256=abc123def456...
```

**Verification (Python):**
```python
import hmac
import hashlib

def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    """Verify webhook signature."""
    expected = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    # Signature format: "sha256=<hex>"
    provided = signature.replace("sha256=", "")
    return hmac.compare_digest(expected, provided)

# Usage
from flask import request

@app.route("/webhook", methods=["POST"])
def webhook():
    signature = request.headers.get("X-Strix-Signature")
    if not verify_webhook(request.get_data(), signature, WEBHOOK_SECRET):
        return "Invalid signature", 401
    
    process_alert(request.json)
    return "OK", 200
```

**Secret Configuration:**
The webhook secret is set via `STRIX_WEBHOOK_SECRET` environment variable (32+ random bytes, base64 encoded). All webhooks share the same secret.

### IP Allowlist (Recommended)

Strix webhooks originate from your Strix deployment IPs. Configure your firewall/load balancer to only accept webhook traffic from these IPs.

### HTTPS Required

Webhook URLs **must** use HTTPS. HTTP URLs are rejected at registration.

---

## Retry Policy

| Attempt | Delay | Cumulative |
|---------|-------|------------|
| 1 | Immediate | 0s |
| 2 | 10 seconds | 10s |
| 3 | 30 seconds | 40s |
| 4 | 1 minute | 1m 40s |
| 5 | 5 minutes | 6m 40s |
| 6 | 15 minutes | 21m 40s |
| 7 | 1 hour | 1h 21m |

- **Max retries:** 7
- **Total window:** ~1 hour 22 minutes
- **Timeout:** 10 seconds per attempt
- **Success:** 2xx response within timeout
- **Failure:** Non-2xx, timeout, or connection error

After max retries, the alert is logged but not retried further.

---

## Integration Examples

### Slack

**Webhook URL:** `https://hooks.slack.com/services/<WORKSPACE_ID>/<CHANNEL_ID>/<TOKEN>`

**Custom Payload (via Slack Workflow Builder or middleware):**
```json
{
  "blocks": [
    {
      "type": "header",
      "text": {"type": "plain_text", "text": "🔴 Strix Alert: Critical Findings"}
    },
    {
      "type": "section",
      "fields": [
        {"type": "mrkdwn", "text": "*Target:*\nhttps://example.com"},
        {"type": "mrkdwn", "text": "*Profile:*\nweb-deep"},
        {"type": "mrkdwn", "text": "*Verdict:*\nFAIL"},
        {"type": "mrkdwn", "text": "*Job:*\njob_abc123"}
      ]
    },
    {
      "type": "section",
      "text": {"type": "mrkdwn", "text": "*Top Findings:*\n• SQL Injection (Critical)\n• XSS (High)\n• IDOR (Medium)"}
    },
    {
      "type": "actions",
      "elements": [
        {
          "type": "button",
          "text": {"type": "plain_text", "text": "View Report"},
          "url": "https://strix.example.com/api/assess/job_abc123/report.html",
          "style": "primary"
        }
      ]
    }
  ]
}
```

### Microsoft Teams

**Webhook URL:** `https://outlook.office.com/webhook/...`

```json
{
  "@type": "MessageCard",
  "@context": "http://schema.org/extensions",
  "themeColor": "FF0000",
  "summary": "Strix Security Alert",
  "sections": [
    {
      "activityTitle": "🔴 Strix Assessment Completed",
      "activitySubtitle": "Critical findings detected",
      "facts": [
        {"name": "Target", "value": "https://example.com"},
        {"name": "Profile", "value": "web-deep"},
        {"name": "Verdict", "value": "FAIL"},
        {"name": "Job ID", "value": "job_abc123"}
      ],
      "markdown": true
    },
    {
      "title": "Top Findings",
      "text": "• **SQL Injection** (Critical) - Search parameter\n• **XSS** (High) - Reflected in results\n• **IDOR** (Medium) - User endpoint"
    }
  ],
  "potentialAction": [
    {
      "@type": "OpenUri",
      "name": "View Report",
      "targets": [{"os": "default", "uri": "https://strix.example.com/api/assess/job_abc123/report.html"}]
    }
  ]
}
```

### PagerDuty

**Webhook URL:** `https://events.pagerduty.com/v2/enqueue`

```json
{
  "routing_key": "YOUR_INTEGRATION_KEY",
  "event_action": "trigger",
  "dedup_key": "strix-job_abc123",
  "payload": {
    "summary": "Strix: Critical findings on https://example.com",
    "source": "strix",
    "severity": "critical",
    "component": "example.com",
    "group": "security",
    "class": "vulnerability",
    "custom_details": {
      "job_id": "job_abc123",
      "profile": "web-deep",
      "verdict": "fail",
      "findings": [
        {"category": "SQL Injection", "severity": "critical", "location": "https://example.com/search?q=test"},
        {"category": "XSS", "severity": "high", "location": "https://example.com/search?q=<script>"}
      ],
      "report_url": "https://strix.example.com/api/assess/job_abc123/report.html"
    }
  }
}
```

### Generic HTTP Endpoint

**Simple receiver (Flask):**
```python
from flask import Flask, request, jsonify
import hmac
import hashlib
import os

app = Flask(__name__)
WEBHOOK_SECRET = os.environ["STRIX_WEBHOOK_SECRET"]

def verify_signature(payload, signature):
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    provided = signature.replace("sha256=", "")
    return hmac.compare_digest(expected, provided)

@app.route("/strix-webhook", methods=["POST"])
def strix_webhook():
    signature = request.headers.get("X-Strix-Signature")
    if not signature or not verify_signature(request.get_data(), signature):
        return jsonify({"error": "Invalid signature"}), 401
    
    data = request.json
    event = data.get("event")
    
    if event == "assessment_completed":
        handle_completed(data)
    elif event == "assessment_failed":
        handle_failed(data)
    elif event == "schedule_triggered":
        handle_schedule(data)
    
    return jsonify({"status": "received"}), 200

def handle_completed(data):
    verdict = data.get("verdict", "")
    target = data["target"]
    critical = data.get("severity_counts", {}).get("critical", 0)
    high = data.get("severity_counts", {}).get("high", 0)
    
    if critical > 0 or high > 0:
        # Page on-call, create ticket, etc.
        create_incident(target, data["job_id"], data["findings"])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
```

### AWS Lambda + API Gateway

```python
import json
import hmac
import hashlib
import os
import boto3

WEBHOOK_SECRET = os.environ["STRIX_WEBHOOK_SECRET"]
SNS_TOPIC_ARN = os.environ["ALERT_SNS_TOPIC"]

sns = boto3.client("sns")

def verify_signature(payload, signature):
    expected = hmac.new(
        WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()
    provided = signature.replace("sha256=", "")
    return hmac.compare_digest(expected, provided)

def lambda_handler(event, context):
    signature = event.get("headers", {}).get("X-Strix-Signature")
    body = event.get("body", "")
    
    if not signature or not verify_signature(body.encode(), signature):
        return {"statusCode": 401, "body": "Invalid signature"}
    
    data = json.loads(body)
    
    # Forward to SNS for fan-out
    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Message=json.dumps(data),
        Subject=f"Strix Alert: {data['event']}"
    )
    
    return {"statusCode": 200, "body": "OK"}
```

---

## Testing Webhooks

### 1. Local Testing with ngrok

```bash
# Start local receiver
python receiver.py  # Listens on port 8080

# Expose via ngrok
ngrok http 8080
# → https://abc123.ngrok.io

# Register webhook
curl -X POST https://strix.example.com/api/alerts/webhook \
  -H "Authorization: Bearer sk_admin_..." \
  -d '{"name": "local-test", "url": "https://abc123.ngrok.io/strix-webhook"}'
```

### 2. Test with curl

```bash
# Simulate webhook payload
PAYLOAD='{"event": "assessment_completed", "target": "https://example.com", "verdict": "fail", "severity_counts": {"critical": 1}}'
SIGNATURE=$(printf '%s' "$PAYLOAD" | STRIX_WEBHOOK_SECRET="$STRIX_WEBHOOK_SECRET" python3 -c 'import hashlib, hmac, os, sys; print(hmac.new(os.environ["STRIX_WEBHOOK_SECRET"].encode(), sys.stdin.buffer.read(), hashlib.sha256).hexdigest())')
curl -X POST https://abc123.ngrok.io/strix-webhook \
  -H "Content-Type: application/json" \
  -H "X-Strix-Signature: sha256=$SIGNATURE" \
  -d "$PAYLOAD"
```

### 3. Verify in Strix

Check monitor status:
```bash
curl -H "Authorization: Bearer sk_admin_..." \
  https://strix.example.com/api/monitor/status
```

---

## Troubleshooting

### Webhook Not Receiving Events

1. **Check monitor is running:**
   ```bash
   curl -H "Authorization: Bearer sk_admin_..." \
     https://strix.example.com/api/monitor/status
   # Should show "running": true
   ```

2. **Check targets are configured:**
   ```bash
   curl -H "Authorization: Bearer sk_admin_..." \
     https://strix.example.com/api/monitor/status
   # Check "targets" array
   ```

3. **Check webhook is registered:**
   - No list endpoint; check audit log for `webhook_added` event

4. **Check network connectivity:**
   - Strix must reach your webhook URL
   - Verify firewall/security groups allow Strix IPs

### Signature Verification Failing

1. **Ensure `STRIX_WEBHOOK_SECRET` is set** on both Strix and receiver
2. **Use raw request body** for HMAC (not parsed JSON)
3. **Check encoding:** payload must be bytes, secret must be string

### Events Delayed

- Monitor interval defaults to 300s (5 min)
- Reduce with `interval_seconds` in monitor config (min 30s)
- Schedule runs are triggered by cron, not monitor interval

---

## Best Practices

### 1. Idempotent Processing

Use `job_id` or `dedup_key` (job_id) to avoid duplicate processing:

```python
def handle_completed(data):
    job_id = data["job_id"]
    if redis.setnx(f"strix:processed:{job_id}", "1"):
        # First time seeing this job
        process_findings(data)
    else:
        # Already processed
        logger.info(f"Duplicate webhook for {job_id}")
```

### 2. Async Processing

Return 2xx quickly, process in background:

```python
@app.route("/webhook", methods=["POST"])
def webhook():
    verify_signature(...)
    queue.enqueue(process_alert, request.json)  # Redis/RQ, Celery, etc.
    return "OK", 200
```

### 3. Structured Logging

```python
import structlog

logger = structlog.get_logger()

def handle_completed(data):
    logger.info(
        "receiver.assessment_completed",
        job_id=data.get("job_id"),
        target=data.get("target"),
        payload_keys=sorted(data)
    )
```

### 4. Alert Routing

Route by severity:

```python
def route_alert(data):
    critical = data.get("severity_counts", {}).get("critical", 0)
    high = data.get("severity_counts", {}).get("high", 0)
    
    if critical > 0:
        notify_pagerduty(data, urgency="high")
    elif high > 0:
        notify_slack(data, channel="#security-high")
    else:
        notify_slack(data, channel="#security-low")
```

---

## Webhook Management API

### Add Webhook (Admin)
```http
POST /api/alerts/webhook
Authorization: Bearer <admin-key>
Content-Type: application/json

{"name": "my-webhook", "url": "https://..."}
```

### Monitor Configuration (Admin)
```http
POST /api/monitor/configure
Authorization: Bearer <admin-key>
Content-Type: application/json

{
  "interval_seconds": 300,
  "targets": ["https://example.com"],
  "replace": true
}
```

### Monitor Status (Any Auth)
```http
GET /api/monitor/status
Authorization: Bearer <any-key>
```

---

## Dead Letter Queue (DLQ)

When webhook delivery fails after all retry attempts, the failed webhook payload is moved to the Dead Letter Queue (DLQ) for inspection and replay.

### DLQ Retention Policy

- **Default retention:** 30 days
- **Configurable via:** `STRIX_DLQ_RETENTION_DAYS` environment variable (1–365 days)
- **Max entries:** 10,000 (oldest evicted when full)
- **Purged automatically** after retention period expires

### Query DLQ Entries

Retrieve failed webhook deliveries for inspection.

```http
GET /api/webhooks/dead-letter
Authorization: Bearer <admin-key>
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 50 | Max entries to return (1–200) |
| `offset` | integer | 0 | Pagination offset |
| `status` | string | all | Filter: `pending`, `replayed`, `failed` |
| `webhook_id` | string | all | Filter by webhook ID |
| `since` | ISO8601 | — | Filter entries after timestamp |
| `until` | ISO8601 | — | Filter entries before timestamp |

**Response:**

```json
{
  "entries": [
    {
      "id": "dlq_abc123def456",
      "webhook_id": "wh_slack-alerts",
      "webhook_name": "slack-alerts",
      "event": "assessment_completed",
      "payload": {
        "event": "assessment_completed",
        "timestamp": "2024-01-15T10:35:00Z",
        "job_id": "job_abc123def456",
        "target": "https://example.com",
        "verdict": "fail",
        "severity_counts": { "critical": 1, "high": 2, "medium": 3 }
      },
      "error": "Connection timeout after 10s",
      "attempts": 7,
      "last_attempt": "2024-01-15T11:57:00Z",
      "created_at": "2024-01-15T10:35:00Z",
      "status": "pending"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

**Python Example:**
```python
import requests
import os

ADMIN_KEY = os.environ["STRIX_API_KEY"]
BASE_URL = "https://strix.example.com"

def list_dlq_entries(status="pending", limit=50):
    resp = requests.get(
        f"{BASE_URL}/api/webhooks/dead-letter",
        headers={"Authorization": f"Bearer {ADMIN_KEY}"},
        params={"status": status, "limit": limit}
    )
    resp.raise_for_status()
    return resp.json()

# List pending DLQ entries
entries = list_dlq_entries(status="pending")
for entry in entries["entries"]:
    print(f"DLQ {entry['id']}: {entry['event']} for {entry['payload']['target']} - {entry['error']}")
```

**curl Example:**
```bash
# List pending DLQ entries
curl -H "Authorization: Bearer sk_admin_..." \
  "https://strix.example.com/api/webhooks/dead-letter?status=pending&limit=20"

# List all DLQ entries for a specific webhook
curl -H "Authorization: Bearer sk_admin_..." \
  "https://strix.example.com/api/webhooks/dead-letter?webhook_id=wh_slack-alerts"
```

---

### Replay DLQ Entry

Retry delivery of a specific failed webhook entry. The replay uses the current webhook configuration (URL, secret).

```http
POST /api/webhooks/dead-letter/{id}/retry
Authorization: Bearer <admin-key>
```

**Path Parameter:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `id` | string | DLQ entry ID (e.g., `dlq_abc123def456`) |

**Response (Success):**
```json
{
  "id": "dlq_abc123def456",
  "status": "replayed",
  "replayed_at": "2024-01-16T08:30:00Z",
  "delivery": {
    "attempt": 1,
    "status_code": 200,
    "response": "OK",
    "latency_ms": 245
  }
}
```

**Response (Failed - re-queued to DLQ):**
```json
{
  "id": "dlq_abc123def456",
  "status": "failed",
  "replayed_at": "2024-01-16T08:30:00Z",
  "delivery": {
    "attempt": 1,
    "status_code": 500,
    "response": "Internal Server Error",
    "latency_ms": 5000
  },
  "error": "Webhook endpoint returned 500"
}
```

**Python Example:**
```python
import requests
import os

ADMIN_KEY = os.environ["STRIX_API_KEY"]
BASE_URL = "https://strix.example.com"

def replay_dlq_entry(dlq_id):
    resp = requests.post(
        f"{BASE_URL}/api/webhooks/dead-letter/{dlq_id}/retry",
        headers={"Authorization": f"Bearer {ADMIN_KEY}"}
    )
    resp.raise_for_status()
    return resp.json()

# Replay a single entry
result = replay_dlq_entry("dlq_abc123def456")
print(f"Replay status: {result['status']}")
if result['status'] == 'replayed':
    print(f"Delivered with status {result['delivery']['status_code']}")
else:
    print(f"Failed again: {result['error']}")

# Bulk replay all pending entries
entries = list_dlq_entries(status="pending")
for entry in entries["entries"]:
    result = replay_dlq_entry(entry["id"])
    print(f"{entry['id']}: {result['status']}")
```

**curl Example:**
```bash
# Replay a single DLQ entry
curl -X POST -H "Authorization: Bearer sk_admin_..." \
  https://strix.example.com/api/webhooks/dead-letter/dlq_abc123def456/retry

# Bulk replay all pending entries (bash)
curl -H "Authorization: Bearer sk_admin_..." \
  "https://strix.example.com/api/webhooks/dead-letter?status=pending" \
  | jq -r '.entries[].id' \
  | xargs -I {} curl -X POST -H "Authorization: Bearer sk_admin_..." \
      https://strix.example.com/api/webhooks/dead-letter/{}/retry
```

---

### DLQ Entry Status Values

| Status | Description |
|--------|-------------|
| `pending` | Awaiting replay, retained until expiration |
| `replayed` | Successfully replayed and delivered |
| `failed` | Replay attempted but failed again (re-queued) |

---

## Limits

| Limit | Value |
|-------|-------|
| Max webhooks | 50 |
| Max monitor targets | 500 |
| Min monitor interval | 30 seconds |
| Max payload size | 1 MB |
| Webhook timeout | 10 seconds |
| Max retries | 7 |

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-01-15 | Initial webhook support |