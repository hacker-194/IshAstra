# Webhooks API

# Webhooks API

Real-time event notifications for assessment lifecycle and findings.

## Overview

Ishastra sends webhook events for key assessment milestones. Configure webhook endpoints to receive real-time updates.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Webhook Flow                                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Ishastra Platform                                                              │
│  ┌─────────────┐                                                            │
│  │ Assessment  │──▶ Event Triggered                                        │
│  │  Complete   │                                                            │
│  └──────┬──────┘                                                            │
│         │                                                                    │
│         ▼                                                                    │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  Webhook Dispatcher                                                 │   │
│  │  • Verifies signature                                               │   │
│  │  • Retries with exponential backoff                                │   │
│  │  • Dead letter queue for failed deliveries                         │   │
│  └────────────────────────────────┬────────────────────────────────────┘   │
│                                   │                                        │
│         ┌─────────────────────────┼─────────────────────────┐             │
│         ▼                         ▼                         ▼             │
│  ┌─────────────┐          ┌─────────────┐          ┌─────────────┐      │
│  │  Your App   │          │  Slack      │          │  PagerDuty  │      │
│  │  /webhook   │          │  Webhook    │          │  Integration│      │
│  └─────────────┘          └─────────────┘          └─────────────┘      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Event Types

| Event | Trigger | Payload |
|-------|---------|---------|
| `assessment.started` | Assessment begins execution | Assessment object |
| `assessment.progress` | Periodic progress updates | Progress object |
| `assessment.completed` | Assessment finishes successfully | Assessment + summary |
| `assessment.failed` | Assessment fails | Assessment + error |
| `assessment.cancelled` | Assessment cancelled | Assessment object |
| `finding.created` | New finding discovered | Finding object |
| `finding.critical` | Critical severity finding | Finding object |
| `scope.activated` | Scope document activated | Scope object |
| `scope.revoked` | Scope document revoked | Scope object |
| `break_glass.requested` | Break-glass access requested | BreakGlassRequest |
| `break_glass.approved` | Break-glass approved | BreakGlassRequest |
| `break_glass.expired` | Break-glass expired | BreakGlassRequest |

## Webhook Configuration

### Create Webhook

```bash
POST /api/v1/webhooks
```

### Request

```json
{
  "url": "https://your-app.com/webhooks/ishastra",
  "events": [
    "assessment.completed",
    "assessment.failed",
    "finding.critical"
  ],
  "secret": "whsec_your-secret-key",
  "description": "Production webhook for assessment completion",
  "active": true
}
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `url` | string | Yes | HTTPS endpoint to receive events |
| `events` | string[] | Yes | Event types to subscribe to |
| `secret` | string | Yes | Signing secret (min 32 chars) |
| `description` | string | No | Human-readable description |
| `active` | bool | No | Enable/disable (default: true) |

### Response (201 Created)

```json
{
  "id": "wh_abc123def456",
  "url": "https://your-app.com/webhooks/ishastra",
  "events": ["assessment.completed", "assessment.failed", "finding.critical"],
  "description": "Production webhook for assessment completion",
  "active": true,
  "created_at": "2024-01-15T10:00:00Z",
  "last_triggered_at": null,
  "failure_count": 0
}
```

## List Webhooks

```bash
GET /api/v1/webhooks
```

### Response (200 OK)

```json
{
  "webhooks": [
    {"id": "wh_abc123...", "url": "https://...", "events": [...], "active": true},
    {"id": "wh_def456...", "url": "https://...", "events": [...], "active": false}
  ]
}
```

## Get Webhook

```bash
GET /api/v1/webhooks/{webhook_id}
```

## Update Webhook

```bash
PATCH /api/v1/webhooks/{webhook_id}
```

### Request

```json
{
  "events": ["assessment.completed", "assessment.failed", "finding.critical", "finding.created"],
  "active": false
}
```

## Delete Webhook

```bash
DELETE /api/v1/webhooks/{webhook_id}
```

## Test Webhook

```bash
POST /api/v1/webhooks/{webhook_id}/test
```

### Response (200 OK)

```json
{
  "success": true,
  "delivered_at": "2024-01-15T10:00:00Z",
  "response_status": 200,
  "response_body": "OK"
}
```

## Event Payload Format

All webhook events follow this structure:

```json
{
  "id": "evt_abc123def456",
  "type": "assessment.completed",
  "api_version": "2024-01-01",
  "created_at": "2024-01-15T10:15:30Z",
  "data": {
    // Event-specific payload
  },
  "metadata": {
    "scope_id": "scope_prod_001",
    "organization_id": "org_abc123"
  }
}
```

### Example: assessment.completed

```json
{
  "id": "evt_abc123def456",
  "type": "assessment.completed",
  "api_version": "2024-01-01",
  "created_at": "2024-01-15T10:15:30Z",
  "data": {
    "assessment": {
      "id": "asm_abc123def456",
      "scope_id": "scope_prod_001",
      "status": "completed",
      "targets": ["https://api.example.com"],
      "adapters": ["http_probe", "nuclei"],
      "created_at": "2024-01-15T10:00:00Z",
      "started_at": "2024-01-15T10:00:05Z",
      "completed_at": "2024-01-15T10:15:30Z",
      "summary": {
        "findings_total": 23,
        "findings_by_severity": {"critical": 1, "high": 5, "medium": 10, "low": 4, "info": 3}
      }
    }
  },
  "metadata": {
    "scope_id": "scope_prod_001",
    "organization_id": "org_abc123"
  }
}
```

### Example: finding.critical

```json
{
  "id": "evt_def456ghi789",
  "type": "finding.critical",
  "api_version": "2024-01-01",
  "created_at": "2024-01-15T10:05:23Z",
  "data": {
    "finding": {
      "id": "fnd_abc123def456",
      "assessment_id": "asm_abc123def456",
      "target": "https://api.example.com",
      "adapter": "nuclei",
      "title": "CVE-2024-1234: Example App RCE",
      "severity": "critical",
      "category": "rce",
      "location": "https://api.example.com/vulnerable-endpoint",
      "discovered_at": "2024-01-15T10:05:23Z"
    }
  },
  "metadata": {
    "scope_id": "scope_prod_001",
    "organization_id": "org_abc123"
  }
}
```

## Signature Verification

Each webhook request includes a signature header:

```
Ishastra-Signature: t=1705312800,v1=sha256=abc123...
```

### Verification Code (Python)

```python
import hmac
import hashlib
import time

def verify_webhook(payload: bytes, signature_header: str, secret: str, tolerance: int = 300) -> bool:
    """
    Verify Ishastra webhook signature.
    
    Args:
        payload: Raw request body
        signature_header: Value of Ishastra-Signature header
        secret: Webhook secret (whsec_...)
        tolerance: Max timestamp drift in seconds (default: 5 min)
    """
    # Parse signature
    parts = {}
    for part in signature_header.split(","):
        k, v = part.split("=", 1)
        parts[k] = v
    
    timestamp = int(parts["t"])
    signature = parts["v1"]
    
    # Check timestamp
    if abs(time.time() - timestamp) > tolerance:
        return False
    
    # Compute expected signature
    signed_payload = f"{timestamp}.{payload.decode()}".encode()
    expected = hmac.new(
        secret.encode(),
        signed_payload,
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(f"sha256={expected}", signature)

# FastAPI example
@app.post("/webhooks/ishastra")
async def strix_webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("Ishastra-Signature")
    
    if not verify_webhook(body, signature, settings.ISHASTRA_WEBHOOK_SECRET):
        raise HTTPException(401, "Invalid signature")
    
    event = json.loads(body)
    # Process event...
    return {"status": "ok"}
```

## Retry Policy

| Attempt | Delay | Max Retries |
|---------|-------|-------------|
| 1 | Immediate | - |
| 2 | 10 seconds | - |
| 3 | 1 minute | - |
| 4 | 10 minutes | - |
| 5 | 1 hour | - |
| 6 | 6 hours | - |
| 7 | 24 hours | 7 total |

- **Timeout**: 30 seconds per attempt
- **Dead letter**: After 7 failures, event moved to DLQ
- **Manual retry**: Available via API

## Delivery Guarantees

- **At-least-once** delivery (idempotent consumers recommended)
- **Ordering**: Events for same assessment delivered in order
- **Deduplication**: Use `id` field to detect duplicates

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `POST /api/v1/webhooks` | 10/min per key |
| `GET /api/v1/webhooks` | 100/min per key |
| `POST /api/v1/webhooks/{id}/test` | 5/min per key |

## Related

- [Authentication](authentication.md)
- [Assessments API](assessments.md)
- [Findings API](findings.md)