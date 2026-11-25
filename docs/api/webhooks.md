# Alert Webhooks

IshAstra delivers redacted alert payloads to HTTPS endpoints. Webhooks are
outbound notifications from the monitor; they are not a public event bus and
there is no inbound webhook delivery route.

## Register a sink

```http
POST /api/alerts/webhook
Authorization: Bearer $ADMIN_KEY
Content-Type: application/json
```

```json
{
  "name": "ops",
  "url": "https://ops.example.com/ishastra-alerts"
}
```

`name` is 1–64 characters matching `^[A-Za-z0-9_.-]+$`; `url` is up to 2048
characters.

### URL requirements

A sink URL is refused unless it:

- uses `https`;
- embeds no credentials (userinfo or sensitive query parameters);
- resolves to a public address (private, loopback and other special-use
  addresses are rejected).

The resolved address is pinned for delivery, so a later DNS change cannot
redirect alerts to a different host.

## Monitor status and configuration

| Route | Description |
|-------|-------------|
| `GET /api/monitor/status` | Running state and configured sinks |
| `POST /api/monitor/configure` | Update monitoring configuration |

## Signature verification

When `ISHASTRA_WEBHOOK_SECRET` is set, every delivery carries:

```
X-Ishastra-Signature: sha256=<hex digest>
X-Ishastra-Signature-Alg: HMAC-SHA256
```

The digest is `HMAC-SHA256(secret, raw request body)`. Verify against the raw
bytes before parsing JSON, and compare in constant time:

```python
import hashlib
import hmac

def verify(body: bytes, signature_header: str, secret: str) -> bool:
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)
```

```python
from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

@app.post("/ishastra-alerts")
async def receive(request: Request):
    body = await request.body()
    header = request.headers.get("X-Ishastra-Signature", "")
    if not verify(body, header, settings.ISHASTRA_WEBHOOK_SECRET):
        raise HTTPException(status_code=401, detail="invalid signature")
    alert = await request.json()
    return {"status": "ok"}
```

## Delivery behavior

- Payloads are JSON and pass through the redaction filter before sending.
- A delivery is successful when the receiver returns a status below `400`.
- Failed deliveries are retried; outcomes are recorded in the metrics
  (`delivered`, `failed`, `refused`).
- Receivers should treat delivery as at-least-once and deduplicate on the alert
  content they need.

## Related

- [Authentication](authentication.md)
- [Assessments API](assessments.md)
- [Monitoring](../deployment/monitoring.md)
