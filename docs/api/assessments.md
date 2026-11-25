# Assessments API

REST API for queueing, running and retrieving authorized assessments. The live
schema is always authoritative: fetch `/openapi.json` from your instance or open
`/docs` for the interactive reference.

## Base URL

All routes are under `/api`:

```
https://your-host/api
```

Authenticate with a Bearer API key (`Authorization: Bearer <key>`). See
[Authentication](authentication.md).

## Create an assessment

```http
POST /api/assess
Idempotency-Key: <optional-uuid>
```

The target must fall inside the caller's authorized scope. The Scope Gate rejects
out-of-scope targets before any network contact.

### Request body

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `target` | string | Yes | Authorized `http(s)` target |
| `profile` | string | No | `web` (default), `web-deep`, `api`, `api-deep`, `network`, `agent` |
| `timeout` | number | No | Overall deadline in seconds, 5–900 (default `120`) |
| `wait` | boolean | No | Run inline and return the finished job with `200`. Default queues the job and returns `202` |
| `policy_id` | string \| null | No | Pin a specific engagement policy (managed mode). Omitted: the tenant's newest valid policy |
| `hybrid_components` | object \| null | No | `{"native": true, "ishastra": true}` for hybrid assessments |
| `auth` | object \| null | No | Per-assessment auth: `token`, `session`, `form_login`, `multi_step` |

```json
{
  "target": "https://app.example.com",
  "profile": "web",
  "timeout": 300,
  "wait": false
}
```

### Queued response (`202 Accepted`)

```json
{
  "id": "job_...",
  "target": "https://app.example.com",
  "profile": "web",
  "actor": "analyst",
  "policy": {},
  "state": "queued",
  "started_at": null,
  "finished_at": null,
  "runs": [],
  "findings": [],
  "error": "",
  "attempts": 0,
  "worker": "",
  "idempotency_key": null,
  "coverage": {},
  "verdict": "",
  "poll_url": "/api/assess/job_...",
  "cancel_url": "/api/assess/job_.../cancel",
  "sarif_url": "/api/assess/job_.../sarif",
  "report_url": "/api/assess/job_.../report.html",
  "audit_chain_hash": "...",
  "deduplicated": false
}
```

With `"wait": true` the same object is returned once the job finishes, with
`state`, `runs`, `findings`, `coverage` and `verdict` populated.

Sending the same `Idempotency-Key` again returns the existing job with
`"deduplicated": true` instead of starting a second assessment.

## Get an assessment

```http
GET /api/assess/{job_id}
```

Returns the job object, including findings and the audit-chain hash.

## List assessments

```http
GET /api/assess?page=1&page_size=50
```

```json
{
  "items": [
    {
      "id": "job_...",
      "target": "https://app.example.com",
      "profile": "web",
      "state": "completed",
      "verdict": "pass",
      "findings_count": 3,
      "poll_url": "/api/assess/job_..."
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 50,
  "has_next": false
}
```

## Cancel and retry

| Route | Description |
|-------|-------------|
| `POST /api/assess/{job_id}/cancel` | Cancel a queued or running job |
| `POST /api/assess/{job_id}/retry` | Re-queue a failed job |

## Outputs and triage

| Route | Returns |
|-------|---------|
| `GET /api/assess/{job_id}/sarif` | SARIF 2.1.0 report |
| `GET /api/assess/{job_id}/report.html` | HTML report |
| `GET /api/assess/{job_id}/report.pdf` | PDF report |
| `GET /api/assess/{job_id}/findings/{fingerprint}` | One finding from the job |
| `GET /api/assess/{job_id}/findings/{fingerprint}/history` | Finding history |
| `GET /api/assess/{job_id}/findings/{fingerprint}/remediation` | Remediation guidance |
| `PATCH /api/assess/{job_id}/triage` | Triage findings for the job |

## Errors

| Status | Meaning |
|--------|---------|
| `401` | Missing or invalid API key |
| `403` | Key lacks write scope or admin rights |
| `422` | Invalid body, or target rejected by the Scope Gate |
| `429` | Rate limited (`Retry-After` header) |
| `503` | Worker or dependency unavailable |

Error bodies are `{"detail": "<message>"}`.

## Related

- [Authentication](authentication.md)
- [Findings API](findings.md)
- [Scope Management](scope-management.md)
- [Webhooks](webhooks.md)
