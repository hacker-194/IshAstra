# Findings API

Findings are aggregated across assessments by a stable **fingerprint**: 32
lowercase hex characters. Full schemas are served at `/openapi.json`; the
interactive reference is at `/docs`.

All routes require `Authorization: Bearer <key>`.

## List findings

```http
GET /api/findings?page=1&page_size=50
```

`page` is 1-based; `page_size` is 1–200 (default 50). Items are distinct
findings across the caller's jobs, newest activity first.

```json
{
  "items": [
    {
      "fingerprint": "0123456789abcdef0123456789abcdef",
      "severity": "high",
      "title": "Missing security header",
      "target": "https://app.example.com",
      "last_seen": 1798761600
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 50,
  "has_next": false
}
```

## Get a finding

```http
GET /api/findings/{fingerprint}
```

The fingerprint must be 32 lowercase hex characters; anything else returns
`422`.

## Trends

```http
GET /api/findings/trends?range=quarter&bucket=month&format=json
```

| Parameter | Values | Description |
|-----------|--------|-------------|
| `start`, `end` | Unix timestamps | Inclusive window; default last 30 days |
| `bucket` | `day`, `week`, `month` | Aggregation bucket (default `day`) |
| `range` | `quarter`, `year`, `all` | Predefined window; overrides `start`/`end` |
| `format` | `json`, `csv` | Response format |

The window may not exceed 366 days and `start` must be before `end`, otherwise
the request returns `400`. The result contains observation, new-finding and
verified-resolution counts per bucket.

## SLA status

```http
GET /api/findings/sla
```

Returns findings against their severity-based remediation SLA.

## Remediation and resolution

| Route | Description |
|-------|-------------|
| `PATCH /api/findings/{fingerprint}/remediation` | Record remediation guidance/status |
| `POST /api/findings/{fingerprint}/resolve` | Verify and record a resolution |

## Exceptions

Accepted-risk and false-positive exceptions live under `/api/exceptions`
(including `/api/exceptions/audit` and `/api/exceptions/expire`). See `/docs`
for the request bodies and available transitions.

## Errors

| Status | Meaning |
|--------|---------|
| `401` | Missing or invalid API key |
| `403` | Key lacks write scope or admin rights |
| `422` | Malformed fingerprint or query |
| `429` | Rate limited (`Retry-After` header) |

## Related

- [Assessments API](assessments.md)
- [Authentication](authentication.md)
- [Scope Management](scope-management.md)
