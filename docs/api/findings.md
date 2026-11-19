# Findings API

# Findings API

REST API for retrieving and managing security findings from assessments.

## Base URL

```
https://api.strix.dev/api/v1
```

## Finding Object

```json
{
  "id": "fnd_abc123def456",
  "assessment_id": "asm_abc123def456",
  "target": "https://api.example.com",
  "adapter": "nuclei",
  "adapter_version": "3.2.0",
  "title": "CVE-2024-1234: Example App RCE",
  "description": "Remote code execution in Example App version < 2.5.0",
  "severity": "critical",
  "category": "rce",
  "location": "https://api.example.com/vulnerable-endpoint",
  "evidence": {
    "template_id": "cve-2024-1234",
    "template_name": "Example App RCE",
    "matched_at": "https://api.example.com/vulnerable-endpoint?param=payload",
    "request": "GET /vulnerable-endpoint?param=payload HTTP/1.1",
    "response": "HTTP/1.1 200 OK\n...",
    "extracted_results": ["command_output"]
  },
  "references": [
    "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
    "https://github.com/projectdiscovery/nuclei-templates"
  ],
  "metadata": {
    "adapter": "nuclei",
    "template": "cves/2024/cve-2024-1234.yaml"
  },
  "discovered_at": "2024-01-15T10:05:23Z",
  "status": "open",
  "acknowledged_at": null,
  "acknowledged_by": null
}
```

## Severity Levels

| Severity | Value | Description |
|----------|-------|-------------|
| `critical` | 0 | Immediate threat, active exploitation |
| `high` | 1 | Serious vulnerability, likely exploitable |
| `medium` | 2 | Moderate risk, conditional exploitation |
| `low` | 3 | Low risk, defense-in-depth |
| `info` | 4 | Informational, no direct risk |

## Status Values

| Status | Description |
|--------|-------------|
| `open` | New finding, not yet addressed |
| `acknowledged` | Team has acknowledged |
| `in_progress` | Fix in progress |
| `resolved` | Fix deployed, verified |
| `false_positive` | Invalid finding |
| `accepted_risk` | Risk accepted with justification |

## List Findings

```bash
GET /findings
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `assessment_id` | string | - | Filter by assessment |
| `scope_id` | string | - | Filter by scope |
| `severity` | string | - | Filter by severity (comma-separated) |
| `category` | string | - | Filter by category |
| `status` | string | - | Filter by status |
| `adapter` | string | - | Filter by adapter |
| `target` | string | - | Filter by target URL (partial match) |
| `from` | datetime | - | Discovered after |
| `to` | datetime | - | Discovered before |
| `limit` | int | 50 | Max results (1-500) |
| `offset` | int | 0 | Pagination offset |
| `sort` | string | `-discovered_at` | Sort field |

### Response (200 OK)

```json
{
  "findings": [
    {"id": "fnd_abc123...", "severity": "critical", ...},
    {"id": "fnd_def456...", "severity": "high", ...}
  ],
  "pagination": {
    "total": 1247,
    "limit": 50,
    "offset": 0,
    "has_more": true
  },
  "summary": {
    "by_severity": {"critical": 3, "high": 12, "medium": 45, "low": 28, "info": 15},
    "by_status": {"open": 88, "acknowledged": 10, "resolved": 5}
  }
}
```

## Get Finding

```bash
GET /findings/{finding_id}
```

### Response (200 OK)

```json
{
  "id": "fnd_abc123def456",
  "assessment_id": "asm_abc123def456",
  "target": "https://api.example.com",
  "adapter": "nuclei",
  "adapter_version": "3.2.0",
  "title": "CVE-2024-1234: Example App RCE",
  "description": "Remote code execution in Example App version < 2.5.0",
  "severity": "critical",
  "category": "rce",
  "location": "https://api.example.com/vulnerable-endpoint",
  "evidence": {...},
  "references": [...],
  "metadata": {...},
  "discovered_at": "2024-01-15T10:05:23Z",
  "status": "open",
  "acknowledged_at": null,
  "acknowledged_by": null
}
```

## Update Finding Status

```bash
PATCH /findings/{finding_id}
```

### Request

```json
{
  "status": "acknowledged",
  "note": "Investigating - assigned to backend team"
}
```

### Valid Status Transitions

```
open → acknowledged → in_progress → resolved
open → false_positive
open → accepted_risk (requires justification)
acknowledged → open (reopen)
in_progress → acknowledged (pause)
resolved → open (regression)
```

### Response (200 OK)

```json
{
  "id": "fnd_abc123def456",
  "status": "acknowledged",
  "acknowledged_at": "2024-01-15T14:30:00Z",
  "acknowledged_by": "user_john",
  "updated_at": "2024-01-15T14:30:00Z"
}
```

## Bulk Update Findings

```bash
PATCH /findings/bulk
```

### Request

```json
{
  "finding_ids": ["fnd_abc123", "fnd_def456", "fnd_ghi789"],
  "status": "acknowledged",
  "note": "Batch triage - sprint planning"
}
```

### Response (200 OK)

```json
{
  "updated": 3,
  "failed": 0,
  "results": [
    {"id": "fnd_abc123", "status": "acknowledged"},
    {"id": "fnd_def456", "status": "acknowledged"},
    {"id": "fnd_ghi789", "status": "acknowledged"}
  ]
}
```

## Get Finding Statistics

```bash
GET /findings/stats
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `scope_id` | string | Filter by scope |
| `from` | datetime | Start date |
| `to` | datetime | End date |
| `group_by` | string | `severity`, `category`, `adapter`, `target` |

### Response (200 OK)

```json
{
  "total": 1247,
  "by_severity": {"critical": 3, "high": 12, "medium": 45, "low": 28, "info": 15},
  "by_category": {"rce": 2, "sqli": 5, "xss": 8, "crypto": 12, "auth": 6, "headers": 15, "config": 23},
  "by_adapter": {"nuclei": 45, "dynamic_validation": 32, "http_probe": 28, "crawler": 15, "nmap": 8},
  "by_status": {"open": 88, "acknowledged": 10, "in_progress": 5, "resolved": 85, "false_positive": 12, "accepted_risk": 3},
  "trend": {
    "period": "30d",
    "data": [
      {"date": "2024-01-01", "new": 5, "resolved": 3},
      {"date": "2024-01-02", "new": 8, "resolved": 6}
    ]
  }
}
```

## Export Findings

```bash
GET /findings/export
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `format` | enum | `json` | `json`, `csv`, `sarif`, `html` |
| `assessment_id` | string | - | Filter by assessment |
| `scope_id` | string | - | Filter by scope |
| `severity` | string | - | Filter by severity |
| `include_evidence` | bool | `false` | Include full evidence |

### Response (200 OK)

```json
{
  "format": "sarif",
  "generated_at": "2024-01-15T15:00:00Z",
  "download_url": "https://api.strix.dev/api/v1/downloads/export_abc123.sarif",
  "expires_at": "2024-01-15T16:00:00Z"
}
```

## SARIF Format

```json
{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Strix",
          "version": "3.5.0",
          "informationUri": "https://strix.dev"
        }
      },
      "results": [
        {
          "ruleId": "CVE-2024-1234",
          "level": "error",
          "message": {"text": "Remote code execution in Example App version < 2.5.0"},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "https://api.example.com/vulnerable-endpoint"},
                "region": {"startLine": 1}
              }
            }
          ],
          "properties": {
            "severity": "critical",
            "category": "rce",
            "adapter": "nuclei",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-1234"]
          }
        }
      ]
    }
  ]
}
```

## CSV Format

```csv
id,assessment_id,target,adapter,severity,category,title,discovered_at,status
fnd_abc123,asm_abc123,https://api.example.com,nuclei,critical,rce,CVE-2024-1234: RCE,2024-01-15T10:05:23Z,open
fnd_def456,asm_abc123,https://app.example.com,http_probe,high,headers,Missing CSP Header,2024-01-15T10:06:12Z,open
```

## Finding Categories

| Category | Description | Common Adapters |
|----------|-------------|-----------------|
| `rce` | Remote code execution | nuclei, dynamic_validation |
| `sqli` | SQL injection | nuclei, sqlmap, dynamic_validation |
| `xss` | Cross-site scripting | nuclei, dynamic_validation, crawler |
| `idor` | Insecure direct object reference | dynamic_validation |
| `auth` | Authentication issues | dynamic_validation, http_probe |
| `crypto` | Cryptographic weaknesses | http_probe, nuclei |
| `headers` | Missing security headers | http_probe |
| `config` | Misconfiguration | nuclei, nikto, crawler |
| `exposure` | Information disclosure | crawler, nikto, nuclei |
| `outdated` | Outdated software | nuclei, nikto, nmap |
| `network` | Open ports/services | nmap |
| `csrf` | CSRF vulnerabilities | crawler, dynamic_validation |
| `rate_limit` | Rate limiting issues | dynamic_validation |
| `business` | Business logic flaws | dynamic_validation |

## Error Responses

### 404 Not Found

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Finding not found",
    "details": {"finding_id": "fnd_abc123def456"}
  }
}
```

### 400 Bad Request

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid status transition",
    "details": {"current_status": "resolved", "requested_status": "open", "reason": "Cannot reopen resolved finding without regression evidence"}
  }
}
```

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `GET /findings` | 100/min per key |
| `GET /findings/{id}` | 200/min per key |
| `PATCH /findings/{id}` | 50/min per key |
| `PATCH /findings/bulk` | 10/min per key |
| `GET /findings/export` | 5/min per key |

## Related

- [Authentication](../api/authentication.md)
- [Assessments API](../api/assessments.md)
- [Scope Management](../api/scope-management.md)
- [Built-in Adapters](../adapters/built-in.md)
- [External Adapters](../adapters/external.md)
- [Custom Adapters](../adapters/custom.md)
- [Adapter SDK](../adapters/sdk.md)