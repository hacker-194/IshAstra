# Assessments API

# Assessments API

REST API for creating, managing, and monitoring security assessments.

## Base URL

```
https://api.strix.dev/api/v1
```

## Assessment Object

```json
{
  "id": "asm_abc123def456",
  "scope_id": "scope_prod_001",
  "status": "running",
  "targets": ["https://api.example.com", "https://app.example.com"],
  "adapters": ["http_probe", "crawler", "nuclei"],
  "options": {
    "http_probe": {"timeout": 10},
    "nuclei": {"severity": ["critical", "high"]}
  },
  "created_at": "2024-01-15T10:00:00Z",
  "started_at": "2024-01-15T10:00:05Z",
  "completed_at": null,
  "progress": {
    "total_targets": 2,
    "completed_targets": 1,
    "current_target": "https://app.example.com"
  },
  "summary": {
    "findings_total": 0,
    "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
  },
  "created_by": "key_abc123"
}
```

## Status Values

| Status | Description |
|--------|-------------|
| `pending` | Queued, waiting for worker |
| `running` | Actively executing |
| `completed` | Finished successfully |
| `failed` | Execution failed |
| `cancelled` | Cancelled by user |
| `partial` | Some targets failed |

## Create Assessment

```bash
POST /assessments
```

### Request

```json
{
  "scope_id": "scope_prod_001",
  "targets": [
    "https://api.example.com",
    "https://app.example.com"
  ],
  "adapters": ["http_probe", "crawler", "dynamic_validation", "nuclei"],
  "options": {
    "http_probe": {
      "timeout": 10,
      "follow_redirects": true
    },
    "crawler": {
      "max_pages": 100,
      "max_depth": 3
    },
    "dynamic_validation": {
      "test_auth_bypass": true,
      "test_idor": true
    },
    "nuclei": {
      "severity": ["critical", "high", "medium"],
      "rate_limit": 100
    }
  },
  "priority": "normal",
  "callback_url": "https://your-app.com/webhooks/assessment-complete"
}
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scope_id` | string | Yes | Scope document ID |
| `targets` | string[] | Yes | Target URLs (1-100) |
| `adapters` | string[] | Yes | Adapter names to run |
| `options` | object | No | Per-adapter configuration |
| `priority` | enum | No | `low`, `normal`, `high` (default: `normal`) |
| `callback_url` | string | No | Webhook on completion |

### Response (202 Accepted)

```json
{
  "id": "asm_abc123def456",
  "scope_id": "scope_prod_001",
  "status": "pending",
  "targets": ["https://api.example.com", "https://app.example.com"],
  "adapters": ["http_probe", "crawler", "nuclei"],
  "options": {...},
  "created_at": "2024-01-15T10:00:00Z",
  "started_at": null,
  "completed_at": null,
  "progress": {"total_targets": 2, "completed_targets": 0},
  "summary": {"findings_total": 0, "findings_by_severity": {...}},
  "created_by": "key_abc123"
}
```

## Get Assessment

```bash
GET /assessments/{assessment_id}
```

### Response (200 OK)

```json
{
  "id": "asm_abc123def456",
  "scope_id": "scope_prod_001",
  "status": "completed",
  "targets": ["https://api.example.com", "https://app.example.com"],
  "adapters": ["http_probe", "crawler", "nuclei"],
  "options": {...},
  "created_at": "2024-01-15T10:00:00Z",
  "started_at": "2024-01-15T10:00:05Z",
  "completed_at": "2024-01-15T10:15:30Z",
  "progress": {"total_targets": 2, "completed_targets": 2},
  "summary": {
    "findings_total": 23,
    "findings_by_severity": {"critical": 1, "high": 5, "medium": 10, "low": 4, "info": 3}
  },
  "created_by": "key_abc123"
}
```

## List Assessments

```bash
GET /assessments
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scope_id` | string | - | Filter by scope |
| `status` | string | - | Filter by status |
| `from` | datetime | - | Created after |
| `to` | datetime | - | Created before |
| `limit` | int | 50 | Max results (1-500) |
| `offset` | int | 0 | Pagination offset |
| `sort` | string | `-created_at` | Sort field (prefix `-` for desc) |

### Response (200 OK)

```json
{
  "assessments": [
    {"id": "asm_abc123...", "status": "completed", ...},
    {"id": "asm_def456...", "status": "running", ...}
  ],
  "pagination": {
    "total": 142,
    "limit": 50,
    "offset": 0,
    "has_more": true
  }
}
```

## Cancel Assessment

```bash
POST /assessments/{assessment_id}/cancel
```

### Response (200 OK)

```json
{
  "id": "asm_abc123def456",
  "status": "cancelled",
  "cancelled_at": "2024-01-15T10:05:00Z"
}
```

## Get Assessment Progress (Streaming)

```bash
GET /assessments/{assessment_id}/progress
```

### Response (Server-Sent Events)

```
event: progress
data: {"completed_targets": 1, "current_target": "https://app.example.com", "findings_so_far": 12}

event: progress
data: {"completed_targets": 2, "current_target": null, "findings_so_far": 23}

event: complete
data: {"status": "completed", "summary": {...}}
```

## Retry Failed Assessment

```bash
POST /assessments/{assessment_id}/retry
```

### Request

```json
{
  "targets": ["https://failed-target.example.com"],  // Optional: retry specific targets
  "adapters": ["nuclei"]  // Optional: retry specific adapters
}
```

### Response (202 Accepted)

```json
{
  "id": "asm_new789ghi012",
  "parent_assessment_id": "asm_abc123def456",
  "status": "pending",
  ...
}
```

## Export Assessment Report

```bash
GET /assessments/{assessment_id}/report
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `format` | enum | `json` | `json`, `html`, `pdf`, `sarif` |
| `include_evidence` | bool | `false` | Include raw evidence in report |

### Response (200 OK)

```json
{
  "assessment_id": "asm_abc123def456",
  "generated_at": "2024-01-15T10:16:00Z",
  "format": "json",
  "report": {
    "metadata": {...},
    "summary": {...},
    "findings": [...],
    "targets": [...],
    "adapters_run": [...]
  }
}
```

## Error Responses

### 400 Bad Request

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request",
    "details": {
      "field_errors": {
        "targets": "At least one target required",
        "adapters": "Unknown adapter: 'invalid_adapter'"
      }
    }
  }
}
```

### 404 Not Found

```json
{
  "error": {
    "code": "NOT_FOUND",
    "message": "Assessment not found",
    "details": {"assessment_id": "asm_abc123def456"}
  }
}
```

### 409 Conflict

```json
{
  "error": {
    "code": "CONFLICT",
    "message": "Assessment already running for this scope",
    "details": {"existing_assessment_id": "asm_existing123"}
  }
}
```

### 422 Unprocessable Entity

```json
{
  "error": {
    "code": "SCOPE_GATE_DENIED",
    "message": "Target not authorized by scope",
    "details": {
      "target": "https://internal.example.com",
      "scope_id": "scope_prod_001",
      "reason": "Host not in include_hosts list"
    }
  }
}
```

## Adapter-Specific Options

### HTTP Probe

```json
{
  "http_probe": {
    "follow_redirects": true,
    "max_redirects": 10,
    "timeout": 10,
    "check_security_headers": true,
    "check_cookies": true,
    "check_methods": true,
    "tech_detection": true
  }
}
```

### Crawler

```json
{
  "crawler": {
    "max_pages": 100,
    "max_depth": 3,
    "max_concurrent": 5,
    "respect_robots_txt": true,
    "follow_external_links": false,
    "extract_forms": true,
    "extract_js_endpoints": true,
    "check_sensitive_paths": true
  }
}
```

### Dynamic Validation

```json
{
  "dynamic_validation": {
    "test_auth_bypass": true,
    "test_idor": true,
    "idor_endpoints": ["/api/users/{id}"],
    "test_xss": true,
    "test_sqli": true,
    "test_rate_limit": true
  }
}
```

### Nuclei

```json
{
  "nuclei": {
    "templates": ["cves/", "vulnerabilities/"],
    "severity": ["critical", "high", "medium"],
    "rate_limit": 150,
    "timeout": 10,
    "headless": false
  }
}
```

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `POST /assessments` | 10/min per key |
| `GET /assessments` | 100/min per key |
| `GET /assessments/{id}` | 200/min per key |
| `GET /assessments/{id}/progress` | 10 concurrent per key |

## Related

- [Authentication](../api/authentication.md)
- [Findings API](../api/findings.md)
- [Scope Management](../api/scope-management.md)
- [Webhooks](../api/webhooks.md)
- [Built-in Adapters](../adapters/built-in.md)
- [External Adapters](../adapters/external.md)
- [Custom Adapters](../adapters/custom.md)
- [Adapter SDK](../adapters/sdk.md)