# Built-in Adapters

# Built-in Adapters

Strix's built-in adapters for passive and active security assessment.

## Overview

| Adapter | Purpose | Scope Gate | Async |
|---------|---------|------------|-------|
| HTTP Probe | Header analysis, tech detection | ✅ Per request | ✅ |
| Crawler | Link discovery, form extraction | ✅ Per URL | ✅ |
| Dynamic Validation | Runtime behavior, auth testing | ✅ Per request | ✅ |

All built-in adapters **re-check Scope Gate before every connection**.

---

## HTTP Probe Adapter

**Class**: `HTTPProbeAdapter`  
**Name**: `http_probe`  
**Targets**: `http`, `https`

### Purpose

Passive analysis of HTTP responses for security headers, technology fingerprints, and configuration issues.

### Capabilities

| Check | Finding ID | Severity | Description |
|-------|------------|----------|-------------|
| Security Headers | `HTTP-MISSING-*` | MEDIUM/HIGH | CSP, HSTS, X-Frame-Options, etc. |
| Server Disclosure | `HTTP-SERVER-DISCLOSURE` | INFO | Server header reveals version |
| Cookie Security | `HTTP-INSECURE-COOKIE` | MEDIUM | Missing Secure/HttpOnly/SameSite |
| HTTP Methods | `HTTP-DANGEROUS-METHOD` | MEDIUM | TRACE, PUT, DELETE enabled |
| Redirect Chain | `HTTP-REDIRECT-CHAIN` | INFO | Redirect analysis |
| Technology | `HTTP-TECH-*` | INFO | Framework, CMS, language detection |

### Configuration

```json
{
  "adapters": {
    "http_probe": {
      "follow_redirects": true,
      "max_redirects": 10,
      "timeout": 10,
      "user_agent": "Strix/3.5.0 (+https://strix.dev)",
      "check_security_headers": true,
      "check_cookies": true,
      "check_methods": true,
      "tech_detection": true
    }
  }
}
```

### Security Headers Checked

| Header | Required | Finding if Missing |
|--------|----------|-------------------|
| Content-Security-Policy | Yes | `HTTP-MISSING-CSP` (HIGH) |
| Strict-Transport-Security | HTTPS only | `HTTP-MISSING-HSTS` (HIGH) |
| X-Frame-Options | Yes | `HTTP-MISSING-XFO` (MEDIUM) |
| X-Content-Type-Options | Yes | `HTTP-MISSING-XCTO` (LOW) |
| Referrer-Policy | Yes | `HTTP-MISSING-RP` (LOW) |
| Permissions-Policy | No | `HTTP-MISSING-PP` (INFO) |
| Cross-Origin-Opener-Policy | No | `HTTP-MISSING-COOP` (INFO) |
| Cross-Origin-Resource-Policy | No | `HTTP-MISSING-CORP` (INFO) |

### Example Findings

```json
{
  "id": "HTTP-MISSING-CSP",
  "title": "Missing Content-Security-Policy Header",
  "description": "The Content-Security-Policy header is not set, leaving the application vulnerable to XSS attacks.",
  "severity": "HIGH",
  "category": "headers",
  "location": "https://api.example.com/",
  "evidence": {
    "response_headers": {
      "server": "nginx/1.24.0",
      "date": "Mon, 15 Jan 2024 10:00:00 GMT"
    },
    "missing_headers": ["Content-Security-Policy"]
  },
  "references": [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    "https://owasp.org/www-project-secure-headers/"
  ],
  "metadata": {
    "adapter": "http_probe",
    "adapter_version": "1.0.0"
  }
}
```

---

## Crawler Adapter

**Class**: `CrawlerAdapter`  
**Name**: `crawler`  
**Targets**: `http`, `https`

### Purpose

Discovers application surface through link following, form extraction, and JavaScript analysis.

### Capabilities

| Feature | Finding ID | Severity | Description |
|---------|------------|----------|-------------|
| Link Discovery | `CRAWL-DISCOVERED-*` | INFO | New endpoints found |
| Form Analysis | `CRAWL-FORM-*` | MEDIUM/HIGH | CSRF, file upload, auth forms |
| JS Endpoints | `CRAWL-JS-ENDPOINT` | INFO | API endpoints in JavaScript |
| Sensitive Paths | `CRAWL-SENSITIVE-PATH` | MEDIUM | `.git`, `.env`, backups, admin |
| Robots.txt | `CRAWL-ROBOTS-*` | INFO | Disallowed paths |
| Sitemap | `CRAWL-SITEMAP-*` | INFO | Discovered URLs |

### Configuration

```json
{
  "adapters": {
    "crawler": {
      "max_pages": 100,
      "max_depth": 3,
      "max_concurrent": 5,
      "respect_robots_txt": true,
      "follow_external_links": false,
      "extract_forms": true,
      "extract_js_endpoints": true,
      "check_sensitive_paths": true,
      "sensitive_paths": [
        ".git", ".env", ".env.*", "backup", "bak",
        "admin", "phpmyadmin", "wp-admin", ".well-known"
      ],
      "timeout": 15,
      "delay": 0.5
    }
  }
}
```

### Example Findings

```json
{
  "id": "CRAWL-FORM-NO-CSRF",
  "title": "Form Missing CSRF Protection",
  "description": "Form at /login accepts POST without CSRF token.",
  "severity": "MEDIUM",
  "category": "csrf",
  "location": "https://app.example.com/login",
  "evidence": {
    "form_action": "/login",
    "form_method": "POST",
    "inputs": ["username", "password"],
    "csrf_token_present": false
  },
  "references": [
    "https://owasp.org/www-community/attacks/csrf"
  ],
  "metadata": {
    "adapter": "crawler",
    "adapter_version": "1.0.0",
    "depth": 1
  }
}
```

---

## Dynamic Validation Adapter

**Class**: `DynamicValidationAdapter`  
**Name**: `dynamic_validation`  
**Targets**: `http`, `https`

### Purpose

Active testing of runtime behavior including authentication, authorization, input validation, and business logic.

### Capabilities

| Test Category | Finding ID | Severity | Description |
|---------------|------------|----------|-------------|
| Auth Bypass | `DYN-AUTH-BYPASS` | CRITICAL | Authentication bypass |
| IDOR | `DYN-IDOR` | HIGH | Insecure Direct Object Reference |
| XSS Reflected | `DYN-XSS-REFLECTED` | HIGH | Reflected XSS |
| XSS Stored | `DYN-XSS-STORED` | CRITICAL | Stored XSS |
| SQL Injection | `DYN-SQLI` | CRITICAL | SQL injection |
| Command Injection | `DYN-CMD-INJECTION` | CRITICAL | OS command injection |
| Path Traversal | `DYN-PATH-TRAVERSAL` | HIGH | Directory traversal |
| Rate Limit | `DYN-RATE-LIMIT-BYPASS` | MEDIUM | Rate limiting bypass |
| Business Logic | `DYN-BIZ-LOGIC-*` | VARIES | Application-specific |

### Configuration

```json
{
  "adapters": {
    "dynamic_validation": {
      "test_auth_bypass": true,
      "test_idor": true,
      "idor_endpoints": [
        "/api/users/{id}",
        "/api/orders/{id}",
        "/api/documents/{id}"
      ],
      "test_xss": true,
      "xss_payloads": ["<script>alert(1)</script>", ""><img src=x onerror=alert(1)>"],
      "test_sqli": true,
      "sqli_payloads": ["'", "\"", "1 OR 1=1", "1; DROP TABLE users"],
      "test_cmd_injection": true,
      "test_path_traversal": true,
      "test_rate_limit": true,
      "rate_limit_threshold": 100,
      "test_business_logic": true,
      "business_logic_tests": [
        "coupon_reuse",
        "quantity_manipulation",
        "race_condition"
      ],
      "timeout": 30,
      "max_requests_per_endpoint": 50
    }
  }
}
```

### IDOR Testing

```python
# Example IDOR test flow
async def _test_idor(self):
    for endpoint in self.config.options.get("idor_endpoints", []):
        # Get valid IDs from crawled data
        valid_ids = await self._get_valid_ids(endpoint)
        
        for test_id in self._generate_test_ids(valid_ids):
            url = endpoint.format(id=test_id)
            dest = await self._authorize_connection(url)
            resp = await self._make_request("GET", url)
            
            if resp.status == 200:
                if self._is_sensitive_data(resp):
                    yield Finding(
                        id=f"DYN-IDOR-{endpoint}",
                        title="Insecure Direct Object Reference",
                        severity=Severity.HIGH,
                        location=url,
                        evidence={
                            "tested_id": test_id,
                            "response_status": resp.status,
                            "data_sample": self._sample(resp.body)
                        }
                    )
```

### Example Findings

```json
{
  "id": "DYN-IDOR-/api/users/{id}",
  "title": "Insecure Direct Object Reference - User API",
  "description": "API endpoint /api/users/{id} returns user data without authorization check.",
  "severity": "HIGH",
  "category": "idor",
  "location": "https://api.example.com/api/users/999",
  "evidence": {
    "tested_id": "999",
    "response_status": 200,
    "data_sample": {"id": 999, "email": "victim@example.com", "ssn": "123-45-6789"}
  },
  "references": [
    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
  ],
  "metadata": {
    "adapter": "dynamic_validation",
    "adapter_version": "1.0.0",
    "test_type": "idor"
  }
}
```

---

## Scope Gate Integration

All built-in adapters inherit from `BaseAdapter` and **must** call `_authorize_connection()` before any outbound request.

```python
class BaseAdapter(ABC):
    async def _make_request(self, method: str, url: str, **kwargs) -> Response:
        """Helper that enforces Scope Gate"""
        dest = await self._authorize_connection(url)
        return await self._connect_to_pinned(dest, method, **kwargs)

    async def _authorize_connection(self, url: str) -> Destination:
        """MUST be called before ANY outbound connection"""
        return await self.scope_gate.validate_outbound(url, self.scope)
```

### Connection Flow

```
Adapter.run()
    │
    ▼
for each target/URL:
    │
    ▼
_authorize_connection(url)
    │
    ▼
ScopeGate.validate_outbound()
    │
    ├── Layer 1: URL/Host check
    ├── Layer 2: DNS + IP check
    └── Layer 3: Returns pinned Destination
    │
    ▼
_connect_to_pinned(dest)
    │
    ├── Connect to dest.ip:dest.port
    ├── Set Host: dest.host
    ├── Verify TLS for dest.host
    │
    ▼
Execute tool logic
    │
    ▼
Yield Finding objects
```

---

## Running Built-in Adapters

### Via API

```bash
# Submit assessment with built-in adapters
curl -X POST https://api.strix.dev/api/v1/assessments \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "scope_id": "scope-123",
    "targets": ["https://app.example.com"],
    "adapters": ["http_probe", "crawler", "dynamic_validation"]
  }'
```

### Via CLI

```bash
# Run single adapter
strix adapter run http_probe --target https://example.com --scope scope.json

# Run all built-in
strix adapter run-all --target https://example.com --scope scope.json
```

### Programmatically

```python
from strix.core.adapters import adapter_registry, AdapterConfig
from strix.core.scope import ScopeGate, ScopeDocument

scope = ScopeDocument.from_file("scope.json")
gate = ScopeGate(scope)

config = AdapterConfig(
    scope=scope,
    target="https://app.example.com",
    options={},
    scope_gate=gate
)

# Run HTTP Probe
adapter = adapter_registry.get("http_probe")(config)
async for finding in adapter.run():
    print(finding.title, finding.severity)
```

---

## Performance

| Adapter | Typical Duration | Max Concurrent | Memory |
|---------|------------------|----------------|--------|
| HTTP Probe | 1-5s | 50 | 50MB |
| Crawler | 30-300s | 10 | 200MB |
| Dynamic Validation | 60-600s | 5 | 500MB |

---

## Extending Built-in Adapters

### Custom Security Headers

```python
class CustomHTTPProbeAdapter(HTTPProbeAdapter):
    name = "custom_http_probe"
    
    async def _check_security_headers(self, resp):
        # Parent checks
        async for f in super()._check_security_headers(resp):
            yield f
        
        # Custom: Expect-CT
        if "expect-ct" not in resp.headers:
            yield Finding(
                id="HTTP-MISSING-EXPECT-CT",
                title="Missing Expect-CT Header",
                severity=Severity.LOW,
                ...
            )
```

---

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| Adapter timeout | Target slow | Increase timeout |
| Scope Gate DENY | IP not authorized | Add CIDR to scope |
| Too many requests | Crawler aggressive | Reduce max_pages, increase delay |
| No findings | Target blocked | Check WAF, authentication |
| Memory spike | Large crawl | Reduce max_depth, max_pages |

---

## Related

- [External Tools](../adapters/external.md)
- [Custom Adapters](../adapters/custom.md)
- [Adapter SDK](../adapters/sdk.md)
- [Architecture: Adapters](../architecture/adapters.md)
- [API: Assessments](../api/assessments.md)