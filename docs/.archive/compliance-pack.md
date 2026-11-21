# Compliance Pack Guide

Ishastra generates **compliance evidence packs** mapped to regulatory frameworks. This guide covers the supported frameworks, evidence structure, and how to use them for audits.

---

## Supported Frameworks

| Framework | Sector | Jurisdiction | Key Controls Mapped |
|-----------|--------|--------------|---------------------|
| **NRB** | Banking | Nepal | NRB Directive 7/074, 8/075, 11/076 |
| **NTA** | Telecommunications | Nepal | NTA Cybersecurity Byelaw 2078 |
| **NCSP** | National Critical Infrastructure | Nepal | National Cyber Security Policy 2080 |

---

## Evidence Pack Structure

Each compliance pack is a JSON document containing:

```json
{
  "schema_version": "1.0",
  "generated_at": "2024-01-15T10:35:00Z",
  "framework": "NRB",
  "target": "https://ibank.examplebank.com",
  "job_id": "job_abc123",
  "authorization": {
    "program": "NRB Compliance Assessment",
    "authorized_by": "CISO",
    "authorization_ref": "NRB-DIR-SEC-2024-001"
  },
  "assessment": {
    "profile": "web-deep",
    "state": "completed",
    "verdict": "pass",
    "coverage": {"http-headers": {"pages": 1, "findings": 0}}
  },
  "findings": [
    {
      "fingerprint": "a1b2c3d4...",
      "category": "Missing Security Header",
      "severity": "medium",
      "title": "Missing HSTS Header",
      "description": "HTTP Strict Transport Security not enforced",
      "location": "https://ibank.examplebank.com/",
      "evidence": {"header": "Strict-Transport-Security"},
      "compliance_refs": ["NRB-7.2.3", "NRB-8.1.4"],
      "status": "new",
      "created_at": 1705312805
    }
  ],
  "mappings": {
    "NRB-7.2.3": {
      "control": "Secure communication channels",
      "findings": ["a1b2c3d4..."],
      "status": "non_compliant"
    },
    "NRB-8.1.4": {
      "control": "Transport encryption",
      "findings": ["a1b2c3d4..."],
      "status": "non_compliant"
    }
  },
  "summary": "2 finding(s) mapped to NRB controls",
  "integrity": {
    "chain_valid": true,
    "chain_hash": "sha256:abc123..."
  }
}
```

---

## Generating Compliance Packs

### Via CLI
```bash
# Generate NRB evidence pack
ishastra evidence --target https://ibank.examplebank.com --framework NRB --output nrb-evidence.json

# Generate NTA evidence pack
ishastra evidence --target https://api.telecom.com --framework NTA --output nta-evidence.json

# Generate NCSP evidence pack
ishastra evidence --target https://critical.gov.np --framework NCSP --output ncsp-evidence.json
```

### Via API
```bash
curl -X POST http://localhost:8000/api/evidence \
  -H "Authorization: Bearer $ISHASTRA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://ibank.examplebank.com",
    "framework": "NRB"
  }' \
  -o nrb-evidence.json
```

### From Existing Assessment
```bash
# Generate pack from completed job
curl -X GET http://localhost:8000/api/assess/job_abc123/evidence?framework=NRB \
  -H "Authorization: Bearer $ISHASTRA_API_KEY" \
  -o nrb-evidence.json
```

---

## NRB (Nepal Rastra Bank) Mapping

### Directive 7/074 - Information Security Policy

| Control ID | Control Title | Ishastra Finding Categories |
|------------|---------------|-------------------------|
| NRB-7.1 | Information Security Policy | Policy documentation findings |
| NRB-7.2 | Network Security | `missing_hsts`, `missing_csp`, `weak_tls_config` |
| NRB-7.2.3 | Secure communication channels | `missing_hsts`, `weak_cipher_suite` |
| NRB-7.3 | Access Control | `auth_bypass`, `idor`, `privilege_escalation` |
| NRB-7.4 | Application Security | `sqli_indicator`, `xss_indicator`, `path_traversal` |
| NRB-7.5 | Vulnerability Management | All vulnerability findings |

### Directive 8/075 - Cyber Resilience Framework

| Control ID | Control Title | Ishastra Finding Categories |
|------------|---------------|-------------------------|
| NRB-8.1 | Identify | Asset exposure (`git_exposure`, `open_tcp_port`) |
| NRB-8.1.4 | Transport encryption | `missing_hsts`, `weak_tls_config` |
| NRB-8.2 | Protect | Header hardening (`missing_csp`, `missing_hsts`, `missing_x_frame_options`) |
| NRB-8.3 | Detect | `sqli_indicator`, `xss_indicator`, `ssrf_indicator` |
| NRB-8.4 | Respond | Finding lifecycle (triaged → fix_verified) |
| NRB-8.5 | Recover | Backup exposure, disaster recovery findings |

### Directive 11/076 - Digital Banking Security

| Control ID | Control Title | Ishastra Finding Categories |
|------------|---------------|-------------------------|
| NRB-11.2 | API Security | `auth_bypass`, `idor`, `rate_limit_bypass`, `broken_object_auth` |
| NRB-11.3 | Mobile App Security | `insecure_storage`, `weak_certificate_pinning` |
| NRB-11.4 | Transaction Security | `csrf_missing`, `clickjacking_vulnerable` |

---

## NTA (Nepal Telecommunications Authority) Mapping

### Cybersecurity Byelaw 2078

| Control ID | Control Title | Ishastra Finding Categories |
|------------|---------------|-------------------------|
| NTA-4.1 | Network perimeter security | `open_tcp_port`, `service_exposure`, `banner_disclosure` |
| NTA-4.2 | Secure configuration | `missing_hsts`, `weak_cipher_suite`, `default_credentials` |
| NTA-4.3 | Vulnerability assessment | All `*_indicator` findings, `sqli`, `xss`, `rce` |
| NTA-4.4 | Access control | `auth_bypass`, `privilege_escalation`, `session_fixation` |
| NTA-4.5 | Monitoring & logging | `missing_security_headers`, `information_disclosure` |
| NTA-4.6 | Incident response | Finding lifecycle tracking |
| NTA-4.7 | Third-party risk | `supply_chain_exposure`, `outdated_component` |

---

## NCSP (National Cyber Security Policy) Mapping

### National Cyber Security Policy 2080

| Control ID | Control Title | Ishastra Finding Categories |
|------------|---------------|-------------------------|
| NCSP-3.1 | Critical infrastructure protection | `scada_exposure`, `ics_protocol_exposure` |
| NCSP-3.2 | Network security monitoring | `missing_hsts`, `weak_tls`, `open_management_port` |
| NCSP-3.3 | Application security | `sqli`, `xss`, `ssrf`, `xxe`, `deserialization` |
| NCSP-3.4 | Identity & access management | `auth_bypass`, `idor`, `mfa_bypass`, `session_hijack` |
| NCSP-3.5 | Data protection | `pii_exposure`, `credential_leak`, `encryption_absent` |
| NCSP-3.6 | Supply chain security | `dependency_confusion`, `malicious_package` |
| NCSP-3.7 | Incident management | Finding lifecycle, audit trail |

---

## Evidence Pack Fields

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | Evidence pack schema version |
| `generated_at` | ISO8601 | Generation timestamp |
| `framework` | enum | `NRB`, `NTA`, `NCSP`, `CUSTOM` |
| `target` | string | Assessed target URL |
| `job_id` | string | Source assessment job ID |
| `authorization` | object | Authorization metadata |
| `assessment` | object | Profile, state, verdict, coverage |
| `findings` | array | Normalized findings with compliance refs |
| `mappings` | object | Framework control → findings mapping |
| `summary` | string | Human-readable summary |
| `integrity` | object | Audit chain verification |

---

## Finding Compliance Refs

Each finding includes `compliance_refs` array mapping to framework controls:

```json
{
  "fingerprint": "a1b2c3d4...",
  "category": "Missing HSTS Header",
  "severity": "medium",
  "compliance_refs": ["NRB-7.2.3", "NRB-8.1.4", "NTA-4.2", "NCSP-3.2"],
  "evidence": {"header": "Strict-Transport-Security", "expected": "max-age=31536000"}
}
```

### Adding Custom Mappings

Extend `src/ishastra/core/evidence.py`:

```python
COMPLIANCE_MAPPINGS = {
    "NRB": {
        "missing_hsts": ["NRB-7.2.3", "NRB-8.1.4"],
        "missing_csp": ["NRB-7.2.4", "NRB-8.2.1"],
        "sqli_indicator": ["NRB-7.4.2"],
        # Add your mappings
    },
    "NTA": {
        "missing_hsts": ["NTA-4.2"],
        "open_tcp_port": ["NTA-4.1"],
        # Add your mappings
    },
    "NCSP": {
        "missing_hsts": ["NCSP-3.2"],
        "sqli_indicator": ["NCSP-3.3"],
        # Add your mappings
    },
}
```

---

## Audit Chain Integrity

Every evidence pack includes integrity verification:

```json
"integrity": {
  "chain_valid": true,
  "chain_hash": "sha256:abc123def456..."
}
```

- **chain_valid**: Audit chain HMAC verified
- **chain_hash**: Current chain head hash for offline verification

Verify offline:
```bash
# Using Ishastra Proof verification
curl -X POST http://localhost:8000/api/proof/verify \
  -H "Content-Type: application/json" \
  -d '{"proof": <evidence_pack_proof>}'
```

---

## Report Templates

### Executive Summary (NRB)
```markdown
# NRB Compliance Assessment - Executive Summary

**Target**: https://ibank.examplebank.com
**Authorization**: NRB-DIR-SEC-2024-001
**Assessment Date**: 2024-01-15
**Profile**: web-deep
**Verdict**: FAIL (2 medium findings)

## Control Coverage
| Directive | Controls Tested | Compliant | Non-Compliant |
|-----------|-----------------|-----------|---------------|
| 7/074 | 5 | 3 | 2 |
| 8/075 | 5 | 4 | 1 |
| 11/076 | 3 | 3 | 0 |

## Critical Gaps
1. **NRB-7.2.3** - Missing HSTS on banking portal
2. **NRB-8.1.4** - Transport encryption not enforced

## Recommendations
1. Implement HSTS with preload on all banking subdomains
2. Enforce TLS 1.2+ with strong cipher suites
```

### Technical Detail (NTA)
```markdown
# NTA Cybersecurity Assessment - Technical Findings

## Network Perimeter (NTA-4.1)
| Finding | Severity | Port/Service | Evidence |
|---------|----------|--------------|----------|
| Open management port | High | 22/SSH | Banner: OpenSSH 7.9 |
| Service exposure | Medium | 3306/MySQL | Version: 5.7.33 |

## Secure Configuration (NTA-4.2)
| Finding | Severity | Control | Remediation |
|---------|----------|---------|-------------|
| Weak TLS config | Medium | NTA-4.2 | Disable TLS 1.0/1.1 |
| Missing security headers | Low | NTA-4.2 | Add CSP, HSTS, X-Frame-Options |
```

---

## Integration with GRC Tools

### Export for RSA Archer
```bash
ishastra evidence --target https://example.com --framework NRB \
  --format archer --output archer-import.json
```

### Export for ServiceNow GRC
```bash
ishastra evidence --target https://example.com --framework NTA \
  --format servicenow --output sn-import.json
```

### Custom Format
```python
from ishastra.core.evidence import generate_evidence_pack

pack = generate_evidence_pack(
    target="https://example.com",
    framework="NRB",
    job_id="job_abc123",
    custom_format=lambda p: transform_for_your_tool(p)
)
```

---

## Continuous Compliance

### Scheduled Evidence Generation
```bash
# Create daily compliance schedule
curl -X POST http://localhost:8000/api/schedules \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{
    "target": "https://ibank.examplebank.com",
    "cron_expression": "0 2 * * *",
    "timezone": "Asia/Kathmandu",
    "profile": "web-deep",
    "policy_id": "pol_nrb_001"
  }'
```

### Webhook for Evidence Pack Completion
```bash
# Configure webhook to push evidence to GRC
curl -X POST http://localhost:8000/api/alerts/webhook \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{
    "name": "grc-evidence-push",
    "url": "https://grc.example.com/api/ishastra/evidence"
  }'
```

### Retention Policy
Evidence packs follow `ISHASTRA_RETENTION_DAYS` (default 90 days). For compliance, configure longer retention:
```bash
export ISHASTRA_RETENTION_DAYS=2555  # 7 years for regulatory compliance
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No mappings for finding | Add mapping in `COMPLIANCE_MAPPINGS` dict |
| Framework not recognized | Check `framework` parameter spelling (NRB, NTA, NCSP) |
| Evidence pack empty | Ensure job completed with findings; check `verdict` |
| Integrity verification failed | Audit chain tampered; investigate immediately |
| PDF generation fails | Install WeasyPrint system deps (pango, harfbuzz, cairo) |