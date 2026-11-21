# NRB Compliance Audit Guide

**Auditor-Ready Documentation for Nepal Rastra Bank Cybersecurity Directives**

This guide enables auditors to verify Ishastra assessment evidence against NRB Directive 7/074 (Information Security Policy), Directive 8/075 (Cyber Resilience Framework), and Directive 11/076 (Digital Banking Security).

---

## 1. Framework Overview

| Attribute | Value |
|-----------|-------|
| **Regulator** | Nepal Rastra Bank (NRB) |
| **Directives** | 7/074, 8/075, 11/076 |
| **Sector** | Banking & Financial Institutions |
| **Jurisdiction** | Nepal |
| **Ishastra Coverage** | 17 controls across 3 directives |

### Directive Scope

| Directive | Title | Controls | Focus Area |
|-----------|-------|----------|------------|
| **7/074** | Information Security Policy | 5 (NRB-7.1 to NRB-7.5) | Governance, network, access, app sec, vuln mgmt |
| **8/075** | Cyber Resilience Framework | 5 (NRB-8.1 to NRB-8.5) | Identify, Protect, Detect, Respond, Recover |
| **11/076** | Digital Banking Security | 3 (NRB-11.2 to NRB-11.4) | API, Mobile, Transaction security |

---

## 2. Control Mapping Matrix

### Directive 7/074: Information Security Policy

| Control ID | Title | Ishastra Detection Categories | Evidence Required |
|------------|-------|---------------------------|-------------------|
| **NRB-7.1** | Information Security Policy | `missing_security_policy`, `outdated_policy`, `policy_not_board_approved` | Policy document, board approval, review date, version |
| **NRB-7.2** | Network Security | `open_management_ports`, `missing_segmentation`, `weak_firewall_rules`, `unencrypted_admin`, `exposed_database`, `missing_hsts`, `weak_cipher_suite`, `missing_csp` | Firewall config, network diagram, IDS alerts, TLS config, header analysis |
| **NRB-7.2.3** | Secure Communication Channels | `missing_hsts`, `weak_cipher_suite`, `cleartext_transmission`, `weak_tls`, `certificate_issues` | TLS config, cipher suites, HSTS header, certificate details |
| **NRB-7.3** | Access Control | `excessive_privileges`, `default_credentials`, `missing_mfa`, `orphaned_accounts`, `weak_password_policy`, `privilege_escalation`, `auth_bypass`, `idor` | Access matrix, review logs, MFA enrollment, password policy |
| **NRB-7.4** | Application Security | `sqli`, `xss`, `rce`, `idor`, `broken_auth`, `sensitive_data_exposure`, `xxe`, `ssrf`, `csrf`, `open_redirect`, `path_traversal`, `broken_object_auth` | SAST/DAST reports, WAF logs, patch records, code reviews |
| **NRB-7.5** | Vulnerability Management | `outdated_component`, `known_vulnerability`, `missing_patches`, `supply_chain_exposure`, `dependency_confusion` | Scan reports, patch logs, risk assessments, SBOM |

### Directive 8/075: Cyber Resilience Framework

| Control ID | Title | Ishastra Detection Categories | Evidence Required |
|------------|-------|---------------------------|-------------------|
| **NRB-8.1** | Identify | `git_exposure`, `open_tcp_port`, `service_exposure`, `banner_disclosure`, `unidentified_assets`, `shadow_it` | Asset inventory, risk register, exposure assessment |
| **NRB-8.1.4** | Transport Encryption | `missing_hsts`, `weak_tls_config`, `cleartext_transmission`, `weak_cipher_suite`, `certificate_issues` | TLS configuration, cipher suites, certificate inventory, HSTS preload |
| **NRB-8.2** | Protect | `missing_csp`, `missing_hsts`, `missing_x_frame_options`, `weak_cookie_flags`, `excessive_privileges`, `missing_mfa` | Security headers, access matrix, encryption audit, baselines |
| **NRB-8.3** | Detect | `sqli_indicator`, `xss_indicator`, `ssrf_indicator`, `missing_logging`, `log_tampering`, `no_siem`, `slow_detection` | SIEM config, log samples, alert rules, threat intel, detection metrics |
| **NRB-8.4** | Respond | `missing_ir_plan`, `slow_response`, `incomplete_containment`, `missing_root_cause`, `no_lessons_learned` | IR plan, incident logs, response timelines, RCA reports, reviews |
| **NRB-8.5** | Recover | `backup_exposure`, `untested_dr`, `backup_failures`, `missing_rto_rpo`, `no_bcp` | BCP document, DR test results, backup logs, RTO/RPO definition |

### Directive 11/076: Digital Banking Security

| Control ID | Title | Ishastra Detection Categories | Evidence Required |
|------------|-------|---------------------------|-------------------|
| **NRB-11.2** | API Security | `auth_bypass`, `idor`, `rate_limit_bypass`, `broken_object_auth`, `mass_assignment`, `excessive_data_exposure` | API gateway config, auth scheme, rate limits, audit logs, schema validation |
| **NRB-11.3** | Mobile App Security | `insecure_storage`, `weak_certificate_pinning`, `missing_root_detection`, `debug_code_present`, `weak_obfuscation`, `hardcoded_secrets` | Mobile SAST, pinning verification, storage encryption, anti-tamper test |
| **NRB-11.4** | Transaction Security | `csrf_missing`, `clickjacking_vulnerable`, `transaction_replay`, `missing_transaction_signing`, `fraud_rule_bypass` | CSRF tokens, X-Frame-Options, transaction signing, fraud detection |

---

## 3. Automated Compliance Checks

Ishastra runs the following automated verification checks for NRB compliance:

### 3.1 Encryption at Rest/In Transit (NRB-7.2.3, NRB-8.1.4)

```python
check_encryption_at_rest(job_findings)
```

**Verifies**: TLS 1.2+, strong ciphers (ECDHE+AES-GCM), HSTS with preload, certificate validity, database/backup encryption.

**Pass Criteria**: Zero findings in categories: `unencrypted_storage`, `weak_crypto`, `certificate_issues`, `cleartext_transmission`, `weak_tls`.

### 3.2 Access Control Review (NRB-7.3)

```python
check_access_control_rbac_mfa(job_findings)
```

**Verifies**: RBAC implementation, MFA enforcement, session management (15-min timeout, secure cookies, rotation), privileged access logging, quarterly access reviews.

**Pass Criteria**: Zero findings in: `excessive_privileges`, `default_credentials`, `missing_mfa`, `orphaned_accounts`, `weak_password_policy`, `privilege_escalation`, `auth_bypass`, `session_fixation`, `session_hijack`.

### 3.3 Audit Log Integrity (NRB-8.3, NRB-8.4)

```python
check_audit_log_integrity(job_findings)
```

**Verifies**: HMAC-SHA256 chained audit logs, SIEM deployment, immutable log storage, integrity monitoring, 7-year retention.

**Pass Criteria**: Zero findings in: `missing_logging`, `log_tampering`, `no_siem`.

### 3.4 Data Retention & Disposal (NRB-8.5, NRB-7.5)

```python
check_data_retention_disposal(job_findings)
```

**Verifies**: Retention schedules per NRB, secure disposal (crypto erasure), PII encryption, backup encryption, cross-border DPA.

**Pass Criteria**: Zero findings in: `backup_exposure`, `pii_exposure`, `credential_leak`, `data_offshore`, `uncontrolled_transfer`.

### 3.5 Incident Response (NRB-8.4)

```python
check_incident_response(job_findings)
```

**Verifies**: Documented IR plan, <4hr detection, <24hr containment, RCA completion, lessons learned, quarterly tabletop exercises.

**Pass Criteria**: Zero findings in: `missing_ir_plan`, `slow_response`, `incomplete_containment`, `missing_root_cause`, `no_lessons_learned`.

### 3.6 Vulnerability Management (NRB-7.5)

```python
check_vulnerability_management(job_findings)
```

**Verifies**: Continuous scanning (SAST/DAST/SCA/container), critical patch <72hr, high <30 days, SBOM maintenance, supply chain monitoring.

**Pass Criteria**: Zero findings in: `outdated_component`, `known_vulnerability`, `missing_patches`, `supply_chain_exposure`, `dependency_confusion`.

---

## 4. Evidence Pack Structure

### 4.1 JSON Evidence Pack

```bash
ishastra evidence --target https://bank.example.com --framework NRB --output nrb-evidence.json
```

**Key Sections**:
- `metadata`: Target, job, authorization, scope
- `summary`: Control counts, compliance score, findings
- `by_framework`: NRB-specific control results
- `controls`: Detailed control status with matched findings
- `findings`: All findings with compliance_refs
- `compliance_checks`: Automated verification results
- `audit_trail`: HMAC chain verification

### 4.2 CSV Export (Auditor Workbook)

```bash
ishastra evidence --target https://bank.example.com --framework NRB --format csv --output nrb-audit.csv
```

**Columns**: Control ID, Framework, Title, Category, Severity, Status, Description, Check Status, Findings Count, Top Finding, Recommendation, Matched Findings, Gaps, Evidence Required, Cross-Refs

### 4.3 OSCAL Assessment Results

```bash
ishastra evidence --target https://bank.example.com --framework NRB --format oscal --output nrb-oscal.json
```

**Standard**: NIST OSCAL 1.1.3 for GRC tool import (RSA Archer, ServiceNow GRC)

### 4.4 Bilingual HTML Report (Print to PDF)

```bash
ishastra evidence --target https://bank.example.com --framework NRB --format html --locale ne_NP --output nrb-report.html
```

**Features**: English + Nepali, Nepali calendar dates, Devanagari fonts, auditor-ready formatting.

---

## 5. Auditor Verification Procedures

### 5.1 Evidence Integrity Verification

```bash
# Verify HMAC audit chain
ishastra audit verify --pack nrb-evidence.json

# Or via API
curl -X POST https://ishastra.example.com/api/proof/verify \
  -H "Content-Type: application/json" \
  -d '{"proof": <evidence_pack_proof>}'
```

**Expected Result**: `chain_valid: true` with matching `chain_hash`.

### 5.2 Control Coverage Verification

| Directive | Controls Defined | Controls Assessed | Coverage |
|-----------|-----------------|-------------------|----------|
| 7/074 | 6 | 6 | 100% |
| 8/075 | 6 | 6 | 100% |
| 11/076 | 3 | 3 | 100% |
| **Total** | **15** | **15** | **100%** |

### 5.3 Finding Traceability

Each finding includes `compliance_refs` mapping to NRB controls:

```json
{
  "fingerprint": "a1b2c3d4...",
  "category": "missing_hsts",
  "severity": "medium",
  "compliance_refs": ["NRB-7.2.3", "NRB-8.1.4"],
  "evidence": {"header": "Strict-Transport-Security", "expected": "max-age=31536000"}
}
```

**Verification**: Cross-reference finding fingerprint with audit chain entry.

### 5.4 Automated Check Results

Review `compliance_checks.nrb` array for 6 automated verifications:

```json
{
  "control": "NRB-7.2.3 / NRB-8.1.4",
  "description": "Encryption at rest and in transit verification",
  "status": "pass",
  "findings_count": 0,
  "matched_findings": [],
  "recommendation": "Enforce TLS 1.2+ with strong cipher suites..."
}
```

---

## 6. Ishastra Feature Coverage for NRB

| Ishastra Feature | NRB Controls Covered | Automated Checks |
|---------------|---------------------|------------------|
| Scope Enforcement | 7.1, 7.3, 8.1 | Scope validation, authorization verification |
| Audit Chain | 8.3, 8.4 | HMAC integrity, chain verification |
| Redaction | 7.5 | PII/credential redaction |
| Evidence Packs | 7.1, 8.4 | Multi-format generation |
| Finding Lifecycle | 8.4 | SLA tracking, workflow validation |
| Vulnerability Scanning | 7.4, 7.5 | Scan coverage, remediation tracking |
| TLS Analysis | 7.2.3, 8.1.4 | Version, cipher, HSTS checks |
| Header Analysis | 7.2, 8.2 | CSP, HSTS, X-Frame-Options |
| Auth Testing | 7.3, 11.2 | MFA, session, bypass detection |
| API Security | 11.2 | OWASP API Top 10 |
| Mobile Testing | 11.3 | Pinning, storage, anti-tamper |
| Infra Scanning | 7.2, 8.1 | Port scan, service detection, CVE matching |
| Cloud Config Review | 7.2, 7.3 | CIS benchmarks, IAM, storage |
| Compliance Scheduling | 7.1, 8.4 | Quarterly evidence generation |
| Retention Management | 8.5 | Policy enforcement, backup encryption |
| Bilingual Reporting | 7.1 | EN/NE templates, Nepali dates |

---

## 7. Common Audit Findings & Remediation

### Finding: Missing HSTS Header (NRB-7.2.3, NRB-8.1.4)

**Evidence**: `Strict-Transport-Security` header absent on banking portal

**Remediation**:
```nginx
# Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

**Verification**: Re-scan confirms header present with `max-age=31536000`.

### Finding: Weak TLS Configuration (NRB-7.2.3, NRB-8.1.4)

**Evidence**: TLS 1.0/1.1 enabled, weak ciphers (CBC, RC4, 3DES)

**Remediation**:
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
```

**Verification**: `nmap --script ssl-enum-ciphers` shows only TLS 1.2+ with AEAD ciphers.

### Finding: Missing MFA on Admin Panel (NRB-7.3)

**Evidence**: Admin panel accessible with password only

**Remediation**:
- Deploy FIDO2/WebAuthn or TOTP MFA
- Enforce for all privileged accounts
- Implement step-up authentication for sensitive operations

**Verification**: Auth testing confirms MFA challenge on admin login.

### Finding: SQL Injection Indicator (NRB-7.4, NRB-8.3)

**Evidence**: User input concatenated into SQL query in search endpoint

**Remediation**:
- Use parameterized queries / prepared statements
- Implement WAF with SQLi rules
- Conduct code review for all database interactions

**Verification**: SAST/DAST re-scan shows no SQLi indicators.

---

## 8. Continuous Compliance

### 8.1 Scheduled Evidence Generation

```bash
# Create quarterly schedule (NRB requirement)
curl -X POST https://ishastra.example.com/api/schedules \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{
    "target": "https://bank.example.com",
    "cron_expression": "0 2 1 */3 *",
    "timezone": "Asia/Kathmandu",
    "profile": "web-deep",
    "policy_id": "pol_nrb_001",
    "frameworks": ["nrb"]
  }'
```

### 8.2 Webhook for GRC Integration

```bash
curl -X POST https://ishastra.example.com/api/alerts/webhook \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{
    "name": "nrb-grc-push",
    "url": "https://grc.bank.example.com/api/ishastra/evidence",
    "events": ["evidence_pack_generated"],
    "frameworks": ["nrb"]
  }'
```

### 8.3 Retention Configuration

```bash
# 7-year retention for NRB compliance
export ISHASTRA_RETENTION_DAYS=2555
```

---

## 9. Auditor Checklist

- [ ] Evidence pack JSON schema validates
- [ ] HMAC audit chain verification passes (`ishastra audit verify`)
- [ ] All 15 NRB controls assessed (100% coverage)
- [ ] Finding `compliance_refs` map to correct NRB controls
- [ ] Automated checks executed (6/6 for NRB)
- [ ] Critical gaps documented with remediation tracking
- [ ] Bilingual report generated (EN/NE) for local review
- [ ] OSCAL export imports into GRC tool
- [ ] Retention policy configured (2555 days)
- [ ] Authorization letter references match `scope_authorized_by` and `authorization_ref`
- [ ] Scope document excludes non-authorized assets
- [ ] Chain hash matches auditor's independent verification

---

## 10. References

- [NRB Directive 7/074](https://nrb.org.np) - Information Security Policy
- [NRB Directive 8/075](https://nrb.org.np) - Cyber Resilience Framework
- [NRB Directive 11/076](https://nrb.org.np) - Digital Banking Security
- [ISO 27001](https://iso.org/27001) - Information Security Management
- [NIST CSF](https://nist.gov/cyberframework) - Cybersecurity Framework
- [PCI DSS](https://pcisecuritystandards.org) - Payment Card Industry DSS
- [Ishastra Source](https://github.com/ishastra-project/ishastra) - MIT Licensed

---

*This guide is part of the Ishastra open-source compliance evidence pack generator. All mappings and checks are MIT-licensed and auditable.*