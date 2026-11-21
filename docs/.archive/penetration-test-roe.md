# Penetration Test Rules of Engagement

**Document Version:** 1.0  
**Effective Date:** 2026-11-16  
**Expiration Date:** 2027-02-16  
**Program:** ishastra-v3.5.0-hardened  
**Authorization Reference:** PENTEST-2026-001

---

## 1. Purpose and Scope

This document establishes the Rules of Engagement (RoE) for authorized penetration testing against the Ishastra v3.5.0-hardened platform. All testing activities MUST comply with these rules. Deviation requires written approval from the Security Team.

### 1.1 Authorized Targets

| Component | Base URL | Type | Authentication |
|-----------|----------|------|----------------|
| Ishastra API | https://api.ishastra.local | REST API | Bearer Token / Session Cookie |
| Ishastra Web UI | https://app.ishastra.local | SPA | Session Cookie / API Key Header |
| Ishastra Admin Panel | https://admin.ishastra.local | Admin Panel | Session Cookie + MFA / Admin API Key |

### 1.2 In-Scope API Endpoints

```
/api/assess                    POST   - Create assessment
/api/assess/{id}               GET    - Get assessment details
/api/assess/{id}/cancel        POST   - Cancel assessment
/api/assess/{id}/sarif         GET    - Export SARIF
/api/assess/{id}/findings/{fp} PATCH  - Update finding status
/api/report                    POST   - Generate report
/api/probe                     POST   - Probe target
/api/scope                     GET    - Get scope
/api/keys/create               POST   - Create API key (admin)
/api/keys/rotate/{tenant}      POST   - Rotate API key (admin)
/api/keys/revoke/{tenant}      POST   - Revoke API key (admin)
/api/policies                  POST   - Create policy (admin)
/api/policies/{id}             PATCH  - Update policy (admin)
/api/policies/{id}/revoke      POST   - Revoke policy (admin)
/api/users                     GET/POST - List/Create users (admin)
/api/alerts/webhook            POST   - Create webhook (admin)
/api/proof/verify              POST   - Verify proof
/api/audit                     GET    - Get audit log
/api/audit/verify              GET    - Verify audit chain
/api/metrics                   GET    - Prometheus metrics (admin)
/api/findings                  GET    - List findings
/api/findings/{fp}             GET    - Get finding details
/api/findings/{fp}/remediation PATCH  - Update remediation
/api/findings/{fp}/exception   POST   - Create risk exception
/api/assets                    GET    - List assets
/api/tenants                   GET    - List tenants (admin)
/api/tenants/{id}              GET    - Get tenant details (admin)
/api/version                   GET    - Version info
```

### 1.3 Out of Scope

The following are **EXPLICITLY PROHIBITED**:

- Third-party services (GitHub, Docker Hub, PyPI, container registries)
- Infrastructure layer (Kubernetes, cloud provider consoles, DNS management)
- CI/CD pipelines (GitHub Actions, build systems)
- Local development environments
- Physical security testing
- Social engineering (phishing, vishing, physical access)
- Supply chain attacks
- DoS/DDoS testing (load testing only within defined limits)
- Employee workstations or corporate network
- Any system not listed in Section 1.1

---

## 2. Testing Constraints

### 2.1 Testing Windows

| Window | Schedule | Notes |
|--------|----------|-------|
| Standard | 09:00-18:00 UTC, Mon-Fri | Primary testing window |
| Extended | 08:00-20:00 UTC, Mon-Fri | By prior arrangement only |
| Emergency | 24/7 | CRITICAL findings only; requires immediate notification |

### 2.2 Rate Limits

| Activity | Limit | Enforcement |
|----------|-------|-------------|
| API requests (authenticated) | 100 req/min per IP | Automatic 429 response |
| Auth endpoints (keys, users) | 5 req/5min per IP | Automatic 429 response |
| Assessment creation | 20 req/min per tenant | Automatic 429 response |
| Admin operations | 50 req/min per IP | Automatic 429 response |
| Concurrent scanners | 3 maximum | Manual coordination |
| Fuzzing | 1000 req/min max | Automatic throttling |

### 2.3 Prohibited Techniques

- **DoS/DDoS**: Any volumetric, protocol, or application-layer denial of service
- **Credential Stuffing**: Automated login attempts against test accounts
- **Brute Force**: >10 auth attempts/minute against any endpoint
- **Scanner Evasion**: Fragmentation, encoding evasion, timing evasion beyond 1000 req/min
- **Data Exfiltration**: Attempting to access production data or PII
- **Lateral Movement**: Pivoting from Ishastra to other systems
- **Persistence**: Installing backdoors, webshells, or scheduled tasks
- **Social Engineering**: Any human-targeted attacks

---

## 3. Credentials and Access

### 3.1 Provided Credentials

| Role | Credential Type | Provided Via |
|------|-----------------|--------------|
| Test Tenant (Analyst) | API Key `strix_...` | Encrypted email / secure portal |
| Test Admin | API Key `strix_...` | Encrypted email / secure portal |
| Test OIDC User | `pentest-analyst@ishastra.example.com` | Password reset link |
| Test OIDC Admin | `pentest-admin@ishastra.example.com` | Password reset link |

### 3.2 Credential Handling

- Credentials MUST be stored in encrypted password manager
- Credentials MUST NOT be committed to version control
- Credentials MUST NOT be shared with unauthorized personnel
- Credentials MUST be rotated after testing concludes
- API keys MUST be used via `Authorization: Bearer <key>` header only

---

## 4. Communication and Notification

### 4.1 Required Notifications

| Event | Timeline | Channel |
|-------|----------|---------|
| Testing start | At window start | Email: security@ishastra.example.com |
| CRITICAL finding | Within 1 hour | Email + Phone: +1-XXX-XXX-XXXX |
| HIGH finding | Within 4 hours | Email |
| Service disruption | Immediately | Email + Phone |
| Testing pause/end | At window end | Email |
| Retest request | After remediation | Email |

### 4.2 Emergency Contacts

| Role | Name | Email | Phone |
|------|------|-------|-------|
| Security Lead | [Name] | security@ishastra.example.com | +1-XXX-XXX-XXXX |
| Platform Engineer | [Name] | platform@ishastra.example.com | +1-XXX-XXX-XXXX |
| Incident Commander | [Name] | incident@ishastra.example.com | +1-XXX-XXX-XXXX |

### 4.3 Communication Format

All finding notifications MUST include:
- Finding title and severity (CVSS 3.1)
- Affected component and endpoint
- Steps to reproduce (minimal, non-destructive)
- Impact assessment
- Suggested remediation
- Evidence (screenshots, logs, request/response)

---

## 5. Data Handling and Evidence

### 5.1 Data Classification

| Data Type | Classification | Handling |
|-----------|----------------|----------|
| Test credentials | Secret | Encrypted storage, destroy after test |
| API responses (findings) | Confidential | Encrypted transit/storage |
| PII (if any encountered) | Restricted | **DO NOT ACCESS** - Report immediately |
| Credentials (if any found) | Restricted | **DO NOT USE** - Report immediately |
| Screenshots/logs | Confidential | Encrypted storage, 90-day retention |
| Final report | Confidential | Encrypted delivery |

### 5.2 Evidence Retention

- Raw evidence: 90 days post-engagement
- Final report: 3 years
- Credentials: Destroyed within 24 hours of test completion

### 5.3 Report Delivery

- Format: SARIF + PDF executive summary
- Encryption: PGP (key provided) or password-protected ZIP via secure portal
- Deadline: 14 calendar days after testing window closes

---

## 6. Vulnerability Scoring and Classification

### 6.1 Severity Ratings (CVSS 3.1)

| Rating | CVSS Score | SLA (Remediation) |
|--------|------------|-------------------|
| CRITICAL | 9.0-10.0 | 24 hours |
| HIGH | 7.0-8.9 | 72 hours |
| MEDIUM | 4.0-6.9 | 14 days |
| LOW | 0.1-3.9 | 30 days |
| INFO | 0.0 | Next release |

### 6.2 OWASP Top 10 Mapping

All findings MUST be mapped to OWASP Top 10 2021 categories:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable and Outdated Components
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging and Monitoring Failures
- A10: Server-Side Request Forgery (SSRF)

---

## 7. Testing Methodology

### 7.1 Phases

1. **Reconnaissance** (Passive only): DNS, SSL certs, public docs, headers
2. **Mapping**: API endpoint discovery, auth flows, parameter enumeration
3. **Vulnerability Analysis**: Automated + manual testing per OWASP Top 10
4. **Exploitation** (Controlled): Proof-of-concept only, NO data access
5. **Post-Exploitation** (Simulated): Impact assessment without actual access
6. **Reporting**: Document findings with evidence and remediation

### 7.2 Required Test Coverage

| OWASP Category | Minimum Tests |
|----------------|---------------|
| A01: Broken Access Control | 10 (IDOR, privilege escalation, tenant isolation) |
| A02: Cryptographic Failures | 5 (TLS, key management, encryption at rest) |
| A03: Injection | 15 (SQLi, NoSQLi, command injection, LDAP, template) |
| A04: Insecure Design | 5 (business logic, auth flows, policy bypass) |
| A05: Security Misconfiguration | 10 (headers, defaults, debug, CORS, CSP) |
| A06: Vulnerable Components | 5 (dependency scan, version analysis) |
| A07: Auth Failures | 10 (brute force, session, MFA, token handling) |
| A08: Integrity Failures | 5 (supply chain, CI/CD, unsigned artifacts) |
| A09: Logging Failures | 5 (audit coverage, alerting, retention) |
| A10: SSRF | 5 (URL validation, allowlists, internal access) |

---

## 8. Exploitation Boundaries

### 8.1 Permitted

- Proof-of-concept exploits that demonstrate impact WITHOUT:
  - Accessing/modifying data belonging to other tenants
  - Disrupting service availability
  - Modifying system configuration
  - Establishing persistence

### 8.2 Prohibited

- **Any** data access beyond proof-of-concept
- **Any** modification of database records
- **Any** privilege escalation to admin/root
- **Any** lateral movement
- **Any** credential theft or reuse
- **Any** destructive testing (DELETE, DROP, format, etc.)

### 8.3 Proof-of-Concept Requirements

PoC MUST:
- Be minimal (single request demonstrating issue)
- Include `X-Pentest-PoC: true` header
- Not modify persistent state
- Be documented with exact request/response

---

## 9. Incident Response

### 9.1 Tester-Induced Incidents

If testing causes or discovers an active incident:

1. **STOP** all testing immediately
2. Notify Security Lead via phone + email within 15 minutes
3. Document: time, action, observed impact
4. Do NOT attempt to fix or investigate further
5. Await instructions from Incident Commander

### 9.2 Pre-Existing Compromise

If evidence of pre-existing compromise is found:

1. **STOP** all testing immediately
2. Notify Security Lead via phone + email within 15 minutes
3. Preserve evidence (do not modify logs, files, memory)
4. Document: indicators, timestamps, affected systems
5. Await instructions from Incident Commander

---

## 10. Legal and Compliance

### 10.1 Authorization

This engagement is authorized by:
- **Authorized By:** Security Team
- **Authorization Ref:** PENTEST-2026-001
- **Legal Basis:** Mutual NDA + Penetration Testing Agreement

### 10.2 Compliance

Testing MUST comply with:
- Computer Fraud and Abuse Act (CFAA) - authorized access only
- GDPR/CCPA - no PII access, immediate reporting if encountered
- Industry regulations applicable to Ishastra deployment

### 10.3 Liability

- Tester liability limited to gross negligence or willful misconduct
- Ishastra not liable for tester equipment damage
- Both parties maintain independent insurance

---

## 11. Deliverables

### 11.1 Required Reports

| Deliverable | Format | Deadline |
|-------------|--------|----------|
| Preliminary Findings | Email summary | Daily during testing |
| Draft Technical Report | SARIF + Markdown | 7 days post-test |
| Final Report | SARIF + PDF + Markdown | 14 days post-test |
| Retest Results | SARIF + Markdown | 7 days post-retest |

### 11.2 Report Contents

Each finding MUST include:
- Unique ID (STRIX-PENTEST-YYYY-NNN)
- Title and executive summary
- CVSS 3.1 vector and score
- OWASP Top 10 category
- CWE ID(s)
- Affected component/endpoint
- Detailed reproduction steps
- Impact analysis
- Remediation guidance with code/config examples
- References (CVE, CWE, OWASP, vendor advisories)
- Evidence (request/response, screenshots, logs)

---

## 12. Retesting

### 12.1 Retest Scope

- All CRITICAL and HIGH findings
- MEDIUM findings with exploitability > 5.0
- Any finding where fix validation requires manual testing

### 12.2 Retest Process

1. Ishastra team notifies tester of fix deployment
2. Tester validates fix within 7 days
3. Tester updates finding status: FIXED / PARTIAL / NOT_FIXED
4. If PARTIAL/NOT_FIXED, provide additional evidence
5. Cycle repeats until all in-scope findings are FIXED

---

## 13. Acknowledgment

By conducting testing under this RoE, the tester acknowledges:

- [ ] Read and understood this entire document
- [ ] Will comply with all rules and constraints
- [ ] Has valid authorization (this document + NDA)
- [ ] Will report all findings per Section 4
- [ ] Will handle data per Section 5
- [ ] Will not exceed authorized scope
- [ ] Understands legal implications of non-compliance

**Tester Signature:** _________________________ **Date:** _______________

**Ishastra Security Lead Signature:** _________________________ **Date:** _______________

---

## Appendix A: Scope Document Reference

See `scope-pentest.json` for machine-readable scope definition including:
- Program metadata
- Include/exclude patterns
- Authorized networks and ports
- Rules of engagement (machine-readable)
- Component definitions with endpoints
- Credential placeholders
- Reporting requirements

---

## Appendix B: Testing Checklist

### Pre-Engagement
- [ ] NDA signed and returned
- [ ] RoE signed and returned
- [ ] Credentials received and verified
- [ ] Testing environment accessible
- [ ] Tools configured and tested

### During Testing
- [ ] Daily status emails sent
- [ ] CRITICAL/HIGH findings reported within SLA
- [ ] Evidence collected and encrypted
- [ ] Rate limits respected
- [ ] No prohibited techniques used

### Post-Engagement
- [ ] All credentials destroyed
- [ ] Raw evidence encrypted and stored
- [ ] Draft report delivered
- [ ] Final report delivered
- [ ] Retest scheduled (if applicable)

---

*End of Document*