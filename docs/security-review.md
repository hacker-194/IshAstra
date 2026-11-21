# Security Review Process

# Security Review Process

Ishastra follows a structured security review process for all code changes, releases, and operational procedures.

## Review Types

### 1. Code Review (Every PR)

All changes require security-focused code review:

- **Authentication/Authorization changes** - Mandatory review by security team
- **Scope Gate modifications** - Dual approval required
- **Crypto operations** - Review by cryptography-knowledgeable reviewer
- **New adapters** - Scope Gate integration verification

### 2. Pre-Release Security Review

Before each release:

- Dependency vulnerability scan (`cargo audit`, `pip-audit`, `safety`)
- SAST scan (bandit, semgrep, codeql)
- Container image scan (trivy, grype)
- Scope Gate invariant verification (TLA+ model re-check)

### 3. Periodic Security Audits

- **Quarterly**: Full architecture review
- **Annually**: Third-party penetration test
- **Continuous**: Bug bounty program

## Security Review Checklist

### Authentication & Authorization

- [ ] All endpoints require authentication
- [ ] Role-based access control enforced
- [ ] Scope Gate validation on every outbound request
- [ ] Break-glass requires dual approval + MFA
- [ ] JWT validation uses JWKS rotation

### Data Protection

- [ ] Secrets never in logs or error messages
- [ ] API keys hashed with bcrypt/scrypt
- [ ] Database uses Row-Level Security
- [ ] Encryption at rest (AES-256) and in transit (TLS 1.3)
- [ ] PII handling compliance (GDPR, CCPA)

### Input Validation

- [ ] All inputs validated at API boundary
- [ ] JSON schema validation for all payloads
- [ ] Path traversal prevention
- [ ] SSRF prevention via Scope Gate
- [ ] SQL injection prevention (parameterized queries)

### Cryptography

- [ ] Ed25519 for signatures (no RSA)
- [ ] TLS 1.3 minimum
- [ ] Key rotation implemented
- [ ] No hardcoded secrets or keys
- [ ] Secure random sources (OS CSPRNG)

### Operational Security

- [ ] Audit logging for all security events
- [ ] Alerting on auth failures, scope violations
- [ ] Incident response runbooks current
- [ ] Backup encryption and access control
- [ ] Disaster recovery tested quarterly

## Vulnerability Management

### Reporting

Report security issues to: **security@ishastra.dev**

- PGP key: Available at https://ishastra.dev/.well-known/pgp-key
- Response SLA: 48 hours acknowledgment
- Disclosure: Coordinated disclosure preferred

### Severity Classification

| Severity | CVSS | Response Time | Example |
|----------|------|---------------|---------|
| Critical | 9.0-10.0 | 24 hours | RCE, auth bypass, Scope Gate bypass |
| High | 7.0-8.9 | 72 hours | SQLi, SSRF, privilege escalation |
| Medium | 4.0-6.9 | 2 weeks | XSS, info disclosure, DoS |
| Low | 0.1-3.9 | Next release | Minor info leaks, config issues |

### Remediation Process

1. **Triage** - Confirm, classify, assign
2. **Contain** - Mitigate if actively exploited
3. **Fix** - Develop and test patch
4. **Verify** - Regression tests + security tests
5. **Release** - Coordinated disclosure timeline
6. **Postmortem** - Root cause, process improvements

## Compliance Mapping

Security reviews validate against:

- **NIST 800-53** - See [NIST Mapping](compliance/nist.md)
- **ISO 27001** - See [ISO Mapping](compliance/iso27001.md)
- **SOC 2 Type II** - See [SOC 2 Mapping](compliance/soc2.md)
- **PCI DSS** - See [PCI DSS Mapping](compliance/pci-dss.md)

## Related

- [API Authentication](api/authentication.md)
- [Scope Gate Concepts](scope-gate/concepts.md)
- [Break Glass](scope-gate/break-glass.md)
- [Compliance Overview](compliance/overview.md)
- [Contributing: Development](contributing/development.md)