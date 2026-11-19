# Strix Security Policy

**Version:** 3.5.0  
**Last Updated:** 2026-11-16  
**License:** Apache-2.0 (fully open source)

---

## 🔒 Security Overview

Strix is an authorized security assessment platform designed with security as a foundational principle. This document describes our security model, vulnerability disclosure process, bug bounty program, and security advisories.

### Security Principles

1. **Default Deny** - Scope gate blocks all targets unless explicitly authorized
2. **Tenant Isolation** - Cryptographic key-derived tenant identity, never header-based
3. **Defense in Depth** - Multiple validation layers (URL, DNS, pinned destination)
4. **Audit Integrity** - HMAC-sealed append-only audit chain
5. **Secret Redaction** - Automatic redaction at every output boundary
6. **Minimal Attack Surface** - No shell execution, bounded parsers, strict CSP

---

## 🛡️ Supported Versions

| Version | Supported | Security Updates |
|---------|-----------|------------------|
| 3.5.x (current) | ✅ Yes | Active |
| 3.4.x | ⚠️ Limited | Critical only |
| < 3.4 | ❌ No | None |

---

## 🐛 Reporting a Vulnerability

### Responsible Disclosure

We take security vulnerabilities seriously. Please report them **privately** via:

**🔐 GitHub Security Advisories (Preferred)**
- Navigate to: https://github.com/usestrix/strix/security/advisories/new
- Select "Report a vulnerability"
- Include all details below

**📧 Email (Alternative)**
- security@strix.example.com
- PGP Key: [Available on request]

### Required Information

| Field | Description |
|-------|-------------|
| **Version** | `strix --version` or `GET /api/version` |
| **Scope Mode** | `STRIX_SCOPE_MODE` value (global/managed/auto) |
| **Component** | API, UI, CLI, Scope Gate, Worker, etc. |
| **Severity** | Your CVSS 3.1 assessment |
| **Reproduction** | Minimal steps (Docker `--read-only` + temp `STRIX_DB` preferred) |
| **Impact** | Data access, privilege escalation, DoS, etc. |
| **PoC** | Non-destructive proof-of-concept |

### Response Timeline

| Severity | Acknowledgment | Assessment | Fix Target |
|----------|----------------|------------|------------|
| CRITICAL | 24 hours | 72 hours | 7 days |
| HIGH | 48 hours | 7 days | 14 days |
| MEDIUM | 7 days | 14 days | 30 days |
| LOW | 14 days | 30 days | Next release |

### Disclosure Process

1. **Report received** → Acknowledgment within SLA
2. **Triage** → Validate, assess impact, assign CVE if applicable
3. **Fix development** → Private fork, minimal patch
4. **Testing** → Regression tests, security test cases
5. **Coordinated release** → Patch release + advisory
6. **Public disclosure** → 30 days after fix release (or sooner if exploited)

---

## 💰 Bug Bounty Program

### Scope

| Asset | Type | Max Reward |
|-------|------|------------|
| `api.strix.local` | API | $5,000 |
| `app.strix.local` | Web App | $3,000 |
| `admin.strix.local` | Admin Panel | $5,000 |
| Scope Gate (`core/scope.py`) | Core Logic | $10,000 |
| Audit Chain (`audit.py`) | Core Logic | $8,000 |
| Redaction (`core/redaction.py`) | Core Logic | $5,000 |
| API Auth (`api/security.py`) | Auth | $5,000 |
| Strix Proof (`proof.py`) | Crypto | $8,000 |

### Reward Tiers (CVSS 3.1)

| Severity | CVSS Range | Base Reward | Bonus (Core Logic) |
|----------|------------|-------------|-------------------|
| CRITICAL | 9.0 - 10.0 | $5,000 | 2x |
| HIGH | 7.0 - 8.9 | $2,500 | 2x |
| MEDIUM | 4.0 - 6.9 | $1,000 | 1.5x |
| LOW | 0.1 - 3.9 | $250 | 1x |

### Bonus Multipliers

- **+50%**: First report of vulnerability class
- **+100%**: Core security component (scope gate, audit chain, crypto)
- **+25%**: High-quality PoC with exploit chain
- **+25%**: Suggested fix with test case

### Out of Scope (No Reward)

- DoS/DDoS (rate limiting is configurable)
- Social engineering / phishing
- Physical attacks
- Third-party services (GitHub, Docker, PyPI)
- Infrastructure (K8s, cloud provider)
- Issues requiring unverified assumptions
- Self-XSS requiring user interaction
- Missing security headers on non-authenticated public pages
- TLS configuration (operator responsibility)

### Rules

1. **Test only in scope** - See `scope-pentest.json` and `docs/penetration-test-roe.md`
2. **No automated scanning** > 1000 req/min without coordination
3. **No data access** beyond minimal PoC
4. **No disruption** of service availability
5. **Respect rate limits** - 429 means stop
6. **Single report per vulnerability** - No duplicate bounties
7. **No public disclosure** until coordinated release

### Payment

- Via GitHub Sponsors, PayPal, or bank transfer
- Within 30 days of coordinated disclosure
- Requires W-9/W-8BEN for US tax compliance
- Minimum $100 payout threshold

---

## 🔐 Security Architecture

### Authentication & Authorization

```
┌─────────────────────────────────────────────────────────────┐
│                    REQUEST FLOW                              │
├─────────────────────────────────────────────────────────────┤
│  1. Client → Authorization: Bearer <api_key>                │
│  2. APIKeyStore.validate_async() → SHA-256 lookup           │
│  3. TenantStateMiddleware → request.state.tenant_id         │
│  4. Route handler → SQL WHERE tenant_id = ?                 │
│  5. Response → Redacted at boundary                         │
└─────────────────────────────────────────────────────────────┘
```

**Key Properties:**
- API keys: SHA-256 stored, raw shown once at creation
- Tenant derived **only** from validated key (never headers)
- Tier ordering: `free < pro < enterprise` (principal cannot grant above own)
- Roles: `admin` (manage), `analyst` (assess), `viewer` (read-only)

### Scope Gate (Three-Layer Defense)

| Layer | Check | Enforcement |
|-------|-------|-------------|
| **L1** | URL parsing, host allow/deny, port allowlist | Synchronous, < 1ms |
| **L2** | DNS resolution, IP authorization, special-use denial | Async, 3s timeout, 16 concurrent |
| **L3** | Pinned `Destination` (scheme, host, port, IP) | Adapters MUST connect to pinned IP |

### Security Headers (Implemented in `SecurityHeadersMiddleware`)

| Header | Value | Purpose |
|--------|-------|---------|
| Content-Security-Policy | `default-src 'self'; script-src 'self'; ...` | XSS prevention |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains; preload` | HTTPS enforcement |
| X-Frame-Options | `DENY` | Clickjacking prevention |
| X-Content-Type-Options | `nosniff` | MIME sniffing prevention |
| Referrer-Policy | `strict-origin-when-cross-origin` | Referrer control |
| Permissions-Policy | `geolocation=(), camera=(), microphone=(), ...` | Feature restriction |
| Cross-Origin-Opener-Policy | `same-origin` | Context isolation |
| Cross-Origin-Resource-Policy | `same-origin` | Resource sharing control |
| Cross-Origin-Embedder-Policy | `require-corp` | Explicit cross-origin |
| Cache-Control (auth) | `no-store, no-cache, must-revalidate, private` | Sensitive data protection |

### Rate Limiting

| Endpoint Class | Limit | Backend |
|----------------|-------|---------|
| Auth (keys, users) | 5 req / 5 min / IP | Redis (distributed) |
| Assessments | 20 req / min / tenant | Redis |
| Admin operations | 50 req / min / IP | Redis |
| Anonymous | 10 req / min / IP | Redis |
| Health/Ready | Unlimited | N/A |

### Secret Redaction

Applied at **every** output boundary:
- Findings & SARIF export
- HTML/PDF reports
- Audit log entries
- Webhook payloads
- API error responses

**Patterns:** JWT, AWS keys, GitHub/GitLab/Azure/GCP tokens, PEM keys, bearer tokens, query params (`access_token`, `api_key`, `secret`, `password`, `jwt`), URL userinfo, Set-Cookie values.

---

## 📋 Security Advisories

### STRIX-2024-001: Missing CSRF Protection on State-Changing Endpoints
- **Severity:** HIGH (CVSS 8.8)
- **CWE:** CWE-352
- **Status:** FIXED
- **Fix:** Double-submit cookie CSRF protection (`strix_csrf` cookie, `X-CSRF-Token` header)

### STRIX-2024-002: Insecure Session Cookie Configuration
- **Severity:** HIGH (CVSS 7.5)
- **CWE:** CWE-614
- **Status:** FIXED
- **Fix:** Secure cookie defaults (HttpOnly, Secure, SameSite=Strict)

### STRIX-2024-003: Insufficient Rate Limiting on Auth Endpoints
- **Severity:** MEDIUM (CVSS 5.3)
- **CWE:** CWE-307
- **Status:** FIXED
- **Fix:** Dedicated `SensitiveRateLimitMiddleware` (5 req/5min for key ops)

### STRIX-2024-004: Missing Cache-Control on Authenticated Responses
- **Severity:** MEDIUM (CVSS 4.3)
- **CWE:** CWE-525
- **Status:** FIXED
- **Fix:** `Cache-Control: no-store` on all authenticated responses

### STRIX-2024-005: API Key Visible in Browser History
- **Severity:** LOW (CVSS 3.7)
- **CWE:** CWE-598
- **Status:** PARTIALLY MITIGATED
- **Mitigation:** Bearer header only, sessionStorage, CSRF protection

---

## 🔍 Automated Security Testing

### CI Pipeline (`.github/workflows/security-scan.yml`)

| Scanner | Purpose | Frequency |
|---------|---------|-----------|
| **Bandit** | Python AST static analysis | Every push/PR |
| **Semgrep** | Pattern-based SAST (OWASP, secrets) | Every push/PR |
| **Safety** | Known vuln DB for Python packages | Every push/PR |
| **pip-audit** | PyPA vulnerability scanner | Every push/PR |
| **Trivy** | Container/FS vulnerability scan | Every push/PR + weekly |
| **Hadolint** | Dockerfile security lint | Every push/PR |
| **TruffleHog** | Secret detection in git history | Every PR |
| **Dependency Review** | License + vuln check on PR deps | Every PR |

### Local Security Audit

```bash
# Run all scanners
python scripts/security_audit.py --output-dir reports --fail-on high --format json

# Individual scanners
bandit -r src/ -f json -o bandit-results.json
semgrep scan --config=auto --config=p/security-audit --config=p/owasp-top-ten --json=semgrep.json src/
safety check --json --output safety.json
pip-audit --format=json --output pip-audit.json -r constraints.txt
trivy fs --format json --output trivy.json .
```

### Penetration Testing

- **Scope:** `scope-pentest.json`
- **Rules of Engagement:** `docs/penetration-test-roe.md`
- **Frequency:** Annual third-party + continuous automated
- **Reporting:** SARIF + executive summary within 14 days

---

## ✅ Verification Checklist

| Control | Implementation | Test Coverage |
|---------|----------------|---------------|
| SQL Injection Prevention | Parameterized queries (aiosqlite), no raw SQL | 95% (scope gate) |
| XSS Prevention | CSP, output encoding, redaction | 90% (redaction) |
| CSRF Protection | Double-submit cookie, SameSite=Strict | 100% (middleware) |
| SSRF Prevention | URL validation, allowlist, pinned destination | 95% (scope gate) |
| Path Traversal | Path sanitization, no user-controlled paths | 85% (store) |
| Command Injection | Subprocess with args array, no shell | 100% (adapters) |
| Broken Auth | SHA-256 keys, constant-time compare, rotation | 100% (auth) |
| Sensitive Data Exposure | Redaction at boundaries, no logging of secrets | 90% (redaction) |
| Security Misconfiguration | Secure headers, debug mode off, secure cookies | 100% (middleware) |
| Vulnerable Components | pip-audit, Safety, Trivy in CI | Continuous |

---

## 📚 References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP ASVS 4.0](https://owasp.org/www-project-application-security-verification-standard/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [CVSS 3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [Apache License 2.0](LICENSE)

---

## 📞 Contact

**Security Team:** security@strix.example.com  
**PGP Key:** [keys.openpgp.org](https://keys.openpgp.org/search?q=security%40strix.example.com)  
**Security Advisories:** https://github.com/usestrix/strix/security/advisories

---

*Strix is fully open source under the Apache License 2.0. No open-core split, no paid edition, no proprietary add-ons.*