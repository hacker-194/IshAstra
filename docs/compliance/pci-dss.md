# PCI DSS 4.0.1 Mapping

# PCI DSS 4.0.1 Control Mapping

Mapping of Ishastra controls to Payment Card Industry Data Security Standard v4.0.1.

## Control Summary

| Requirement | Implemented | Partial | Planned | N/A | Notes |
|-------------|-------------|---------|---------|-----|-------|
| Req 1: Network Security | 8 | 1 | 0 | 0 | Scope Gate = network segmentation |
| Req 2: Secure Configuration | 7 | 0 | 1 | 0 | Hardened defaults, GitOps |
| Req 3: Protect Cardholder Data | 5 | 0 | 0 | 1 | No CHD stored (assessment platform) |
| Req 4: Encrypt Transmission | 4 | 0 | 0 | 0 | TLS 1.3 everywhere |
| Req 5: Malware Protection | 4 | 0 | 0 | 0 | Container scanning, admission control |
| Req 6: Secure Development | 12 | 1 | 1 | 0 | TDD, TLA+, security gates |
| Req 7: Access Control | 6 | 0 | 0 | 0 | RBAC, Scope Gate, break-glass |
| Req 8: Identity & Authentication | 8 | 0 | 0 | 0 | API keys, JWT, MFA |
| Req 9: Physical Access | 0 | 0 | 0 | 5 | Cloud provider responsibility |
| Req 10: Logging & Monitoring | 10 | 1 | 0 | 0 | Ishastra Proof, immutable audit |
| Req 11: Testing | 8 | 0 | 0 | 0 | Automated + manual pentest |
| Req 12: Information Security Policy | 6 | 0 | 1 | 0 | Policy-as-Code, documented |

## Requirement 1: Network Security Controls

| Sub-req | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| 1.1.1 | Network security controls | ✅ | Scope Gate default-deny, network policies |
| 1.1.2 | Network diagram | ✅ | Architecture docs, data flow diagrams |
| 1.1.3 | Data flow diagram | ✅ | Documented in architecture/ |
| 1.1.4 | Segmentation | ✅ | Scope Gate CIDR/host/port, network policies |
| 1.1.5 | Review network controls | ✅ | Quarterly review, automated validation |
| 1.2.1 | Default-deny | ✅ | Scope Gate core feature |
| 1.2.2 | Business justification | ✅ | Scope document = business justification |
| 1.2.3 | Secure services | ✅ | TLS 1.3, mTLS, adapter sandboxing |
| 1.3.1 | DMZ / segmentation | ✅ | Namespace isolation, network policies |
| 1.3.2 | Wireless | ❌ N/A | Cloud provider |
| 1.4.1 | Mobile / employee | ❌ N/A | Not applicable |
| 1.4.2 | Personal devices | ❌ N/A | Not applicable |
| 1.5.1 | Documentation | ✅ | All network controls documented |

## Requirement 2: Secure Configurations

| Sub-req | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| 2.1.1 | Default passwords | ✅ | No defaults, generated secrets |
| 2.1.2 | Unnecessary services | ✅ | Distroless, minimal attack surface |
| 2.1.3 | Insecure protocols | ✅ | TLS 1.3 only, no HTTP |
| 2.2.1 | Configuration standards | ✅ | CIS benchmarks, hardened images |
| 2.2.2 | System hardening | ✅ | Immutable containers, read-only FS |
| 2.2.3 | Wireless | ❌ N/A | Cloud provider |
| 2.2.4 | Mobile | ❌ N/A | Not applicable |
| 2.3.1 | Vendor defaults | ✅ | Custom images, no vendor defaults |

## Requirement 3: Protect Stored Cardholder Data

| Sub-req | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| 3.1.1 | Data retention | ✅ | Configurable, crypto erase |
| 3.2.1 | No CHD storage | ✅ | **Ishastra does not store CHD** - assessment platform only |
| 3.2.2 | No SAD storage | ✅ | No sensitive authentication data |
| 3.3.1 | Masking | ✅ | Finding sanitization, PII redaction |
| 3.4.1 | Encryption at rest | ✅ | AES-256-GCM, sealed secrets |
| 3.5.1 | Key management | ✅ | External Secrets Operator, rotation |
| 3.6.1 | Key procedures | ✅ | Documented, automated rotation |
| 3.7.1 | Key storage | ✅ | HSM/KMS backed, never in code |

*Note: Ishastra is a security assessment platform, not a payment processor. It does not store, process, or transmit cardholder data. This mapping shows how Ishastra's architecture supports PCI DSS requirements for systems that DO handle CHD.*

## Requirement 4: Encrypt Transmission

| Sub-req | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| 4.1.1 | Strong cryptography | ✅ | TLS 1.3, AES-256-GCM, ChaCha20-Poly1305 |
| 4.1.2 | TLS 1.3 | ✅ | Minimum TLS 1.3 everywhere |
| 4.2.1 | Pan-primary account number | ✅ | Not applicable (no PAN) |
| 4.3.1 | End-user messaging | ✅ | Not applicable |

## Requirement 5: Malware Protection

| Sub-req | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| 5.1.1 | Anti-malware | ✅ | Trivy, Grype, ClamAV in CI |
| 5.1.2 | Periodic scans | ✅ | Per-commit, daily scheduled |
| 5.2.1 | Detection | ✅ | Real-time container scanning |
| 5.3.1 | Remediation | ✅ | Automated blocking, alerting |
| 5.4.1 | Log retention | ✅ | 1 year minimum, immutable |

## Requirement 6: Secure Development

| Sub-req | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| 6.1.1 | Secure SDLC | ✅ | TDD, threat modeling, TLA+ |
| 6.2.1 | Vulnerability management | ✅ | Dependabot, Trivy, Grype, nuclei |
| 6.2.2 | Critical patches | ✅ | <30 days, automated PRs |
| 6.2.3 | Risk ranking | ✅ | CVSS, exploitability, reachability |
| 6.3.1 | Code review | ✅ | Required PR review, security gates |
| 6.3.2 | Secure coding | ✅ | Rust/Python, type hints, linters |
| 6.3.3 | Training | 🔄 | Developer onboarding (partial) |
| 6.4.1 | Third-party code | ✅ | SBOM, license scan, approved list |
| 6.4.2 | Inventory | ✅ | Syft SBOM, dependency graph |
| 6.4.3 | Patches | ✅ | Automated Dependabot PRs |
| 6.5.1 | Injection prevention | ✅ | Pydantic, parameterized queries, Scope Gate |
| 6.5.2 | XSS prevention | ✅ | No direct HTML, sanitization |
| 6.5.3 | Auth bypass | ✅ | Scope Gate per-request, JWT validation |
| 6.5.4 | IDOR | ✅ | Dynamic validation adapter tests IDOR |
| 6.5.5 | Access control | ✅ | RBAC, RLS, break-glass dual approval |
| 6.5.6 | Crypto failures | ✅ | TLS 1.3, Ed25519, JWKS rotation |
| 6.5.7 | Insecure deserialization | ✅ | Pydantic schemas, no pickle |
| 6.5.8 | Logging failures | ✅ | Structured logging, correlation IDs |
| 6.5.9 | SSRF | ✅ | Scope Gate (core), egress control |
| 6.5.10 | Security misconfiguration | ✅ | GitOps, drift detection, hardening |

## Requirement 7: Restrict Access by Business Need

| Sub-req | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| 7.1.1 | Need-to-know | ✅ | Scoped API keys, per-assessment tokens |
| 7.1.2 | Least privilege | ✅ | RBAC roles, minimal scopes |
| 7.2.1 | Default deny | ✅ | Scope Gate default-deny |
| 7.2.2 | Access review | ✅ | Quarterly automated, manual |
| 7.2.3 | Privileged access | ✅ | Break-glass dual approval, audit |

## Requirement 8: Identify Users & Authenticate Access

| Sub-req | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| 8.1.1 | Unique IDs | ✅ | API key IDs, JWT subjects |
| 8.1.2 | MFA | ✅ | Required for break-glass, admin |
| 8.2.1 | Strong auth | ✅ | 256-bit keys, Ed25519, JWT |
| 8.2.2 | MFA for all | ✅ | Break-glass, admin, CI/CD |
| 8.3.1 | Cryptographic auth | ✅ | API keys, JWT, mTLS |
| 8.3.2 | MFA for remote | ✅ | VPN, mTLS, break-glass |
| 8.4.1 | Service accounts | ✅ | Scoped keys, no human passwords |
| 8.5.1 | Third-party | ✅ | Vendor keys, scoped access |
| 8.6.1 | No shared accounts | ✅ | Unique keys per identity |

## Requirement 9: Physical Access - Cloud Provider

| Sub-req | Title | Status | Note |
|---------|-------|--------|------|
| 9.1.1 to 9.7.1 | All physical controls | ❌ N/A | AWS/GCP/Azure/Oracle responsibility |

## Requirement 10: Log & Monitor All Access

| Sub-req | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| 10.1.1 | Audit trails | ✅ | Ishastra Proof, immutable chain |
| 10.2.1 | Automated audit | ✅ | Per-request Scope Gate logging |
| 10.2.2 | Log all access | ✅ | Every grant/gate/proof/verify |
| 10.2.3 | Log admin | ✅ | All admin actions audited |
| 10.3.1 | Log content | ✅ | Structured JSON, correlation IDs |
| 10.3.2 | Time sync | ✅ | NTP, chrony, RFC3339 |
| 10.4.1 | Log protection | ✅ | Immutable, encryption at rest |
| 10.5.1 | Log review | ✅ | Daily automated, weekly manual |
| 10.6.1 | Log retention | ✅ | 1 year online, 7 years archive |
| 10.7.1 | Alerting | ✅ | PagerDuty, Slack, webhook events |

## Requirement 11: Test Security Regularly

| Sub-req | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| 11.1.1 | Wireless | ❌ N/A | Cloud provider |
| 11.2.1 | Internal vuln scan | ✅ | Trivy, Grype daily |
| 11.2.2 | External vuln scan | ✅ | Nuclei, third-party annually |
| 11.3.1 | Penetration test | ✅ | Annual third-party, continuous |
| 11.3.2 | Segmentation test | ✅ | Scope Gate validation per request |
| 11.4.1 | Intrusion detection | ✅ | Prometheus alerts, finding webhooks |
| 11.5.1 | Change detection | ✅ | ArgoCD drift detection, file integrity |
| 11.6.1 | WAF | 🔄 | Adapter sandboxing (partial) |

## Requirement 12: Information Security Policy

| Sub-req | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| 12.1.1 | Policy | ✅ | Policy-as-Code, documented |
| 12.2.1 | Risk assessment | ✅ | Annual + per-release |
| 12.3.1 | Usage policies | ✅ | Contributing guide, scope docs |
| 12.4.1 | Incident response | ✅ | Runbooks, break-glass, escalation |
| 12.5.1 | Service providers | ✅ | Vendor assessment, contracts |
| 12.6.1 | Security awareness | ⏳ | Training program (planned) |
| 12.7.1 | Screening | ❌ N/A | Organization responsibility |
| 12.8.1 | Third-party agreements | 🔄 | Vendor contracts (partial) |
| 12.9.1 | Incident response plan | ✅ | Documented, version-controlled |
| 12.10.1 | Incident response | ✅ | Tested, updated annually |
| 12.11.1 | CISO / security | ✅ | Defined role, documented |

## Evidence Collection

```bash
# Generate PCI DSS evidence package
ishastra compliance generate --framework pci-dss --output ./pci-evidence/

# Structure:
pci-evidence/
├── requirements/
│   ├── req1-network-security/
│   ├── req2-secure-config/
│   ├── req6-secure-development/
│   ├── req7-access-control/
│   ├── req8-auth/
│   ├── req10-logging/
│   ├── req11-testing/
│   └── req12-policy/
├── mappings/
│   └── pci-dss-mapping.csv
└── artifacts/
    ├── penetration-test-2024.pdf
    ├── tla-verification-report.pdf
    ├── sbom-latest.json
    ├── vulnerability-scan-latest.json
    └── architecture-decision-records/
```

## SAQ Applicability

For organizations using Ishastra as part of their assessment pipeline:

| SAQ Type | Applicable? | Notes |
|----------|-------------|-------|
| SAQ A | ❌ | Not a merchant |
| SAQ A-EP | ❌ | Not e-commerce |
| SAQ B | ❌ | Not importer |
| SAQ B-IP | ❌ | Not standalone terminal |
| SAQ C | ❌ | Not payment application |
| SAQ C-VT | ❌ | Not virtual terminal |
| SAQ D | ✅ | Service provider - Ishastra as assessment tool |
| SAQ P2PE | ❌ | Not P2PE solution |

**As a service provider**: Ishastra supports your SAQ D completion by providing:
- Network segmentation evidence (Req 1)
- Secure configuration baselines (Req 2)
- Encryption in transit/at rest (Req 3, 4)
- Vulnerability management (Req 6)
- Access control (Req 7, 8)
- Logging and monitoring (Req 10)
- Testing (Req 11)

## Related

- [Compliance Overview](overview.md)
- [NIST 800-53 Mapping](nist.md)
- [ISO 27001 Mapping](iso27001.md)
- [SOC 2 Mapping](soc2.md)
- [Scope Gate Concepts](../scope-gate/concepts.md)
- [Security Review](../security-review.md)