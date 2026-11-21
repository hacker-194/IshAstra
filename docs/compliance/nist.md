# NIST 800-53 Rev 5 Mapping

# NIST 800-53 Rev 5 Control Mapping

Comprehensive mapping of Ishastra controls to NIST SP 800-53 Revision 5.

## Control Summary

| Status | Count | Description |
|--------|-------|-------------|
| ✅ Implemented | 89 | Fully implemented with evidence |
| 🔄 Partial | 12 | Partially implemented, compensating controls |
| ⏳ Planned | 8 | On roadmap for next release |
| ❌ Not Applicable | 31 | Physical/environmental (cloud provider) |

## Access Control (AC)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| AC-1 | Policy & Procedures | ✅ | Policy-as-Code, documented in repo |
| AC-2 | Account Management | ✅ | API keys with expiry, RBAC, MFA |
| AC-3 | Access Enforcement | ✅ | Scope Gate default-deny per request |
| AC-4 | Information Flow Enforcement | ✅ | 3-layer validation, tenant isolation |
| AC-5 | Separation of Duties | ✅ | Break-glass dual approval required |
| AC-6 | Least Privilege | ✅ | Scoped API keys, per-assessment tokens |
| AC-7 | Unsuccessful Logon | ✅ | Rate limiting, lockout after 5 failures |
| AC-8 | System Use Notification | ⏳ | Banner on API endpoints (planned) |
| AC-11 | Device Lock | ❌ N/A | Cloud provider responsibility |
| AC-12 | Session Termination | ✅ | JWT TTL 1hr, API key revocation |
| AC-14 | Permitted Actions | ✅ | Adapter allowlist, scope-bound targets |
| AC-17 | Remote Access | ✅ | TLS 1.3, mTLS for internal services |
| AC-19 | Access Control for Mobile | ❌ N/A | No mobile component |
| AC-20 | Use of External Systems | ✅ | Webhook verification, external adapter sandboxing |
| AC-22 | Publicly Accessible Content | ⏳ | Public API docs, no sensitive data |

## Awareness & Training (AT)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| AT-1 | Policy & Procedures | ✅ | Contributing guide, security training |
| AT-2 | Literacy Training | ✅ | Developer onboarding, security review |
| AT-3 | Role-Based Training | ✅ | Admin vs operator vs auditor roles |
| AT-4 | Training Records | 🔄 | Git history, PR reviews (partial automation) |

## Audit & Accountability (AU)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| AU-1 | Policy & Procedures | ✅ | Ishastra Proof audit chain documented |
| AU-2 | Event Selection | ✅ | All grants, gates, proofs, findings logged |
| AU-3 | Content of Audit Records | ✅ | Structured JSON with correlation IDs |
| AU-4 | Audit Storage Capacity | ✅ | Object store with lifecycle policies |
| AU-5 | Response to Audit Failures | ✅ | Alerting on write failures, DLQ |
| AU-6 | Audit Review | ✅ | Daily automated, weekly manual |
| AU-7 | Audit Reduction | ✅ | Structured logs, queryable via API |
| AU-8 | Time Stamps | ✅ | NTP-synced, RFC3339 format |
| AU-9 | Protection of Audit Information | ✅ | Immutable append-only, encryption at rest |
| AU-10 | Non-Repudiation | ✅ | Ed25519 signatures on every event |
| AU-11 | Audit Record Retention | ✅ | 7-year default, configurable |
| AU-12 | Audit Generation | ✅ | Automatic on every Scope Gate decision |
| AU-13 | Monitoring for Information Disclosure | ✅ | Secret scanning, finding sanitization |
| AU-14 | Session Audit | ✅ | Per-assessment correlation IDs |
| AU-16 | Cross-Organizational Auditing | 🔄 | Multi-tenant audit separation (partial) |

## Assessment, Authorization & Monitoring (CA)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| CA-1 | Policy & Procedures | ✅ | Security review process documented |
| CA-2 | Control Assessment | ✅ | TLA+ verification, penetration testing |
| CA-3 | Information Exchange | 🔄 | API for evidence export (partial) |
| CA-5 | Plan of Action & Milestones | ✅ | GitHub Issues with compliance labels |
| CA-6 | Authorization | ✅ | Scope Gate authorization per request |
| CA-7 | Continuous Monitoring | ✅ | Real-time Scope Gate, health checks |
| CA-8 | Penetration Testing | ✅ | Annual third-party, continuous automated |
| CA-9 | Internal System Connections | ✅ | mTLS, network policies, Scope Gate |

## Configuration Management (CM)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| CM-1 | Policy & Procedures | ✅ | GitOps, Policy-as-Code documented |
| CM-2 | Baseline Configuration | ✅ | Helm values, sealed secrets |
| CM-3 | Configuration Change Control | ✅ | PR required, CI validation, ArgoCD |
| CM-4 | Security Impact Analysis | ✅ | Automated in CI, TLA+ model checking |
| CM-5 | Access Restrictions | ✅ | RBAC on config, sealed secrets |
| CM-6 | Configuration Settings | ✅ | Hardened defaults, env-based overrides |
| CM-7 | Least Functionality | ✅ | Minimal containers, distroless images |
| CM-8 | System Component Inventory | ✅ | SBOM generation (Syft), dependency graph |
| CM-9 | Configuration Management Plan | ✅ | Documented in deployment guides |
| CM-10 | Software Usage Restrictions | ✅ | License scanning, approved packages |
| CM-11 | User-Installed Software | ✅ | Container immutable, no runtime install |
| CM-12 | Information Location | ✅ | Data flow docs, tenant isolation |

## Contingency Planning (CP)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| CP-1 | Policy & Procedures | ✅ | Runbooks, DR plan documented |
| CP-2 | Contingency Plan | ✅ | Multi-region, RTO 1hr, RPO 5min |
| CP-3 | Contingency Training | 🔄 | Quarterly drills (partial) |
| CP-4 | Contingency Plan Testing | 🔄 | Annual failover test (partial) |
| CP-6 | Alternate Storage | ✅ | Cross-region S3 replication |
| CP-7 | Alternate Processing | ✅ | k0s multi-cluster, Helm deploy |
| CP-8 | Telecommunications | ✅ | Cloud provider redundancy |
| CP-9 | System Backup | ✅ | Daily PostgreSQL, hourly Redis |
| CP-10 | Recovery & Reconstitution | ✅ | Documented runbooks, automated restore |

## Identification & Authentication (IA)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| IA-1 | Policy & Procedures | ✅ | Auth middleware documented |
| IA-2 | Identifier Management | ✅ | API keys, JWT subjects, scoped |
| IA-3 | Device Identification | ❌ N/A | No device auth |
| IA-4 | Identifier Management | ✅ | Unique key IDs, rotation |
| IA-5 | Authenticator Management | ✅ | 256-bit keys, 90-day rotation |
| IA-6 | Authenticator Feedback | ✅ | No echo, constant-time compare |
| IA-7 | Cryptographic Module | ✅ | Ed25519, TLS 1.3, FIPS mode |
| IA-8 | Replay Resistance | ✅ | Nonce in JWT, timestamp in webhooks |
| IA-11 | Re-Authentication | ✅ | Break-glass requires fresh MFA |

## Incident Response (IR)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| IR-1 | Policy & Procedures | ✅ | Runbooks in docs/runbooks/ |
| IR-2 | Incident Response Training | 🔄 | Team training (partial) |
| IR-3 | Incident Response Testing | 🔄 | Tabletop exercises (partial) |
| IR-4 | Incident Handling | ✅ | Alerting, escalation, break-glass |
| IR-5 | Incident Monitoring | ✅ | Real-time findings, PagerDuty |
| IR-6 | Incident Reporting | ✅ | Webhook events, audit trail |
| IR-7 | Incident Response Assistance | ⏳ | Customer portal (planned) |
| IR-8 | Incident Response Plan | ✅ | Documented, version-controlled |

## Maintenance (MA)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| MA-1 | Policy & Procedures | ✅ | Maintenance windows documented |
| MA-2 | Controlled Maintenance | ✅ | Rolling updates, PDBs, drain |
| MA-3 | Maintenance Tools | ✅ | kubectl, Helm, ArgoCD |
| MA-4 | Nonlocal Maintenance | ✅ | VPN, mTLS, break-glass |
| MA-5 | Maintenance Personnel | ✅ | RBAC, audit trail |

## Media Protection (MP)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| MP-1 | Policy & Procedures | ✅ | Encryption policy documented |
| MP-2 | Media Access | ✅ | IAM on object store, RLS on DB |
| MP-3 | Media Marking | 🔄 | Classification tags (partial) |
| MP-4 | Media Storage | ✅ | Encrypted volumes, TLS transit |
| MP-5 | Media Transport | ✅ | TLS 1.3, signed URLs |
| MP-6 | Media Sanitization | ✅ | Cryptographic erase, key rotation |
| MP-7 | Media Use | ✅ | No removable media in prod |

## Physical & Environmental (PE) - Cloud Provider

| Control | Title | Status | Note |
|---------|-------|--------|------|
| PE-1 to PE-23 | All | ❌ N/A | AWS/GCP/Azure/Oracle responsibility |

## Planning (PL)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| PL-1 | Policy & Procedures | ✅ | Security planning documented |
| PL-2 | System Security Plan | ✅ | Architecture docs, threat model |
| PL-4 | Rules of Behavior | ✅ | Contributing guide, code of conduct |
| PL-8 | Information Security Architecture | ✅ | Documented in architecture/ |
| PL-9 | Central Management | ✅ | GitOps, centralized config |
| PL-10 | Baseline Selection | ✅ | CIS benchmarks, hardened images |
| PL-11 | Baseline Tailoring | ✅ | Environment-specific overlays |

## Personnel Security (PS)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| PS-1 | Policy & Procedures | ✅ | HR policies referenced |
| PS-2 | Position Risk | ✅ | Role-based access, least privilege |
| PS-3 | Personnel Screening | ❌ N/A | Organization responsibility |
| PS-4 | Personnel Termination | ✅ | Key revocation, access removal |
| PS-5 | Personnel Transfer | ✅ | Role change = access review |
| PS-6 | Access Agreements | ✅ | CLA, contributor agreement |
| PS-7 | Third-Party Personnel | 🔄 | Vendor assessment (partial) |
| PS-8 | Personnel Sanctions | ✅ | Immediate revocation on violation |
| PS-9 | Position Descriptions | ✅ | Role definitions in RBAC |

## Risk Assessment (RA)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| RA-1 | Policy & Procedures | ✅ | Threat modeling documented |
| RA-2 | Risk Assessment | ✅ | Annual, plus per-release |
| RA-3 | Risk Assessment Update | ✅ | Continuous via Dependabot, TLA+ |
| RA-5 | Vulnerability Scanning | ✅ | Trivy, Grype, nuclei in CI |
| RA-7 | Supply Chain Risk | ✅ | SBOM, signed images, cosign |

## System & Services Acquisition (SA)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| SA-1 | Policy & Procedures | ✅ | SDLC documented |
| SA-2 | Allocation of Resources | ✅ | Resource quotas, limits |
| SA-3 | System Development Lifecycle | ✅ | GitFlow, CI/CD, staging |
| SA-4 | Acquisition Process | ✅ | Approved vendors, dependency policy |
| SA-5 | System Documentation | ✅ | This docs site, API reference |
| SA-8 | Security Engineering | ✅ | TLA+, Scope Gate, Ishastra Proof |
| SA-9 | External System Services | ✅ | Vendor assessment, contracts |
| SA-10 | Developer Configuration | ✅ | Dev containers, pre-commit |
| SA-11 | Developer Testing | ✅ | Unit, integration, contract, E2E |
| SA-15 | Development Process | ✅ | TDD, security review gates |
| SA-17 | Developer Security Training | 🔄 | Onboarding (partial) |
| SA-22 | Unsupported Components | ✅ | Dependency monitoring, EOL alerts |

## System & Communications Protection (SC)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| SC-1 | Policy & Procedures | ✅ | Network policies documented |
| SC-2 | Application Partitioning | ✅ | Multi-tenancy RLS, network policies |
| SC-3 | Security Function Isolation | ✅ | Separate services, mTLS |
| SC-4 | Information in Shared Resources | ✅ | Tenant isolation, no shared state |
| SC-5 | Denial-of-Service Protection | ✅ | Rate limits, queue limits, K8s HPA |
| SC-7 | Boundary Protection | ✅ | Scope Gate (default-deny), network policies |
| SC-8 | Transmission Confidentiality | ✅ | TLS 1.3 everywhere |
| SC-9 | Transmission Integrity | ✅ | TLS 1.3, mTLS internal |
| SC-10 | Network Disconnect | ✅ | Network policies, pod termination |
| SC-12 | Cryptographic Key Establishment | ✅ | Ed25519, JWKS rotation |
| SC-13 | Cryptographic Protection | ✅ | AES-256-GCM, ChaCha20-Poly1305 |
| SC-15 | Collaborative Computing | ❌ N/A | No collaborative features |
| SC-16 | Transmission of Security Attributes | ✅ | JWT claims, Scope Gate context |
| SC-17 | Public Key Infrastructure | ✅ | cert-manager, JWKS endpoint |
| SC-18 | Mobile Code | ✅ | Adapter sandboxing, no arbitrary code |
| SC-19 | Voice Over IP | ❌ N/A | Not applicable |
| SC-20 | Secure Name/Address Resolution | ✅ | DNS over HTTPS, pinned resolvers |
| SC-21 | Secure Resource Allocation | ✅ | Resource quotas, priority classes |
| SC-22 | Architecture & Provisioning | ✅ | IaC, GitOps, immutable infra |
| SC-23 | Session Authenticity | ✅ | JWT, API keys, mTLS |
| SC-24 | Fail in Known State | ✅ | Default-deny, graceful degradation |
| SC-25 | Thin Nodes | ✅ | Distroless, minimal attack surface |
| SC-26 | Honeypots | ⏳ | Canary deployments (planned) |
| SC-28 | Protection of Information at Rest | ✅ | Encryption, sealed secrets |
| SC-29 | Heterogeneity | ✅ | Multi-arch images, k0s |
| SC-30 | Concealment & Misdirection | ⏳ | Decoy endpoints (planned) |
| SC-31 | Covert Channel Analysis | 🔄 | Side-channel review (partial) |
| SC-32 | System Partitioning | ✅ | Namespaces, network policies |
| SC-34 | Non-Modifiable Executable Code | ✅ | Immutable containers, cosign verify |
| SC-35 | External System Interfaces | ✅ | Webhook verification, API auth |
| SC-36 | Process Isolation | ✅ | Container isolation, gVisor option |
| SC-37 | Outbound Communications | ✅ | Scope Gate (core feature) |
| SC-38 | Operations Security | ✅ | Runbooks, audit, least privilege |
| SC-39 | Process Isolation | ✅ | Same as SC-36 |
| SC-40 | Wireless Link Protection | ❌ N/A | Cloud provider |
| SC-41 | Port & I/O Device Access | ❌ N/A | Cloud provider |
| SC-42 | Sensor Capability & Data | ❌ N/A | Not applicable |
| SC-43 | Usage Restrictions | ✅ | Adapter allowlist, rate limits |
| SC-44 | Detonation Chambers | ✅ | Adapter sandboxing |
| SC-45 | System Time Synchronization | ✅ | NTP, chrony, RFC3339 |

## System & Information Integrity (SI)

| Control | Title | Status | Ishastra Implementation |
|---------|-------|--------|---------------------|
| SI-1 | Policy & Procedures | ✅ | Integrity monitoring documented |
| SI-2 | Flaw Remediation | ✅ | Dependabot, security patches |
| SI-3 | Malicious Code Protection | ✅ | Container scanning, admission control |
| SI-4 | System Monitoring | ✅ | Prometheus, Grafana, alerting |
| SI-5 | Security Alerts | ✅ | PagerDuty, Slack, webhook |
| SI-6 | Security Function Verification | ✅ | Health checks, Scope Gate self-test |
| SI-7 | Software & Firmware Integrity | ✅ | Cosign, SBOM, reproducible builds |
| SI-8 | Spam Protection | ❌ N/A | Not applicable |
| SI-10 | Information Input Validation | ✅ | Pydantic schemas, Scope Gate |
| SI-11 | Error Handling | ✅ | Structured errors, no stack traces |
| SI-12 | Information Management | ✅ | Data classification, retention |
| SI-13 | Predictable Failure Prevention | ✅ | Circuit breakers, timeouts, retries |
| SI-14 | Non-Persistence | ✅ | Ephemeral containers, no local state |
| SI-15 | Information Output Filtering | ✅ | Finding sanitization, PII redaction |
| SI-16 | Memory Protection | ✅ | Rust components, safe languages |
| SI-17 | Fail-Safe Procedures | ✅ | Default-deny, graceful degradation |

## Evidence Collection

```bash
# Generate NIST 800-53 evidence package
ishastra compliance generate --framework nist --output ./nist-evidence/

# Structure:
nist-evidence/
├── controls/
│   ├── AC-3-evidence.json
│   ├── AU-10-evidence.json
│   ├── SC-7-evidence.json
│   └── ...
├── mappings/
│   └── nist-800-53-mapping.csv
└── artifacts/
    ├── tla-verification-report.pdf
    ├── penetration-test-2024.pdf
    └── sbom-latest.json
```

## Related

- [Compliance Overview](overview.md)
- [ISO 27001 Mapping](iso27001.md)
- [SOC 2 Mapping](soc2.md)
- [PCI DSS Mapping](pci-dss.md)
- [Scope Gate Concepts](../scope-gate/concepts.md)
- [Security Review](../security-review.md)