> **Status: control mapping, not certification.** IshAstra has no SOC 2, ISO 27001,
> or PCI DSS attestation and no paid bug bounty. MFA at IdP is enforced by an external
> identity provider when configured; IshAstra does not implement MFA at IdP. API
> authentication is API keys plus OIDC/SAML browser sessions; there is no
> API-key-to-OIDC session exchange. TLS is terminated by the operator. PostgreSQL RLS is
> tested at the database layer and is not a substitute for application tenant
> filters. High availability is not provided.

# Compliance Overview

# Compliance Overview

IshAstra is designed to meet stringent security and compliance requirements out of the box.

## Compliance Posture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        IshAstra Compliance Architecture                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Core Platform Controls                           │   │
│  │  • Default-deny authorization (Scope Gate)                          │   │
│  │  • Cryptographic audit chain (IshAstra Proof)                          │   │
│  │  • Formal verification (TLA+ 6 invariants, 21.4M states)           │   │
│  │  • Multi-tenancy with RLS isolation                                 │   │
│  │  • Break-glass dual approval                                        │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                        │
│         ┌──────────────────────────┼──────────────────────────┐             │
│         ▼                          ▼                          ▼             │
│  ┌───────────────┐          ┌───────────────┐          ┌───────────────┐  │
│  │   NIST 800-53 │          │   ISO 27001   │          │    SOC 2      │  │
│  │   (Rev 5)     │          │   (2022)      │          │   Type II     │  │
│  └───────────────┘          └───────────────┘          └───────────────┘  │
│                                    │                                        │
│                          ┌─────────┴─────────┐                              │
│                          ▼                   ▼                              │
│                   ┌───────────┐        ┌───────────┐                       │
│                   │  PCI DSS  │        │  Custom   │                       │
│                   │  4.0.1    │        │  Frameworks│                       │
│                   └───────────┘        └───────────┘                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Framework Coverage Matrix

| Control Family | NIST 800-53 | ISO 27001 | SOC 2 | PCI DSS | IshAstra Implementation |
|----------------|-------------|-----------|-------|---------|---------------------|
| Access Control | AC-1 to AC-22 | A.5.18, A.8.2 | CC6.1-CC6.8 | Req 7, 8 | Scope Gate, RBAC, Break-glass |
| Audit & Accountability | AU-1 to AU-16 | A.5.15, A.8.15 | CC7.1-CC7.5 | Req 10 | IshAstra Proof, immutable logs |
| Configuration Management | CM-1 to CM-12 | A.5.10, A.8.8 | CC8.1, CC9.1 | Req 2, 6 | Policy-as-Code, GitOps |
| Identification & Authentication | IA-1 to IA-12 | A.5.17, A.8.5 | CC6.1-CC6.3 | Req 8 | API Keys, OIDC session, MFA at IdP |
| Incident Response | IR-1 to IR-10 | A.5.24-A.5.27 | CC7.3-CC7.4 | Req 12 | Break-glass, alerting |
| Media Protection | MP-1 to MP-8 | A.5.20, A.8.10 | CC6.7, CC6.8 | Req 9 | Encryption at rest/transit |
| Physical & Environmental | PE-1 to PE-23 | A.7.1-A.7.9 | - | Req 9 | Cloud provider responsibility |
| Planning | PL-1 to PL-11 | A.5.1-A.5.37 | CC1.1-CC1.5 | Req 12 | Risk assessment, policies |
| Personnel Security | PS-1 to PS-9 | A.5.7-A.5.14 | CC1.4, CC2.3 | Req 12 | MFA at IdP, least privilege |
| Risk Assessment | RA-1 to RA-5 | A.5.1-A.5.3 | CC3.1-CC3.4 | Req 12 | Threat modeling, TLA+ |
| System & Services Acquisition | SA-1 to SA-22 | A.5.30-A.5.37 | CC8.1, CC9.1 | Req 6 | SDLC, dependency scanning |
| System & Communications Protection | SC-1 to SC-45 | A.5.15, A.8.1, A.13 | CC6.7, CC7.2 | Req 2, 3, 4 | TLS, Scope Gate, network policy |
| System & Information Integrity | SI-1 to SI-17 | A.5.13, A.8.7, A.12 | CC7.1-CC7.5 | Req 5, 6, 11 | Validation, monitoring |

## IshAstra-Specific Control Mappings

### Authorization (Scope Gate)

| Control | Standard | IshAstra Implementation |
|---------|----------|---------------------|
| Default-deny network access | NIST SC-7, SC-23 | 3-layer Scope Gate validation |
| IP/DNS pinning | NIST SC-5, SC-23 | Layer 2 DNS resolution + Layer 3 pinning |
| Emergency access | NIST AC-6, ISO A.9.2 | Break-glass dual approval with MFA at IdP |
| Segmentation | NIST SC-7, PCI Req 1 | Network CIDR allowlists, host suffix lists |

### Cryptographic Audit (IshAstra Proof)

| Control | Standard | IshAstra Implementation |
|---------|----------|---------------------|
| Non-repudiation | NIST AU-10, ISO A.8.15 | Ed25519 signatures on every grant/gate/proof |
| Integrity verification | NIST SI-7, ISO A.8.7 | scope-key rotation, tamper-evident receipts |
| Audit trail | NIST AU-2, PCI Req 10 | Immutable append-only chain |

### Multi-Tenancy

| Control | Standard | IshAstra Implementation |
|---------|----------|---------------------|
| Data isolation | NIST SC-2, ISO A.13.1 | ContextVar + PostgreSQL RLS |
| Cross-tenant prevention | NIST AC-4, SOC CC6.7 | Row-level security, tenant context |

## Continuous Compliance

### Automated Evidence Collection

```bash
# Generate compliance evidence package
ishastra compliance generate --framework nist --output evidence/

# Export specific control evidence
ishastra compliance export AC-6 --format pdf --output ./AC-6-evidence.pdf
```

### Continuous Monitoring

| Check | Frequency | Tool |
|-------|-----------|------|
| Scope Gate validation | Per-request | Built-in |
| Certificate expiry | Daily | cert-manager |
| Dependency vulnerabilities | Per-commit | Dependabot |
| Configuration drift | Hourly | ArgoCD/Flux |
| Access review | Quarterly | Custom script |

## Audit Readiness

### Evidence Package Contents

```
evidence/
├── architecture/
│   ├── system-design.pdf
│   ├── data-flow-diagram.pdf
│   └── threat-model.pdf
├── controls/
│   ├── AC-6-breakglass-procedure.pdf
│   ├── SC-7-network-segmentation.pdf
│   └── AU-10-cryptographic-audit.pdf
├── operations/
│   ├── incident-response-plan.pdf
│   ├── backup-recovery-test.pdf
│   └── access-review-2024-Q1.pdf
└── testing/
    ├── penetration-test-2024.pdf
    ├── tla-verification-report.pdf
    └── dependency-scan-latest.json
```

### Auditor Access

Provide read-only auditor role with access to:
- Scope Gate configuration (no secrets)
- Assessment execution logs
- Finding reports (sanitized)
- Compliance dashboard

## Related

- [NIST 800-53 Mapping](nist.md)
- [ISO 27001 Mapping](iso27001.md)
- [SOC 2 Mapping](soc2.md)
- [PCI DSS Mapping](pci-dss.md)
- [Security Review](../security-review.md)