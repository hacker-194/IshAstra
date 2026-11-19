# SOC 2 Type II Mapping

# SOC 2 Type II Control Mapping

Mapping of Strix controls to SOC 2 Trust Services Criteria (Security, Availability, Confidentiality, Processing Integrity, Privacy).

## Control Summary

| Trust Principle | Criteria | Implemented | Partial | Planned | N/A |
|-----------------|----------|-------------|---------|---------|-----|
| Security (CC) | CC1.1-CC9.2 | 31 | 3 | 2 | 0 |
| Availability | A1.1-A1.3 | 5 | 1 | 0 | 0 |
| Confidentiality | C1.1-C1.2 | 4 | 0 | 1 | 0 |
| Processing Integrity | PI1.1-PI1.5 | 6 | 1 | 0 | 0 |
| Privacy | P1.1-P8.1 | 5 | 2 | 1 | 2 |

## Security (Common Criteria - CC)

### CC1.0 - Control Environment

| Criterion | Status | Strix Implementation |
|-----------|--------|---------------------|
| CC1.1 | ✅ | Code of conduct, contributor agreement, security policy |
| CC1.2 | ✅ | RBAC, separation of duties, break-glass dual approval |
| CC1.3 | ✅ | Threat modeling, risk assessment, TLA+ verification |
| CC1.4 | ✅ | Competency requirements, onboarding, security training |
| CC1.5 | ✅ | Accountability via audit trail, Strix Proof, key rotation |

### CC2.0 - Communication & Information

| Criterion | Status | Strix Implementation |
|-----------|--------|---------------------|
| CC2.1 | ✅ | API docs, runbooks, incident communication plan |
| CC2.2 | ✅ | Security.txt, responsible disclosure, webhook events |
| CC2.3 | ✅ | Internal alerts, PagerDuty, Slack, email notifications |

### CC3.0 - Risk Assessment

| Criterion | Status | Strix Implementation |
|-----------|--------|---------------------|
| CC3.1 | ✅ | Annual risk assessment, per-release threat modeling |
| CC3.2 | ✅ | Supply chain risk: SBOM, Dependabot, Trivy, cosign |
| CC3.3 | ✅ | Change risk: CI gates, TLA+ model checking |
| CC3.4 | ✅ | Vendor risk: Cloud provider assessment, dependency policy |

### CC4.0 - Monitoring Activities

| Criterion | Status | Strix Implementation |
|-----------|--------|---------------------|
| CC4.1 | ✅ | Prometheus, Grafana, health checks, alerting |
| CC4.2 | ✅ | Log aggregation, correlation IDs, structured JSON |
| CC4.3 | ✅ | Real-time Scope Gate validation, finding alerts |

### CC5.0 - Control Activities

| Criterion | Status | Strix Implementation |
|-----------|--------|---------------------|
| CC5.1 | ✅ | Policy-as-Code, GitOps, CI/CD gates |
| CC5.2 | ✅ | Scope Gate (default-deny), adapter sandboxing |
| CC5.3 | ✅ | Network policies, mTLS, namespace isolation |

### CC6.0 - Logical & Physical Access

| Criterion | Status | Strix Implementation |
|-----------|--------|---------------------|
| CC6.1 | ✅ | API keys, JWT, scoped tokens, 90-day rotation |
| CC6.2 | ✅ | Break-glass dual approval, MFA, audit trail |
| CC6.3 | ✅ | RLS, tenant isolation, ContextVar separation |
| CC6.4 | ✅ | Network policies, egress control, Scope Gate |
| CC6.5 | ✅ | Encryption at rest (AES-256), in transit (TLS 1.3) |
| CC6.6 | ✅ | Sealed secrets, External Secrets Operator, key rotation |
| CC6.7 | ✅ | Immutable containers, distroless, no runtime install |
| CC6.8 | ✅ | Container scanning, admission control, gVisor option |

### CC7.0 - System Operations

| Criterion | Status | Strix Implementation |
|-----------|--------|---------------------|
| CC7.1 | ✅ | Vulnerability scanning: Trivy, Grype, nuclei in CI |
| CC7.2 | ✅ | Penetration testing: annual third-party, continuous |
| CC7.3 | ✅ | Incident response: runbooks, break-glass, escalation |
| CC7.4 | ✅ | Monitoring: real-time findings, PagerDuty, webhooks |
| CC7.5 | ✅ | Forensics: Strix Proof, immutable audit trail, correlation IDs |

### CC8.0 - Change Management

| Criterion | Status | Strix Implementation |
|-----------|--------|---------------------|
| CC8.1 | ✅ | GitFlow, PR required, CI validation, ArgoCD |
| CC8.2 | ✅ | Automated testing: unit, integration, contract, E2E |
| CC8.3 | ✅ | Staging environment, canary deployments |
| CC8.4 | ✅ | Rollback: Helm rollback, ArgoCD sync, DB migrations |
| CC8.5 | 🔄 | Emergency changes: break-glass for config (partial) |

### CC9.0 - Risk Mitigation

| Criterion | Status | Strix Implementation |
|-----------|--------|---------------------|
| CC9.1 | ✅ | Business continuity: multi-region, RTO 1hr, RPO 5min |
| CC9.2 | ✅ | Disaster recovery: documented runbooks, automated restore |

## Availability (A)

| Criterion | Status | Strix Implementation |
|-----------|--------|---------------------|
| A1.1 | ✅ | k0s multi-cluster, multi-AZ, HPA, PDBs |
| A1.2 | ✅ | Health checks, readiness/liveness probes, circuit breakers |
| A1.3 | ✅ | Daily PostgreSQL backup, hourly Redis, cross-region replication |

## Confidentiality (C)

| Criterion | Status | Strix Implementation |
|-----------|--------|---------------------|
| C1.1 | ✅ | Data classification: finding severity, PII tags, scope tags |
| C1.2 | ✅ | Encryption at rest, TLS 1.3, sealed secrets, key rotation |

## Processing Integrity (PI)

| Criterion | Status | Strix Implementation |
|-----------|--------|---------------------|
| PI1.1 | ✅ | Scope Gate validation per request, default-deny |
| PI1.2 | ✅ | Idempotent assessment operations, deduplication |
| PI1.3 | ✅ | Structured error handling, no data loss on failure |
| PI1.4 | ✅ | Retry with exponential backoff, DLQ for failed webhooks |
| PI1.5 | ✅ | TLA+ verified invariants, formal verification |

## Privacy (P)

| Criterion | Status | Strix Implementation |
|-----------|--------|---------------------|
| P1.1 | ✅ | Privacy notice in API docs, data processing agreement |
| P1.2 | ✅ | Data minimization: only assessment targets, no PII collection |
| P1.3 | ✅ | Purpose limitation: security assessment only |
| P1.4 | ✅ | Retention: configurable, default 7 years, crypto erase |
| P1.5 | 🔄 | Access rights: GDPR subject requests (partial API) |
| P1.6 | ✅ | Disclosure: only to authorized scope, tenant isolation |
| P1.7 | ✅ | Quality: finding sanitization, PII redaction |
| P1.8 | ✅ | Monitoring: audit trail, breach notification runbook |

## Evidence Collection

```bash
# Generate SOC 2 evidence package
strix compliance generate --framework soc2 --output ./soc2-evidence/

# Structure:
soc2-evidence/
├── controls/
│   ├── CC6.1-evidence.json
│   ├── CC7.2-evidence.json
│   ├── A1.1-evidence.json
│   └── ...
├── mappings/
│   └── soc2-mapping.csv
└── artifacts/
    ├── penetration-test-2024.pdf
    ├── tla-verification-report.pdf
    ├── sbom-latest.json
    ├── architecture-decision-records/
    └── incident-response-runbooks/
```

## Type II Readiness

### Continuous Monitoring (Required for Type II)

| Control | Monitoring | Frequency | Evidence |
|---------|------------|-----------|----------|
| CC6.1 | API key rotation | Daily | Rotation logs |
| CC6.3 | Tenant isolation | Per-request | Scope Gate logs |
| CC7.1 | Vulnerability scan | Per-commit + daily | Trivy/Gripe reports |
| CC7.2 | Penetration test | Annual + continuous | Pentest report |
| CC8.1 | Change control | Per-PR | Git history, CI logs |
| A1.1 | Uptime | Continuous | Prometheus/Grafana |

### Auditor Expectations

1. **Period**: Minimum 6 months (prefer 12)
2. **Population**: All production systems
3. **Testing**: Walkthrough + sample testing
4. **Exceptions**: Documented with compensating controls

## Related

- [Compliance Overview](overview.md)
- [NIST 800-53 Mapping](nist.md)
- [ISO 27001 Mapping](iso27001.md)
- [PCI DSS Mapping](pci-dss.md)
- [Scope Gate Concepts](../scope-gate/concepts.md)
- [Security Review](../security-review.md)