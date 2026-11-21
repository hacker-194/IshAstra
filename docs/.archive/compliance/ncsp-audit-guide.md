# NCSP Compliance Audit Guide

**Auditor-Ready Documentation for National Cyber Security Policy 2080**

This guide enables auditors to verify Ishastra assessment evidence against Nepal's National Cyber Security Policy 2080 for critical infrastructure protection and national cyber resilience.

---

## 1. Framework Overview

| Attribute | Value |
|-----------|-------|
| **Authority** | National Cyber Security Council / npCERT |
| **Policy** | National Cyber Security Policy 2080 |
| **Scope** | Critical Information Infrastructure (CII), All Sectors |
| **Jurisdiction** | Nepal |
| **Ishastra Coverage** | 14 controls (10 core + 4 sector-specific) |

### Policy Sections Covered

| Section | Title | Controls | Focus |
|---------|-------|----------|-------|
| **3.1** | npCERT Coordination | NCSP-2080-01 | CERT integration, threat sharing |
| **3.2** | CII Protection | NCSP-2080-02, Sector controls | CII register, resilience, interdependency |
| **3.3** | Data Sovereignty | NCSP-2080-03 | Localization, cross-border controls |
| **3.4** | Secure Development | NCSP-2080-04 | DevSecOps, SBOM, supply chain |
| **3.5** | Identity & Trust | NCSP-2080-05 | PKI, ZTNA, e-KYC, MFA |
| **3.6** | Workforce Development | NCSP-2080-06 | Certifications, training, awareness |
| **3.7** | Legal Compliance | NCSP-2080-07 | ETA, cybercrime, evidence preservation |
| **4** | Strategy Governance | NCSP-2080-08 | Cyber strategy, risk framework, board oversight |
| **5** | International Cooperation | NCSP-2080-09 | MLAT, threat sharing, joint exercises |
| **6** | Sector Resilience | NCSP-2080-10 + Sector | Banking, Telecom, Gov, Energy |

---

## 2. Control Mapping Matrix

### Core Policy Controls (Sections 3.1-3.7, 4, 5)

| Control ID | Title | Ishastra Detection Categories | Evidence Required |
|------------|-------|---------------------------|-------------------|
| **NCSP-2080-01** | npCERT Coordination | `no_cert_integration`, `missing_threat_intel`, `uncoordinated_response`, `no_cert_reporting`, `missing_exercise_participation` | CERT MOU, threat feeds, exercise records, incident sharing, contacts |
| **NCSP-2080-02** | CII Protection | `missing_cii_id`, `protection_gaps`, `untested_resilience`, `interdependency_unmapped`, `scada_exposure`, `ics_protocol_exposure`, `unidentified_cii`, `missing_protection`, `unreported_incidents`, `supply_chain_risk` | CII register, protection plan, resilience tests, dependency map, SCADA inventory, incident reports |
| **NCSP-2080-03** | Data Sovereignty | `data_offshore`, `uncontrolled_transfer`, `missing_dpa`, `cross_border_transfer`, `pii_exposure`, `credential_leak`, `encryption_absent` | Hosting locations, transfer agreements, DPAs, data classification, encryption config |
| **NCSP-2080-04** | Secure Development | `no_sast`, `no_dast`, `dependency_vulnerabilities`, `insecure_cicd`, `missing_sbom`, `insecure_coding`, `missing_code_review`, `hardcoded_secrets`, `malicious_package` | Pipeline config, scan reports, SBOM, coding standards, code reviews, secret scans |
| **NCSP-2080-05** | Identity & Trust | `weak_auth`, `no_pki`, `certificate_misuse`, `missing_ztna`, `missing_mfa`, `auth_bypass`, `session_hijack`, `certificate_issues` | PKI config, cert inventory, ZTNA architecture, e-KYC integration, MFA enrollment |
| **NCSP-2080-06** | Workforce Development | `uncertified_staff`, `missing_training`, `low_awareness`, `skill_gaps`, `no_certification_path` | Certifications, training records, awareness metrics, skill assessments |
| **NCSP-2080-07** | Legal Compliance | `eta_noncompliance`, `evidence_spoilation`, `unreported_cybercrime`, `missing_audit_trail`, `chain_of_custody_break`, `data_retention_violation` | Compliance attestation, evidence chain, police reports, audit trails, retention policy |
| **NCSP-2080-08** | Strategy Governance | `no_cyber_strategy`, `missing_risk_framework`, `no_metrics_reporting`, `governance_gaps`, `board_oversight_missing` | Strategy doc, risk framework, KPI/KRI dashboard, board reports, improvement plan |
| **NCSP-2080-09** | International Cooperation | `no_international_mou`, `missing_mlat`, `no_threat_sharing`, `no_joint_exercises` | International MOUs, MLAT records, threat sharing agreements, exercise participation |
| **NCSP-2080-10** | Sector Resilience | `banking_resilience_gaps`, `telecom_resilience_gaps`, `energy_resilience_gaps`, `gov_resilience_gaps`, `health_resilience_gaps`, `no_sector_plan` | Sector plans, interdependency analysis, cascade scenarios, RTO/RPO, mutual aid |

### Sector-Specific Controls

| Control ID | Sector | Title | Ishastra Detection Categories | Evidence Required |
|------------|--------|-------|---------------------------|-------------------|
| **NCSP-BANK-001** | Banking | Banking Cyber Resilience | `transaction_fraud`, `core_banking_exposure`, `swift_vulnerabilities`, `atm_security_gaps`, `mobile_banking_weakness`, `card_data_exposure` | Transaction monitoring, fraud rules, core banking segmentation, SWIFT CSP, ATM assessment, mobile test, PCI DSS |
| **NCSP-TELCO-001** | Telecom | Telecom Cyber Resilience | `signaling_vulnerabilities`, `subscriber_data_leak`, `network_resilience_gaps`, `roaming_fraud`, `equipment_vulnerabilities` | Signaling firewall, subscriber data protection, redundancy design, roaming fraud monitoring, equipment cert |
| **NCSP-GOV-001** | Government | Government Cyber Resilience | `gov_system_exposure`, `citizen_data_leak`, `service_disruption_risk`, `classification_mishandling`, `inter_agency_gaps` | System inventory, data classification, continuity plans, classification handling, inter-agency MOUs |
| **NCSP-ENERGY-001** | Energy | Energy Cyber Resilience | `scada_exposure`, `ics_vulnerabilities`, `smart_meter_privacy`, `grid_cascade_risk`, `substation_security` | SCADA diagram, ICS assessment, privacy impact, cascade analysis, physical security |

---

## 3. Automated Compliance Checks

Ishastra runs 8 automated verification checks for NCSP compliance:

### 3.1 npCERT Coordination (NCSP-2080-01)

```python
check_cert_coordination(job_findings)
```

**Verifies**: MOU with npCERT, threat feed integration, national exercise participation (Cyber Drill), incident reporting procedures, 24/7 contact points.

**Pass Criteria**: Zero findings in CERT coordination categories.

### 3.2 CII Protection (NCSP-2080-02)

```python
check_cii_protection(job_findings)
```

**Verifies**: CII register with criticality ratings, defense-in-depth (segmentation, air gaps), annual resilience testing (red team, tabletop, failover), interdependency mapping, npCERT incident reporting.

**Pass Criteria**: Zero findings in CII protection categories.

### 3.3 Data Sovereignty & Localization (NCSP-2080-03)

```python
check_data_sovereignty(job_findings)
```

**Verifies**: Critical data hosted in Nepal, DPAs for cross-border transfers, data classification with controls, AES-256 at rest / TLS 1.2+ in transit, regulatory approval for offshore processing.

**Pass Criteria**: Zero findings in data sovereignty categories.

### 3.4 Secure Development / DevSecOps (NCSP-2080-04)

```python
check_secure_development(job_findings)
```

**Verifies**: DevSecOps pipeline (SAST/DAST/SCA/container/secret scanning), SBOM (SPDX/CycloneDX), secure coding standards with linting, mandatory code review, SLSA supply chain levels, malicious package monitoring.

**Pass Criteria**: Zero findings in secure development categories.

### 3.5 Identity & Trust Services (NCSP-2080-05)

```python
check_identity_trust(job_findings)
```

**Verifies**: National PKI deployment, ZTNA architecture, e-KYC integration, phishing-resistant MFA (FIDO2/passkeys), certificate lifecycle automation.

**Pass Criteria**: Zero findings in identity/trust categories.

### 3.6 Workforce Development (NCSP-2080-06)

```python
check_workforce_development(job_findings)
```

**Verifies**: Certified professionals (CISSP, CISM, CEH, OSCP), NICE-aligned training program, phishing simulations/awareness campaigns, skill gap tracking with development plans, certification career paths.

**Pass Criteria**: Zero findings in workforce categories.

### 3.7 Legal Compliance (NCSP-2080-07)

```python
check_legal_compliance(job_findings)
```

**Verifies**: ETA 2063 compliance for digital records, tamper-evident audit trail (HMAC-SHA256), cybercrime reporting to Nepal Police Cyber Bureau, chain of custody for digital evidence, sectoral retention enforcement.

**Pass Criteria**: Zero findings in legal compliance categories.

### 3.8 Sector Resilience (NCSP-2080-10 + Sector)

```python
check_sector_resilience(job_findings, sector="banking")
```

**Verifies**: Sector-specific resilience plan, interdependency/cascading failure analysis, RTO/RPO definition and testing, mutual aid agreements, regulator alignment (NRB, NTA, MoE, MoHA).

**Pass Criteria**: Zero findings in sector resilience categories.

---

## 4. Evidence Pack Structure

### 4.1 JSON Evidence Pack

```bash
ishastra evidence --target https://critical.gov.np --framework NCSP --output ncsp-evidence.json
```

### 4.2 CSV Export

```bash
ishastra evidence --target https://critical.gov.np --framework NCSP --format csv --output ncsp-audit.csv
```

### 4.3 OSCAL Assessment Results

```bash
ishastra evidence --target https://critical.gov.np --framework NCSP --format oscal --output ncsp-oscal.json
```

### 4.4 Bilingual HTML Report (Nepali for Government Submission)

```bash
ishastra evidence --target https://critical.gov.np --framework NCSP --format html --locale ne_NP --output ncsp-report.html
```

---

## 5. Auditor Verification Procedures

### 5.1 Evidence Integrity

```bash
ishastra audit verify --pack ncsp-evidence.json
```

### 5.2 Control Coverage

| Policy Section | Controls Defined | Controls Assessed | Coverage |
|----------------|-----------------|-------------------|----------|
| 3.1 (npCERT) | 1 | 1 | 100% |
| 3.2 (CII) | 1 + sectors | 1 + sectors | 100% |
| 3.3 (Data Sovereignty) | 1 | 1 | 100% |
| 3.4 (DevSecOps) | 1 | 1 | 100% |
| 3.5 (Identity/Trust) | 1 | 1 | 100% |
| 3.6 (Workforce) | 1 | 1 | 100% |
| 3.7 (Legal) | 1 | 1 | 100% |
| 4 (Governance) | 1 | 1 | 100% |
| 5 (International) | 1 | 1 | 100% |
| 6 (Sector Resilience) | 1 + 4 sectors | 1 + 4 sectors | 100% |
| **Total** | **14** | **14** | **100%** |

### 5.3 Finding Traceability

```json
{
  "fingerprint": "a1b2c3d4...",
  "category": "scada_exposure",
  "severity": "critical",
  "compliance_refs": ["NCSP-2080-02", "NCSP-ENERGY-001"],
  "evidence": {"protocol": "Modbus/TCP", "port": 502, "exposure": "Internet-accessible HMI"}
}
```

### 5.4 Automated Check Results

Review `compliance_checks.ncsp` for 8 automated verifications.

---

## 6. Ishastra Feature Coverage for NCSP

| Ishastra Feature | NCSP Controls Covered | Automated Checks |
|---------------|---------------------|------------------|
| Scope Enforcement | 3.2, 3.7 | CII scope, evidence chain |
| Audit Chain | 3.1, 3.7 | HMAC integrity, chain verification |
| Redaction | 3.3, 3.7 | PII/credential redaction |
| Evidence Packs | 3.1, 3.7 | Multi-format, npCERT submission |
| Finding Lifecycle | 3.1, 3.7 | SLA, incident tracking |
| Vulnerability Scanning | 3.4 | DevSecOps pipeline |
| TLS Analysis | 3.3, 3.5 | Encryption verification |
| Header Analysis | 3.3 | Security headers |
| Auth Testing | 3.5 | ZTNA, MFA, PKI |
| API Security | 3.4 | Secure development |
| Telecom Signaling | 3.2, 6 | Telecom sector resilience |
| Infra Scanning | 3.2 | CII asset discovery |
| Cloud Config | 3.2, 3.3 | CII cloud, data localization |
| Compliance Scheduling | 3.1, 3.7, 4 | Quarterly, board reporting |
| Retention Management | 3.3, 3.7 | Localization, legal retention |
| Bilingual Reporting | 3.7 | EN/NE for government/npCERT |

---

## 7. Common Audit Findings & Remediation

### Finding: No npCERT Integration (NCSP-2080-01)

**Evidence**: No threat feed integration, no Cyber Drill participation, no incident sharing MOU

**Remediation**:
- Execute MOU with npCERT for threat intelligence sharing
- Integrate npCERT feeds into SIEM (STIX/TAXII)
- Participate in annual National Cyber Drill
- Define incident reporting SOP to npCERT (24hr critical)

**Verification**: npCERT confirms feed integration and exercise participation.

### Finding: CII Not Identified (NCSP-2080-02)

**Evidence**: No CII register, critical assets unmapped, no resilience testing

**Remediation**:
- Conduct CII identification workshop with sector regulator
- Register CII with npCERT per NCSP 2080 Section 3.2
- Implement defense-in-depth for identified CII
- Schedule annual resilience testing (red team + tabletop)

**Verification**: CII register submitted to npCERT with test results.

### Finding: Critical Data Hosted Offshore (NCSP-2080-03)

**Evidence**: Customer PII, financial data in foreign cloud without DPA

**Remediation**:
- Migrate critical data to Nepal-hosted infrastructure
- Execute DPAs for any required cross-border processing
- Implement data classification with handling procedures
- Encrypt all sensitive data (AES-256 at rest, TLS 1.3 in transit)

**Verification**: Data residency audit confirms Nepal hosting; DPAs on file.

### Finding: No SBOM / DevSecOps Pipeline (NCSP-2080-04)

**Evidence**: No SAST/DAST/SCA in CI/CD, no SBOM generation, no supply chain monitoring

**Remediation**:
```yaml
# Example GitLab CI DevSecOps stages
stages:
  - sast
  - dast
  - sca
  - container_scan
  - secret_scan
  - sbom_generate
  - deploy
```

- Integrate SAST (Semgrep/CodeQL), DAST (OWASP ZAP), SCA (Dependabot/Trivy)
- Generate SPDX/CycloneDX SBOM on every release
- Enable SLSA Level 2+ supply chain integrity
- Monitor for malicious packages (OSS Index, OSV)

**Verification**: Pipeline runs show all scan stages passing; SBOM artifacts generated.

### Finding: No National PKI / ZTNA (NCSP-2080-05)

**Evidence**: Password-only auth, no digital certificates, no zero trust architecture

**Remediation**:
- Deploy National PKI for digital signatures/authentication
- Implement ZTNA (e.g., Cloudflare Access, Tailscale, Pomerium)
- Integrate e-KYC for citizen-facing services
- Enforce FIDO2/WebAuthn for privileged access

**Verification**: ZTNA policy enforces device posture + MFA; PKI certs issued.

### Finding: Cybercrime Not Reported (NCSP-2080-07)

**Evidence**: Security incidents not reported to Nepal Police Cyber Bureau

**Remediation**:
- Establish reporting SOP with Cyber Bureau contact points
- Define reportable incident criteria per Cybercrime Act
- Automate evidence preservation (HMAC chain + forensic images)
- Train IR team on chain of custody procedures

**Verification**: Test report filed and acknowledged by Cyber Bureau.

### Finding: Energy Sector SCADA Exposed (NCSP-2080-02, NCSP-ENERGY-001)

**Evidence**: Modbus/TCP (port 502), DNP3 (port 20000) accessible from IT network/Internet

**Remediation**:
- Air-gap OT network from IT/Internet
- Deploy unidirectional gateways (data diodes) for historian access
- Implement IEC 62443 zones/conduits segmentation
- Conduct ICS-specific pen test (no exploitation)

**Verification**: Network scan shows no OT protocols reachable from IT/Internet.

---

## 8. Continuous Compliance

### 8.1 Scheduled Evidence (Quarterly per NCSP)

```bash
curl -X POST https://ishastra.example.com/api/schedules \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{
    "target": "https://critical.gov.np",
    "cron_expression": "0 2 1 */3 *",
    "timezone": "Asia/Kathmandu",
    "profile": "cii-deep",
    "policy_id": "pol_ncsp_001",
    "frameworks": ["ncsp"],
    "sector": "government"
  }'
```

### 8.2 npCERT Webhook

```bash
curl -X POST https://ishastra.example.com/api/alerts/webhook \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{
    "name": "ncert-evidence-push",
    "url": "https://ncert.gov.np/api/ishastra/evidence",
    "events": ["evidence_pack_generated", "critical_finding"],
    "frameworks": ["ncsp"]
  }'
```

### 8.3 Retention (Per Legal Requirements)

```bash
export ISHASTRA_RETENTION_DAYS=2555  # 7 years minimum
```

---

## 9. Auditor Checklist

- [ ] Evidence pack JSON validates
- [ ] HMAC audit chain verified (`ishastra audit verify`)
- [ ] All 14 NCSP controls assessed (100% coverage)
- [ ] Finding `compliance_refs` map to correct NCSP controls
- [ ] 8/8 automated checks executed
- [ ] Sector-specific controls verified (if applicable)
- [ ] Data sovereignty/localization verified
- [ ] npCERT coordination evidence (MOU, feeds, exercises)
- [ ] Critical gaps documented with remediation
- [ ] Bilingual report generated (EN/NE for government)
- [ ] OSCAL export imports to GRC
- [ ] Retention configured per legal requirements
- [ ] Authorization references match
- [ ] Scope matches CII register
- [ ] Chain hash independently verified

---

## 10. References

- [National Cyber Security Policy 2080](https://ncsc.gov.np)
- [npCERT](https://ncert.gov.np) - National Computer Emergency Response Team
- [Electronic Transactions Act 2063](https://molaw.gov.np)
- [Cybercrime Act](https://molaw.gov.np)
- [IEC 62443](https://iec.ch/62443) - Industrial Automation Security
- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf) - Secure Software Development Framework
- [SLSA](https://slsa.dev) - Supply Chain Levels for Software Artifacts
- [Ishastra Source](https://github.com/ishastra-project/ishastra) - MIT Licensed

---

*Part of Ishastra open-source compliance evidence pack generator. All mappings MIT-licensed and auditable.*