# NTA Compliance Audit Guide

**Auditor-Ready Documentation for Nepal Telecommunications Authority Cybersecurity Byelaw 2078**

This guide enables auditors to verify Ishastra assessment evidence against NTA Cybersecurity Byelaw 2078 for telecommunications sector compliance.

---

## 1. Framework Overview

| Attribute | Value |
|-----------|-------|
| **Regulator** | Nepal Telecommunications Authority (NTA) |
| **Regulation** | Cybersecurity Byelaw 2078 |
| **Sector** | Telecommunications / ISPs |
| **Jurisdiction** | Nepal |
| **Ishastra Coverage** | 16 controls (7 core + 9 telecom-specific) |

### Byelaw Scope

| Section | Title | Controls | Focus Area |
|---------|-------|----------|------------|
| **4.1** | Network Infrastructure Security | NTA-4.1, NTA-SS7-001, NTA-DIAMETER-001, NTA-GTP-001, NTA-5G-001 | Perimeter, signaling, 5G |
| **4.2** | Secure Configuration | NTA-4.2 | Hardening, baselines, drift |
| **4.3** | Vulnerability Assessment | NTA-4.3 | Scanning, pen testing, patching |
| **4.4** | Access Control | NTA-4.4 | RBAC, MFA, PAM, sessions |
| **4.5** | Monitoring & Logging | NTA-4.5 | SIEM, logs, threat intel |
| **4.6** | Incident Response | NTA-4.6 | IR plan, 4-hr NTA notification |
| **4.7** | Third-Party Risk | NTA-4.7 | Vendor assessment, equipment cert |

---

## 2. Control Mapping Matrix

### Core Byelaw Controls (Sections 4.1-4.7)

| Control ID | Title | Ishastra Detection Categories | Evidence Required |
|------------|-------|---------------------------|-------------------|
| **NTA-4.1** | Network Perimeter Security | `open_tcp_port`, `service_exposure`, `banner_disclosure`, `exposed_database`, `open_management_ports`, `missing_segmentation`, `weak_firewall_rules`, `unencrypted_admin`, `signaling_exposure` | Firewall rulebase, topology, perimeter scans, IDS/IPS config, DMZ config |
| **NTA-4.2** | Secure Configuration | `missing_hsts`, `weak_cipher_suite`, `default_credentials`, `weak_tls_config`, `missing_csp`, `missing_security_headers`, `weak_cookie_flags`, `debug_enabled`, `excessive_services`, `insecure_defaults` | Baseline configs, drift reports, change logs, hardening checklists, cipher config |
| **NTA-4.3** | Vulnerability Assessment | `sqli`, `xss`, `rce`, `idor`, `broken_auth`, `sensitive_data_exposure`, `xxe`, `ssrf`, `csrf`, `open_redirect`, `path_traversal`, `outdated_component`, `known_vulnerability`, `missing_patches`, `supply_chain_exposure`, `dependency_confusion` | SAST/DAST reports, pen test reports, patch records, scan results, risk assessments, SBOM |
| **NTA-4.4** | Access Control | `auth_bypass`, `privilege_escalation`, `session_fixation`, `session_hijack`, `missing_mfa`, `excessive_privileges`, `default_credentials`, `orphaned_accounts`, `weak_password_policy`, `credential_stuffing`, `password_spray`, `mfa_bypass` | Access matrix, MFA enrollment, PAM logs, session config, lifecycle records, access reviews |
| **NTA-4.5** | Monitoring & Logging | `missing_logging`, `log_tampering`, `no_siem`, `slow_detection`, `missing_security_headers`, `information_disclosure`, `anomalous_traffic`, `unmonitored_systems` | SIEM architecture, retention policy, alert rules, threat intel, audit trails, detection metrics |
| **NTA-4.6** | Incident Response | `missing_ir_plan`, `slow_response`, `late_reporting`, `incomplete_rca`, `missing_remediation`, `incomplete_containment`, `no_lessons_learned`, `unreported_incidents` | IR plan, NTA notifications, incident logs, RCA reports, remediation tracking, tabletop exercises |
| **NTA-4.7** | Third-Party Risk | `unassessed_vendors`, `missing_contracts`, `vendor_breach`, `uncertified_equipment`, `firmware_tampering`, `default_credentials_equipment`, `end_of_life_equipment`, `supply_chain_risk` | Vendor register, assessments, security clauses, certifications, firmware hashes, inventory, EOL plan |

### Telecom-Specific Signaling Controls

| Control ID | Title | Ishastra Detection Categories | Evidence Required |
|------------|-------|---------------------------|-------------------|
| **NTA-SS7-001** | SS7 Signaling Security | `ss7_vulnerabilities`, `ss7_location_tracking`, `ss7_interception`, `ss7_fraud_indicators`, `roaming_fraud_indicators` | SS7 firewall config, message filtering, anomaly detection, roaming agreements, fraud monitoring |
| **NTA-DIAMETER-001** | Diameter Protocol Security | `diameter_vulnerabilities`, `diameter_tls_missing`, `diameter_overload`, `diameter_replay` | Diameter agent config, TLS config, overload control, message validation |
| **NTA-GTP-001** | GTP Protocol Security | `gtp_vulnerabilities`, `gtp_tunnel_hijack`, `gtp_spoofing`, `gtp_encryption_missing` | GTP firewall, tunnel validation, anti-spoofing, encryption verification |
| **NTA-5G-001** | 5G Network Security | `5g_sba_exposure`, `nef_vulnerabilities`, `slice_isolation_bypass`, `supi_exposure`, `ausf_bypass` | SBA security, NEF config, slice isolation, SUPI protection, AUSF config |

---

## 3. Automated Compliance Checks

Ishastra runs 9 automated verification checks for NTA compliance:

### 3.1 Network Perimeter Security (NTA-4.1)

```python
check_network_perimeter(job_findings)
```

**Verifies**: Default-deny firewall rules, network segmentation (DMZ/core/management), disabled unnecessary services, IDS/IPS with telecom signatures, quarterly external pen testing.

**Pass Criteria**: Zero findings in perimeter exposure categories.

### 3.2 Secure Configuration Management (NTA-4.2)

```python
check_secure_configuration(job_findings)
```

**Verifies**: CIS benchmarks, TLS 1.2+ with ECDHE+AES-GCM, HSTS/CSP/security headers, no default credentials, configuration drift detection, debug disabled.

**Pass Criteria**: Zero findings in configuration weakness categories.

### 3.3 Vulnerability Assessment (NTA-4.3)

```python
check_vulnerability_assessment(job_findings)
```

**Verifies**: Continuous scanning (SAST/DAST/SCA/container), annual third-party pen testing, critical patch <72hr / high <30 days, SBOM, CI/CD integration.

**Pass Criteria**: Zero findings in vulnerability categories.

### 3.4 Access Control (NTA-4.4)

```python
check_access_control(job_findings)
```

**Verifies**: RBAC with least privilege, MFA for admin/remote access, session management (15-min timeout, secure cookies, rotation), PAM for critical systems, quarterly access reviews.

**Pass Criteria**: Zero findings in access control categories.

### 3.5 Monitoring & Logging (NTA-4.5)

```python
check_monitoring_logging(job_findings)
```

**Verifies**: SIEM with centralized aggregation, HMAC-SHA256 tamper-evident logs, 1-year retention (7 years for signaling/customer data), telecom threat intel feeds, <15-min detection SLA.

**Pass Criteria**: Zero findings in monitoring/logging categories.

### 3.6 Incident Response & NTA Reporting (NTA-4.6)

```python
check_incident_response(job_findings)
```

**Verifies**: IR plan with telecom playbooks (SS7, Diameter, 5G), 4-hour NTA notification process, quarterly tabletop exercises with NTA liaison, full incident tracking.

**Pass Criteria**: Zero findings in incident response categories.

### 3.7 Third-Party Risk (NTA-4.7)

```python
check_third_party_risk(job_findings)
```

**Verifies**: Vendor register with risk classification, security clauses in contracts, NTA type approval for equipment, firmware integrity verification, EOL tracking, supply chain threat intel.

**Pass Criteria**: Zero findings in third-party risk categories.

### 3.8 Telecom Signaling Security (NTA-SS7-001, NTA-DIAMETER-001, NTA-GTP-001)

```python
check_telecom_signaling(job_findings)
```

**Verifies**: SS7/Diameter/GTP firewalls with stateful inspection, message filtering/anomaly detection, Diameter TLS 1.2+, GTP-U encryption (IPsec), roaming fraud monitoring, GSMA threat sharing.

**Pass Criteria**: Zero findings in signaling vulnerability categories.

### 3.9 5G Network Security (NTA-5G-001)

```python
check_5g_security(job_findings)
```

**Verifies**: SBA mutual TLS + OAuth2, NEF rate limiting/auth, network slice isolation, SUPI protection (SUCI), AUSF/UDM hardening.

**Pass Criteria**: Zero findings in 5G security categories.

---

## 4. Evidence Pack Structure

### 4.1 JSON Evidence Pack

```bash
ishastra evidence --target https://telco.example.com --framework NTA --output nta-evidence.json
```

### 4.2 CSV Export (Auditor Workbook)

```bash
ishastra evidence --target https://telco.example.com --framework NTA --format csv --output nta-audit.csv
```

### 4.3 OSCAL Assessment Results

```bash
ishastra evidence --target https://telco.example.com --framework NTA --format oscal --output nta-oscal.json
```

### 4.4 Bilingual HTML Report

```bash
ishastra evidence --target https://telco.example.com --framework NTA --format html --locale ne_NP --output nta-report.html
```

---

## 5. Auditor Verification Procedures

### 5.1 Evidence Integrity

```bash
ishastra audit verify --pack nta-evidence.json
```

### 5.2 Control Coverage

| Byelaw Section | Controls Defined | Controls Assessed | Coverage |
|----------------|-----------------|-------------------|----------|
| 4.1 (incl. telecom) | 11 | 11 | 100% |
| 4.2 | 1 | 1 | 100% |
| 4.3 | 1 | 1 | 100% |
| 4.4 | 1 | 1 | 100% |
| 4.5 | 1 | 1 | 100% |
| 4.6 | 1 | 1 | 100% |
| 4.7 | 1 | 1 | 100% |
| **Total** | **17** | **17** | **100%** |

### 5.3 Finding Traceability

```json
{
  "fingerprint": "a1b2c3d4...",
  "category": "ss7_vulnerabilities",
  "severity": "critical",
  "compliance_refs": ["NTA-4.1", "NTA-SS7-001"],
  "evidence": {"protocol": "SS7", "vulnerability": "Location tracking via AnyTimeInterrogation"}
}
```

### 5.4 Automated Check Results

Review `compliance_checks.nta` for 9 automated verifications.

---

## 6. Ishastra Feature Coverage for NTA

| Ishastra Feature | NTA Controls Covered | Automated Checks |
|---------------|---------------------|------------------|
| Scope Enforcement | 4.1, 4.4 | Scope validation |
| Audit Chain | 4.5, 4.6 | HMAC integrity |
| Redaction | 4.2 | CDR/PII redaction |
| Evidence Packs | 4.6 | Multi-format, NTA notification |
| Finding Lifecycle | 4.6 | SLA tracking, 4-hr notification |
| Vulnerability Scanning | 4.3 | Continuous scanning |
| TLS Analysis | 4.2 | Cipher, protocol verification |
| Header Analysis | 4.2, 4.5 | Security headers |
| Auth Testing | 4.4 | MFA, session, PAM |
| API Security | 4.3 | OWASP API Top 10 |
| Telecom Signaling | 4.1 (SS7, Diameter, GTP, 5G) | Protocol fuzzing, anomaly detection |
| Infra Scanning | 4.1 | Port scan, service enum, CVE |
| Cloud Config | 4.1, 4.2 | CIS, IAM, storage |
| Compliance Scheduling | 4.6 | Quarterly evidence, NTA webhook |
| Retention Management | 4.5 | 1yr/7yr retention policies |
| Bilingual Reporting | 4.6 | EN/NE for NTA submission |

---

## 7. Common Audit Findings & Remediation

### Finding: SS7 Vulnerabilities (NTA-4.1, NTA-SS7-001)

**Evidence**: SS7 AnyTimeInterrogation enables location tracking; no SS7 firewall

**Remediation**:
- Deploy SS7 firewall with stateful inspection
- Implement message filtering (block ATI, PSI, RI unless authorized)
- Enable anomaly detection for signaling patterns
- GSMA FS.11 compliance for roaming interfaces

**Verification**: SS7 pen test confirms firewall blocks unauthorized messages.

### Finding: Diameter TLS Missing (NTA-4.2, NTA-DIAMETER-001)

**Evidence**: Diameter over TCP (port 3868) without TLS

**Remediation**:
```ini
# Diameter TLS configuration
[transport]
tls = true
tls_port = 5868
cert_file = /etc/diameter/server.pem
key_file = /etc/diameter/server.key
ca_file = /etc/diameter/ca.pem
verify_peer = true
cipher_suite = ECDHE-RSA-AES256-GCM-SHA384
```

**Verification**: `openssl s_client -connect diameter:5868` shows TLS 1.2+ handshake.

### Finding: GTP-U Unencrypted (NTA-4.1, NTA-GTP-001)

**Evidence**: User plane traffic (GTP-U) unencrypted on S1-U/S5/S8 interfaces

**Remediation**:
- Deploy IPsec ESP for GTP-U tunnels
- Use AES-256-GCM with 256-bit keys
- Implement anti-replay protection

**Verification**: Packet capture shows ESP encapsulation on GTP-U ports.

### Finding: 4-Hour NTA Notification Gap (NTA-4.6)

**Evidence**: No documented 4-hour notification procedure to NTA

**Remediation**:
- Create NTA notification template with required fields
- Automate alerting to NTA contact points
- Integrate with SIEM for auto-ticketing
- Quarterly tabletop with NTA liaison

**Verification**: Tabletop exercise demonstrates <4hr notification.

### Finding: Default Credentials on Telecom Equipment (NTA-4.2, NTA-4.7)

**Evidence**: Base station / core network elements with vendor default passwords

**Remediation**:
- Change all defaults during commissioning
- Enforce password complexity per NTA-4.4
- Use centralized credential vault
- Audit quarterly for credential drift

**Verification**: Credential scan shows no default passwords.

---

## 8. Continuous Compliance

### 8.1 Scheduled Evidence (Quarterly per NTA)

```bash
curl -X POST https://ishastra.example.com/api/schedules \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{
    "target": "https://telco.example.com",
    "cron_expression": "0 2 1 */3 *",
    "timezone": "Asia/Kathmandu",
    "profile": "telecom-deep",
    "policy_id": "pol_nta_001",
    "frameworks": ["nta"]
  }'
```

### 8.2 NTA Notification Webhook

```bash
curl -X POST https://ishastra.example.com/api/alerts/webhook \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{
    "name": "nta-incident-alert",
    "url": "https://nta.gov.np/api/incident-receive",
    "events": ["critical_finding", "evidence_pack_generated"],
    "frameworks": ["nta"]
  }'
```

### 8.3 Retention (7 Years for Signaling/Customer Data)

```bash
export ISHASTRA_RETENTION_DAYS=2555  # 7 years
```

---

## 9. Auditor Checklist

- [ ] Evidence pack JSON validates against schema
- [ ] HMAC audit chain verified (`ishastra audit verify`)
- [ ] All 17 NTA controls assessed (100% coverage)
- [ ] Finding `compliance_refs` map to correct NTA controls
- [ ] 9/9 automated checks executed
- [ ] Telecom-specific signaling controls verified (SS7, Diameter, GTP, 5G)
- [ ] 4-hour NTA notification procedure documented and tested
- [ ] Critical gaps documented with remediation tracking
- [ ] Bilingual report generated for NTA submission
- [ ] OSCAL export imports to GRC
- [ ] Retention configured (2555 days)
- [ ] Authorization letter references match
- [ ] Scope excludes non-authorized networks
- [ ] Chain hash independently verified

---

## 10. References

- [NTA Cybersecurity Byelaw 2078](https://nta.gov.np)
- [GSMA FS.01-FS.18](https://gsma.com/fraud-security) - Telecom security guidelines
- [3GPP TS 33.210](https://3gpp.org) - 3G/4G/5G security architecture
- [3GPP TS 33.501](https://3gpp.org) - 5G security
- [ISO 27001](https://iso.org/27001) - ISMS
- [Ishastra Source](https://github.com/hacker-194/IshAstra) - Apache-2.0 licensed

---

*Part of Ishastra open-source compliance evidence pack generator. All mappings MIT-licensed and auditable.*