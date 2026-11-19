"""NTA (Nepal Telecommunications Authority) Compliance Controls.

Maps Strix findings to NTA Cybersecurity Byelaw 2078 controls.
All mappings are Apache-2.0-licensed and open for audit.
"""

from __future__ import annotations

from typing import Any

# ─── NTA Cybersecurity Byelaw 2078 Controls ───
NTA_CONTROLS: dict[str, dict[str, Any]] = {
    "NTA-4.1": {
        "title": "Network Perimeter Security",
        "description": "Core network protection, perimeter defense, boundary security controls",
        "byelaw": "2078",
        "section": "4.1",
        "category": "network_perimeter",
        "severity": "critical",
        "detection": [
            "open_tcp_port",
            "service_exposure",
            "banner_disclosure",
            "exposed_database",
            "open_management_ports",
            "missing_segmentation",
            "weak_firewall_rules",
            "unencrypted_admin",
            "signaling_exposure",
        ],
        "evidence_required": [
            "firewall_rulebase",
            "network_topology",
            "perimeter_scan_results",
            "ids_ips_configuration",
            "dmz_configuration",
            "boundary_device_configs",
        ],
        "references": ["ISO 27001 A.13.1", "NIST CSF PR.AC-5", "GSMA FS.01"],
    },
    "NTA-4.2": {
        "title": "Secure Configuration Management",
        "description": "Hardened baselines, configuration drift detection, change management",
        "byelaw": "2078",
        "section": "4.2",
        "category": "secure_configuration",
        "severity": "high",
        "detection": [
            "missing_hsts",
            "weak_cipher_suite",
            "default_credentials",
            "weak_tls_config",
            "missing_csp",
            "missing_security_headers",
            "weak_cookie_flags",
            "debug_enabled",
            "excessive_services",
            "insecure_defaults",
        ],
        "evidence_required": [
            "baseline_configurations",
            "drift_reports",
            "change_management_logs",
            "hardening_checklists",
            "cipher_suite_configuration",
            "header_security_analysis",
        ],
        "references": ["ISO 27001 A.12.1", "NIST CSF PR.IP-1", "CIS Benchmarks"],
    },
    "NTA-4.3": {
        "title": "Vulnerability Assessment & Management",
        "description": "Continuous scanning, penetration testing, patch management, risk prioritization",
        "byelaw": "2078",
        "section": "4.3",
        "category": "vulnerability_management",
        "severity": "high",
        "detection": [
            "sqli",
            "xss",
            "rce",
            "idor",
            "broken_auth",
            "sensitive_data_exposure",
            "xxe",
            "ssrf",
            "csrf",
            "open_redirect",
            "path_traversal",
            "outdated_component",
            "known_vulnerability",
            "missing_patches",
            "supply_chain_exposure",
            "dependency_confusion",
            "all_vulnerability_findings",
        ],
        "evidence_required": [
            "sast_dast_reports",
            "penetration_test_reports",
            "patch_management_records",
            "vulnerability_scan_results",
            "risk_assessments",
            "remediation_timelines",
            "sbom",
        ],
        "references": ["ISO 27001 A.12.6", "NIST CSF DE.CM-8", "OWASP Top 10"],
    },
    "NTA-4.4": {
        "title": "Access Control & Identity Management",
        "description": "RBAC, MFA, privileged access management, session controls, identity lifecycle",
        "byelaw": "2078",
        "section": "4.4",
        "category": "access_control",
        "severity": "critical",
        "detection": [
            "auth_bypass",
            "privilege_escalation",
            "session_fixation",
            "session_hijack",
            "missing_mfa",
            "excessive_privileges",
            "default_credentials",
            "orphaned_accounts",
            "weak_password_policy",
            "credential_stuffing",
            "password_spray",
            "mfa_bypass",
        ],
        "evidence_required": [
            "access_control_matrix",
            "mfa_enrollment_rates",
            "privileged_access_logs",
            "session_management_config",
            "identity_lifecycle_records",
            "access_review_reports",
            "password_policy_enforcement",
        ],
        "references": ["ISO 27001 A.9.2", "NIST CSF PR.AC-1", "GSMA FS.08"],
    },
    "NTA-4.5": {
        "title": "Security Monitoring & Logging",
        "description": "SIEM deployment, log aggregation, alerting, threat intelligence, audit trail",
        "byelaw": "2078",
        "section": "4.5",
        "category": "monitoring_logging",
        "severity": "high",
        "detection": [
            "missing_logging",
            "log_tampering",
            "no_siem",
            "slow_detection",
            "missing_security_headers",
            "information_disclosure",
            "anomalous_traffic",
            "unmonitored_systems",
        ],
        "evidence_required": [
            "siem_architecture",
            "log_retention_policy",
            "alert_rules_and_tuning",
            "threat_intel_integration",
            "audit_trail_samples",
            "detection_metrics",
            "log_integrity_verification",
        ],
        "references": ["ISO 27001 A.12.4", "NIST CSF DE.CM-1", "GSMA FS.10"],
    },
    "NTA-4.6": {
        "title": "Incident Response & Reporting",
        "description": "IR plan, mandatory 4-hour NTA notification, root cause analysis, remedial tracking",
        "byelaw": "2078",
        "section": "4.6",
        "category": "incident_response",
        "severity": "critical",
        "detection": [
            "missing_ir_plan",
            "slow_response",
            "late_reporting",
            "incomplete_rca",
            "missing_remediation",
            "incomplete_containment",
            "no_lessons_learned",
            "unreported_incidents",
        ],
        "evidence_required": [
            "ir_plan_document",
            "nta_notification_records",
            "incident_response_logs",
            "rca_reports",
            "remediation_tracking",
            "post_incident_reviews",
            "tabletop_exercise_records",
        ],
        "references": ["ISO 27001 A.16.1", "NIST CSF RS.RP-1", "NTA Byelaw 2078 Sec 4.6"],
    },
    "NTA-4.7": {
        "title": "Third-Party & Supply Chain Risk",
        "description": "Vendor assessment, contract security, equipment certification, firmware integrity",
        "byelaw": "2078",
        "section": "4.7",
        "category": "third_party_risk",
        "severity": "high",
        "detection": [
            "unassessed_vendors",
            "missing_contracts",
            "vendor_breach",
            "uncertified_equipment",
            "firmware_tampering",
            "default_credentials_equipment",
            "end_of_life_equipment",
            "supply_chain_risk",
        ],
        "evidence_required": [
            "vendor_register",
            "assessment_reports",
            "security_clauses_in_contracts",
            "certification_records",
            "firmware_hash_verification",
            "equipment_inventory",
            "eol_management_plan",
            "supply_chain_audit",
        ],
        "references": ["ISO 27001 A.15.1", "NIST CSF ID.SC-3", "GSMA FS.14"],
    },
}

# ─── Telecom-Specific Controls (Extended) ───
NTA_TELECOM_CONTROLS: dict[str, dict[str, Any]] = {
    "NTA-SS7-001": {
        "title": "SS7 Signaling Security",
        "description": "SS7 firewall, message filtering, anomaly detection, roaming fraud prevention",
        "byelaw": "2078",
        "section": "Signaling Security",
        "category": "signaling_security",
        "severity": "critical",
        "detection": [
            "ss7_vulnerabilities",
            "ss7_location_tracking",
            "ss7_interception",
            "ss7_fraud_indicators",
            "roaming_fraud_indicators",
        ],
        "evidence_required": [
            "ss7_firewall_config",
            "message_filtering_rules",
            "anomaly_detection_config",
            "roaming_agreements",
            "fraud_monitoring_dashboard",
        ],
        "references": ["GSMA FS.02", "GSMA FS.11", "3GPP TS 33.210"],
    },
    "NTA-DIAMETER-001": {
        "title": "Diameter Protocol Security",
        "description": "Diameter agent, message validation, overload control, TLS encryption",
        "byelaw": "2078",
        "section": "Signaling Security",
        "category": "signaling_security",
        "severity": "critical",
        "detection": [
            "diameter_vulnerabilities",
            "diameter_tls_missing",
            "diameter_overload",
            "diameter_replay",
        ],
        "evidence_required": [
            "diameter_agent_config",
            "tls_configuration",
            "overload_control_policy",
            "message_validation_rules",
        ],
        "references": ["3GPP TS 33.210", "RFC 6733"],
    },
    "NTA-GTP-001": {
        "title": "GTP Protocol Security",
        "description": "GTP-C/GTP-U protection, tunnel validation, anti-spoofing, encryption",
        "byelaw": "2078",
        "section": "Signaling Security",
        "category": "signaling_security",
        "severity": "critical",
        "detection": [
            "gtp_vulnerabilities",
            "gtp_tunnel_hijack",
            "gtp_spoofing",
            "gtp_encryption_missing",
        ],
        "evidence_required": [
            "gtp_firewall_config",
            "tunnel_validation_rules",
            "anti_spoofing_config",
            "encryption_verification",
        ],
        "references": ["3GPP TS 33.210", "GSMA FS.13"],
    },
    "NTA-5G-001": {
        "title": "5G Network Security",
        "description": "SBA security, NEF protection, network slicing isolation, SUPI protection",
        "byelaw": "2078",
        "section": "5G Security",
        "category": "5g_security",
        "severity": "critical",
        "detection": [
            "5g_sba_exposure",
            "nef_vulnerabilities",
            "slice_isolation_bypass",
            "supi_exposure",
            "ausf_bypass",
        ],
        "evidence_required": [
            "sba_security_architecture",
            "nef_security_config",
            "slice_isolation_verification",
            "supi_protection_measures",
            "ausf_security_config",
        ],
        "references": ["3GPP TS 33.501", "GSMA FS.18"],
    },
}

# ─── Combined NTA Mappings ───
NTA_MAPPINGS: dict[str, dict[str, Any]] = {}
NTA_MAPPINGS.update(NTA_CONTROLS)
NTA_MAPPINGS.update(NTA_TELECOM_CONTROLS)

# ─── Finding Category to NTA Control Mapping ───
NTA_CATEGORY_MAPPING: dict[str, list[str]] = {
    # Network Perimeter
    "open_tcp_port": ["NTA-4.1"],
    "service_exposure": ["NTA-4.1"],
    "banner_disclosure": ["NTA-4.1"],
    "exposed_database": ["NTA-4.1"],
    "open_management_ports": ["NTA-4.1"],
    "missing_segmentation": ["NTA-4.1"],
    "weak_firewall_rules": ["NTA-4.1"],
    "unencrypted_admin": ["NTA-4.1"],
    "signaling_exposure": ["NTA-4.1", "NTA-SS7-001"],
    # Secure Configuration
    "missing_hsts": ["NTA-4.2"],
    "weak_cipher_suite": ["NTA-4.2"],
    "default_credentials": ["NTA-4.2", "NTA-4.4"],
    "weak_tls_config": ["NTA-4.2"],
    "missing_csp": ["NTA-4.2"],
    "missing_security_headers": ["NTA-4.2", "NTA-4.5"],
    "weak_cookie_flags": ["NTA-4.2"],
    "debug_enabled": ["NTA-4.2"],
    "excessive_services": ["NTA-4.2"],
    "insecure_defaults": ["NTA-4.2"],
    # Vulnerability Management
    "sqli": ["NTA-4.3"],
    "xss": ["NTA-4.3"],
    "rce": ["NTA-4.3"],
    "idor": ["NTA-4.3"],
    "broken_auth": ["NTA-4.3"],
    "sensitive_data_exposure": ["NTA-4.3"],
    "xxe": ["NTA-4.3"],
    "ssrf": ["NTA-4.3"],
    "csrf": ["NTA-4.3"],
    "open_redirect": ["NTA-4.3"],
    "path_traversal": ["NTA-4.3"],
    "outdated_component": ["NTA-4.3"],
    "known_vulnerability": ["NTA-4.3"],
    "missing_patches": ["NTA-4.3"],
    "supply_chain_exposure": ["NTA-4.3", "NTA-4.7"],
    "dependency_confusion": ["NTA-4.3", "NTA-4.7"],
    "all_vulnerability_findings": ["NTA-4.3"],
    # Access Control
    "auth_bypass": ["NTA-4.4"],
    "privilege_escalation": ["NTA-4.4"],
    "session_fixation": ["NTA-4.4"],
    "session_hijack": ["NTA-4.4"],
    "missing_mfa": ["NTA-4.4"],
    "excessive_privileges": ["NTA-4.4"],
    "orphaned_accounts": ["NTA-4.4"],
    "weak_password_policy": ["NTA-4.4"],
    "credential_stuffing": ["NTA-4.4"],
    "password_spray": ["NTA-4.4"],
    "mfa_bypass": ["NTA-4.4"],
    # Monitoring & Logging
    "missing_logging": ["NTA-4.5"],
    "log_tampering": ["NTA-4.5"],
    "no_siem": ["NTA-4.5"],
    "slow_detection": ["NTA-4.5"],
    "information_disclosure": ["NTA-4.5"],
    "anomalous_traffic": ["NTA-4.5"],
    "unmonitored_systems": ["NTA-4.5"],
    # Incident Response
    "missing_ir_plan": ["NTA-4.6"],
    "slow_response": ["NTA-4.6"],
    "late_reporting": ["NTA-4.6"],
    "incomplete_rca": ["NTA-4.6"],
    "missing_remediation": ["NTA-4.6"],
    "incomplete_containment": ["NTA-4.6"],
    "no_lessons_learned": ["NTA-4.6"],
    "unreported_incidents": ["NTA-4.6"],
    # Third Party Risk
    "unassessed_vendors": ["NTA-4.7"],
    "missing_contracts": ["NTA-4.7"],
    "vendor_breach": ["NTA-4.7"],
    "uncertified_equipment": ["NTA-4.7"],
    "firmware_tampering": ["NTA-4.7"],
    "default_credentials_equipment": ["NTA-4.7"],
    "end_of_life_equipment": ["NTA-4.7"],
    "supply_chain_risk": ["NTA-4.7"],
    # Telecom Specific
    "ss7_vulnerabilities": ["NTA-SS7-001"],
    "ss7_location_tracking": ["NTA-SS7-001"],
    "ss7_interception": ["NTA-SS7-001"],
    "ss7_fraud_indicators": ["NTA-SS7-001"],
    "roaming_fraud_indicators": ["NTA-SS7-001"],
    "diameter_vulnerabilities": ["NTA-DIAMETER-001"],
    "diameter_tls_missing": ["NTA-DIAMETER-001"],
    "diameter_overload": ["NTA-DIAMETER-001"],
    "diameter_replay": ["NTA-DIAMETER-001"],
    "gtp_vulnerabilities": ["NTA-GTP-001"],
    "gtp_tunnel_hijack": ["NTA-GTP-001"],
    "gtp_spoofing": ["NTA-GTP-001"],
    "gtp_encryption_missing": ["NTA-GTP-001"],
    "5g_sba_exposure": ["NTA-5G-001"],
    "nef_vulnerabilities": ["NTA-5G-001"],
    "slice_isolation_bypass": ["NTA-5G-001"],
    "supi_exposure": ["NTA-5G-001"],
    "ausf_bypass": ["NTA-5G-001"],
}

# ─── Automated Check Functions ───


def check_network_perimeter(job_findings: list) -> dict[str, Any]:
    """Verify network perimeter security compliance (NTA-4.1)."""
    perimeter_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "open_tcp_port",
            "service_exposure",
            "banner_disclosure",
            "exposed_database",
            "open_management_ports",
            "missing_segmentation",
            "weak_firewall_rules",
            "unencrypted_admin",
            "signaling_exposure",
        )
    ]

    return {
        "control": "NTA-4.1",
        "description": "Network perimeter security",
        "status": "pass" if len(perimeter_findings) == 0 else "fail",
        "findings_count": len(perimeter_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in perimeter_findings
        ],
        "recommendation": (
            "Implement default-deny firewall rules at network boundaries. "
            "Segment networks (DMZ, core, management) with strict inter-zone controls. "
            "Disable unnecessary services and management interfaces on public networks. "
            "Deploy IDS/IPS at perimeter with signatures for telecom signaling protocols. "
            "Conduct quarterly external penetration testing."
        ),
    }


def check_secure_configuration(job_findings: list) -> dict[str, Any]:
    """Verify secure configuration management compliance (NTA-4.2)."""
    config_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "missing_hsts",
            "weak_cipher_suite",
            "default_credentials",
            "weak_tls_config",
            "missing_csp",
            "missing_security_headers",
            "weak_cookie_flags",
            "debug_enabled",
            "excessive_services",
            "insecure_defaults",
        )
    ]

    return {
        "control": "NTA-4.2",
        "description": "Secure configuration management",
        "status": "pass" if len(config_findings) == 0 else "fail",
        "findings_count": len(config_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in config_findings
        ],
        "recommendation": (
            "Establish hardened configuration baselines per CIS benchmarks. "
            "Enforce TLS 1.2+ with ECDHE+AES-GCM ciphers. Enable HSTS, CSP, and all "
            "security headers. Remove default credentials before deployment. "
            "Implement configuration drift detection with automated remediation. "
            "Disable debug modes and excessive services in production."
        ),
    }


def check_vulnerability_assessment(job_findings: list) -> dict[str, Any]:
    """Verify vulnerability assessment compliance (NTA-4.3)."""
    vuln_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "sqli",
            "xss",
            "rce",
            "idor",
            "broken_auth",
            "sensitive_data_exposure",
            "xxe",
            "ssrf",
            "csrf",
            "open_redirect",
            "path_traversal",
            "outdated_component",
            "known_vulnerability",
            "missing_patches",
            "supply_chain_exposure",
            "dependency_confusion",
        )
    ]

    return {
        "control": "NTA-4.3",
        "description": "Vulnerability assessment and management",
        "status": "pass" if len(vuln_findings) == 0 else "fail",
        "findings_count": len(vuln_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in vuln_findings
        ],
        "recommendation": (
            "Implement continuous vulnerability scanning (SAST, DAST, SCA, container). "
            "Conduct annual third-party penetration testing. "
            "Patch critical vulnerabilities within 72 hours, high within 30 days. "
            "Maintain SBOM and monitor for supply chain vulnerabilities. "
            "Integrate vulnerability management into CI/CD pipeline."
        ),
    }


def check_access_control(job_findings: list) -> dict[str, Any]:
    """Verify access control compliance (NTA-4.4)."""
    access_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "auth_bypass",
            "privilege_escalation",
            "session_fixation",
            "session_hijack",
            "missing_mfa",
            "excessive_privileges",
            "default_credentials",
            "orphaned_accounts",
            "weak_password_policy",
            "credential_stuffing",
            "password_spray",
            "mfa_bypass",
        )
    ]

    return {
        "control": "NTA-4.4",
        "description": "Access control and identity management",
        "status": "pass" if len(access_findings) == 0 else "fail",
        "findings_count": len(access_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in access_findings
        ],
        "recommendation": (
            "Implement RBAC with least privilege principle. "
            "Enforce MFA for all administrative and remote access. "
            "Implement session management: timeout 15 min, secure cookies, rotation on login. "
            "Deploy privileged access management (PAM) for critical systems. "
            "Conduct quarterly access reviews and revoke orphaned accounts."
        ),
    }


def check_monitoring_logging(job_findings: list) -> dict[str, Any]:
    """Verify monitoring and logging compliance (NTA-4.5)."""
    monitoring_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "missing_logging",
            "log_tampering",
            "no_siem",
            "slow_detection",
            "information_disclosure",
            "anomalous_traffic",
            "unmonitored_systems",
        )
    ]

    return {
        "control": "NTA-4.5",
        "description": "Security monitoring and logging",
        "status": "pass" if len(monitoring_findings) == 0 else "fail",
        "findings_count": len(monitoring_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in monitoring_findings
        ],
        "recommendation": (
            "Deploy SIEM with centralized log aggregation from all critical systems. "
            "Implement tamper-evident logging with HMAC-SHA256 chaining. "
            "Retain logs minimum 1 year (7 years for signaling/customer data). "
            "Integrate threat intelligence feeds for telecom-specific threats. "
            "Define alerting rules with <15 minute detection target for critical events."
        ),
    }


def check_incident_response(job_findings: list) -> dict[str, Any]:
    """Verify incident response compliance (NTA-4.6)."""
    ir_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "missing_ir_plan",
            "slow_response",
            "late_reporting",
            "incomplete_rca",
            "missing_remediation",
            "incomplete_containment",
            "no_lessons_learned",
            "unreported_incidents",
        )
    ]

    return {
        "control": "NTA-4.6",
        "description": "Incident response and mandatory NTA reporting",
        "status": "pass" if len(ir_findings) == 0 else "fail",
        "findings_count": len(ir_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in ir_findings
        ],
        "recommendation": (
            "Maintain documented IR plan with telecom-specific playbooks (SS7, Diameter, 5G). "
            "Establish 4-hour NTA notification process with predefined templates. "
            "Conduct quarterly tabletop exercises including NTA liaison. "
            "Track all incidents through containment, eradication, recovery, and lessons learned. "
            "Implement automated incident detection and alerting with SLA tracking."
        ),
    }


def check_third_party_risk(job_findings: list) -> dict[str, Any]:
    """Verify third-party risk management compliance (NTA-4.7)."""
    vendor_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "unassessed_vendors",
            "missing_contracts",
            "vendor_breach",
            "uncertified_equipment",
            "firmware_tampering",
            "default_credentials_equipment",
            "end_of_life_equipment",
            "supply_chain_risk",
        )
    ]

    return {
        "control": "NTA-4.7",
        "description": "Third-party and supply chain risk management",
        "status": "pass" if len(vendor_findings) == 0 else "fail",
        "findings_count": len(vendor_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in vendor_findings
        ],
        "recommendation": (
            "Maintain vendor register with risk classifications. "
            "Require security clauses in all telecom equipment and service contracts. "
            "Verify equipment certification (NTA type approval) before deployment. "
            "Implement firmware integrity verification (signed images, hash validation). "
            "Track EOL equipment and plan replacements. Monitor supply chain threat intel."
        ),
    }


def check_telecom_signaling(job_findings: list) -> dict[str, Any]:
    """Verify telecom signaling security compliance (NTA-SS7-001, DIAMETER, GTP)."""
    signaling_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "ss7_vulnerabilities",
            "ss7_location_tracking",
            "ss7_interception",
            "ss7_fraud_indicators",
            "roaming_fraud_indicators",
            "diameter_vulnerabilities",
            "diameter_tls_missing",
            "diameter_overload",
            "diameter_replay",
            "gtp_vulnerabilities",
            "gtp_tunnel_hijack",
            "gtp_spoofing",
            "gtp_encryption_missing",
        )
    ]

    return {
        "control": "NTA-SS7-001 / NTA-DIAMETER-001 / NTA-GTP-001",
        "description": "Telecom signaling security (SS7, Diameter, GTP)",
        "status": "pass" if len(signaling_findings) == 0 else "fail",
        "findings_count": len(signaling_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in signaling_findings
        ],
        "recommendation": (
            "Deploy SS7/Diameter/GTP firewalls with stateful inspection. "
            "Implement message filtering and anomaly detection for signaling traffic. "
            "Encrypt Diameter with TLS 1.2+. Implement GTP-U encryption (IPsec). "
            "Monitor roaming interfaces for fraud indicators. "
            "Participate in GSMA Fraud and Security Group threat sharing."
        ),
    }


def check_5g_security(job_findings: list) -> dict[str, Any]:
    """Verify 5G network security compliance (NTA-5G-001)."""
    g5_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "5g_sba_exposure",
            "nef_vulnerabilities",
            "slice_isolation_bypass",
            "supi_exposure",
            "ausf_bypass",
        )
    ]

    return {
        "control": "NTA-5G-001",
        "description": "5G network security (SBA, NEF, Slicing, SUPI)",
        "status": "pass" if len(g5_findings) == 0 else "fail",
        "findings_count": len(g5_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in g5_findings
        ],
        "recommendation": (
            "Secure Service-Based Architecture (SBA) with mutual TLS and OAuth2. "
            "Protect Network Exposure Function (NEF) with rate limiting and authentication. "
            "Enforce network slice isolation at control and user plane. "
            "Implement SUPI protection (encryption, SUCI). "
            "Harden AUSF/UDM with strong authentication and monitoring."
        ),
    }


def run_all_nta_checks(job_findings: list) -> list[dict[str, Any]]:
    """Run all NTA automated compliance checks."""
    return [
        check_network_perimeter(job_findings),
        check_secure_configuration(job_findings),
        check_vulnerability_assessment(job_findings),
        check_access_control(job_findings),
        check_monitoring_logging(job_findings),
        check_incident_response(job_findings),
        check_third_party_risk(job_findings),
        check_telecom_signaling(job_findings),
        check_5g_security(job_findings),
    ]


__all__ = [
    "NTA_MAPPINGS",
    "NTA_CONTROLS",
    "NTA_TELECOM_CONTROLS",
    "NTA_CATEGORY_MAPPING",
    "check_network_perimeter",
    "check_secure_configuration",
    "check_vulnerability_assessment",
    "check_access_control",
    "check_monitoring_logging",
    "check_incident_response",
    "check_third_party_risk",
    "check_telecom_signaling",
    "check_5g_security",
    "run_all_nta_checks",
]
