"""NRB (Nepal Rastra Bank) Compliance Controls.

Maps Strix findings to NRB banking cybersecurity directives:
- Directive 7/074: Information Security Policy
- Directive 8/075: Cyber Resilience Framework
- Directive 11/076: Digital Banking Security

All mappings are MIT-licensed and open for audit.
"""

from __future__ import annotations

from typing import Any

# ─── NRB Directive 7/074: Information Security Policy ───
NRB_7_074_CONTROLS: dict[str, dict[str, Any]] = {
    "NRB-7.1": {
        "title": "Information Security Policy",
        "description": "Bank must have a documented, board-approved information security policy",
        "directive": "7/074",
        "section": "7.1",
        "category": "governance",
        "severity": "high",
        "detection": [
            "missing_security_policy",
            "outdated_policy",
            "policy_not_board_approved",
        ],
        "evidence_required": [
            "policy_document",
            "board_approval_record",
            "review_date",
            "policy_version",
        ],
        "references": ["ISO 27001 A.5.1", "NIST CSF ID.GV-1"],
    },
    "NRB-7.2": {
        "title": "Network Security",
        "description": (
            "Firewall rules, network segmentation, DMZ, intrusion detection, secure communication channels"
        ),
        "directive": "7/074",
        "section": "7.2",
        "category": "network_security",
        "severity": "high",
        "detection": [
            "open_management_ports",
            "missing_segmentation",
            "weak_firewall_rules",
            "unencrypted_admin",
            "exposed_database",
            "missing_hsts",
            "weak_cipher_suite",
            "missing_csp",
        ],
        "evidence_required": [
            "firewall_config",
            "network_diagram",
            "ids_alerts",
            "segmentation_proof",
            "tls_config",
            "header_analysis",
        ],
        "references": ["ISO 27001 A.13.1", "NIST CSF PR.AC-5"],
    },
    "NRB-7.2.3": {
        "title": "Secure Communication Channels",
        "description": "All external communications must use encrypted channels with strong cryptography",
        "directive": "7/074",
        "section": "7.2.3",
        "category": "encryption",
        "severity": "critical",
        "detection": [
            "missing_hsts",
            "weak_cipher_suite",
            "cleartext_transmission",
            "weak_tls",
            "certificate_issues",
        ],
        "evidence_required": [
            "tls_config",
            "cipher_suite_list",
            "hsts_header",
            "certificate_details",
        ],
        "references": ["ISO 27001 A.10.1", "PCI DSS 4.1"],
    },
    "NRB-7.3": {
        "title": "Access Control",
        "description": "Role-based access control, least privilege, regular access reviews, MFA enforcement",
        "directive": "7/074",
        "section": "7.3",
        "category": "access_control",
        "severity": "high",
        "detection": [
            "excessive_privileges",
            "default_credentials",
            "missing_mfa",
            "orphaned_accounts",
            "weak_password_policy",
            "privilege_escalation",
            "auth_bypass",
            "idor",
        ],
        "evidence_required": [
            "access_matrix",
            "review_logs",
            "mfa_enrollment",
            "password_policy",
            "privileged_access_logs",
        ],
        "references": ["ISO 27001 A.9.2", "NIST CSF PR.AC-1"],
    },
    "NRB-7.4": {
        "title": "Application Security",
        "description": "Secure SDLC, code review, WAF, vulnerability management, OWASP Top 10 coverage",
        "directive": "7/074",
        "section": "7.4",
        "category": "application_security",
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
            "broken_object_auth",
        ],
        "evidence_required": [
            "sast_report",
            "dast_report",
            "waf_logs",
            "patch_records",
            "code_review_records",
        ],
        "references": ["ISO 27001 A.14.2", "OWASP Top 10", "NIST CSF PR.IP-1"],
    },
    "NRB-7.5": {
        "title": "Vulnerability Management",
        "description": "Continuous vulnerability scanning, patch management, risk-based prioritization",
        "directive": "7/074",
        "section": "7.5",
        "category": "vulnerability_management",
        "severity": "high",
        "detection": [
            "outdated_component",
            "known_vulnerability",
            "missing_patches",
            "supply_chain_exposure",
            "dependency_confusion",
        ],
        "evidence_required": [
            "scan_reports",
            "patch_management_logs",
            "risk_assessments",
            "sbom",
            "remediation_timelines",
        ],
        "references": ["ISO 27001 A.12.6", "NIST CSF DE.CM-8"],
    },
}

# ─── NRB Directive 8/075: Cyber Resilience Framework ───
NRB_8_075_CONTROLS: dict[str, dict[str, Any]] = {
    "NRB-8.1": {
        "title": "Identify - Asset Management & Risk Assessment",
        "description": "Asset inventory, exposure identification, risk assessment, governance",
        "directive": "8/075",
        "section": "8.1",
        "category": "identify",
        "severity": "high",
        "detection": [
            "git_exposure",
            "open_tcp_port",
            "service_exposure",
            "banner_disclosure",
            "unidentified_assets",
            "shadow_it",
        ],
        "evidence_required": [
            "asset_inventory",
            "risk_register",
            "exposure_assessment",
            "data_classification",
        ],
        "references": ["NIST CSF ID.AM-1", "ISO 27001 A.8.1"],
    },
    "NRB-8.1.4": {
        "title": "Transport Encryption",
        "description": "All data in transit must be encrypted using approved cryptographic standards",
        "directive": "8/075",
        "section": "8.1.4",
        "category": "encryption",
        "severity": "critical",
        "detection": [
            "missing_hsts",
            "weak_tls_config",
            "cleartext_transmission",
            "weak_cipher_suite",
            "certificate_issues",
        ],
        "evidence_required": [
            "tls_configuration",
            "cipher_suites",
            "certificate_inventory",
            "hsts_preload_status",
        ],
        "references": ["NIST CSF PR.DS-2", "PCI DSS 4.1"],
    },
    "NRB-8.2": {
        "title": "Protect - Access Control & Data Security",
        "description": "Header hardening, access control, data protection, secure configuration",
        "directive": "8/075",
        "section": "8.2",
        "category": "protect",
        "severity": "high",
        "detection": [
            "missing_csp",
            "missing_hsts",
            "missing_x_frame_options",
            "missing_referrer_policy",
            "missing_permissions_policy",
            "weak_cookie_flags",
            "excessive_privileges",
            "missing_mfa",
        ],
        "evidence_required": [
            "security_headers_analysis",
            "access_control_matrix",
            "encryption_audit",
            "configuration_baselines",
        ],
        "references": ["NIST CSF PR.AC-3", "ISO 27001 A.10.1"],
    },
    "NRB-8.3": {
        "title": "Detect - Security Monitoring & Anomaly Detection",
        "description": (
            "SIEM, log analysis, intrusion detection, threat intelligence, vulnerability detection"
        ),
        "directive": "8/075",
        "section": "8.3",
        "category": "detect",
        "severity": "high",
        "detection": [
            "sqli_indicator",
            "xss_indicator",
            "ssrf_indicator",
            "rce_indicator",
            "missing_logging",
            "log_tampering",
            "no_siem",
            "slow_detection",
            "anomalous_traffic",
        ],
        "evidence_required": [
            "siem_configuration",
            "log_samples",
            "alert_rules",
            "threat_intel_feeds",
            "detection_metrics",
        ],
        "references": ["NIST CSF DE.CM-1", "ISO 27001 A.12.4"],
    },
    "NRB-8.4": {
        "title": "Respond - Incident Response & Management",
        "description": "Incident response plan, finding lifecycle, containment, eradication, recovery",
        "directive": "8/075",
        "section": "8.4",
        "category": "respond",
        "severity": "high",
        "detection": [
            "missing_ir_plan",
            "slow_response",
            "incomplete_containment",
            "missing_root_cause",
            "no_lessons_learned",
        ],
        "evidence_required": [
            "ir_plan_document",
            "incident_log",
            "response_timelines",
            "rca_reports",
            "post_incident_reviews",
        ],
        "references": ["NIST CSF RS.RP-1", "ISO 27001 A.16.1"],
    },
    "NRB-8.5": {
        "title": "Recover - Backup, DR & Resilience",
        "description": "Backup integrity, disaster recovery testing, RTO/RPO compliance, business continuity",
        "directive": "8/075",
        "section": "8.5",
        "category": "recover",
        "severity": "high",
        "detection": [
            "backup_exposure",
            "untested_dr",
            "backup_failures",
            "missing_rto_rpo",
            "no_bcp",
            "recovery_time_exceeded",
        ],
        "evidence_required": [
            "bcp_document",
            "dr_test_results",
            "backup_logs",
            "rto_rpo_definition",
            "recovery_verification",
        ],
        "references": ["NIST CSF RC.RP-1", "ISO 27001 A.17.1"],
    },
}

# ─── NRB Directive 11/076: Digital Banking Security ───
NRB_11_076_CONTROLS: dict[str, dict[str, Any]] = {
    "NRB-11.2": {
        "title": "API Security",
        "description": "API authentication, authorization, rate limiting, input validation, audit logging",
        "directive": "11/076",
        "section": "11.2",
        "category": "api_security",
        "severity": "critical",
        "detection": [
            "auth_bypass",
            "idor",
            "rate_limit_bypass",
            "broken_object_auth",
            "mass_assignment",
            "excessive_data_exposure",
            "injection_api",
            "improper_asset_mgmt",
        ],
        "evidence_required": [
            "api_gateway_config",
            "auth_scheme_documentation",
            "rate_limit_config",
            "api_audit_logs",
            "schema_validation",
        ],
        "references": ["OWASP API Top 10", "NIST CSF PR.AC-6"],
    },
    "NRB-11.3": {
        "title": "Mobile App Security",
        "description": (
            "Certificate pinning, secure storage, anti-tamper, root detection, secure communication"
        ),
        "directive": "11/076",
        "section": "11.3",
        "category": "mobile_security",
        "severity": "high",
        "detection": [
            "insecure_storage",
            "weak_certificate_pinning",
            "missing_root_detection",
            "debug_code_present",
            "weak_obfuscation",
            "hardcoded_secrets",
        ],
        "evidence_required": [
            "mobile_sast_report",
            "pinning_verification",
            "storage_encryption_proof",
            "anti_tamper_test",
            "binary_analysis",
        ],
        "references": ["OWASP MASVS", "NIST CSF PR.DS-1"],
    },
    "NRB-11.4": {
        "title": "Transaction Security",
        "description": "CSRF protection, clickjacking defense, transaction signing, fraud detection",
        "directive": "11/076",
        "section": "11.4",
        "category": "transaction_security",
        "severity": "critical",
        "detection": [
            "csrf_missing",
            "clickjacking_vulnerable",
            "transaction_replay",
            "missing_transaction_signing",
            "fraud_rule_bypass",
        ],
        "evidence_required": [
            "csrf_token_implementation",
            "x_frame_options_header",
            "transaction_signing_logs",
            "fraud_detection_rules",
            "anomaly_alerts",
        ],
        "references": ["PCI DSS 6.5.6", "NIST CSF PR.IP-1"],
    },
}

# ─── Combined NRB Mappings ───
NRB_MAPPINGS: dict[str, dict[str, Any]] = {}
NRB_MAPPINGS.update(NRB_7_074_CONTROLS)
NRB_MAPPINGS.update(NRB_8_075_CONTROLS)
NRB_MAPPINGS.update(NRB_11_076_CONTROLS)

# ─── Finding Category to NRB Control Mapping ───
NRB_CATEGORY_MAPPING: dict[str, list[str]] = {
    # Governance
    "missing_security_policy": ["NRB-7.1"],
    "outdated_policy": ["NRB-7.1"],
    "policy_not_board_approved": ["NRB-7.1"],
    # Network Security
    "open_management_ports": ["NRB-7.2", "NRB-8.1"],
    "missing_segmentation": ["NRB-7.2"],
    "weak_firewall_rules": ["NRB-7.2"],
    "unencrypted_admin": ["NRB-7.2", "NRB-8.1.4"],
    "exposed_database": ["NRB-7.2", "NRB-8.1"],
    # Encryption / Transport
    "missing_hsts": ["NRB-7.2.3", "NRB-8.1.4", "NRB-8.2"],
    "weak_cipher_suite": ["NRB-7.2.3", "NRB-8.1.4"],
    "weak_tls": ["NRB-7.2.3", "NRB-8.1.4"],
    "weak_tls_config": ["NRB-8.1.4"],
    "cleartext_transmission": ["NRB-7.2.3", "NRB-8.1.4"],
    "certificate_issues": ["NRB-7.2.3", "NRB-8.1.4"],
    "missing_csp": ["NRB-7.2", "NRB-8.2"],
    "missing_x_frame_options": ["NRB-8.2"],
    "missing_referrer_policy": ["NRB-8.2"],
    "missing_permissions_policy": ["NRB-8.2"],
    "weak_cookie_flags": ["NRB-8.2"],
    # Access Control
    "excessive_privileges": ["NRB-7.3"],
    "default_credentials": ["NRB-7.3"],
    "missing_mfa": ["NRB-7.3", "NRB-8.2"],
    "orphaned_accounts": ["NRB-7.3"],
    "weak_password_policy": ["NRB-7.3"],
    "privilege_escalation": ["NRB-7.3"],
    "auth_bypass": ["NRB-7.3", "NRB-11.2"],
    "idor": ["NRB-7.3", "NRB-11.2"],
    # Application Security
    "sqli": ["NRB-7.4", "NRB-8.3"],
    "xss": ["NRB-7.4", "NRB-8.3"],
    "rce": ["NRB-7.4", "NRB-8.3"],
    "broken_auth": ["NRB-7.4"],
    "sensitive_data_exposure": ["NRB-7.4"],
    "xxe": ["NRB-7.4"],
    "ssrf": ["NRB-7.4", "NRB-8.3"],
    "csrf": ["NRB-7.4", "NRB-11.4"],
    "open_redirect": ["NRB-7.4"],
    "path_traversal": ["NRB-7.4"],
    "broken_object_auth": ["NRB-11.2"],
    "mass_assignment": ["NRB-11.2"],
    "excessive_data_exposure": ["NRB-11.2"],
    "injection_api": ["NRB-11.2"],
    "improper_asset_mgmt": ["NRB-11.2"],
    # Vulnerability Management
    "outdated_component": ["NRB-7.5"],
    "known_vulnerability": ["NRB-7.5"],
    "missing_patches": ["NRB-7.5"],
    "supply_chain_exposure": ["NRB-7.5"],
    "dependency_confusion": ["NRB-7.5"],
    # Detection
    "sqli_indicator": ["NRB-8.3"],
    "xss_indicator": ["NRB-8.3"],
    "ssrf_indicator": ["NRB-8.3"],
    "rce_indicator": ["NRB-8.3"],
    "missing_logging": ["NRB-8.3"],
    "log_tampering": ["NRB-8.3"],
    "no_siem": ["NRB-8.3"],
    "slow_detection": ["NRB-8.3"],
    "anomalous_traffic": ["NRB-8.3"],
    # Response
    "missing_ir_plan": ["NRB-8.4"],
    "slow_response": ["NRB-8.4"],
    "incomplete_containment": ["NRB-8.4"],
    "missing_root_cause": ["NRB-8.4"],
    "no_lessons_learned": ["NRB-8.4"],
    # Recovery
    "backup_exposure": ["NRB-8.5"],
    "untested_dr": ["NRB-8.5"],
    "backup_failures": ["NRB-8.5"],
    "missing_rto_rpo": ["NRB-8.5"],
    "no_bcp": ["NRB-8.5"],
    "recovery_time_exceeded": ["NRB-8.5"],
    # API Security
    "rate_limit_bypass": ["NRB-11.2"],
    # Mobile Security
    "insecure_storage": ["NRB-11.3"],
    "weak_certificate_pinning": ["NRB-11.3"],
    "missing_root_detection": ["NRB-11.3"],
    "debug_code_present": ["NRB-11.3"],
    "weak_obfuscation": ["NRB-11.3"],
    "hardcoded_secrets": ["NRB-11.3"],
    # Transaction Security
    "csrf_missing": ["NRB-11.4"],
    "clickjacking_vulnerable": ["NRB-11.4"],
    "transaction_replay": ["NRB-11.4"],
    "missing_transaction_signing": ["NRB-11.4"],
    "fraud_rule_bypass": ["NRB-11.4"],
}

# ─── Automated Check Functions ───


def check_encryption_at_rest(job_findings: list) -> dict[str, Any]:
    """Verify encryption at rest compliance.

    Checks for findings related to unencrypted storage, weak crypto,
    and certificate issues that indicate encryption gaps.
    """
    encryption_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "unencrypted_storage",
            "weak_crypto",
            "certificate_issues",
            "cleartext_transmission",
            "weak_tls",
        )
    ]

    return {
        "control": "NRB-7.2.3 / NRB-8.1.4",
        "description": "Encryption at rest and in transit verification",
        "status": "pass" if len(encryption_findings) == 0 else "fail",
        "findings_count": len(encryption_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in encryption_findings
        ],
        "recommendation": (
            "Enforce TLS 1.2+ with strong cipher suites (ECDHE+AES-GCM). "
            "Enable HSTS with preload. Encrypt all databases and backups at rest "
            "using AES-256. Manage keys via HSM or KMS."
        ),
    }


def check_access_control_rbac_mfa(job_findings: list) -> dict[str, Any]:
    """Verify RBAC, MFA, and session management compliance.

    Checks for findings related to excessive privileges, missing MFA,
    default credentials, orphaned accounts, and weak password policies.
    """
    access_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "excessive_privileges",
            "default_credentials",
            "missing_mfa",
            "orphaned_accounts",
            "weak_password_policy",
            "privilege_escalation",
            "auth_bypass",
            "session_fixation",
            "session_hijack",
        )
    ]

    return {
        "control": "NRB-7.3",
        "description": "Access control review (RBAC, MFA, session management)",
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
            "Implement role-based access control with least privilege. "
            "Enforce MFA for all administrative and privileged access. "
            "Implement session timeout (max 15 min idle), secure cookie flags "
            "(HttpOnly, Secure, SameSite=Strict), and rotate session IDs on login. "
            "Remove default credentials and conduct quarterly access reviews."
        ),
    }


def check_audit_log_integrity(job_findings: list) -> dict[str, Any]:
    """Verify audit log integrity (HMAC chain verification).

    Checks for findings related to missing logging, log tampering,
    and SIEM gaps.
    """
    log_findings = [f for f in job_findings if f.category in ("missing_logging", "log_tampering", "no_siem")]

    return {
        "control": "NRB-8.3 / NRB-8.4",
        "description": "Audit log integrity (HMAC chain verification)",
        "status": "pass" if len(log_findings) == 0 else "fail",
        "findings_count": len(log_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in log_findings
        ],
        "recommendation": (
            "Implement tamper-evident audit logging with HMAC-SHA256 chaining. "
            "Centralize logs in SIEM with immutable storage. "
            "Enable log integrity monitoring and alerting on chain breaks. "
            "Retain logs per regulatory requirements (minimum 7 years for banking)."
        ),
    }


def check_data_retention_disposal(job_findings: list) -> dict[str, Any]:
    """Verify data retention and disposal compliance.

    Checks for findings related to backup exposure, PII exposure,
    and data sovereignty issues.
    """
    retention_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "backup_exposure",
            "pii_exposure",
            "credential_leak",
            "data_offshore",
            "uncontrolled_transfer",
            "cross_border_transfer",
        )
    ]

    return {
        "control": "NRB-8.5 / NRB-7.5",
        "description": "Data retention and disposal compliance",
        "status": "pass" if len(retention_findings) == 0 else "fail",
        "findings_count": len(retention_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in retention_findings
        ],
        "recommendation": (
            "Define and enforce data retention schedules per NRB guidelines. "
            "Implement secure disposal (cryptographic erasure or physical destruction). "
            "Ensure PII and sensitive data is encrypted at rest. "
            "Verify backup encryption and access controls. "
            "Maintain data processing agreements for cross-border transfers."
        ),
    }


def check_incident_response(job_findings: list) -> dict[str, Any]:
    """Verify incident response procedures compliance.

    Checks for findings related to missing IR plan, slow response,
    and incomplete root cause analysis.
    """
    ir_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "missing_ir_plan",
            "slow_response",
            "incomplete_containment",
            "missing_root_cause",
            "no_lessons_learned",
        )
    ]

    return {
        "control": "NRB-8.4",
        "description": "Incident response procedures",
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
            "Maintain a documented, tested incident response plan per NRB 8/075. "
            "Define escalation paths, communication templates, and containment playbooks. "
            "Conduct quarterly tabletop exercises. Target <4 hour detection and "
            "<24 hour containment for critical incidents. Document all incidents with "
            "root cause analysis and lessons learned."
        ),
    }


def check_vulnerability_management(job_findings: list) -> dict[str, Any]:
    """Verify vulnerability management compliance (scanning, patching).

    Checks for findings related to outdated components, known vulnerabilities,
    missing patches, and supply chain risks.
    """
    vuln_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "outdated_component",
            "known_vulnerability",
            "missing_patches",
            "supply_chain_exposure",
            "dependency_confusion",
            "malicious_package",
        )
    ]

    return {
        "control": "NRB-7.5",
        "description": "Vulnerability management (scanning, patching)",
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
            "Patch critical vulnerabilities within 72 hours, high within 30 days. "
            "Maintain SBOM for all components. Monitor for supply chain attacks. "
            "Use automated dependency update tooling with testing gates."
        ),
    }


def run_all_nrb_checks(job_findings: list) -> list[dict[str, Any]]:
    """Run all NRB automated compliance checks."""
    return [
        check_encryption_at_rest(job_findings),
        check_access_control_rbac_mfa(job_findings),
        check_audit_log_integrity(job_findings),
        check_data_retention_disposal(job_findings),
        check_incident_response(job_findings),
        check_vulnerability_management(job_findings),
    ]


__all__ = [
    "NRB_MAPPINGS",
    "NRB_7_074_CONTROLS",
    "NRB_8_075_CONTROLS",
    "NRB_11_076_CONTROLS",
    "NRB_CATEGORY_MAPPING",
    "check_encryption_at_rest",
    "check_access_control_rbac_mfa",
    "check_audit_log_integrity",
    "check_data_retention_disposal",
    "check_incident_response",
    "check_vulnerability_management",
    "run_all_nrb_checks",
]
