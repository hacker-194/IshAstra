"""NCSP (National Cyber Security Policy 2080) Compliance Controls.

Maps Strix findings to Nepal's National Cyber Security Policy 2080 controls.
All mappings are MIT-licensed and open for audit.
"""

from __future__ import annotations

from typing import Any

# ─── NCSP 2080 Controls ───
NCSP_CONTROLS: dict[str, dict[str, Any]] = {
    "NCSP-2080-01": {
        "title": "National CERT Coordination (npCERT)",
        "description": "Integration with npCERT, threat intelligence sharing, coordinated incident response",
        "policy": "NCSP 2080",
        "section": "3.1",
        "category": "cert_coordination",
        "severity": "high",
        "detection": [
            "no_cert_integration",
            "missing_threat_intel",
            "uncoordinated_response",
            "no_cert_reporting",
            "missing_exercise_participation",
        ],
        "evidence_required": [
            "cert_mou",
            "threat_feed_configuration",
            "exercise_participation_records",
            "incident_sharing_logs",
            "cert_contact_points",
        ],
        "references": ["NCSP 2080 Section 3.1", "ISO 27001 A.16.1", "FIRST CSIRT Framework"],
    },
    "NCSP-2080-02": {
        "title": "Critical Information Infrastructure (CII) Protection",
        "description": (
            "Sectoral CII identification, protection standards, resilience testing, interdependency mapping"
        ),
        "policy": "NCSP 2080",
        "section": "3.2",
        "category": "critical_infrastructure",
        "severity": "critical",
        "detection": [
            "missing_cii_id",
            "protection_gaps",
            "untested_resilience",
            "interdependency_unmapped",
            "scada_exposure",
            "ics_protocol_exposure",
            "unidentified_cii",
            "missing_protection",
            "unreported_incidents",
            "supply_chain_risk",
        ],
        "evidence_required": [
            "cii_register",
            "protection_plan",
            "resilience_test_results",
            "dependency_map",
            "scada_ics_inventory",
            "network_segmentation_proof",
            "incident_reports",
            "supply_chain_audit",
        ],
        "references": ["NCSP 2080 Section 3.2", "NIST CSF ID.AM-5", "IEC 62443"],
    },
    "NCSP-2080-03": {
        "title": "Data Sovereignty & Localization",
        "description": (
            "Critical data hosted in Nepal, cross-border transfer controls, data processing agreements"
        ),
        "policy": "NCSP 2080",
        "section": "3.3",
        "category": "data_sovereignty",
        "severity": "high",
        "detection": [
            "data_offshore",
            "uncontrolled_transfer",
            "missing_dpa",
            "cross_border_transfer",
            "pii_exposure",
            "credential_leak",
            "encryption_absent",
        ],
        "evidence_required": [
            "hosting_locations",
            "transfer_agreements",
            "dpa_records",
            "data_classification",
            "encryption_configuration",
            "localization_attestation",
        ],
        "references": ["NCSP 2080 Section 3.3", "Electronic Transactions Act 2063", "GDPR Art 44-50"],
    },
    "NCSP-2080-04": {
        "title": "Secure Software Development (DevSecOps)",
        "description": "DevSecOps adoption, secure coding standards, supply chain security, SBOM",
        "policy": "NCSP 2080",
        "section": "3.4",
        "category": "secure_development",
        "severity": "high",
        "detection": [
            "no_sast",
            "no_dast",
            "dependency_vulnerabilities",
            "insecure_cicd",
            "missing_sbom",
            "insecure_coding",
            "missing_code_review",
            "hardcoded_secrets",
            "malicious_package",
        ],
        "evidence_required": [
            "pipeline_configuration",
            "scan_reports",
            "sbom",
            "coding_standards",
            "code_review_records",
            "secret_scanning_results",
            "supply_chain_security_policy",
        ],
        "references": ["NCSP 2080 Section 3.4", "NIST SSDF", "OWASP SAMM", "SLSA"],
    },
    "NCSP-2080-05": {
        "title": "Identity & Trust Services",
        "description": (
            "National PKI, digital signatures, e-KYC, zero trust architecture, strong authentication"
        ),
        "policy": "NCSP 2080",
        "section": "3.5",
        "category": "identity_trust",
        "severity": "medium",
        "detection": [
            "weak_auth",
            "no_pki",
            "certificate_misuse",
            "missing_ztna",
            "missing_mfa",
            "auth_bypass",
            "session_hijack",
            "certificate_issues",
        ],
        "evidence_required": [
            "pki_configuration",
            "certificate_inventory",
            "ztna_architecture",
            "ekyc_integration",
            "digital_signature_usage",
            "mfa_enrollment",
            "auth_strength_assessment",
        ],
        "references": ["NCSP 2080 Section 3.5", "Electronic Transactions Act 2063", "NIST CSF PR.AC-1"],
    },
    "NCSP-2080-06": {
        "title": "Cybersecurity Workforce Development",
        "description": "Certified professionals, training programs, awareness campaigns, skill frameworks",
        "policy": "NCSP 2080",
        "section": "3.6",
        "category": "workforce",
        "severity": "medium",
        "detection": [
            "uncertified_staff",
            "missing_training",
            "low_awareness",
            "skill_gaps",
            "no_certification_path",
        ],
        "evidence_required": [
            "certification_records",
            "training_completion_records",
            "awareness_campaign_metrics",
            "skill_assessment_results",
            "career_framework_alignment",
        ],
        "references": ["NCSP 2080 Section 3.6", "NICE Framework", "ISO 27001 A.7.2"],
    },
    "NCSP-2080-07": {
        "title": "Legal & Regulatory Compliance",
        "description": (
            "Electronic Transactions Act compliance, cybercrime reporting, evidence preservation, audit trail"
        ),
        "policy": "NCSP 2080",
        "section": "3.7",
        "category": "legal_compliance",
        "severity": "high",
        "detection": [
            "eta_noncompliance",
            "evidence_spoilation",
            "unreported_cybercrime",
            "missing_audit_trail",
            "chain_of_custody_break",
            "data_retention_violation",
        ],
        "evidence_required": [
            "compliance_attestation",
            "evidence_chain_verification",
            "police_reports",
            "audit_trail_samples",
            "retention_policy",
            "legal_hold_procedures",
        ],
        "references": ["NCSP 2080 Section 3.7", "Electronic Transactions Act 2063", "Cybercrime Act"],
    },
    "NCSP-2080-08": {
        "title": "National Cyber Security Strategy Implementation",
        "description": (
            "Strategy governance, risk management framework, metrics and reporting, continuous improvement"
        ),
        "policy": "NCSP 2080",
        "section": "4",
        "category": "governance",
        "severity": "high",
        "detection": [
            "no_cyber_strategy",
            "missing_risk_framework",
            "no_metrics_reporting",
            "governance_gaps",
            "board_oversight_missing",
        ],
        "evidence_required": [
            "cyber_strategy_document",
            "risk_management_framework",
            "kpi_kri_dashboard",
            "board_reporting_records",
            "continuous_improvement_plan",
        ],
        "references": ["NCSP 2080 Section 4", "ISO 27001 Clause 4-10", "NIST CSF Govern"],
    },
    "NCSP-2080-09": {
        "title": "International Cooperation",
        "description": (
            "Cross-border collaboration, mutual legal assistance, threat intelligence sharing, "
            "joint exercises"
        ),
        "policy": "NCSP 2080",
        "section": "5",
        "category": "international_cooperation",
        "severity": "medium",
        "detection": [
            "no_international_mou",
            "missing_mlat",
            "no_threat_sharing",
            "no_joint_exercises",
        ],
        "evidence_required": [
            "international_mous",
            "mlat_records",
            "threat_sharing_agreements",
            "exercise_participation",
        ],
        "references": ["NCSP 2080 Section 5", "Budapest Convention", "ASEAN Cybersecurity"],
    },
    "NCSP-2080-10": {
        "title": "Critical Sector Resilience",
        "description": "Banking, telecom, energy, government, health sector specific resilience requirements",
        "policy": "NCSP 2080",
        "section": "6",
        "category": "sector_resilience",
        "severity": "critical",
        "detection": [
            "banking_resilience_gaps",
            "telecom_resilience_gaps",
            "energy_resilience_gaps",
            "gov_resilience_gaps",
            "health_resilience_gaps",
            "no_sector_plan",
        ],
        "evidence_required": [
            "sector_resilience_plans",
            "interdependency_analysis",
            "cascading_failure_scenarios",
            "recovery_time_objectives",
            "mutual_aid_agreements",
        ],
        "references": ["NCSP 2080 Section 6", "NRB Directives", "NTA Byelaws", "Sectoral Guidelines"],
    },
}

# ─── Sector-Specific NCSP Controls ───
NCSP_SECTOR_CONTROLS: dict[str, dict[str, Any]] = {
    "NCSP-BANK-001": {
        "title": "Banking Sector Cyber Resilience",
        "description": "NRB-aligned controls: transaction security, fraud detection, core banking protection",
        "policy": "NCSP 2080 / NRB 11/076",
        "section": "6.1",
        "category": "banking_resilience",
        "severity": "critical",
        "detection": [
            "transaction_fraud",
            "core_banking_exposure",
            "swift_vulnerabilities",
            "atm_security_gaps",
            "mobile_banking_weakness",
            "card_data_exposure",
        ],
        "evidence_required": [
            "transaction_monitoring_config",
            "fraud_detection_rules",
            "core_banking_segmentation",
            "swift_csp_compliance",
            "atm_security_assessment",
            "mobile_app_security_test",
            "pci_dss_aoc",
        ],
        "references": ["NCSP 2080 Section 6", "NRB 11/076", "PCI DSS", "SWIFT CSP"],
    },
    "NCSP-TELCO-001": {
        "title": "Telecom Sector Cyber Resilience",
        "description": (
            "NTA-aligned controls: signaling security, subscriber data protection, network resilience"
        ),
        "policy": "NCSP 2080 / NTA 2078",
        "section": "6.2",
        "category": "telecom_resilience",
        "severity": "critical",
        "detection": [
            "signaling_vulnerabilities",
            "subscriber_data_leak",
            "network_resilience_gaps",
            "roaming_fraud",
            "equipment_vulnerabilities",
        ],
        "evidence_required": [
            "signaling_firewall_config",
            "subscriber_data_protection",
            "network_redundancy_design",
            "roaming_fraud_monitoring",
            "equipment_certification",
        ],
        "references": ["NCSP 2080 Section 6", "NTA 2078", "GSMA FS", "3GPP Security"],
    },
    "NCSP-GOV-001": {
        "title": "Government Sector Cyber Resilience",
        "description": (
            "Government systems protection, citizen data privacy, service continuity, classification handling"
        ),
        "policy": "NCSP 2080",
        "section": "6.3",
        "category": "government_resilience",
        "severity": "critical",
        "detection": [
            "gov_system_exposure",
            "citizen_data_leak",
            "service_disruption_risk",
            "classification_mishandling",
            "inter_agency_gaps",
        ],
        "evidence_required": [
            "gov_system_inventory",
            "data_classification_policy",
            "continuity_plans",
            "classification_handling_procedures",
            "inter_agency_mous",
        ],
        "references": ["NCSP 2080 Section 6", "Government Security Guidelines", "Data Protection Act"],
    },
    "NCSP-ENERGY-001": {
        "title": "Energy Sector Cyber Resilience",
        "description": (
            "Power grid protection, SCADA/ICS security, smart meter privacy, cascade failure prevention"
        ),
        "policy": "NCSP 2080",
        "section": "6.4",
        "category": "energy_resilience",
        "severity": "critical",
        "detection": [
            "scada_exposure",
            "ics_vulnerabilities",
            "smart_meter_privacy",
            "grid_cascade_risk",
            "substation_security",
        ],
        "evidence_required": [
            "scada_network_diagram",
            "ics_security_assessment",
            "smart_meter_privacy_impact",
            "cascade_analysis",
            "physical_security_review",
        ],
        "references": ["NCSP 2080 Section 6", "IEC 62443", "NERC CIP", "Energy Sector Guidelines"],
    },
}

# ─── Combined NCSP Mappings ───
NCSP_MAPPINGS: dict[str, dict[str, Any]] = {}
NCSP_MAPPINGS.update(NCSP_CONTROLS)
NCSP_MAPPINGS.update(NCSP_SECTOR_CONTROLS)

# ─── Finding Category to NCSP Control Mapping ───
NCSP_CATEGORY_MAPPING: dict[str, list[str]] = {
    # CERT Coordination
    "no_cert_integration": ["NCSP-2080-01"],
    "missing_threat_intel": ["NCSP-2080-01"],
    "uncoordinated_response": ["NCSP-2080-01"],
    "no_cert_reporting": ["NCSP-2080-01"],
    "missing_exercise_participation": ["NCSP-2080-01"],
    # CII Protection
    "missing_cii_id": ["NCSP-2080-02"],
    "protection_gaps": ["NCSP-2080-02"],
    "untested_resilience": ["NCSP-2080-02"],
    "interdependency_unmapped": ["NCSP-2080-02"],
    "scada_exposure": ["NCSP-2080-02", "NCSP-ENERGY-001"],
    "ics_protocol_exposure": ["NCSP-2080-02"],
    "unidentified_cii": ["NCSP-2080-02"],
    "missing_protection": ["NCSP-2080-02"],
    "unreported_incidents": ["NCSP-2080-02"],
    "supply_chain_risk": ["NCSP-2080-02", "NCSP-2080-04"],
    # Data Sovereignty
    "data_offshore": ["NCSP-2080-03"],
    "uncontrolled_transfer": ["NCSP-2080-03"],
    "missing_dpa": ["NCSP-2080-03"],
    "cross_border_transfer": ["NCSP-2080-03"],
    "pii_exposure": ["NCSP-2080-03", "NCSP-2080-05"],
    "credential_leak": ["NCSP-2080-03", "NCSP-2080-05"],
    "encryption_absent": ["NCSP-2080-03", "NCSP-2080-05"],
    # Secure Development
    "no_sast": ["NCSP-2080-04"],
    "no_dast": ["NCSP-2080-04"],
    "dependency_vulnerabilities": ["NCSP-2080-04"],
    "insecure_cicd": ["NCSP-2080-04"],
    "missing_sbom": ["NCSP-2080-04"],
    "insecure_coding": ["NCSP-2080-04"],
    "missing_code_review": ["NCSP-2080-04"],
    "hardcoded_secrets": ["NCSP-2080-04"],
    "malicious_package": ["NCSP-2080-04"],
    # Identity & Trust
    "weak_auth": ["NCSP-2080-05"],
    "no_pki": ["NCSP-2080-05"],
    "certificate_misuse": ["NCSP-2080-05"],
    "missing_ztna": ["NCSP-2080-05"],
    "missing_mfa": ["NCSP-2080-05"],
    "auth_bypass": ["NCSP-2080-05"],
    "session_hijack": ["NCSP-2080-05"],
    "certificate_issues": ["NCSP-2080-05"],
    # Workforce
    "uncertified_staff": ["NCSP-2080-06"],
    "missing_training": ["NCSP-2080-06"],
    "low_awareness": ["NCSP-2080-06"],
    "skill_gaps": ["NCSP-2080-06"],
    "no_certification_path": ["NCSP-2080-06"],
    # Legal Compliance
    "eta_noncompliance": ["NCSP-2080-07"],
    "evidence_spoilation": ["NCSP-2080-07"],
    "unreported_cybercrime": ["NCSP-2080-07"],
    "missing_audit_trail": ["NCSP-2080-07"],
    "chain_of_custody_break": ["NCSP-2080-07"],
    "data_retention_violation": ["NCSP-2080-07"],
    # Governance
    "no_cyber_strategy": ["NCSP-2080-08"],
    "missing_risk_framework": ["NCSP-2080-08"],
    "no_metrics_reporting": ["NCSP-2080-08"],
    "governance_gaps": ["NCSP-2080-08"],
    "board_oversight_missing": ["NCSP-2080-08"],
    # International Cooperation
    "no_international_mou": ["NCSP-2080-09"],
    "missing_mlat": ["NCSP-2080-09"],
    "no_threat_sharing": ["NCSP-2080-09"],
    "no_joint_exercises": ["NCSP-2080-09"],
    # Sector Resilience
    "banking_resilience_gaps": ["NCSP-2080-10", "NCSP-BANK-001"],
    "telecom_resilience_gaps": ["NCSP-2080-10", "NCSP-TELCO-001"],
    "gov_resilience_gaps": ["NCSP-2080-10", "NCSP-GOV-001"],
    "energy_resilience_gaps": ["NCSP-2080-10", "NCSP-ENERGY-001"],
    "health_resilience_gaps": ["NCSP-2080-10"],
    "no_sector_plan": ["NCSP-2080-10"],
    # Banking Sector
    "transaction_fraud": ["NCSP-BANK-001"],
    "core_banking_exposure": ["NCSP-BANK-001"],
    "swift_vulnerabilities": ["NCSP-BANK-001"],
    "atm_security_gaps": ["NCSP-BANK-001"],
    "mobile_banking_weakness": ["NCSP-BANK-001"],
    "card_data_exposure": ["NCSP-BANK-001"],
    # Telecom Sector
    "signaling_vulnerabilities": ["NCSP-TELCO-001"],
    "subscriber_data_leak": ["NCSP-TELCO-001"],
    "network_resilience_gaps": ["NCSP-TELCO-001"],
    "roaming_fraud": ["NCSP-TELCO-001"],
    "equipment_vulnerabilities": ["NCSP-TELCO-001"],
    # Government Sector
    "gov_system_exposure": ["NCSP-GOV-001"],
    "citizen_data_leak": ["NCSP-GOV-001"],
    "service_disruption_risk": ["NCSP-GOV-001"],
    "classification_mishandling": ["NCSP-GOV-001"],
    "inter_agency_gaps": ["NCSP-GOV-001"],
    # Energy Sector
    "ics_vulnerabilities": ["NCSP-ENERGY-001"],
    "smart_meter_privacy": ["NCSP-ENERGY-001"],
    "grid_cascade_risk": ["NCSP-ENERGY-001"],
    "substation_security": ["NCSP-ENERGY-001"],
}

# ─── Automated Check Functions ───


def check_cert_coordination(job_findings: list) -> dict[str, Any]:
    """Verify npCERT coordination compliance (NCSP-2080-01)."""
    cert_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "no_cert_integration",
            "missing_threat_intel",
            "uncoordinated_response",
            "no_cert_reporting",
            "missing_exercise_participation",
        )
    ]

    return {
        "control": "NCSP-2080-01",
        "description": "National CERT coordination (npCERT)",
        "status": "pass" if len(cert_findings) == 0 else "fail",
        "findings_count": len(cert_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in cert_findings
        ],
        "recommendation": (
            "Establish MOU with npCERT for threat intelligence sharing. "
            "Integrate npCERT threat feeds into SIEM. "
            "Participate in national cyber exercises (e.g., Cyber Drill). "
            "Define incident reporting procedures to npCERT within required timeframes. "
            "Maintain 24/7 contact points for coordinated response."
        ),
    }


def check_cii_protection(job_findings: list) -> dict[str, Any]:
    """Verify Critical Information Infrastructure protection compliance (NCSP-2080-02)."""
    cii_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "missing_cii_id",
            "protection_gaps",
            "untested_resilience",
            "interdependency_unmapped",
            "scada_exposure",
            "ics_protocol_exposure",
            "unidentified_cii",
            "missing_protection",
            "unreported_incidents",
            "supply_chain_risk",
        )
    ]

    return {
        "control": "NCSP-2080-02",
        "description": "Critical Information Infrastructure protection",
        "status": "pass" if len(cii_findings) == 0 else "fail",
        "findings_count": len(cii_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in cii_findings
        ],
        "recommendation": (
            "Maintain CII register with asset criticality ratings. "
            "Implement defense-in-depth for CII: network segmentation, air gaps where feasible. "
            "Conduct annual resilience testing (red team, tabletop, failover). "
            "Map interdependencies between CII sectors. "
            "Report CII incidents to npCERT within mandated timeframes."
        ),
    }


def check_data_sovereignty(job_findings: list) -> dict[str, Any]:
    """Verify data sovereignty and localization compliance (NCSP-2080-03)."""
    sovereignty_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "data_offshore",
            "uncontrolled_transfer",
            "missing_dpa",
            "cross_border_transfer",
            "pii_exposure",
            "credential_leak",
            "encryption_absent",
        )
    ]

    return {
        "control": "NCSP-2080-03",
        "description": "Data sovereignty and localization",
        "status": "pass" if len(sovereignty_findings) == 0 else "fail",
        "findings_count": len(sovereignty_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in sovereignty_findings
        ],
        "recommendation": (
            "Host critical data within Nepal's borders per NCSP 2080. "
            "Implement Data Processing Agreements (DPAs) for all cross-border transfers. "
            "Classify data and apply appropriate controls per classification. "
            "Encrypt sensitive data at rest (AES-256) and in transit (TLS 1.2+). "
            "Obtain regulatory approval for any required offshore processing."
        ),
    }


def check_secure_development(job_findings: list) -> dict[str, Any]:
    """Verify secure software development compliance (NCSP-2080-04)."""
    dev_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "no_sast",
            "no_dast",
            "dependency_vulnerabilities",
            "insecure_cicd",
            "missing_sbom",
            "insecure_coding",
            "missing_code_review",
            "hardcoded_secrets",
            "malicious_package",
        )
    ]

    return {
        "control": "NCSP-2080-04",
        "description": "Secure software development (DevSecOps)",
        "status": "pass" if len(dev_findings) == 0 else "fail",
        "findings_count": len(dev_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in dev_findings
        ],
        "recommendation": (
            "Implement DevSecOps pipeline: SAST, DAST, SCA, container scanning, secret scanning. "
            "Generate and maintain SBOM (SPDX/CycloneDX) for all releases. "
            "Enforce secure coding standards with automated linting. "
            "Require code review for all changes. Implement SLSA supply chain levels. "
            "Monitor for malicious packages and dependency confusion attacks."
        ),
    }


def check_identity_trust(job_findings: list) -> dict[str, Any]:
    """Verify identity and trust services compliance (NCSP-2080-05)."""
    identity_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "weak_auth",
            "no_pki",
            "certificate_misuse",
            "missing_ztna",
            "missing_mfa",
            "auth_bypass",
            "session_hijack",
            "certificate_issues",
        )
    ]

    return {
        "control": "NCSP-2080-05",
        "description": "Identity and trust services (PKI, ZTNA, e-KYC)",
        "status": "pass" if len(identity_findings) == 0 else "fail",
        "findings_count": len(identity_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in identity_findings
        ],
        "recommendation": (
            "Deploy National PKI for digital signatures and authentication. "
            "Implement Zero Trust Network Access (ZTNA) architecture. "
            "Integrate e-KYC for customer onboarding. "
            "Enforce MFA with phishing-resistant factors (FIDO2, passkeys). "
            "Monitor certificate lifecycle and automate renewal."
        ),
    }


def check_workforce_development(job_findings: list) -> dict[str, Any]:
    """Verify cybersecurity workforce development compliance (NCSP-2080-06)."""
    workforce_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "uncertified_staff",
            "missing_training",
            "low_awareness",
            "skill_gaps",
            "no_certification_path",
        )
    ]

    return {
        "control": "NCSP-2080-06",
        "description": "Cybersecurity workforce development",
        "status": "pass" if len(workforce_findings) == 0 else "fail",
        "findings_count": len(workforce_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in workforce_findings
        ],
        "recommendation": (
            "Maintain certified cybersecurity professionals (CISSP, CISM, CEH, OSCP). "
            "Implement role-based training program aligned with NICE framework. "
            "Conduct regular phishing simulations and awareness campaigns. "
            "Track skill gaps and create individual development plans. "
            "Establish certification career path with organizational support."
        ),
    }


def check_legal_compliance(job_findings: list) -> dict[str, Any]:
    """Verify legal and regulatory compliance (NCSP-2080-07)."""
    legal_findings = [
        f
        for f in job_findings
        if f.category
        in (
            "eta_noncompliance",
            "evidence_spoilation",
            "unreported_cybercrime",
            "missing_audit_trail",
            "chain_of_custody_break",
            "data_retention_violation",
        )
    ]

    return {
        "control": "NCSP-2080-07",
        "description": "Legal and regulatory compliance (ETA, Cybercrime Act)",
        "status": "pass" if len(legal_findings) == 0 else "fail",
        "findings_count": len(legal_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in legal_findings
        ],
        "recommendation": (
            "Ensure Electronic Transactions Act 2063 compliance for digital records. "
            "Implement tamper-evident audit trail with HMAC-SHA256 chaining. "
            "Report cybercrimes to Nepal Police Cyber Bureau within mandated timeframe. "
            "Maintain chain of custody for digital evidence. "
            "Enforce data retention policies per sectoral regulations."
        ),
    }


def check_sector_resilience(job_findings: list, sector: str | None = None) -> dict[str, Any]:
    """Verify sector-specific resilience compliance (NCSP-2080-10)."""
    sector_findings_map = {
        "banking": [
            "transaction_fraud",
            "core_banking_exposure",
            "swift_vulnerabilities",
            "atm_security_gaps",
            "mobile_banking_weakness",
            "card_data_exposure",
            "banking_resilience_gaps",
        ],
        "telecom": [
            "signaling_vulnerabilities",
            "subscriber_data_leak",
            "network_resilience_gaps",
            "roaming_fraud",
            "equipment_vulnerabilities",
            "telecom_resilience_gaps",
        ],
        "government": [
            "gov_system_exposure",
            "citizen_data_leak",
            "service_disruption_risk",
            "classification_mishandling",
            "inter_agency_gaps",
            "gov_resilience_gaps",
        ],
        "energy": [
            "scada_exposure",
            "ics_vulnerabilities",
            "smart_meter_privacy",
            "grid_cascade_risk",
            "substation_security",
            "energy_resilience_gaps",
        ],
    }

    sectors_to_check = [sector] if sector else list(sector_findings_map.keys())
    all_findings = []

    for sec in sectors_to_check:
        sec_findings = [f for f in job_findings if f.category in sector_findings_map.get(sec, [])]
        all_findings.extend(sec_findings)

    return {
        "control": "NCSP-2080-10",
        "description": f"Sector-specific cyber resilience ({', '.join(sectors_to_check)})",
        "status": "pass" if len(all_findings) == 0 else "fail",
        "findings_count": len(all_findings),
        "matched_findings": [
            {
                "fingerprint": f.fingerprint,
                "category": f.category,
                "title": f.title,
                "severity": f.severity,
                "evidence": f.evidence[:200],
            }
            for f in all_findings
        ],
        "recommendation": (
            "Develop and maintain sector-specific resilience plans per NCSP 2080 Section 6. "
            "Map interdependencies and conduct cascading failure scenario analysis. "
            "Define and test RTO/RPO for critical services. "
            "Establish mutual aid agreements with sector peers. "
            "Align with sectoral regulators (NRB, NTA, MoE, MoHA)."
        ),
    }


def run_all_ncsp_checks(job_findings: list, sector: str | None = None) -> list[dict[str, Any]]:
    """Run all NCSP automated compliance checks."""
    return [
        check_cert_coordination(job_findings),
        check_cii_protection(job_findings),
        check_data_sovereignty(job_findings),
        check_secure_development(job_findings),
        check_identity_trust(job_findings),
        check_workforce_development(job_findings),
        check_legal_compliance(job_findings),
        check_sector_resilience(job_findings, sector),
    ]


__all__ = [
    "NCSP_MAPPINGS",
    "NCSP_CONTROLS",
    "NCSP_SECTOR_CONTROLS",
    "NCSP_CATEGORY_MAPPING",
    "check_cert_coordination",
    "check_cii_protection",
    "check_data_sovereignty",
    "check_secure_development",
    "check_identity_trust",
    "check_workforce_development",
    "check_legal_compliance",
    "check_sector_resilience",
    "run_all_ncsp_checks",
]
