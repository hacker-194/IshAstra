"""Control Mapping Matrix: Strix Features → NRB/NTA/NCSP Controls.

Unified mapping matrix for all three Nepal regulatory frameworks.
Provides cross-framework traceability and automated compliance verification.
"""

from __future__ import annotations

from typing import Any

from strix.compliance.ncsp import NCSP_CATEGORY_MAPPING, NCSP_MAPPINGS
from strix.compliance.nrb import NRB_CATEGORY_MAPPING, NRB_MAPPINGS
from strix.compliance.nta import NTA_CATEGORY_MAPPING, NTA_MAPPINGS

# ─── Unified Control Registry ───
ALL_CONTROLS: dict[str, dict[str, Any]] = {}
ALL_CONTROLS.update(NRB_MAPPINGS)
ALL_CONTROLS.update(NTA_MAPPINGS)
ALL_CONTROLS.update(NCSP_MAPPINGS)

# ─── Unified Category Mapping ───
UNIFIED_CATEGORY_MAPPING: dict[str, dict[str, list[str]]] = {}

# Build unified mapping from all frameworks
for category, controls in NRB_CATEGORY_MAPPING.items():
    if category not in UNIFIED_CATEGORY_MAPPING:
        UNIFIED_CATEGORY_MAPPING[category] = {}
    UNIFIED_CATEGORY_MAPPING[category]["nrb"] = controls

for category, controls in NTA_CATEGORY_MAPPING.items():
    if category not in UNIFIED_CATEGORY_MAPPING:
        UNIFIED_CATEGORY_MAPPING[category] = {}
    UNIFIED_CATEGORY_MAPPING[category]["nta"] = controls

for category, controls in NCSP_CATEGORY_MAPPING.items():
    if category not in UNIFIED_CATEGORY_MAPPING:
        UNIFIED_CATEGORY_MAPPING[category] = {}
    UNIFIED_CATEGORY_MAPPING[category]["ncsp"] = controls


# ─── Framework Metadata ───
FRAMEWORK_METADATA: dict[str, dict[str, Any]] = {
    "nrb": {
        "name": "Nepal Rastra Bank",
        "full_name": "Nepal Rastra Bank Cybersecurity Directives",
        "directives": ["7/074", "8/075", "11/076"],
        "sector": "banking",
        "jurisdiction": "Nepal",
        "authority": "Nepal Rastra Bank",
        "control_count": len(NRB_MAPPINGS),
        "color": "#2e7d32",
        "description": (
            "Banking sector cybersecurity regulations covering information security policy, "
            "cyber resilience, and digital banking security"
        ),
    },
    "nta": {
        "name": "Nepal Telecommunications Authority",
        "full_name": "NTA Cybersecurity Byelaw 2078",
        "byelaw": "2078",
        "sector": "telecommunications",
        "jurisdiction": "Nepal",
        "authority": "Nepal Telecommunications Authority",
        "control_count": len(NTA_MAPPINGS),
        "color": "#1565c0",
        "description": (
            "Telecommunications sector cybersecurity regulations covering network security, "
            "signaling protection, and incident reporting"
        ),
    },
    "ncsp": {
        "name": "National Cyber Security Policy",
        "full_name": "National Cyber Security Policy 2080",
        "policy": "2080",
        "sector": "national_critical_infrastructure",
        "jurisdiction": "Nepal",
        "authority": "National Cyber Security Council / npCERT",
        "control_count": len(NCSP_MAPPINGS),
        "color": "#c2185b",
        "description": (
            "National policy for critical infrastructure protection, data sovereignty, "
            "secure development, and cyber resilience"
        ),
    },
}

# ─── Control Categories Across Frameworks ───
CONTROL_CATEGORIES: dict[str, dict[str, Any]] = {
    "governance": {
        "name": "Governance & Policy",
        "description": "Security policies, board oversight, risk management frameworks",
        "frameworks": ["nrb", "ncsp"],
        "controls": {
            "nrb": ["NRB-7.1"],
            "ncsp": ["NCSP-2080-08"],
        },
    },
    "network_security": {
        "name": "Network Security",
        "description": "Perimeter defense, segmentation, firewall management",
        "frameworks": ["nrb", "nta", "ncsp"],
        "controls": {
            "nrb": ["NRB-7.2", "NRB-8.1"],
            "nta": ["NTA-4.1"],
            "ncsp": ["NCSP-2080-02"],
        },
    },
    "encryption": {
        "name": "Encryption & Cryptography",
        "description": "Data protection at rest and in transit, key management",
        "frameworks": ["nrb", "nta", "ncsp"],
        "controls": {
            "nrb": ["NRB-7.2.3", "NRB-8.1.4"],
            "nta": ["NTA-4.2"],
            "ncsp": ["NCSP-2080-03", "NCSP-2080-05"],
        },
    },
    "access_control": {
        "name": "Access Control & Identity",
        "description": "RBAC, MFA, privileged access, session management",
        "frameworks": ["nrb", "nta", "ncsp"],
        "controls": {
            "nrb": ["NRB-7.3"],
            "nta": ["NTA-4.4"],
            "ncsp": ["NCSP-2080-05"],
        },
    },
    "application_security": {
        "name": "Application Security",
        "description": "Secure SDLC, vulnerability management, OWASP coverage",
        "frameworks": ["nrb", "nta", "ncsp"],
        "controls": {
            "nrb": ["NRB-7.4", "NRB-11.2"],
            "nta": ["NTA-4.3"],
            "ncsp": ["NCSP-2080-04"],
        },
    },
    "vulnerability_management": {
        "name": "Vulnerability Management",
        "description": "Continuous scanning, patch management, supply chain security",
        "frameworks": ["nrb", "nta", "ncsp"],
        "controls": {
            "nrb": ["NRB-7.5"],
            "nta": ["NTA-4.3"],
            "ncsp": ["NCSP-2080-04"],
        },
    },
    "monitoring_logging": {
        "name": "Security Monitoring & Logging",
        "description": "SIEM, log integrity, threat detection, audit trails",
        "frameworks": ["nrb", "nta", "ncsp"],
        "controls": {
            "nrb": ["NRB-8.3"],
            "nta": ["NTA-4.5"],
            "ncsp": ["NCSP-2080-07"],
        },
    },
    "incident_response": {
        "name": "Incident Response",
        "description": "IR planning, detection, containment, reporting, lessons learned",
        "frameworks": ["nrb", "nta", "ncsp"],
        "controls": {
            "nrb": ["NRB-8.4"],
            "nta": ["NTA-4.6"],
            "ncsp": ["NCSP-2080-01", "NCSP-2080-07"],
        },
    },
    "recovery_resilience": {
        "name": "Recovery & Resilience",
        "description": "Backup, DR, BCP, RTO/RPO, sector resilience",
        "frameworks": ["nrb", "nta", "ncsp"],
        "controls": {
            "nrb": ["NRB-8.5"],
            "nta": ["NTA-4.6"],
            "ncsp": ["NCSP-2080-02", "NCSP-2080-10"],
        },
    },
    "third_party_risk": {
        "name": "Third-Party & Supply Chain Risk",
        "description": "Vendor assessment, equipment certification, firmware integrity",
        "frameworks": ["nrb", "nta", "ncsp"],
        "controls": {
            "nrb": ["NRB-7.7"],
            "nta": ["NTA-4.7"],
            "ncsp": ["NCSP-2080-04"],
        },
    },
    "data_protection": {
        "name": "Data Protection & Privacy",
        "description": "PII protection, data sovereignty, localization, consent",
        "frameworks": ["nrb", "nta", "ncsp"],
        "controls": {
            "nrb": ["NRB-7.5"],
            "nta": ["NTA-4.2"],
            "ncsp": ["NCSP-2080-03"],
        },
    },
    "signaling_security": {
        "name": "Telecom Signaling Security",
        "description": "SS7, Diameter, GTP, 5G SBA protection",
        "frameworks": ["nta", "ncsp"],
        "controls": {
            "nta": ["NTA-SS7-001", "NTA-DIAMETER-001", "NTA-GTP-001", "NTA-5G-001"],
            "ncsp": ["NCSP-TELCO-001"],
        },
    },
    "sector_resilience": {
        "name": "Sector-Specific Resilience",
        "description": "Banking, telecom, government, energy sector requirements",
        "frameworks": ["ncsp"],
        "controls": {
            "ncsp": ["NCSP-BANK-001", "NCSP-TELCO-001", "NCSP-GOV-001", "NCSP-ENERGY-001"],
        },
    },
    "cert_coordination": {
        "name": "CERT Coordination",
        "description": "npCERT integration, threat sharing, coordinated response",
        "frameworks": ["ncsp"],
        "controls": {
            "ncsp": ["NCSP-2080-01"],
        },
    },
    "workforce": {
        "name": "Cybersecurity Workforce",
        "description": "Certifications, training, awareness, skill development",
        "frameworks": ["ncsp"],
        "controls": {
            "ncsp": ["NCSP-2080-06"],
        },
    },
    "legal_compliance": {
        "name": "Legal & Regulatory Compliance",
        "description": "ETA compliance, cybercrime reporting, evidence preservation",
        "frameworks": ["ncsp"],
        "controls": {
            "ncsp": ["NCSP-2080-07"],
        },
    },
    "international_cooperation": {
        "name": "International Cooperation",
        "description": "Cross-border collaboration, MLAT, joint exercises",
        "frameworks": ["ncsp"],
        "controls": {
            "ncsp": ["NCSP-2080-09"],
        },
    },
}


# ─── Strix Feature to Control Mapping ───
STRIX_FEATURE_MAPPING: dict[str, dict[str, Any]] = {
    "scope_enforcement": {
        "name": "Scope Enforcement & Authorization",
        "description": "Fail-closed scope validation, atomic reload, managed policies",
        "frameworks": {
            "nrb": ["NRB-7.1", "NRB-7.3", "NRB-8.1"],
            "nta": ["NTA-4.4", "NTA-4.1"],
            "ncsp": ["NCSP-2080-02", "NCSP-2080-07"],
        },
        "automated_checks": ["scope_validation", "authorization_verification"],
    },
    "audit_chain": {
        "name": "Tamper-Evident Audit Chain",
        "description": "HMAC-SHA256 chained audit log with integrity verification",
        "frameworks": {
            "nrb": ["NRB-8.3", "NRB-8.4"],
            "nta": ["NTA-4.5", "NTA-4.6"],
            "ncsp": ["NCSP-2080-07", "NCSP-2080-01"],
        },
        "automated_checks": ["audit_chain_integrity", "hmac_verification"],
    },
    "redaction": {
        "name": "Automated Redaction",
        "description": "PII/credential redaction at rest and in logs/SARIF",
        "frameworks": {
            "nrb": ["NRB-7.5"],
            "nta": ["NTA-4.2"],
            "ncsp": ["NCSP-2080-03", "NCSP-2080-07"],
        },
        "automated_checks": ["redaction_verification", "pii_detection"],
    },
    "evidence_packs": {
        "name": "Multi-Framework Evidence Packs",
        "description": "JSON/CSV/OSCAL/SARIF/PDF exports for NRB, NTA, NCSP",
        "frameworks": {
            "nrb": ["NRB-7.1", "NRB-8.4"],
            "nta": ["NTA-4.6"],
            "ncsp": ["NCSP-2080-07", "NCSP-2080-01"],
        },
        "automated_checks": ["evidence_pack_generation", "format_validation"],
    },
    "finding_lifecycle": {
        "name": "Finding Lifecycle Management",
        "description": "Triaged → Fix Verified workflow with SLA tracking",
        "frameworks": {
            "nrb": ["NRB-8.4"],
            "nta": ["NTA-4.6"],
            "ncsp": ["NCSP-2080-01", "NCSP-2080-07"],
        },
        "automated_checks": ["sla_tracking", "workflow_validation"],
    },
    "vulnerability_scanning": {
        "name": "Integrated Vulnerability Scanning",
        "description": "SAST, DAST, SCA, container, secret scanning",
        "frameworks": {
            "nrb": ["NRB-7.4", "NRB-7.5"],
            "nta": ["NTA-4.3"],
            "ncsp": ["NCSP-2080-04"],
        },
        "automated_checks": ["scan_coverage", "remediation_tracking"],
    },
    "tls_analysis": {
        "name": "TLS/SSL Configuration Analysis",
        "description": "Cipher suites, certificate validation, HSTS, protocol versions",
        "frameworks": {
            "nrb": ["NRB-7.2.3", "NRB-8.1.4"],
            "nta": ["NTA-4.2"],
            "ncsp": ["NCSP-2080-03", "NCSP-2080-05"],
        },
        "automated_checks": ["tls_version_check", "cipher_strength", "hsts_check"],
    },
    "header_analysis": {
        "name": "Security Header Analysis",
        "description": "CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy",
        "frameworks": {
            "nrb": ["NRB-7.2", "NRB-8.2"],
            "nta": ["NTA-4.2"],
            "ncsp": ["NCSP-2080-03"],
        },
        "automated_checks": ["header_completeness", "header_strength"],
    },
    "auth_testing": {
        "name": "Authentication & Authorization Testing",
        "description": "MFA bypass, session fixation, privilege escalation, IDOR, broken auth",
        "frameworks": {
            "nrb": ["NRB-7.3", "NRB-11.2"],
            "nta": ["NTA-4.4"],
            "ncsp": ["NCSP-2080-05"],
        },
        "automated_checks": ["mfa_check", "session_security", "auth_bypass_detection"],
    },
    "api_security": {
        "name": "API Security Testing",
        "description": "OWASP API Top 10: BOLA, broken auth, rate limiting, mass assignment",
        "frameworks": {
            "nrb": ["NRB-11.2"],
            "nta": ["NTA-4.3"],
            "ncsp": ["NCSP-2080-04"],
        },
        "automated_checks": ["api_enum", "authz_testing", "rate_limit_test"],
    },
    "mobile_testing": {
        "name": "Mobile Application Security",
        "description": "Certificate pinning, secure storage, anti-tamper, root detection",
        "frameworks": {
            "nrb": ["NRB-11.3"],
            "nta": ["NTA-4.7"],
            "ncsp": ["NCSP-2080-04"],
        },
        "automated_checks": ["pinning_check", "storage_encryption", "anti_tamper"],
    },
    "telecom_signaling": {
        "name": "Telecom Signaling Security",
        "description": "SS7, Diameter, GTP, 5G SBA vulnerability assessment",
        "frameworks": {
            "nta": ["NTA-SS7-001", "NTA-DIAMETER-001", "NTA-GTP-001", "NTA-5G-001"],
            "ncsp": ["NCSP-TELCO-001", "NCSP-2080-02"],
        },
        "automated_checks": ["signaling_scan", "protocol_fuzzing"],
    },
    "infrastructure_scanning": {
        "name": "Infrastructure & Network Scanning",
        "description": "Port scanning, service enumeration, banner grabbing, CVE matching",
        "frameworks": {
            "nrb": ["NRB-7.2", "NRB-8.1"],
            "nta": ["NTA-4.1"],
            "ncsp": ["NCSP-2080-02"],
        },
        "automated_checks": ["port_scan", "service_detection", "cve_matching"],
    },
    "cloud_configuration": {
        "name": "Cloud Configuration Review",
        "description": "AWS/Azure/GCP security posture, IAM, storage, networking",
        "frameworks": {
            "nrb": ["NRB-7.2", "NRB-7.3"],
            "nta": ["NTA-4.1", "NTA-4.2"],
            "ncsp": ["NCSP-2080-02", "NCSP-2080-03"],
        },
        "automated_checks": ["cis_benchmark", "iam_analysis", "storage_public_access"],
    },
    "compliance_scheduling": {
        "name": "Automated Compliance Scheduling",
        "description": "Quarterly/yearly evidence pack generation, trend reports, webhooks",
        "frameworks": {
            "nrb": ["NRB-7.1", "NRB-8.4"],
            "nta": ["NTA-4.6"],
            "ncsp": ["NCSP-2080-01", "NCSP-2080-07", "NCSP-2080-08"],
        },
        "automated_checks": ["schedule_execution", "report_generation"],
    },
    "retention_management": {
        "name": "Data Retention & Disposal",
        "description": "Configurable retention policies, encrypted backups, secure disposal",
        "frameworks": {
            "nrb": ["NRB-8.5"],
            "nta": ["NTA-4.5"],
            "ncsp": ["NCSP-2080-03", "NCSP-2080-07"],
        },
        "automated_checks": ["retention_enforcement", "backup_encryption"],
    },
    "bilingual_reporting": {
        "name": "Bilingual (EN/NE) Reporting",
        "description": "English and Nepali report templates with local date/currency formatting",
        "frameworks": {
            "nrb": ["NRB-7.1"],
            "nta": ["NTA-4.6"],
            "ncsp": ["NCSP-2080-07"],
        },
        "automated_checks": ["locale_rendering", "translation_completeness"],
    },
}

# ─── Cross-Framework Control Mapping ───
CROSS_FRAMEWORK_MAPPING: dict[str, list[str]] = {
    # NRB → NTA / NCSP
    "NRB-7.1": ["NTA-4.2", "NCSP-2080-08"],
    "NRB-7.2": ["NTA-4.1", "NTA-4.2", "NCSP-2080-02"],
    "NRB-7.2.3": ["NTA-4.2", "NCSP-2080-03", "NCSP-2080-05"],
    "NRB-7.3": ["NTA-4.4", "NCSP-2080-05"],
    "NRB-7.4": ["NTA-4.3", "NCSP-2080-04"],
    "NRB-7.5": ["NTA-4.3", "NTA-4.7", "NCSP-2080-04"],
    "NRB-8.1": ["NTA-4.1", "NCSP-2080-02"],
    "NRB-8.1.4": ["NTA-4.2", "NCSP-2080-03"],
    "NRB-8.2": ["NTA-4.2", "NTA-4.4", "NCSP-2080-05"],
    "NRB-8.3": ["NTA-4.5", "NCSP-2080-07"],
    "NRB-8.4": ["NTA-4.6", "NCSP-2080-01", "NCSP-2080-07"],
    "NRB-8.5": ["NTA-4.6", "NCSP-2080-02", "NCSP-2080-10"],
    "NRB-11.2": ["NTA-4.3", "NCSP-2080-04", "NCSP-BANK-001"],
    "NRB-11.3": ["NTA-4.7", "NCSP-2080-04"],
    "NRB-11.4": ["NTA-4.3", "NCSP-2080-04", "NCSP-BANK-001"],
    # NTA → NCSP
    "NTA-4.1": ["NCSP-2080-02"],
    "NTA-4.2": ["NCSP-2080-03", "NCSP-2080-05"],
    "NTA-4.3": ["NCSP-2080-04"],
    "NTA-4.4": ["NCSP-2080-05"],
    "NTA-4.5": ["NCSP-2080-07"],
    "NTA-4.6": ["NCSP-2080-01", "NCSP-2080-07"],
    "NTA-4.7": ["NCSP-2080-04"],
    "NTA-SS7-001": ["NCSP-TELCO-001", "NCSP-2080-02"],
    "NTA-DIAMETER-001": ["NCSP-TELCO-001", "NCSP-2080-02"],
    "NTA-GTP-001": ["NCSP-TELCO-001", "NCSP-2080-02"],
    "NTA-5G-001": ["NCSP-TELCO-001", "NCSP-2080-02"],
}


# ─── Helper Functions ───


def get_controls_for_framework(framework: str) -> dict[str, dict[str, Any]]:
    """Get all controls for a specific framework."""
    framework = framework.lower()
    if framework == "nrb":
        return NRB_MAPPINGS
    if framework == "nta":
        return NTA_MAPPINGS
    if framework == "ncsp":
        return NCSP_MAPPINGS
    return {}


def get_controls_for_category(category: str, framework: str | None = None) -> list[str]:
    """Get control IDs for a category, optionally filtered by framework."""
    if category not in UNIFIED_CATEGORY_MAPPING:
        return []

    if framework:
        framework = framework.lower()
        return UNIFIED_CATEGORY_MAPPING[category].get(framework, [])

    # Return all controls across frameworks
    all_controls = []
    for fw_controls in UNIFIED_CATEGORY_MAPPING[category].values():
        all_controls.extend(fw_controls)
    return all_controls


def get_frameworks_for_control(control_id: str) -> list[str]:
    """Get frameworks that a control belongs to."""
    control_id = control_id.upper()
    frameworks = []
    if control_id in NRB_MAPPINGS:
        frameworks.append("nrb")
    if control_id in NTA_MAPPINGS:
        frameworks.append("nta")
    if control_id in NCSP_MAPPINGS:
        frameworks.append("ncsp")
    return frameworks


def get_cross_framework_controls(control_id: str) -> list[str]:
    """Get equivalent controls in other frameworks."""
    control_id = control_id.upper()
    return CROSS_FRAMEWORK_MAPPING.get(control_id, [])


def get_strix_features_for_framework(framework: str) -> dict[str, dict[str, Any]]:
    """Get Strix features that map to a framework's controls."""
    framework = framework.lower()
    result = {}
    for feature_id, feature in STRIX_FEATURE_MAPPING.items():
        if framework in feature["frameworks"]:
            result[feature_id] = feature
    return result


def get_strix_features_for_control(control_id: str) -> list[str]:
    """Get Strix features that map to a specific control."""
    control_id = control_id.upper()
    features = []
    for feature_id, feature in STRIX_FEATURE_MAPPING.items():
        for controls in feature["frameworks"].values():
            if control_id in controls:
                features.append(feature_id)
                break
    return features


# ─── ScopeGate Control Matrix ───
# Each scope control names the requirement it satisfies and the code or test
# that proves it, so a report cites evidence instead of asserting compliance.
SCOPE_CONTROLS: dict[str, dict[str, Any]] = {
    "authorization_record": {
        "control": "An authorization record names who approved what",
        "soc2": ["CC6.1", "CC6.3"],
        "iso_27001": ["A.5.15", "A.5.18"],
        "evidence": "src/strix/core/scope.py Scope.__post_init__ (program, authorized_by, authorization_ref)",
    },
    "default_deny": {
        "control": "No target is contacted without an explicit allowlist entry",
        "soc2": ["CC6.1", "CC6.6"],
        "iso_27001": ["A.8.20", "A.8.22"],
        "evidence": "tests/unit/test_scope.py and tests/security/test_scope_gate_adversarial.py",
    },
    "signed_authorization": {
        "control": "Authorization is signed and verified against published keys",
        "soc2": ["CC6.1", "CC7.2"],
        "iso_27001": ["A.8.24", "A.5.17"],
        "evidence": "src/strix/core/scope_signing.py, tests/unit/test_scope_signing.py",
    },
    "revocation_and_freshness": {
        "control": "Authorization can be withdrawn and cannot be replayed after it expires",
        "soc2": ["CC6.3", "CC7.2"],
        "iso_27001": ["A.5.18", "A.8.16"],
        "evidence": "revoke_scope/is_valid + signed issued_at freshness, tests/unit/test_scope_signing.py",
    },
    "tenant_isolation": {
        "control": "A tenant's job is judged only against its own authorization",
        "soc2": ["CC6.1", "CC6.4"],
        "iso_27001": ["A.5.15", "A.8.3"],
        "evidence": "bound() in scope.py, tenant_scope_snapshot_async() in policies.py",
    },
    "denial_audit_trail": {
        "control": "Every refusal is recorded and countable",
        "soc2": ["CC7.2", "CC7.3"],
        "iso_27001": ["A.8.15", "A.8.16"],
        "evidence": "security_denied audit event, strix_scope_gate_decisions_total, test_scope_metrics.py",
    },
}


def get_scope_control_matrix() -> dict[str, Any]:
    """Scope controls with SOC 2 / ISO 27001 requirements and their evidence."""
    return {
        "controls": SCOPE_CONTROLS,
        "frameworks": {"soc2": "SOC 2 Trust Services Criteria", "iso_27001": "ISO/IEC 27001:2022"},
        "total": len(SCOPE_CONTROLS),
    }


def build_mapping_matrix(frameworks: list[str] | None = None) -> dict[str, Any]:
    """Build a complete mapping matrix for the given frameworks."""
    if frameworks is None:
        frameworks = ["nrb", "nta", "ncsp"]

    # Filter to only valid frameworks
    valid_frameworks = [fw for fw in frameworks if fw in FRAMEWORK_METADATA]

    matrix = {
        "metadata": {
            "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "frameworks": valid_frameworks,
            "requested_frameworks": frameworks,
            "total_controls": sum(FRAMEWORK_METADATA[fw]["control_count"] for fw in valid_frameworks),
        },
        "frameworks": {fw: FRAMEWORK_METADATA[fw] for fw in valid_frameworks},
        "categories": {},
        "controls": {},
        "strix_features": {},
        "scope_controls": SCOPE_CONTROLS,
        "cross_framework": {},
    }

    # Add categories
    for cat_id, cat in CONTROL_CATEGORIES.items():
        cat_frameworks = [fw for fw in cat["frameworks"] if fw in frameworks]
        if cat_frameworks:
            matrix["categories"][cat_id] = {
                **cat,
                "frameworks": cat_frameworks,
                "controls": {fw: cat["controls"].get(fw, []) for fw in cat_frameworks},
            }

    # Add controls
    for fw in frameworks:
        controls = get_controls_for_framework(fw)
        matrix["controls"][fw] = {
            control_id: {
                "title": control["title"],
                "category": control["category"],
                "severity": control["severity"],
                "description": control["description"],
                "detection": control["detection"],
                "evidence_required": control["evidence_required"],
                "references": control.get("references", []),
            }
            for control_id, control in controls.items()
        }

    # Add Strix features
    for feature_id, feature in STRIX_FEATURE_MAPPING.items():
        feature_frameworks = {fw: ctrls for fw, ctrls in feature["frameworks"].items() if fw in frameworks}
        if feature_frameworks:
            matrix["strix_features"][feature_id] = {
                "name": feature["name"],
                "description": feature["description"],
                "frameworks": feature_frameworks,
                "automated_checks": feature["automated_checks"],
            }

    # Add cross-framework mappings
    for ctrl_id, xfw_controls in CROSS_FRAMEWORK_MAPPING.items():
        source_fw = get_frameworks_for_control(ctrl_id)
        if not source_fw:
            continue
        if source_fw[0] not in frameworks:
            continue
        filtered = [c for c in xfw_controls if get_frameworks_for_control(c)[0] in frameworks]
        if filtered:
            matrix["cross_framework"][ctrl_id] = filtered

    return matrix


def export_mapping_matrix_csv(matrix: dict[str, Any]) -> str:
    """Export mapping matrix as CSV."""
    import csv
    from io import StringIO

    output = StringIO()
    writer = csv.writer(output)

    writer.writerow(
        [
            "Framework",
            "Control ID",
            "Control Title",
            "Category",
            "Severity",
            "Description",
            "Detection Categories",
            "Evidence Required",
            "References",
            "Strix Features",
            "Cross-Framework Equivalents",
        ]
    )

    for fw, controls in matrix.get("controls", {}).items():
        fw_meta = FRAMEWORK_METADATA.get(fw, {})
        fw_name = fw_meta.get("name", fw.upper())

        for control_id, control in controls.items():
            # Find Strix features for this control
            features = get_strix_features_for_control(control_id)
            cross_refs = get_cross_framework_controls(control_id)

            writer.writerow(
                [
                    fw_name,
                    control_id,
                    control["title"],
                    control["category"],
                    control["severity"],
                    control["description"],
                    "; ".join(control["detection"]),
                    "; ".join(control["evidence_required"]),
                    "; ".join(control.get("references", [])),
                    "; ".join(features),
                    "; ".join(cross_refs),
                ]
            )

    return output.getvalue()


__all__ = [
    "ALL_CONTROLS",
    "UNIFIED_CATEGORY_MAPPING",
    "FRAMEWORK_METADATA",
    "CONTROL_CATEGORIES",
    "STRIX_FEATURE_MAPPING",
    "CROSS_FRAMEWORK_MAPPING",
    "get_controls_for_framework",
    "get_controls_for_category",
    "get_frameworks_for_control",
    "get_cross_framework_controls",
    "get_strix_features_for_framework",
    "get_strix_features_for_control",
    "build_mapping_matrix",
    "export_mapping_matrix_csv",
]
