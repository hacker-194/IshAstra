"""Compliance evidence pack generation for Nepal regulatory frameworks.

Maps Strix findings to NRB (banking), NTA (telecom), NCSP (national cyber)
controls and produces auditor-ready evidence in multiple formats.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from io import StringIO
from typing import Any

from strix.core.findings import Finding

# ─── NRB (Nepal Rastra Bank) Directives Mappings ───
NRB_MAPPINGS: dict[str, dict[str, Any]] = {
    "NRB-DIR-001": {
        "title": "Information Security Policy",
        "description": "Bank must have a documented, board-approved information security policy",
        "category": "governance",
        "severity": "high",
        "detection": ["missing_security_policy", "outdated_policy"],
        "evidence_required": ["policy_document", "board_approval_record", "review_date"],
    },
    "NRB-DIR-002": {
        "title": "Access Control Management",
        "description": "Role-based access control, least privilege, regular access reviews",
        "category": "access_control",
        "severity": "high",
        "detection": [
            "excessive_privileges",
            "default_credentials",
            "missing_mfa",
            "orphaned_accounts",
            "weak_password_policy",
        ],
        "evidence_required": ["access_matrix", "review_logs", "mfa_enrollment", "password_policy"],
    },
    "NRB-DIR-003": {
        "title": "Network Security & Segmentation",
        "description": "Firewall rules, network segmentation, DMZ, intrusion detection",
        "category": "network_security",
        "severity": "high",
        "detection": [
            "open_management_ports",
            "missing_segmentation",
            "weak_firewall_rules",
            "unencrypted_admin",
            "exposed_database",
        ],
        "evidence_required": ["firewall_config", "network_diagram", "ids_alerts", "segmentation_proof"],
    },
    "NRB-DIR-004": {
        "title": "Application Security",
        "description": "Secure SDLC, code review, WAF, vulnerability management",
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
        ],
        "evidence_required": ["sast_report", "dast_report", "waf_logs", "patch_records"],
    },
    "NRB-DIR-005": {
        "title": "Data Protection & Encryption",
        "description": "Encryption at rest/transit, key management, data classification, PII protection",
        "category": "data_protection",
        "severity": "high",
        "detection": [
            "cleartext_transmission",
            "weak_tls",
            "unencrypted_storage",
            "pii_exposure",
            "weak_crypto",
            "certificate_issues",
        ],
        "evidence_required": ["tls_config", "encryption_audit", "key_management", "data_inventory"],
    },
    "NRB-DIR-006": {
        "title": "Security Monitoring & Incident Response",
        "description": "SIEM, log retention, incident response plan, threat intelligence",
        "category": "monitoring",
        "severity": "medium",
        "detection": [
            "missing_logging",
            "log_tampering",
            "no_siem",
            "slow_detection",
            "missing_ir_plan",
        ],
        "evidence_required": ["siem_config", "log_samples", "ir_plan", "drill_records", "retention_policy"],
    },
    "NRB-DIR-007": {
        "title": "Third-Party Risk Management",
        "description": "Vendor assessment, contract security clauses, ongoing monitoring",
        "category": "third_party",
        "severity": "medium",
        "detection": ["unassessed_vendors", "missing_contracts", "vendor_breach"],
        "evidence_required": ["vendor_register", "assessment_reports", "contracts", "monitoring_logs"],
    },
    "NRB-DIR-008": {
        "title": "Business Continuity & Disaster Recovery",
        "description": "BCP/DRP tested annually, RTO/RPO defined, backup integrity verified",
        "category": "resilience",
        "severity": "high",
        "detection": ["no_bcp", "untested_dr", "backup_failures", "missing_rto_rpo"],
        "evidence_required": ["bcp_document", "dr_test_results", "backup_logs", "rto_rpo_definition"],
    },
}

# ─── NTA (Nepal Telecommunications Authority) Bylaws Mappings ───
NTA_MAPPINGS: dict[str, dict[str, Any]] = {
    "NTA-BYL-001": {
        "title": "Network Infrastructure Security",
        "description": "Core network protection, signaling security, roaming fraud prevention",
        "category": "network_infrastructure",
        "severity": "critical",
        "detection": [
            "ss7_vulnerabilities",
            "diameter_vulnerabilities",
            "gtp_vulnerabilities",
            "signaling_exposure",
            "roaming_fraud_indicators",
        ],
        "evidence_required": ["signaling_firewall_config", "roaming_agreements", "fraud_monitoring"],
    },
    "NTA-BYL-002": {
        "title": "Subscriber Data Protection",
        "description": "CDR protection, location privacy, consent management, data localization",
        "category": "data_protection",
        "severity": "high",
        "detection": [
            "cdr_exposure",
            "location_leak",
            "consent_violation",
            "cross_border_transfer",
        ],
        "evidence_required": [
            "cdr_access_logs",
            "consent_records",
            "localization_proof",
            "encryption_config",
        ],
    },
    "NTA-BYL-003": {
        "title": "Critical Information Infrastructure Protection",
        "description": "CII identification, protection measures, incident reporting to NTA",
        "category": "critical_infrastructure",
        "severity": "critical",
        "detection": [
            "unidentified_cii",
            "missing_protection",
            "unreported_incidents",
            "supply_chain_risk",
        ],
        "evidence_required": [
            "cii_register",
            "protection_measures",
            "incident_reports",
            "supply_chain_audit",
        ],
    },
    "NTA-BYL-004": {
        "title": "Telecom Equipment Security",
        "description": "Equipment certification, firmware integrity, supply chain verification",
        "category": "equipment_security",
        "severity": "high",
        "detection": [
            "uncertified_equipment",
            "firmware_tampering",
            "default_credentials_equipment",
            "end_of_life_equipment",
        ],
        "evidence_required": ["certification_records", "firmware_hashes", "inventory", "eol_schedule"],
    },
    "NTA-BYL-005": {
        "title": "Cybersecurity Incident Reporting",
        "description": "Mandatory reporting within 4 hours, root cause analysis, remedial actions",
        "category": "incident_reporting",
        "severity": "high",
        "detection": ["late_reporting", "incomplete_rca", "missing_remediation"],
        "evidence_required": ["incident_log", "nta_notifications", "rca_reports", "remediation_tracking"],
    },
}

# ─── NCSP (National Cyber Security Policy 2080) Mappings ───
NCSP_MAPPINGS: dict[str, dict[str, Any]] = {
    "NCSP-2080-01": {
        "title": "National CERT Coordination",
        "description": "Integration with npCERT, threat intelligence sharing, coordinated response",
        "category": "cert_coordination",
        "severity": "high",
        "detection": ["no_cert_integration", "missing_threat_intel", "uncoordinated_response"],
        "evidence_required": ["cert_mou", "threat_feed_config", "exercise_participation"],
    },
    "NCSP-2080-02": {
        "title": "Critical Infrastructure Protection",
        "description": "Sectoral CII identification, protection standards, resilience testing",
        "category": "critical_infrastructure",
        "severity": "critical",
        "detection": [
            "missing_cii_id",
            "protection_gaps",
            "untested_resilience",
            "interdependency_unmapped",
        ],
        "evidence_required": ["cii_register", "protection_plan", "test_results", "dependency_map"],
    },
    "NCSP-2080-03": {
        "title": "Data Sovereignty & Localization",
        "description": "Critical data hosted in Nepal, cross-border transfer controls",
        "category": "data_sovereignty",
        "severity": "high",
        "detection": ["data_offshore", "uncontrolled_transfer", "missing_dpa"],
        "evidence_required": ["hosting_locations", "transfer_agreements", "dpa_records"],
    },
    "NCSP-2080-04": {
        "title": "Secure Software Development",
        "description": "DevSecOps adoption, secure coding standards, supply chain security",
        "category": "secure_development",
        "severity": "high",
        "detection": [
            "no_sast",
            "no_dast",
            "dependency_vulnerabilities",
            "insecure_cicd",
            "missing_sbom",
        ],
        "evidence_required": ["pipeline_config", "scan_reports", "sbom", "coding_standards"],
    },
    "NCSP-2080-05": {
        "title": "Identity & Trust Services",
        "description": "National PKI, digital signatures, e-KYC, zero trust architecture",
        "category": "identity_trust",
        "severity": "medium",
        "detection": ["weak_auth", "no_pki", "certificate_misuse", "missing_ztna"],
        "evidence_required": ["pki_config", "cert_inventory", "ztna_architecture", "ekyc_integration"],
    },
    "NCSP-2080-06": {
        "title": "Cybersecurity Workforce Development",
        "description": "Certified professionals, training programs, awareness campaigns",
        "category": "workforce",
        "severity": "medium",
        "detection": ["uncertified_staff", "missing_training", "low_awareness"],
        "evidence_required": ["certifications", "training_records", "awareness_metrics"],
    },
    "NCSP-2080-07": {
        "title": "Legal & Regulatory Compliance",
        "description": "Electronic Transactions Act compliance, cybercrime reporting, evidence preservation",
        "category": "legal_compliance",
        "severity": "high",
        "detection": [
            "eta_noncompliance",
            "evidence_spoilation",
            "unreported_cybercrime",
        ],
        "evidence_required": ["compliance_attestation", "evidence_chain", "police_reports"],
    },
}

ALL_MAPPINGS = {"nrb": NRB_MAPPINGS, "nta": NTA_MAPPINGS, "ncsp": NCSP_MAPPINGS}


def load_mappings(frameworks: list[str]) -> dict[str, dict[str, Any]]:
    """Load control mappings for the given frameworks."""
    result: dict[str, dict[str, Any]] = {}
    for fw in frameworks:
        fw_lower = fw.lower()
        if fw_lower in ALL_MAPPINGS:
            result.update(ALL_MAPPINGS[fw_lower])
    return result


# ─── Finding-to-Control Matching ───

CATEGORY_TO_DETECTIONS: dict[str, list[str]] = {
    "sqli": ["sqli"],
    "xss": ["xss"],
    "rce": ["rce"],
    "idor": ["idor"],
    "broken_auth": ["broken_auth", "weak_auth", "default_credentials"],
    "sensitive_data_exposure": [
        "sensitive_data_exposure",
        "pii_exposure",
        "cdr_exposure",
        "data_offshore",
    ],
    "xxe": ["xxe"],
    "ssrf": ["ssrf"],
    "csrf": ["csrf"],
    "open_redirect": ["open_redirect"],
    "open_tcp_port": ["open_management_ports", "exposed_database", "signaling_exposure"],
    "weak_tls": ["weak_tls", "cleartext_transmission", "unencrypted_admin", "certificate_issues"],
    "weak_crypto": ["weak_crypto"],
    "missing_mfa": ["missing_mfa", "missing_mfa", "weak_auth"],
    "default_credentials": ["default_credentials", "default_credentials_equipment"],
    "excessive_privileges": ["excessive_privileges"],
    "orphaned_accounts": ["orphaned_accounts"],
    "weak_password_policy": ["weak_password_policy"],
    "missing_segmentation": ["missing_segmentation"],
    "weak_firewall_rules": ["weak_firewall_rules"],
    "unencrypted_storage": ["unencrypted_storage"],
    "missing_logging": ["missing_logging"],
    "log_tampering": ["log_tampering"],
    "no_siem": ["no_siem"],
    "slow_detection": ["slow_detection"],
    "missing_ir_plan": ["missing_ir_plan"],
    "unassessed_vendors": ["unassessed_vendors", "supply_chain_risk"],
    "missing_contracts": ["missing_contracts"],
    "no_bcp": ["no_bcp"],
    "untested_dr": ["untested_dr", "untested_resilience"],
    "backup_failures": ["backup_failures"],
    "missing_rto_rpo": ["missing_rto_rpo"],
    "ss7_vulnerabilities": ["ss7_vulnerabilities"],
    "diameter_vulnerabilities": ["diameter_vulnerabilities"],
    "gtp_vulnerabilities": ["gtp_vulnerabilities"],
    "location_leak": ["location_leak"],
    "consent_violation": ["consent_violation"],
    "cross_border_transfer": ["cross_border_transfer", "uncontrolled_transfer"],
    "unidentified_cii": ["unidentified_cii", "missing_cii_id"],
    "missing_protection": ["missing_protection", "protection_gaps"],
    "unreported_incidents": ["unreported_incidents"],
    "uncertified_equipment": ["uncertified_equipment"],
    "firmware_tampering": ["firmware_tampering"],
    "end_of_life_equipment": ["end_of_life_equipment"],
    "late_reporting": ["late_reporting"],
    "incomplete_rca": ["incomplete_rca"],
    "missing_remediation": ["missing_remediation"],
    "no_cert_integration": ["no_cert_integration"],
    "missing_threat_intel": ["missing_threat_intel"],
    "uncoordinated_response": ["uncoordinated_response"],
    "interdependency_unmapped": ["interdependency_unmapped"],
    "data_offshore": ["data_offshore"],
    "uncontrolled_transfer": ["uncontrolled_transfer"],
    "missing_dpa": ["missing_dpa"],
    "no_sast": ["no_sast"],
    "no_dast": ["no_dast"],
    "dependency_vulnerabilities": ["dependency_vulnerabilities"],
    "insecure_cicd": ["insecure_cicd"],
    "missing_sbom": ["missing_sbom"],
    "no_pki": ["no_pki"],
    "certificate_misuse": ["certificate_misuse"],
    "missing_ztna": ["missing_ztna"],
    "uncertified_staff": ["uncertified_staff"],
    "missing_training": ["missing_training"],
    "low_awareness": ["low_awareness"],
    "eta_noncompliance": ["eta_noncompliance"],
    "evidence_spoilation": ["evidence_spoilation"],
    "unreported_cybercrime": ["unreported_cybercrime"],
}


def match_findings_to_controls(
    findings: list[Finding], mappings: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Match findings to controls. Returns control_id -> control_result."""
    control_results: dict[str, dict[str, Any]] = {}

    for control_id, control in mappings.items():
        control_results[control_id] = {
            "control_id": control_id,
            "title": control["title"],
            "category": control["category"],
            "severity": control["severity"],
            "description": control["description"],
            "status": "pass",
            "matched_findings": [],
            "evidence": [],
            "gaps": [],
        }

    for finding in findings:
        detections = CATEGORY_TO_DETECTIONS.get(finding.category, [])
        if not detections:
            detections = [finding.category]

        for control_id, control in mappings.items():
            control_detections = control.get("detection", [])
            for detection in detections:
                if detection in control_detections:
                    cr = control_results[control_id]
                    cr["status"] = "fail"
                    cr["matched_findings"].append(
                        {
                            "fingerprint": finding.fingerprint,
                            "category": finding.category,
                            "title": finding.title,
                            "severity": finding.severity,
                            "confidence": finding.confidence,
                            "evidence": finding.evidence,
                            "location": finding.location,
                        }
                    )
                    cr["gaps"].append(
                        f"{finding.category}: {finding.evidence[:100]}"
                    )
                    break

    return control_results


def build_evidence_pack(
    job: Any,
    mappings: dict[str, dict[str, Any]],
    include_passing: bool = False,
) -> dict[str, Any]:
    """Build the full evidence pack from job findings and control mappings."""
    control_results = match_findings_to_controls(job.findings, mappings)

    if not include_passing:
        control_results = {
            k: v for k, v in control_results.items() if v["status"] != "pass"
        }

    total_controls = len(mappings)
    failed_controls = len([c for c in control_results.values() if c["status"] == "fail"])
    passed_controls = total_controls - failed_controls
    total_findings = len(job.findings)

    by_framework: dict[str, dict[str, Any]] = {}
    for control_id, result in control_results.items():
        framework = control_id.split("-")[0].lower()
        if framework not in by_framework:
            by_framework[framework] = {"controls": [], "failed": 0, "total": 0}
        by_framework[framework]["controls"].append(result)
        by_framework[framework]["total"] += 1
        if result["status"] == "fail":
            by_framework[framework]["failed"] += 1

    by_category: dict[str, dict[str, Any]] = {}
    for result in control_results.values():
        cat = result["category"]
        if cat not in by_category:
            by_category[cat] = {"controls": [], "failed": 0, "total": 0}
        by_category[cat]["controls"].append(result)
        by_category[cat]["total"] += 1
        if result["status"] == "fail":
            by_category[cat]["failed"] += 1

    compliance_score = round(
        (passed_controls / total_controls * 100) if total_controls > 0 else 100, 1
    )

    pack = {
        "metadata": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "target": job.target,
            "profile": job.profile,
            "actor": job.actor,
            "job_id": job.id,
            "job_state": job.state.value,
            "job_verdict": job.verdict,
            "tool_version": "strix-evidence/1.0",
            "scope_program": job.policy.get("scope_program", ""),
            "scope_authorized_by": job.policy.get("scope_authorized_by", ""),
            "authorization_ref": job.policy.get("authorization_ref", ""),
        },
        "summary": {
            "total_controls_assessed": total_controls,
            "controls_with_gaps": failed_controls,
            "controls_passing": passed_controls,
            "total_findings": total_findings,
            "compliance_score": compliance_score,
        },
        "by_framework": by_framework,
        "by_category": by_category,
        "controls": list(control_results.values()),
        "findings": [f.to_dict() for f in job.findings],
    }
    pack["audit_chain"] = {
        "note": "This evidence pack references the Strix audit chain for "
        "tamper-evident verification. Run `strix audit verify` to validate "
        "the chain integrity."
    }
    return pack


# ─── Output Formatters ───

def to_csv(pack: dict[str, Any]) -> str:
    """Export evidence pack as CSV."""
    output = StringIO()
    writer = csv.writer(output)

    writer.writerow(
        [
            "Control ID",
            "Framework",
            "Title",
            "Category",
            "Severity",
            "Status",
            "Description",
            "Matched Findings Count",
            "Gap Details",
            "Evidence Required",
        ]
    )

    for control in pack.get("controls", []):
        framework = control["control_id"].split("-")[0].upper()
        fw_name = {"nrb": "NRB", "nta": "NTA", "ncsp": "NCSP"}.get(
            framework.lower(), framework
        )
        writer.writerow(
            [
                control["control_id"],
                fw_name,
                control["title"],
                control["category"],
                control["severity"],
                control["status"],
                control["description"],
                len(control["matched_findings"]),
                "; ".join(control["gaps"]) if control["gaps"] else "—",
                "; ".join(
                    ALL_MAPPINGS.get(framework.lower(), {})
                    .get(control["control_id"], {})
                    .get("evidence_required", [])
                ),
            ]
        )

    return output.getvalue()


def to_oscal(pack: dict[str, Any]) -> str:
    """Export evidence pack as OSCAL Assessment Results (JSON)."""
    oscal: dict[str, Any] = {
        "assessment-results": {
            "uuid": f"urn:uuid:{pack['metadata']['job_id']}",
            "metadata": {
                "title": f"Compliance Evidence Pack for {pack['metadata']['target']}",
                "published": pack["metadata"]["generated_at"],
                "version": "1.0",
                "oscal-version": "1.1.3",
                "roles": [
                    {
                        "id": "assessor",
                        "title": "Assessor",
                        "party-uuids": [pack["metadata"]["actor"]],
                    }
                ],
                "parties": [
                    {
                        "uuid": pack["metadata"]["actor"],
                        "type": "organization",
                        "name": pack["metadata"]["actor"],
                    }
                ],
            },
            "import-ap": {
                "href": f"#assessment-plan-{pack['metadata']['scope_program']}",
            },
            "results": [],
        }
    }

    for control in pack.get("controls", []):
        status_map = {
            "pass": "satisfied",
            "fail": "not-satisfied",
            "gap": "other",
        }
        finding_refs = [
            f"urn:uuid:{f['fingerprint']}" for f in control["matched_findings"]
        ]

        oscal["assessment-results"]["results"].append(
            {
                "title": control["title"],
                "description": control["description"],
                "status": status_map.get(control["status"], "other"),
                "evaluation": {
                    "controls": [
                        {
                            "control-id": control["control_id"],
                            "satisfied": control["status"] == "pass",
                            "finding-refs": finding_refs,
                            "remarks": (
                                "; ".join(control["gaps"])
                                if control["gaps"]
                                else "Control satisfied"
                            ),
                        }
                    ]
                },
            }
        )

    oscal["assessment-results"]["back-matter"] = {
        "resources": [
            {
                "uuid": f"urn:uuid:{f['fingerprint']}",
                "title": f["title"],
                "description": f["description"],
                "props": [
                    {"name": "severity", "value": f["severity"]},
                    {"name": "confidence", "value": f["confidence"]},
                    {"name": "category", "value": f["category"]},
                ],
            }
            for f in pack.get("findings", [])
        ]
    }

    return json.dumps(oscal, indent=2)


def printable_html(pack: dict[str, Any]) -> str:
    """Export a printable HTML report (open it and use Print to PDF)."""
    meta = pack["metadata"]
    summary = pack["summary"]

    # Build controls by framework HTML (no f-strings with loops)
    fw_tables = []
    for fw_key, fw_data in pack.get("by_framework", {}).items():
        fw_name = fw_key.upper()
        rows = []
        for control in fw_data["controls"]:
            status_class = "fail" if control["status"] == "fail" else "pass"
            sev_class = f"severity-{control['severity']}"
            gaps = "; ".join(control["gaps"]) if control["gaps"] else "—"
            rows.append(
                f"            <tr class=\"{status_class}\">"
                f"                <td>{control['control_id']}</td>"
                f"                <td>{control['title']}</td>"
                f"                <td>{control['category']}</td>"
                f"                <td class=\"{sev_class}\">{control['severity'].upper()}</td>"
                f"                <td class=\"status-{control['status']}\">{control['status'].upper()}</td>"
                f"                <td>{gaps}</td>"
                f"            </tr>"
            )
        rows_str = "\n".join(rows)
        fw_table = f"""    <h3><span class="framework-badge framework-{fw_key}">{fw_name}</span>
        {fw_data['failed']}/{fw_data['total']} Controls with Gaps</h3>
    <table>
        <thead>
            <tr>
                <th>Control ID</th>
                <th>Title</th>
                <th>Category</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Gaps</th>
            </tr>
        </thead>
        <tbody>
{rows_str}
        </tbody>
    </table>"""
        fw_tables.append(fw_table)

    # Build findings detail HTML
    findings_rows = []
    for finding in pack.get("findings", []):
        sev_class = f"severity-{finding['severity']}"
        findings_rows.append(
            f"        <tr>"
            f"            <td>{finding['fingerprint'][:16]}...</td>"
            f"            <td>{finding['category']}</td>"
            f"            <td>{finding['title']}</td>"
            f"            <td class=\"{sev_class}\">{finding['severity'].upper()}</td>"
            f"            <td>{finding['confidence'].upper()}</td>"
            f"            <td>{finding['location']}</td>"
            f"            <td><div class=\"finding-item\">"
            f"{finding['evidence'][:200]}"
            f"{'...' if len(finding['evidence']) > 200 else ''}</div></td>"
            f"        </tr>"
        )
    findings_str = "\n".join(findings_rows)

    html = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Compliance Evidence Pack - {target}</title>
    <style>
        body {{ font-family: 'DejaVu Sans', Arial, sans-serif; margin: 40px;
                line-height: 1.6; background: #fff; }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #16213e; padding-bottom: 10px;
               font-size: 24px; }}
        h2 {{ color: #16213e; border-bottom: 1px solid #0f3460; padding-bottom: 5px;
               margin-top: 30px; font-size: 18px; }}
        h3 {{ color: #0f3460; font-size: 14px; }}
        .metadata {{ background: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 30px; }}
        .metadata table {{ width: 100%; border-collapse: collapse; }}
        .metadata td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
        .metadata td:first-child {{ font-weight: bold; width: 30%; }}
        .summary {{ display: flex; gap: 20px; margin-bottom: 30px; flex-wrap: wrap; }}
        .stat-card {{ background: #1a1a2e; color: white; padding: 20px;
                      border-radius: 8px; min-width: 150px; flex: 1; text-align: center; }}
        .stat-card.fail {{ background: #e74c3c; }}
        .stat-card.pass {{ background: #27ae60; }}
        .stat-card.warn {{ background: #f39c12; }}
        .stat-value {{ font-size: 36px; font-weight: bold; }}
        .stat-label {{ font-size: 14px; opacity: 0.9; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #1a1a2e; color: white; font-size: 12px; }}
        tr.fail {{ background: #fdf2f2; }}
        tr.pass {{ background: #f0fdf4; }}
        .severity-critical {{ color: #c0392b; font-weight: bold; }}
        .severity-high {{ color: #e74c3c; font-weight: bold; }}
        .severity-medium {{ color: #f39c12; }}
        .severity-low {{ color: #3498db; }}
        .status-fail {{ color: #e74c3c; font-weight: bold; }}
        .status-pass {{ color: #27ae60; font-weight: bold; }}
        .framework-badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px;
                            font-size: 11px; font-weight: bold; margin-right: 8px; }}
        .framework-nrb {{ background: #e8f5e9; color: #2e7d32; }}
        .framework-nta {{ background: #e3f2fd; color: #1565c0; }}
        .framework-ncsp {{ background: #fce4ec; color: #c2185b; }}
        .finding-list {{ font-size: 13px; }}
        .finding-item {{ margin: 5px 0; padding: 8px; background: #fafafa; border-left: 3px solid #0f3460; }}
        .page-break {{ page-break-before: always; }}
        @media print {{ .no-print {{ display: none; }} }}
        .compliance-score {{ font-size: 48px; font-weight: bold; text-align: center; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>Compliance Evidence Pack</h1>        <div class="compliance-score {compliance_class}">
        {compliance_score}%
    </div>

    <div class="metadata">
        <table>
            <tr><td>Target</td><td>{target}</td></tr>
            <tr><td>Assessment Profile</td><td>{profile}</td></tr>
            <tr><td>Actor</td><td>{actor}</td></tr>
            <tr><td>Job ID</td><td>{job_id}</td></tr>
            <tr><td>Scope Program</td><td>{scope_program}</td></tr>
            <tr><td>Authorized By</td><td>{scope_authorized_by}</td></tr>
            <tr><td>Authorization Ref</td><td>{authorization_ref}</td></tr>
            <tr><td>Generated</td><td>{generated_at}</td></tr>
            <tr><td>Tool Version</td><td>{tool_version}</td></tr>
        </table>
    </div>

    <div class="summary">
        <div class="stat-card">
            <div class="stat-value">{total_controls_assessed}</div>
            <div class="stat-label">Total Controls</div>
        </div>
        <div class="stat-card {summary_class}">
            <div class="stat-value">{controls_passing}</div>
            <div class="stat-label">Controls Passing</div>
        </div>
        <div class="stat-card fail">
            <div class="stat-value">{controls_with_gaps}</div>
            <div class="stat-label">Controls with Gaps</div>
        </div>
        <div class="stat-card warn">
            <div class="stat-value">{total_findings}</div>
            <div class="stat-label">Total Findings</div>
        </div>
    </div>""".format(
        target=meta["target"],
        profile=meta["profile"],
        actor=meta["actor"],
        job_id=meta["job_id"],
        scope_program=meta["scope_program"],
        scope_authorized_by=meta["scope_authorized_by"],
        authorization_ref=meta["authorization_ref"],
        generated_at=meta["generated_at"],
        tool_version="strix-evidence/1.0",
        total_controls_assessed=summary["total_controls_assessed"],
        controls_passing=summary["controls_passing"],
        controls_with_gaps=summary["controls_with_gaps"],
        total_findings=summary["total_findings"],
        summary_class=(
            "fail"
            if summary["controls_with_gaps"] > summary["controls_passing"]
            else "pass"
        ),
        compliance_class=(
            "pass" if summary["compliance_score"] >= 80 else "fail"
        ),
        compliance_score=summary["compliance_score"],
    )

    html += "<div class='page-break'></div>"
    html += "<h2>Controls by Framework</h2>"

    for fw_table in fw_tables:
        html += fw_table

    html += "<div class='page-break'></div>"
    html += "<h2>Findings Detail</h2>"
    html += "<table>"
    html += "<thead>"
    html += "<tr>"
    html += "<th>Fingerprint</th>"
    html += "<th>Category</th>"
    html += "<th>Title</th>"
    html += "<th>Severity</th>"
    html += "<th>Confidence</th>"
    html += "<th>Location</th>"
    html += "<th>Evidence</th>"
    html += "</tr>"
    html += "</thead>"
    html += "<tbody>"
    html += findings_str
    html += "</tbody>"
    html += "</table>"

    html += "<div class='page-break no-print'></div>"
    html += "<h2>Audit Chain Verification</h2>"
    html += "<p>This evidence pack is backed by Strix's tamper-evident audit chain (HMAC-SHA256)."
    html += " To verify integrity, run: <code>strix audit verify</code></p>"
    html += "<p class='no-print'><small>Generated by Strix Evidence Pack Generator v1.0 |"
    html += " {generated_at}</small></p>".format(generated_at=meta["generated_at"])

    html += "</body>"
    html += "</html>"

    return html

# ─── Scope Template Functions ───


def list_scope_templates() -> list[str]:
    """List available Nepal sector scope templates."""
    return ["bank", "telco", "gov", "global"]


def get_scope_template(sector: str) -> dict | None:
    """Get a conservative scope template for the given sector.

    Templates deliberately authorize only a placeholder client domain and no
    networks: the old ISP-wide CIDRs and ``*.com.np`` / ``*.gov.np`` wildcards
    would have authorized millions of third-party hosts. Add the client's own
    hosts and CIDRs after the signed authorization letter names them.

    Sectors: bank (NRB), telco (NTA), gov (NCSP 2080), global.
    """
    common_exclude = [
        "test.%(base)s",
        "dev.%(base)s",
        "staging.%(base)s",
    ]

    if sector == "bank":
        return {
            "program": "NRB Bank Assessment (template)",
            "authorized_by": "REPLACE: client CISO / signer",
            "authorization_ref": "REPLACE: engagement-YYYY-NNN",
            "include": [
                "*.examplebank.com.np",
                "api.examplebank.com.np",
                "mobile.examplebank.com.np",
            ],
            "exclude": [p % {"base": "examplebank.com.np"} for p in common_exclude],
            "authorized_networks": [],
            "allowed_ports": [443, 80],
            "allow_broad_networks": False,
        }
    if sector == "telco":
        return {
            "program": "NTA Telecom Assessment (template)",
            "authorized_by": "REPLACE: client CISO / signer",
            "authorization_ref": "REPLACE: engagement-YYYY-NNN",
            "include": [
                "*.exampletelco.com.np",
                "sip.exampletelco.com.np",
            ],
            "exclude": [p % {"base": "exampletelco.com.np"} for p in common_exclude],
            "authorized_networks": [],
            "allowed_ports": [443, 5061],
            "allow_broad_networks": False,
        }
    if sector == "gov":
        return {
            "program": "NCSP 2080 Government Assessment (template)",
            "authorized_by": "REPLACE: authorized government officer",
            "authorization_ref": "REPLACE: engagement-YYYY-NNN",
            "include": ["*.example.gov.np"],
            "exclude": [p % {"base": "example.gov.np"} for p in common_exclude],
            "authorized_networks": [],
            "allowed_ports": [443],
            "allow_broad_networks": False,
        }
    if sector == "global":
        return {
            "program": "Global Assessment (template)",
            "authorized_by": "REPLACE: engagement signer",
            "authorization_ref": "REPLACE: engagement-YYYY-NNN",
            "include": ["*.example.com"],
            "exclude": [p % {"base": "example.com"} for p in common_exclude],
            "authorized_networks": [],
            "allowed_ports": [443, 80],
            "allow_broad_networks": False,
        }
    return None
