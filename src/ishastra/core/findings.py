"""Normalized findings, evidence hygiene, and SARIF 2.1.0 export.

Severity, confidence and verification are separate axes on purpose: "port 6379 is
open" is an observed fact at high confidence, while its business risk is an
inference. Nothing here may invent evidence — an adapter reports what it saw.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Any

from ishastra import __version__
from ishastra.core.redaction import redact

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")
VERIFICATIONS = ("observed", "inferred", "unverified")


FINDING_STATES = (
    "new",
    "triaged",
    "in_progress",
    "fix_verified",
    "closed",
    "reopened",
    "deferred",
)

_VALID_TRANSITIONS = {
    "new": {"triaged", "deferred"},
    "triaged": {"in_progress", "deferred", "closed"},
    "in_progress": {"fix_verified", "reopened", "deferred"},
    "fix_verified": {"closed", "reopened"},
    "closed": set(),
    "reopened": {"in_progress", "fix_verified"},
    "deferred": {"triaged", "in_progress"},
}

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SARIF_SCORE = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "info": "0.0",
}


@dataclass(frozen=True)
class Finding:
    """One normalized observation about one asset."""

    asset: str
    category: str
    title: str
    severity: str
    confidence: str
    detector: str
    detector_version: str
    evidence: str
    location: str = ""
    description: str = ""
    remediation: str = ""

    cwe: str = ""
    cvss_score: str = "0.0"
    business_impact: str = "low"
    asset_criticality: str = "medium"
    risk_rating: str = "low"
    exploit_available: bool = False
    user_impact: str = "none"
    compliance_refs: tuple[str, ...] = ()
    remediation_status: str = "pending"
    discovered_date: str = ""
    reported_date: str = ""
    resolved_date: str = ""
    verification: str = "observed"
    status: str = "new"
    sources: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name, allowed in (
            ("severity", SEVERITIES),
            ("confidence", CONFIDENCES),
            ("verification", VERIFICATIONS),
            ("status", FINDING_STATES),
        ):
            value = getattr(self, name)
            if value not in allowed:
                raise ValueError(f"{name}={value!r} must be one of {allowed}")
        if not self.category or not self.title or not self.evidence:
            raise ValueError("category, title and evidence are required")

    @property
    def fingerprint(self) -> str:
        """Identity of the underlying issue: asset + category + location.

        Deliberately excludes severity/confidence so the same issue reported by
        two tools merges, while the same category on a different location does not.
        """
        basis = "\x1f".join((self.asset.strip().lower(), self.category, self.location.strip().lower()))
        return hashlib.sha256(basis.encode()).hexdigest()[:32]

    def to_dict(self) -> dict[str, Any]:
        data = {
            "fingerprint": self.fingerprint,
            "asset": self.asset,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "verification": self.verification,
            "status": self.status,
            "detector": self.detector,
            "detector_version": self.detector_version,
            "location": self.location,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "cvss_score": self.cvss_score,
            "business_impact": self.business_impact,
            "asset_criticality": self.asset_criticality,
            "risk_rating": self.risk_rating,
            "exploit_available": self.exploit_available,
            "user_impact": self.user_impact,
            "compliance_refs": list(self.compliance_refs),
            "remediation_status": self.remediation_status,
            "discovered_date": self.discovered_date,
            "reported_date": self.reported_date,
            "resolved_date": self.resolved_date,
            "sources": list(self.sources or (self.detector,)),
        }
        return redact(data)


SLA_DAYS: dict[str, int] = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
    "info": 365,
}


SLA_DUE_SOON_SECONDS = 7 * 86400.0

SEVERITY_RANK: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def sla_due_at(severity: str, first_seen: float, *, days: int | None = None) -> float:
    """Unix timestamp by which a ``severity`` finding must be remediated."""
    window = days if days is not None else SLA_DAYS.get(severity, SLA_DAYS["medium"])
    return first_seen + window * 86400.0


def sla_status(due_at: float | None, now: float, *, resolved: bool = False) -> str:
    """``resolved`` | ``none`` | ``overdue`` | ``due_soon`` | ``on_track``.

    ``now`` is a parameter rather than a clock read so callers stay testable
    and one request judges every finding against the same instant.
    """
    if resolved:
        return "resolved"
    if due_at is None:
        return "none"
    if due_at <= now:
        return "overdue"
    if due_at - now <= SLA_DUE_SOON_SECONDS:
        return "due_soon"
    return "on_track"


def allowed_transitions(status: str) -> tuple[str, ...]:
    """Statuses this finding may move to from ``status`` (empty when closed)."""
    return tuple(sorted(_VALID_TRANSITIONS.get(status, set())))


def validate_transition(from_status: str, to_status: str) -> None:
    """Validate that a finding state transition is allowed.

    Uses the defensive security finding lifecycle (Week 1-2 from startup plan).
    Raises ValueError if the transition is invalid.
    """
    allowed = _VALID_TRANSITIONS.get(from_status)
    if allowed is None:
        raise ValueError(f"Unknown from-status: {from_status}")
    if to_status not in allowed:
        raise ValueError(
            f"Invalid transition: {from_status!r} → {to_status!r}. Allowed from {from_status}: {allowed}"
        )


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Merge findings that share a fingerprint, keeping the most severe one."""
    merged: dict[str, Finding] = {}
    for item in findings:
        current = merged.get(item.fingerprint)
        if current is None:
            merged[item.fingerprint] = item
            continue
        more_severe = SEVERITIES.index(item.severity) < SEVERITIES.index(current.severity)
        winner = item if more_severe else current
        merged_sources = (
            *(current.sources or (current.detector,)),
            *(item.sources or (item.detector,)),
        )
        merged[item.fingerprint] = replace(winner, sources=tuple(dict.fromkeys(merged_sources)))
    return sorted(merged.values(), key=lambda f: (SEVERITIES.index(f.severity), f.fingerprint))


def to_sarif(findings: Iterable[Finding], *, tool_version: str = __version__) -> dict[str, Any]:
    """SARIF 2.1.0 document (https://docs.oasis-open.org/sarif/sarif/v2.1.0/)."""
    items = list(findings)
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in items:
        rule_id = finding.category
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.remediation or "Review the evidence for this finding."},
                "properties": {
                    "tags": ["security", finding.cwe] if finding.cwe else ["security"],
                    "security-severity": _SARIF_SCORE[finding.severity],
                },
            },
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": redact(f"{finding.title}: {finding.evidence}")},
            "partialFingerprints": {"strixFinding/v1": finding.fingerprint},
            "properties": {
                "severity": finding.severity,
                "confidence": finding.confidence,
                "verification": finding.verification,
                "detector": finding.detector,
                "detectorVersion": finding.detector_version,
                "asset": finding.asset,
                "evidence": redact(finding.evidence),
            },
        }
        uri = finding.location or finding.asset
        line = None

        if "://" not in uri:
            match = re.match(r"^(.*):([1-9][0-9]*)$", uri)
            if match:
                uri, line = match.group(1), int(match.group(2))
        if uri:
            physical_location: dict[str, Any] = {
                "artifactLocation": {"uri": redact(uri)},
            }
            if line is not None:
                physical_location["region"] = {"startLine": line}
            result["locations"] = [{"physicalLocation": physical_location}]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ishastra",
                        "informationUri": "https://github.com/hacker-194/IshAstra",
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "severityCounts": {s: sum(1 for f in items if f.severity == s) for s in SEVERITIES},
                },
            }
        ],
    }


_COMPLIANCE_WEIGHTS: dict[str, int] = {
    "PCI-DSS": 10,
    "HIPAA": 9,
    "GDPR": 8,
    "ISO27001": 7,
    "SOC2": 6,
    "CCPA": 5,
    "NIST-CSF": 5,
    "FINRA": 6,
    "PCI": 10,
}


def compliance_weight(self) -> int:
    """Return the regulatory weight of this finding's compliance references.

    Used for prioritization: findings that affect regulated frameworks
    get higher remediation priority.

    Returns:
        Integer weight (higher = more critical for compliance).
        Defaults to 1 if no compliance refs are set.
    """
    total = 0
    for ref in self.compliance_refs or ():
        total += _COMPLIANCE_WEIGHTS.get(ref, 1)
    return total if total > 0 else 1


def compliance_gap_analysis(self) -> dict[str, Any]:
    """Analyze this finding's compliance gaps and requirements.

    Returns a structured analysis of which regulatory frameworks
    this finding impacts and the severity of the gap.

    Returns:
        Dictionary with framework, control_id, gap_severity, and remediation_priority.
    """
    frameworks: list[str] = list(self.compliance_refs or ())

    if not frameworks:
        return {
            "frameworks": [],
            "gap_severity": "none",
            "remediation_priority": "low",
            "description": "No compliance frameworks referenced",
        }

    severity_weight = {"critical": 10, "high": 7, "medium": 4, "low": 1}.get(self.severity, 1)
    criticality_weight = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1,
    }.get(self.asset_criticality, 1)

    combined = severity_weight * criticality_weight

    if combined >= 50 or self.exploit_available:
        gap_severity = "critical"
    elif combined >= 25:
        gap_severity = "high"
    elif combined >= 10:
        gap_severity = "medium"
    else:
        gap_severity = "low"

    priority = compliance_weight(self)
    priority = min(priority * 2, 100) if gap_severity in ("critical", "high") else min(priority, 50)

    return {
        "frameworks": frameworks,
        "gap_severity": gap_severity,
        "remediation_priority": "high" if priority > 70 else "medium" if priority > 30 else "low",
        "cwe": self.cwe,
        "cvss": self.cvss_score,
        "finding_title": self.title,
        "description": self.description,
    }


def regulatory_summary(findings: list[Finding]) -> dict[str, Any]:
    """Generate a regulatory compliance summary for a list of findings.

    Aggregates compliance coverage across all findings, showing which
    frameworks have the most gaps and the overall compliance posture.

    Args:
        findings: List of Findings to analyze.

    Returns:
        Dictionary with framework coverage, gap counts, and priority matrix.
    """
    framework_findings: dict[str, list[Finding]] = {}
    for f in findings:
        for ref in f.compliance_refs or ():
            framework_findings.setdefault(ref, []).append(f)

    framework_counts: dict[str, int] = {k: len(v) for k, v in framework_findings.items()}

    gap_severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        analysis = compliance_gap_analysis(f)
        gap_severity_counts[analysis["gap_severity"]] = (
            gap_severity_counts.get(analysis["gap_severity"], 0) + 1
        )

    total_frameworks = len(_COMPLIANCE_WEIGHTS)
    active_frameworks = len(framework_findings)
    coverage_percent = (active_frameworks / total_frameworks * 100) if total_frameworks else 0

    high_priority = [
        f.title for f in findings if f.risk_rating in ("high", "critical") and compliance_weight(f) > 5
    ]

    return {
        "total_frameworks": total_frameworks,
        "active_frameworks": active_frameworks,
        "coverage_percent": round(coverage_percent, 1),
        "framework_counts": framework_counts,
        "gap_severity_distribution": gap_severity_counts,
        "high_priority_findings": high_priority,
        "total_findings": len(findings),
    }
