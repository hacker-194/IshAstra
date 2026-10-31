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

from strix import __version__
from strix.core.redaction import CREDENTIAL, redact  # noqa: F401  (re-exported)

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")
VERIFICATIONS = ("observed", "inferred", "unverified")
STATUSES = ("open", "resolved", "accepted", "false_positive")

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}
# CVSS-style bands, for consumers that sort on security-severity
_SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5",
                "low": "3.0", "info": "0.0"}


# redact() and CREDENTIAL are imported from strix.core.redaction above and
# re-exported here: every consumer of findings (store, audit, SARIF, tests)
# keeps its existing import path while the pattern set is centrally hardened.


@dataclass(frozen=True)
class Finding:
    """One normalized observation about one asset."""

    asset: str                  # url or host the finding is about
    category: str               # stable machine id, e.g. "sqli", "open_tcp_port"
    title: str
    severity: str               # what it would cost you
    confidence: str             # how sure the detector is
    detector: str               # adapter id that produced it
    detector_version: str
    evidence: str               # what was observed, reproducible
    location: str = ""          # url, host:port, file:line
    description: str = ""
    remediation: str = ""
    cwe: str = ""
    verification: str = "observed"
    status: str = "open"
    sources: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name, allowed in (("severity", SEVERITIES), ("confidence", CONFIDENCES),
                              ("verification", VERIFICATIONS), ("status", STATUSES)):
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
        basis = "\x1f".join((self.asset.strip().lower(), self.category,
                             self.location.strip().lower()))
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
            "sources": list(self.sources or (self.detector,)),
        }
        return redact(data)


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
        merged_sources = (*(current.sources or (current.detector,)),
                          *(item.sources or (item.detector,)))
        merged[item.fingerprint] = replace(
            winner, sources=tuple(dict.fromkeys(merged_sources)))
    return sorted(merged.values(),
                  key=lambda f: (SEVERITIES.index(f.severity), f.fingerprint))


def to_sarif(findings: Iterable[Finding], *, tool_version: str = __version__) -> dict[str, Any]:
    """SARIF 2.1.0 document (https://docs.oasis-open.org/sarif/sarif/v2.1.0/)."""
    items = list(findings)
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for finding in items:
        rule_id = finding.category
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": finding.title},
            "help": {"text": finding.remediation or "Review the evidence for this finding."},
            "properties": {
                "tags": ["security", finding.cwe] if finding.cwe else ["security"],
                "security-severity": _SARIF_SCORE[finding.severity],
            },
        })
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
        # Local code scanners store locations as relative-path:line. Convert
        # that notation to SARIF's artifactLocation + region schema. URL assets
        # and host:port exposure locations remain unchanged.
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
        "runs": [{
            "tool": {"driver": {
                "name": "strix",
                "informationUri": "https://github.com/usestrix/strix",
                "version": tool_version,
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {
                "severityCounts": {s: sum(1 for f in items if f.severity == s) for s in SEVERITIES},
            },
        }],
    }
