"""Import findings from external scanner formats into the internal Finding model."""

from __future__ import annotations

import contextlib
import json
import re
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ishastra.core.findings import Finding

# Severity mappings from external tools to internal model
SARIF_LEVEL_TO_SEVERITY = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}

NUCLEI_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

# ZAP numeric risk codes: 3=High, 2=Medium, 1=Low, 0=Informational
ZAP_RISKCODE_TO_SEVERITY = {
    "3": "high",
    "2": "medium",
    "1": "low",
    "0": "info",
}
ZAP_RISK_TO_SEVERITY = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
}


def _normalize_severity(value: str, mapping: dict[str, str]) -> str:
    """Normalize severity using a mapping, defaulting to info."""
    return mapping.get(value.lower(), "info")


def _normalize_confidence(value: str) -> str:
    """Normalize confidence to internal model."""
    value = value.lower()
    if value in ("high", "certain", "confirmed"):
        return "high"
    if value in ("medium", "tentative", "likely"):
        return "medium"
    return "low"


def _normalize_verification(value: str) -> str:
    """Normalize verification to internal model."""
    value = value.lower()
    if value in ("observed", "confirmed", "verified"):
        return "observed"
    if value in ("inferred", "deduced", "correlated"):
        return "inferred"
    return "unverified"


def _extract_cwe(tags: list[str] | None, message_text: str = "") -> str:
    """Extract CWE ID from tags or message."""
    if tags:
        for tag in tags:
            match = re.match(r"cwe[-\s]?(\d+)", tag, re.IGNORECASE)
            if match:
                return f"CWE-{match.group(1)}"
    # Try to extract from message
    match = re.search(r"CWE[-\s]?(\d+)", message_text, re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"
    return ""


def _parse_sarif_location(location: dict[str, Any]) -> tuple[str, str]:
    """Extract asset and location from SARIF physical location."""
    artifact = location.get("artifactLocation", {})
    uri = artifact.get("uri", "")
    region = location.get("region", {})
    start_line = region.get("startLine")
    if start_line:
        return uri, f"{uri}:{start_line}"
    return uri, uri


def import_sarif(file_path: str | Path) -> list[Finding]:
    """Import findings from a SARIF 2.1.0 file.

    Args:
        file_path: Path to the SARIF JSON file.

    Returns:
        List of normalized Finding objects.
    """
    path = Path(file_path)
    content = path.read_text()
    sarif = json.loads(content)

    findings: list[Finding] = []

    for run in sarif.get("runs", []):
        tool = run.get("tool", {}).get("driver", {})
        detector = tool.get("name", "sarif")
        detector_version = tool.get("version", "")

        rules = {rule["id"]: rule for rule in tool.get("rules", [])}

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})

            level = result.get("level", "warning")
            severity = _normalize_severity(level, SARIF_LEVEL_TO_SEVERITY)

            message = result.get("message", {}).get("text", "")
            title = rule.get("shortDescription", {}).get("text", rule_id)
            if not title:
                title = message[:100] if message else rule_id

            # Extract location
            asset = ""
            location = ""
            for loc in result.get("locations", []):
                physical = loc.get("physicalLocation", {})
                asset_uri, location_uri = _parse_sarif_location(physical)
                if asset_uri:
                    asset = asset_uri
                    location = location_uri
                    break

            # If no location, use rule ID as asset
            if not asset:
                asset = rule_id

            # Extract CWE from rule properties
            cwe = ""
            props = rule.get("properties", {})
            tags = props.get("tags", [])
            if tags:
                cwe = _extract_cwe(tags, message)

            # Evidence
            evidence = message or rule.get("help", {}).get("text", "")

            # Confidence and verification
            confidence = "medium"
            verification = "observed"
            partial_fingerprints = result.get("partialFingerprints", {})
            if "confidence" in partial_fingerprints:
                confidence = _normalize_confidence(partial_fingerprints["confidence"])
            if "verification" in partial_fingerprints:
                verification = _normalize_verification(partial_fingerprints["verification"])

            # Remediation
            remediation = rule.get("help", {}).get("text", "")

            # CVSS
            cvss_score = "0.0"
            if "security-severity" in props:
                with contextlib.suppress(ValueError, TypeError):
                    cvss_score = str(float(props["security-severity"]))

            finding = Finding(
                asset=asset,
                category=rule_id,
                title=title,
                severity=severity,
                confidence=confidence,
                detector=detector,
                detector_version=detector_version,
                evidence=evidence,
                location=location,
                description=message,
                remediation=remediation,
                cwe=cwe,
                cvss_score=cvss_score,
                verification=verification,
                sources=(detector,),
            )
            findings.append(finding)

    return findings


def import_nuclei(file_path: str | Path) -> list[Finding]:
    """Import findings from Nuclei JSONL output.

    Args:
        file_path: Path to the Nuclei JSONL output file.

    Returns:
        List of normalized Finding objects.
    """
    path = Path(file_path)
    findings: list[Finding] = []

    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Nuclei output structure
            template_id = data.get("template-id", data.get("templateID", ""))
            info = data.get("info", {})
            severity = _normalize_severity(info.get("severity", "info"), NUCLEI_SEVERITY_MAP)

            # Extract host/URL as asset
            host = data.get("host", "")
            matched = data.get("matched-at", data.get("matchedAt", ""))
            asset = host or matched

            # Location
            location = matched or host

            # Title from template name
            title = info.get("name", template_id)

            # Description
            description = info.get("description", "")

            # Tags for CWE
            tags = info.get("tags", [])
            cwe = _extract_cwe(tags, description)

            # Evidence
            evidence = data.get("extracted-results", data.get("extractedResults", []))
            if isinstance(evidence, list):
                evidence = "; ".join(str(e) for e in evidence)
            elif not evidence:
                evidence = data.get("curl-command", data.get("curlCommand", ""))
            if not evidence:
                evidence = f"Nuclei finding: {template_id} matched at {matched or host}"

            # Remediation
            remediation = info.get("remediation", info.get("reference", ""))

            # Detector info
            detector = "nuclei"
            detector_version = data.get("version", "")

            # Confidence based on severity
            confidence = "high" if severity in ("critical", "high") else "medium"

            finding = Finding(
                asset=asset,
                category=template_id,
                title=title,
                severity=severity,
                confidence=confidence,
                detector=detector,
                detector_version=detector_version,
                evidence=evidence,
                location=location,
                description=description,
                remediation=remediation,
                cwe=cwe,
                verification="observed",
                sources=(detector,),
            )
            findings.append(finding)

    return findings


def import_zap(file_path: str | Path) -> list[Finding]:
    """Import findings from ZAP JSON report.

    Args:
        file_path: Path to the ZAP JSON report file.

    Returns:
        List of normalized Finding objects.
    """
    path = Path(file_path)
    content = path.read_text()
    zap = json.loads(content)

    findings: list[Finding] = []

    # ZAP JSON structure has "site" array with "alerts"
    for site in zap.get("site", []):
        host = site.get("@host", site.get("host", ""))
        port = site.get("@port", site.get("port", ""))
        asset = f"{host}:{port}" if port else host

        for alert in site.get("alerts", []):
            # Risk level to severity - ZAP uses "risk" field (High/Medium/Low/Informational)
            # and numeric "riskcode" (3/2/1/0). Prefer the "risk" field.
            risk = alert.get("risk", alert.get("riskcode", "Informational"))
            severity = _normalize_severity(risk, ZAP_RISK_TO_SEVERITY)

            # Plugin ID as category
            plugin_id = alert.get("pluginid", alert.get("pluginId", ""))
            category = f"zap-{plugin_id}"

            # Title
            title = alert.get("name", alert.get("alert", "ZAP Finding"))

            # Description
            description = alert.get("desc", alert.get("description", ""))

            # Evidence - instances
            instances = alert.get("instances", [])
            evidence_parts = []
            location_parts = []
            for inst in instances:
                uri = inst.get("uri", "")
                method = inst.get("method", "")
                param = inst.get("param", "")
                evidence_parts.append(f"{method} {uri} (param: {param})")
                location_parts.append(uri)
            evidence = "; ".join(evidence_parts) if evidence_parts else description
            location = location_parts[0] if location_parts else asset

            # CWE
            cwe_id = alert.get("cweid", alert.get("cweId", ""))
            cwe = f"CWE-{cwe_id}" if cwe_id and cwe_id != "0" else ""

            # Remediation
            remediation = alert.get("solution", "") or alert.get("references", "")

            # Confidence
            confidence_map = {"high": "high", "medium": "medium", "low": "low"}
            confidence = confidence_map.get(alert.get("confidence", "").lower(), "medium")

            finding = Finding(
                asset=asset,
                category=category,
                title=title,
                severity=severity,
                confidence=confidence,
                detector="zap",
                detector_version=zap.get("@version", zap.get("version", "")),
                evidence=evidence,
                location=location,
                description=description,
                remediation=remediation,
                cwe=cwe,
                verification="observed",
                sources=("zap",),
            )
            findings.append(finding)

    return findings


def import_findings(
    file_path: str | Path,
    format: str,
    engagement: str = "",
    job: str = "",
) -> list[Finding]:
    """Import findings from a file in the specified format.

    Args:
        file_path: Path to the input file.
        format: One of "sarif", "nuclei", "zap".
        engagement: Optional engagement reference for metadata.
        job: Optional job ID for metadata.

    Returns:
        List of normalized Finding objects.
    """
    format = format.lower()
    if format == "sarif":
        findings = import_sarif(file_path)
    elif format == "nuclei":
        findings = import_nuclei(file_path)
    elif format == "zap":
        findings = import_zap(file_path)
    else:
        raise ValueError(f"Unsupported format: {format}. Use sarif, nuclei, or zap.")

    # Tag provenance; rebuild by position (Finding is frozen and duplicates
    # compare equal, so list.index() would tag the same finding twice).
    if engagement or job:
        extra: tuple[str, ...] = (f"engagement:{engagement}",) if engagement else ()
        extra += (f"job:{job}",) if job else ()
        stamp = datetime.now(UTC).isoformat()
        findings = [
            replace(
                f,
                sources=f.sources + extra,
                discovered_date=f.discovered_date or stamp,
                reported_date=f.reported_date or stamp,
            )
            for f in findings
        ]

    return findings
