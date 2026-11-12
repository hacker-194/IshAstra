"""Normalized findings: validation, dedup, redaction, SARIF."""
import pytest

from strix.core.findings import Finding, dedupe, redact, to_sarif


def make(**overrides):
    base = dict(
        asset="http://app.example/",
        category="xss",
        title="Reflected XSS",
        severity="high",
        confidence="medium",
        detector="strix-http",
        detector_version="3.1.0",
        evidence="marker reflected verbatim for parameter q",
        location="http://app.example/?q",
        remediation="Encode output.",
        cwe="CWE-79",
    )
    base.update(overrides)
    return Finding(**base)


def test_invalid_severity_is_rejected():
    with pytest.raises(ValueError):
        make(severity="catastrophic")


def test_missing_evidence_is_rejected():
    with pytest.raises(ValueError):
        make(evidence="")


def test_fingerprint_ignores_severity_but_not_location():
    assert make(severity="low").fingerprint == make(severity="critical").fingerprint
    assert make().fingerprint != make(location="http://app.example/?id").fingerprint
    assert make().fingerprint != make(category="sqli").fingerprint


def test_duplicate_findings_merge_and_keep_both_sources():
    first = make(detector="strix-http", detector_version="3.1.0")
    second = make(detector="zap", detector_version="2.15", severity="critical",
                  confidence="high", evidence="alert 40018 fired for parameter q")
    merged = dedupe([first, second])
    assert len(merged) == 1
    assert merged[0].severity == "critical"          # keeps the more severe report
    assert set(merged[0].sources) == {"strix-http", "zap"}
    assert len({first.fingerprint, second.fingerprint}) == 1


def test_different_locations_stay_separate():
    assert len(dedupe([make(location="http://app.example/a"),
                       make(location="http://app.example/b")])) == 2


def test_redaction_keeps_ids_and_strips_credentials():
    payload = {"evidence": "found api_key=sk_live_abc123 in query",
               "category": "secret", "target": "http://monkey.com/?password=hunter2"}
    clean = redact(payload)
    assert "sk_live_abc123" not in str(clean)
    assert "hunter2" not in str(clean)
    assert clean["category"] == "secret"              # finding id survives
    assert "monkey.com" in clean["target"]            # hostname survives


def test_sarif_document_follows_the_spec_shape():
    document = to_sarif([make()], tool_version="3.1.0")
    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "strix"
    assert run["tool"]["driver"]["version"] == "3.1.0"
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["id"] == "xss"
    assert rule["properties"]["security-severity"] == "8.0"
    result = run["results"][0]
    assert result["ruleId"] == "xss"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "http://app.example/?q"
    assert result["properties"]["evidence"] == "marker reflected verbatim for parameter q"
    assert result["partialFingerprints"]["strixFinding/v1"] == make().fingerprint


def test_sarif_maps_code_locations_to_artifact_regions():
    item = make(asset="sample-repo", location="src/app.py:42", detector="semgrep")
    result = to_sarif([item])["runs"][0]["results"][0]
    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "src/app.py"
    assert physical["region"]["startLine"] == 42


def test_sarif_levels_track_severity():
    levels = {severity: to_sarif([make(severity=severity)])["runs"][0]["results"][0]["level"]
              for severity in ("critical", "high", "medium", "low", "info")}
    assert levels == {"critical": "error", "high": "error", "medium": "warning",
                      "low": "note", "info": "note"}


def test_to_dict_redacts_evidence_but_not_category():
    data = make(category="secret", evidence="token=abcd1234 present").to_dict()
    assert "abcd1234" not in data["evidence"]
    assert data["category"] == "secret"
