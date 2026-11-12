"""Real Trivy binary integration for the code-scan SCA path.

The fixture-normalized tests in ``test_detection_expansion.py`` prove the
parser; this module proves the *pipeline*: a real manifest, the real trivy
binary, the local vulnerability database, and the normalized finding that
comes out the other end — plus the negative fixture (patched version ⇒ the
CVE must disappear).
"""
from __future__ import annotations

import shutil

import pytest

from strix.code_scan import scan_codebase

_VULNERABLE_LOCK = """{
  "name": "strix-trivy-lab",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "strix-trivy-lab", "version": "1.0.0",
         "dependencies": {"lodash": "4.17.20"}},
    "node_modules/lodash": {"version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
      "integrity": "sha512-PlhdFcillOINfeV7lwGRjLfZm6GrJv1EBZuYzUENiaMxQyB2gUzN2vp2"
                   "jGqxSmgJoxFmEzPGvmYsbDyZB4MeA=="}
  }
}
"""

_PATCHED_LOCK = _VULNERABLE_LOCK.replace("4.17.20", "4.17.21")


def _write_repo(tmp_path, lock: str):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package-lock.json").write_text(lock, encoding="utf-8")
    (repo / "app.js").write_text(
        "const _ = require('lodash');\nmodule.exports = _.clamp;\n",
        encoding="utf-8")
    return repo


@pytest.mark.skipif(shutil.which("trivy") is None,
                    reason="trivy binary not installed")
def test_real_trivy_reports_known_cve_with_normalized_fields(tmp_path):
    repo = _write_repo(tmp_path, _VULNERABLE_LOCK)
    report = scan_codebase(repo, timeout=180.0, enable_semgrep=False,
                           enable_bandit=False, enable_trivy=True)
    assert "trivy-fs" in report.tools_run
    lodash = [f for f in report.findings
              if f.detector == "trivy-fs" and f.category.startswith("sca_CVE-2021-23337")]
    assert lodash, f"CVE-2021-23337 missing from: {sorted(f.category for f in report.findings)}"
    finding = lodash[0]
    # Normalized, honest fields: pinned version named, fixed version named,
    # evidence points at the manifest inside the snapshot-relative layout.
    assert "lodash@4.17.20" in finding.evidence
    assert "fixed version" in finding.evidence
    assert finding.confidence == "high"
    assert finding.location == "package-lock.json"
    assert finding.remediation.startswith("Upgrade lodash")


@pytest.mark.skipif(shutil.which("trivy") is None,
                    reason="trivy binary not installed")
def test_real_trivy_patched_version_clears_the_cve(tmp_path):
    repo = _write_repo(tmp_path, _PATCHED_LOCK)
    report = scan_codebase(repo, timeout=180.0, enable_semgrep=False,
                           enable_bandit=False, enable_trivy=True)
    stale = [f for f in report.findings
             if f.detector == "trivy-fs" and "CVE-2021-23337" in f.category]
    assert not stale, "a patched dependency was still reported vulnerable"
