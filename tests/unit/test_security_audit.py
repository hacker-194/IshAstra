"""An audit that skipped scanners must never report PASSED."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "security_audit.py"
_spec = importlib.util.spec_from_file_location("security_audit", _SCRIPT)
assert _spec is not None and _spec.loader is not None
security_audit = importlib.util.module_from_spec(_spec)
# The module must be registered before execution: dataclasses resolves
# ``cls.__module__`` through sys.modules while the script is still importing.
sys.modules[_spec.name] = security_audit
_spec.loader.exec_module(security_audit)


def _result(scanner: str, status: str) -> object:
    return security_audit.ScanResult(
        scanner=scanner,
        status=status,
        findings=[],
        summary={},
        duration_seconds=0.0,
    )


def test_missing_scanner_passes_the_report() -> None:
    """An audit that skipped scanners should still pass with warnings status."""
    results = [_result("bandit", "passed"), _result("semgrep", "error")]
    assert security_audit.unavailable_scanners(results) == ["semgrep"]
    report = security_audit.generate_report(results, Path("."), "json")
    assert '"overall_status": "warnings"' in report


def test_skipped_scanner_passes_the_report() -> None:
    """An audit with skipped scanners should still pass with warnings status."""
    results = [_result("pip-audit", "passed"), _result("trivy", "skipped")]
    assert security_audit.unavailable_scanners(results) == ["trivy"]
    markdown = security_audit.generate_report(results, Path("."), "markdown")
    assert "warnings" in markdown.lower()


def test_every_scanner_ran_and_clean_passes() -> None:
    results = [_result("bandit", "passed"), _result("pip-audit", "passed")]
    assert security_audit.unavailable_scanners(results) == []
    report = security_audit.generate_report(results, Path("."), "json")
    assert '"overall_status": "passed"' in report
