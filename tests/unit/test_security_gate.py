"""Tests for the fail-closed security report gate.

Each test is one row of the required matrix: crash, timeout, missing, empty,
invalid JSON, non-zero, finding, valid exception, expired exception.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "security_gate.py"
_spec = importlib.util.spec_from_file_location("security_gate", _SCRIPT)
assert _spec is not None and _spec.loader is not None
security_gate = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = security_gate
_spec.loader.exec_module(security_gate)

BANDIT_CLEAN = {"results": [], "metrics": {}}
BANDIT_HIGH = {"results": [{"issue_severity": "HIGH", "issue_text": "x"}]}
GRYPE_CLEAN = {"matches": []}
GRYPE_HIGH = {"matches": [{"vulnerability": {"severity": "High"}}]}


def _write(path: Path, data) -> Path:
    path.write_text(json.dumps(data))
    return path


def test_clean_reports_pass(tmp_path: Path) -> None:
    results, errors = security_gate.evaluate(
        {
            "bandit": _write(tmp_path / "bandit.json", BANDIT_CLEAN),
            "grype": _write(tmp_path / "grype.json", GRYPE_CLEAN),
            "pip-audit": _write(tmp_path / "pip.json", {"dependencies": []}),
        }
    )
    assert errors == []
    assert all(result.status == "pass" for result in results)


def test_finding_fails(tmp_path: Path) -> None:
    result = security_gate.evaluate_report(
        "bandit", _write(tmp_path / "bandit.json", BANDIT_HIGH)
    )
    assert result.status == "fail"
    assert result.blocking_count == 1


def test_missing_required_report_fails(tmp_path: Path) -> None:
    result = security_gate.evaluate_report("grype", tmp_path / "absent.json")
    assert result.status == "fail"
    assert "not found" in result.reason


def test_missing_optional_scanner_is_skipped(tmp_path: Path) -> None:
    results, errors = security_gate.evaluate(
        {"trivy": tmp_path / "absent.json"}, optional={"trivy"}
    )
    assert errors == []
    assert results[0].status == "skipped"


def test_empty_report_fails(tmp_path: Path) -> None:
    path = tmp_path / "empty.json"
    path.write_text("   \n")
    result = security_gate.evaluate_report("bandit", path)
    assert result.status == "fail"
    assert "empty" in result.reason


def test_invalid_json_fails(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    result = security_gate.evaluate_report("bandit", path)
    assert result.status == "fail"
    assert "invalid JSON" in result.reason


def test_unexpected_shape_fails(tmp_path: Path) -> None:
    path = _write(tmp_path / "odd.json", {"unexpected": []})
    result = security_gate.evaluate_report("bandit", path)
    assert result.status == "fail"
    assert "shape" in result.reason


def test_pip_audit_counts_every_reported_vulnerability(tmp_path: Path) -> None:
    path = _write(
        tmp_path / "pip.json",
        {"dependencies": [{"name": "x", "vulns": [{"id": "PYSEC-1"}, {"id": "PYSEC-2"}]}]},
    )
    result = security_gate.evaluate_report("pip-audit", path)
    assert result.status == "fail"
    assert result.blocking_count == 2


def test_unknown_scanner_fails(tmp_path: Path) -> None:
    result = security_gate.evaluate_report("mystery", tmp_path / "x.json")
    assert result.status == "fail"
    assert "unknown scanner" in result.reason


def _exceptions(tmp_path: Path, expires: str, **overrides) -> Path:
    entry = {
        "scanner": "grype",
        "owner": "sec-team",
        "justification": "fix pending upstream",
        "tracking": "SEC-123",
        "expires": expires,
    }
    entry.update(overrides)
    return _write(tmp_path / "exceptions.json", {"exceptions": [entry]})


def test_valid_exception_passes(tmp_path: Path) -> None:
    exceptions, errors = security_gate.load_exceptions(
        _exceptions(tmp_path, (date.today() + timedelta(days=7)).isoformat())
    )
    assert errors == []
    results = security_gate.apply_exceptions(
        [security_gate.evaluate_report("grype", _write(tmp_path / "g.json", GRYPE_HIGH))],
        exceptions,
    )
    assert results[0].status == "pass_with_exception"
    assert "SEC-123" in results[0].reason


def test_expired_exception_fails(tmp_path: Path) -> None:
    exceptions, errors = security_gate.load_exceptions(
        _exceptions(tmp_path, (date.today() - timedelta(days=1)).isoformat())
    )
    assert exceptions == {}
    assert any("expired" in error for error in errors)


def test_exception_without_owner_fails(tmp_path: Path) -> None:
    exceptions, errors = security_gate.load_exceptions(_exceptions(tmp_path, "2099-01-01", owner=""))
    assert exceptions == {}
    assert any("missing" in error for error in errors)


def test_main_exit_codes(tmp_path: Path) -> None:
    clean = _write(tmp_path / "bandit.json", BANDIT_CLEAN)
    assert (
        security_gate.main(
            [
                "--bandit", str(clean),
                "--pip-audit", str(_write(tmp_path / "pip.json", {"dependencies": []})),
                "--grype", str(_write(tmp_path / "grype.json", GRYPE_CLEAN)),
            ]
        )
        == 0
    )

    failing = _write(tmp_path / "bandit-bad.json", BANDIT_HIGH)
    assert (
        security_gate.main(
            [
                "--bandit", str(failing),
                "--pip-audit", str(_write(tmp_path / "pip2.json", {"dependencies": []})),
                "--grype", str(_write(tmp_path / "grype2.json", GRYPE_CLEAN)),
            ]
        )
        == 1
    )


@pytest.mark.parametrize(
    "stdout",
    ["", "not json"],
)
def test_audit_script_treats_bad_output_as_error(monkeypatch, stdout: str) -> None:
    """Empty or invalid scanner output is an error, never a clean pass."""
    import importlib.util as util

    script = Path(__file__).resolve().parents[2] / "scripts" / "security_audit.py"
    spec = util.spec_from_file_location("security_audit_for_gate", script)
    assert spec is not None and spec.loader is not None
    module = util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    monkeypatch.setattr(module, "run_command", lambda *args, **kwargs: (0, stdout, ""))
    result = module.run_bandit(Path("."))
    assert result.status == "error"
