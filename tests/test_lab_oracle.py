"""Oracle-backed regression tests: the lab, the matcher and the real tools.

The oracle is the contract between the lab's fixed behavior and the
adapters' claimed behavior. These tests fail the suite the moment an
adapter starts over-claiming (wrong verification level), under-detecting
(a bait goes dark), or hallucinating (a negative route is flagged).
"""
from __future__ import annotations

import json
import shutil
from typing import Any

import pytest

from strix.core.adapters import ADAPTERS, NucleiAdapter
from strix.core.findings import Finding
from strix.lab import evaluate as lab_evaluate
from strix.lab.target import LabServer, LabTarget


# ---------------------------------------------------------------------------
# Oracle hygiene
# ---------------------------------------------------------------------------
def test_oracle_is_well_formed():
    oracle = lab_evaluate.load_oracle()
    assert oracle["oracle_version"].count(".") == 2
    cases = oracle["cases"]
    assert len({case["id"] for case in cases}) == len(cases)
    for case in cases:
        # A case may accept equivalent detectors (native or external tool).
        detectors = (case["detector"] if isinstance(case["detector"], list)
                     else [case["detector"]])
        assert detectors and all(detector in ADAPTERS for detector in detectors), case["id"]
        assert isinstance(case["expect"], bool)
        assert case["match"] in ("exact", "prefix", "any")
        allowed = set(case.get("allowed_verification") or [])
        assert allowed <= {"observed", "inferred", "unverified", "*"}, case["id"]
    positives = [c for c in cases if c["expect"]]
    negatives = [c for c in cases if not c["expect"]]
    assert positives, "an oracle without expectations is not an oracle"
    assert negatives, "an oracle without negative fixtures cannot measure false positives"


def test_lab_server_refuses_non_loopback_bind():
    with pytest.raises(ValueError):
        LabServer(("0.0.0.0", 0))


# ---------------------------------------------------------------------------
# Matcher unit tests (no server, no external tools)
# ---------------------------------------------------------------------------
def _finding(**overrides) -> Finding:
    base: dict[str, Any] = dict(
        asset="http://127.0.0.1:8000/", category="xss", title="t",
        severity="info", confidence="low", detector="strix-http",
        detector_version="test", evidence="e", location="",
        remediation="r", cwe="", verification="unverified", sources=())
    base.update(overrides)
    return Finding(**base)


def test_specific_positive_beats_generic_negative():
    """The git-config hit must satisfy P4, not be swallowed by the N4 catch-all."""
    oracle = lab_evaluate.load_oracle()
    finding = _finding(detector="nuclei", category="git-config",
                       location="http://127.0.0.1:8000/.git/config",
                       verification="observed", confidence="high")
    assigned, unmatched = lab_evaluate.match_findings([finding], oracle)
    assert assigned["P4-git-config-exposure"] == [finding]
    assert not unmatched
    assert not assigned["N4-nuclei-catchall"]


def test_generic_nuclei_hit_is_a_false_alarm():
    oracle = lab_evaluate.load_oracle()
    finding = _finding(detector="nuclei", category="some-other-template",
                       location="http://127.0.0.1:8000/admin",
                       verification="observed", confidence="high")
    assigned, unmatched = lab_evaluate.match_findings([finding], oracle)
    assert assigned["N4-nuclei-catchall"] == [finding]
    assert not unmatched


def test_host_level_nmap_finding_matches_p6():
    oracle = lab_evaluate.load_oracle()
    finding = _finding(detector="nmap", category="open_tcp_port",
                       asset="127.0.0.1", location="127.0.0.1:8000/tcp",
                       verification="observed", confidence="high")
    assigned, unmatched = lab_evaluate.match_findings([finding], oracle)
    assert assigned["P6-open-tcp-port"] == [finding]
    assert not unmatched


def test_missing_csp_instances_roll_up_under_p5():
    oracle = lab_evaluate.load_oracle()
    findings = [
        _finding(category="missing_csp", verification="observed",
                 location=f"http://127.0.0.1:8000{path}", asset=path)
        for path in ("/", "/search?q=term")
    ]
    assigned, unmatched = lab_evaluate.match_findings(findings, oracle)
    assert assigned["P5-missing-csp"] == findings
    assert not unmatched


def test_unmatched_findings_are_surfaced_not_discarded():
    oracle = lab_evaluate.load_oracle()
    finding = _finding(detector="strix-http", category="brand_new_category",
                       location="http://127.0.0.1:8000/search?q=term")
    assigned, unmatched = lab_evaluate.match_findings([finding], oracle)
    assert unmatched == [finding]
    assert all(not items for items in assigned.values())


def test_score_penalizes_false_alarm_and_violated_verification():
    oracle = lab_evaluate.load_oracle()
    # The reflection bait detected, but claiming 'confirmed' breaks the honesty
    # contract even though the category matched.
    finding = _finding(detector="strix-http", category="xss",
                       location="http://127.0.0.1:8000/search?q=term",
                       verification="observed", confidence="high")
    assigned, unmatched = lab_evaluate.match_findings([finding], oracle)
    metrics = lab_evaluate.score(assigned, len(unmatched), oracle)
    assert metrics["true_positives"] == 1
    assert metrics["verification_violations"], "observed must violate P1's unverified bound"


# ---------------------------------------------------------------------------
# Adapter-level oracle runs
# ---------------------------------------------------------------------------
def test_http_and_dynamic_adapters_satisfy_their_oracle_cases():
    """Fast subset: built-in adapters only, no external binary involved."""
    with LabTarget() as lab:
        run = lab_evaluate.run_evaluation(lab=lab, configure_scope=False,
                                          include_nuclei=False,
                                          include_nmap=False)
    assigned = run.assigned
    for case_id in ("P1-reflection-indicator", "P2-open-redirect-observed",
                    "P3-sqli-error-inferred", "P5-missing-csp"):
        assert assigned[case_id], f"{case_id} went dark"
    for case_id in ("N1-safe-no-reflection", "N1b-safe-has-csp",
                    "N2-login-fixed-redirect", "N3-item-no-db-error"):
        assert not assigned[case_id], f"{case_id} produced a false alarm"
    assert not run.metrics["verification_violations"]
    # verification bounds: redirect observed, sql error inferred, reflection unverified
    assert assigned["P2-open-redirect-observed"][0].verification == "observed"
    assert assigned["P3-sqli-error-inferred"][0].verification == "inferred"
    assert assigned["P1-reflection-indicator"][0].verification == "unverified"
    assert assigned["P1-reflection-indicator"][0].severity == "info"


@pytest.mark.skipif(shutil.which("nuclei") is None or shutil.which("nmap") is None,
                    reason="real nuclei/nmap binaries not installed")
def test_full_oracle_with_real_tools():
    """The full contract: every bait detected, every negative clean, with the
    real nuclei and nmap binaries on the production code paths."""
    with LabTarget() as lab:
        run = lab_evaluate.run_evaluation(lab=lab, configure_scope=False)
    metrics = run.metrics
    assert metrics["true_positives"] == metrics["total_positives"], run.human_summary()
    assert metrics["false_positives"] == 0, run.human_summary()
    assert metrics["false_negatives"] == 0
    assert metrics["precision"] == 1.0 and metrics["recall"] == 1.0
    assert not metrics["verification_violations"]
    assert not run.unmatched
    # real tool versions propagated into findings
    nuclei_findings = run.assigned["P4-git-config-exposure"]
    assert nuclei_findings, "nuclei missed the git-config bait"
    assert nuclei_findings[0].detector_version not in ("", "unknown", "0")


def test_missing_nuclei_is_covered_by_the_native_detector(monkeypatch):
    """Nuclei absent is no longer a detection gap: the native detector covers P4."""
    monkeypatch.setattr(NucleiAdapter, "available",
                        lambda self: (False, "nuclei not installed (test stub)"))
    with LabTarget() as lab:
        run = lab_evaluate.run_evaluation(lab=lab, configure_scope=False,
                                          include_nmap=False)
    assert any("nuclei skipped" in note for note in run.notes)
    assert run.detectors_unavailable["nuclei"]
    assert run.metrics["coverage_complete"] is True
    assert run.assigned["P4-git-config-exposure"]
    assert {f.detector for f in run.assigned["P4-git-config-exposure"]} == {"strix-git-exposure"}


def test_unavailable_detector_is_unmeasured_not_a_false_negative(monkeypatch):
    """When no detector can answer a case, it is unmeasured — never a miss."""
    from strix.core.adapters import GitExposureAdapter

    monkeypatch.setattr(NucleiAdapter, "available",
                        lambda self: (False, "nuclei not installed (test stub)"))
    monkeypatch.setattr(GitExposureAdapter, "available",
                        lambda self: (False, "native detector disabled for this test"))
    with LabTarget() as lab:
        run = lab_evaluate.run_evaluation(lab=lab, configure_scope=False,
                                          include_nmap=False)
    assert run.metrics["coverage_complete"] is False
    assert "P4-git-config-exposure" in run.metrics["unmeasured_cases"]
    assert run.metrics["false_negatives"] == 0      # nothing was missed...
    assert run.metrics["recall"] == 1.0             # ...because nothing was asked
    assert run.metrics["measured_positives"] < run.metrics["total_positives"]


def test_cli_refuses_an_incomplete_benchmark(monkeypatch, tmp_path):
    from strix.core.adapters import GitExposureAdapter

    monkeypatch.setattr(NucleiAdapter, "available",
                        lambda self: (False, "nuclei not installed (test stub)"))
    monkeypatch.setattr(GitExposureAdapter, "available",
                        lambda self: (False, "native detector disabled for this test"))
    report = tmp_path / "report.json"
    code = lab_evaluate.main(["--no-nmap", "--report", str(report)])
    assert code == 2                       # incomplete is not a pass
    assert report.exists()
    payload = json.loads(report.read_text())
    assert payload["metrics"]["coverage_complete"] is False
    assert payload["detectors_unavailable"]["nuclei"]
    assert "P4-git-config-exposure" in payload["metrics"]["unmeasured_cases"]


def test_cli_can_accept_a_partial_benchmark_explicitly(monkeypatch, tmp_path):
    from strix.core.adapters import GitExposureAdapter

    monkeypatch.setattr(NucleiAdapter, "available",
                        lambda self: (False, "nuclei not installed (test stub)"))
    monkeypatch.setattr(GitExposureAdapter, "available",
                        lambda self: (False, "native detector disabled for this test"))
    code = lab_evaluate.main(["--no-nmap", "--allow-unmeasured"])
    assert code == 0


def test_workflow_scan_runs_the_production_job_path():
    with LabTarget() as lab:
        run = lab_evaluate.run_evaluation(lab=lab, configure_scope=False,
                                          include_nuclei=False, include_nmap=False,
                                          workflow_profiles=("web",))
    assert run.workflows
    job = run.workflows[0]
    assert job["profile"] == "web"
    assert job["state"] == "completed"
    assert job["coverage"]["total"] >= 2          # strix-http + native git
    assert any("workflow web" in note for note in run.notes)
    # The orchestrated job found the same baits the adapter sweep did.
    assert run.assigned["P1-reflection-indicator"]
    assert run.assigned["P4-git-config-exposure"]
