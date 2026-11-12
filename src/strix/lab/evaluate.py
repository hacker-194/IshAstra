"""Oracle-based detection evaluation: run the real adapters against the lab and
score them against ``oracle.json`` -- production code paths only, the same
adapters, scope gate and tool boundary a real assessment uses.

Usage:
    python -m strix.lab [--report PATH] [--min-precision P] [--min-recall R]
                        [--no-nuclei] [--no-nmap] [--nuclei-subset SUB]

Exit status is 0 when the metrics meet the thresholds, 1 when they do not, 2
when the evaluation itself could not run. A run that cannot complete is never
counted as clean.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from strix.core import jobs, scope
from strix.core.adapter_base import AdapterNotApplicable
from strix.core.adapters import (
    Adapter,
    AdapterError,
    DynamicValidationAdapter,
    GitExposureAdapter,
    HTTPAdapter,
    NmapAdapter,
    NucleiAdapter,
    TCPPortAdapter,
)
from strix.core.findings import Finding
from strix.lab import target as lab_target

ORACLE_PATH = Path(__file__).with_name("oracle.json")

_HTTP_TARGETS = ("/", "/search?q=term", "/safe?q=hello")
_DYNAMIC_TARGETS = (
    "/redirect?to=https://example.com/",
    "/sqlerror?id=1",
    "/login?next=/dashboard",
    "/item?id=7",
)
_NUCLEI_TIMEOUT = 180.0
_NMAP_TIMEOUT = 60.0
_WORKFLOW_TIMEOUT = 180.0
_HTTP_TIMEOUT = 15.0
_DYNAMIC_TIMEOUT = 20.0
_NMAP_VERSION = re.compile(r"Nmap version (\S+)")


def load_oracle(path: Path | None = None) -> dict[str, Any]:
    with (path or ORACLE_PATH).open(encoding="utf-8") as handle:
        return json.load(handle)


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------
def _finding_path(finding: Finding) -> str | None:
    """Best-effort path of the finding's location (query stripped)."""
    for raw in (finding.location, finding.asset):
        if not raw or "://" not in raw:
            continue
        try:
            return urlparse(raw).path or "/"
        except ValueError:
            continue
    return None  # host-level finding (e.g. nmap port)


def _path_matches(case: dict[str, Any], finding_path: str | None) -> bool:
    mode = case.get("match", "exact")
    case_path = case.get("path", "")
    if mode == "any":
        return True
    if mode == "prefix":
        return finding_path is not None and finding_path.startswith(case_path)
    # exact: an empty case path only matches host-level findings
    if case_path == "":
        return finding_path is None
    return finding_path == case_path


def _as_tuple(value: Any) -> tuple[str, ...]:
    """A case field that may name one detector/category or several equivalents."""
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return (str(value),)


def case_detectors(case: dict[str, Any]) -> tuple[str, ...]:
    """Detector ids that could satisfy this case.

    An expectation is about the *behavior*, not the tool: an exposed git config
    is the same finding whether the native detector or nuclei reported it, so a
    case may accept either. Scoring then credits whichever actually ran.
    """
    return _as_tuple(case.get("detector"))


def _matches(finding: Finding, case: dict[str, Any]) -> bool:
    if finding.detector not in case_detectors(case):
        return False
    case_categories = _as_tuple(case.get("category", "*")) or ("*",)
    if "*" not in case_categories and finding.category not in case_categories:
        return False
    return _path_matches(case, _finding_path(finding))


def _specificity(case: dict[str, Any]) -> tuple[int, int]:
    mode = case.get("match", "exact")
    path_score = {"exact": 3, "prefix": 2, "any": 1}.get(mode, 0)
    categories = _as_tuple(case.get("category", "*")) or ("*",)
    category_score = 2 if "*" not in categories else 1
    return path_score, category_score


def match_findings(
    findings: list[Finding], oracle: dict[str, Any]
) -> tuple[dict[str, list[Finding]], list[Finding]]:
    """Assign each finding to its most specific oracle case.

    Returns ``{case_id: [findings]}`` and the findings no case claims.
    """
    cases = oracle.get("cases", [])
    assigned: dict[str, list[Finding]] = {case["id"]: [] for case in cases}
    unmatched: list[Finding] = []
    for finding in findings:
        candidates = [case for case in cases if _matches(finding, case)]
        if not candidates:
            unmatched.append(finding)
            continue
        best = max(candidates, key=_specificity)
        assigned[best["id"]].append(finding)
    return assigned, unmatched


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def score(
    assigned: dict[str, list[Finding]],
    unmatched_count: int,
    oracle: dict[str, Any],
    *,
    detectors_run: set[str] | None = None,
    detectors_unavailable: set[str] | None = None,
) -> dict[str, Any]:
    """Precision/recall against the oracle, with what was not measured called out.

    A positive case whose detector never ran is **unmeasured**, not a miss: a
    deployment without nuclei has not been shown to miss the git-config bait, it
    has not been asked. Counting it as a false negative would understate recall
    and, worse, would let a genuinely broken run look like a tool-installation
    problem. Counting it as a pass would be just as wrong, so it is reported
    separately and ``coverage_complete`` is false.

    ``detectors_run`` names the adapters that actually executed; when it is
    None every case is treated as measured (the historical behaviour, used by
    matcher-only unit tests).
    """
    cases = oracle.get("cases", [])
    positives = [c for c in cases if c.get("expect") is True]
    negatives = [c for c in cases if c.get("expect") is False]

    def measured(case: dict[str, Any]) -> bool:
        if detectors_run is None:
            return True
        return bool(set(case_detectors(case)) & detectors_run)

    measured_positives = [case for case in positives if measured(case)]
    unmeasured = [case["id"] for case in positives if not measured(case)]
    unmeasured_negatives = [
        case["id"]
        for case in negatives
        if detectors_run is not None and not measured(case)
    ]

    tp = sum(1 for case in measured_positives if assigned.get(case["id"]))
    fn = len(measured_positives) - tp
    # A negative case whose detector never ran also proves nothing, but it
    # cannot inflate precision either: it simply contributes no false positive.
    fp = sum(
        1
        for case in negatives
        if assigned.get(case["id"]) and case["id"] not in unmeasured_negatives
    )

    verification_violations: list[str] = []
    for case in measured_positives:
        allowed = set(case.get("allowed_verification") or [])
        if "*" in allowed:
            continue
        for finding in assigned.get(case["id"], []):
            if finding.verification not in allowed:
                verification_violations.append(
                    f"{case['id']}: {finding.category} claimed "
                    f"'{finding.verification}', oracle allows "
                    f"{sorted(allowed)}"
                )

    precision = (tp / (tp + fp)) if (tp + fp) else (1.0 if fn == 0 else 0.0)
    recall = (tp / (tp + fn)) if (tp + fn) else 1.0
    f1 = (
        (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    )
    fp_rate = (fp / len(negatives)) if negatives else 0.0
    return {
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "total_positives": len(positives),
        "measured_positives": len(measured_positives),
        "total_negatives": len(negatives),
        "precision": round(precision, 4),
        # recall over what was actually measured, alongside the explicit list
        # of what was not, so the number is never read out of context.
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fp_rate, 4),
        "coverage_complete": not unmeasured,
        "unmeasured_cases": unmeasured,
        "verification_violations": verification_violations,
        "unmatched_findings": unmatched_count,
    }


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
@dataclass
class EvaluationRun:
    oracle_version: str
    duration_s: float
    tools: dict[str, str] = field(default_factory=dict)
    assigned: dict[str, list[Finding]] = field(default_factory=dict)
    unmatched: list[Finding] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    # Which detectors actually executed, and the production job coverage when
    # the run included workflow-level scans.
    detectors_run: list[str] = field(default_factory=list)
    detectors_unavailable: dict[str, str] = field(default_factory=dict)
    workflows: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "oracle_version": self.oracle_version,
            "duration_s": round(self.duration_s, 2),
            "tools": self.tools,
            "metrics": self.metrics,
            "detectors_run": sorted(self.detectors_run),
            "detectors_unavailable": self.detectors_unavailable,
            "workflows": self.workflows,
            "cases": [
                {"id": case_id, "findings": [f.to_dict() for f in findings]}
                for case_id, findings in self.assigned.items()
            ],
            "unmatched": [f.to_dict() for f in self.unmatched],
            "notes": self.notes,
        }

    def human_summary(self) -> str:
        lines = [
            f"oracle {self.oracle_version} | {self.duration_s:.1f}s | "
            f"tools: {', '.join(f'{k} {v}' for k, v in self.tools.items()) or 'none'}",
            f"precision {self.metrics.get('precision')} | "
            f"recall {self.metrics.get('recall')} | F1 {self.metrics.get('f1')} | "
            f"FP rate {self.metrics.get('false_positive_rate')} "
            f"(TP {self.metrics.get('true_positives')}/"
            f"{self.metrics.get('total_positives')}, "
            f"FP {self.metrics.get('false_positives')}, "
            f"FN {self.metrics.get('false_negatives')})",
        ]
        unmeasured = self.metrics.get("unmeasured_cases") or []
        if unmeasured:
            lines.append("COVERAGE INCOMPLETE — not measured: " + ", ".join(unmeasured))
        unavailable = self.detectors_unavailable
        if unavailable:
            lines.extend(
                f"detector unavailable: {name} ({reason})"
                for name, reason in sorted(unavailable.items())
            )
        if self.workflows:
            lines.append(
                "workflow scans: "
                + ", ".join(
                    f"{item['profile']}={item['state']}" for item in self.workflows
                )
            )
        cases = self.metrics.get("verification_violations") or []
        lines.extend(f"verification violation: {item}" for item in cases)
        lines.extend(
            f"unmatched finding: {f.detector}/{f.category} at "
            f"{f.location or f.asset}"
            for f in self.unmatched
        )
        lines.extend(f"note: {note}" for note in self.notes)
        return "\n".join(lines)


def _assess(
    adapter: Adapter,
    base_url: str,
    paths: Sequence[str],
    *,
    timeout: float,
    ran: set[str] | None = None,
    unavailable: dict[str, str] | None = None,
) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    notes: list[str] = []
    ok, detail = adapter.available()
    if not ok:
        if unavailable is not None:
            unavailable[adapter.id] = detail
        notes.append(f"{adapter.id} skipped: {detail}")
        return findings, notes
    if ran is not None:
        ran.add(adapter.id)
    for path in paths:
        try:
            result = adapter.assess(
                f"{base_url}{path}", timeout=timeout, cancel=threading.Event()
            )
        except AdapterNotApplicable as exc:
            # Not applicable to this route is not a detection miss.
            notes.append(f"{adapter.id} not applicable to {path}: {exc}")
            continue
        findings.extend(result.findings)
        notes.extend(result.notes)
        if result.partial:
            notes.append(f"{adapter.id} reported partial coverage on {path}")
    return findings, notes


def _run_workflow(profile: str, base_url: str) -> tuple[jobs.Job | None, list[str]]:
    """Run one production assessment job against the lab; (job, notes)."""
    notes: list[str] = []
    try:
        job = jobs.run_assessment(
            f"{base_url}/",
            profile=profile,
            actor="lab-evaluation",
            timeout=_WORKFLOW_TIMEOUT,
        )
    except (AdapterError, ValueError) as exc:
        return None, [f"workflow {profile} could not run: {exc}"]
    notes.append(f"workflow {profile}: {job.state.value} — {job.verdict}")
    for run in job.runs:
        if run.state.value != "ok":
            notes.append(
                f"workflow {profile}: {run.adapter} {run.state.value}: {run.detail}"
            )
    return job, notes


def run_evaluation(
    *,
    lab: lab_target.LabTarget | None = None,
    configure_scope: bool = True,
    include_nuclei: bool = True,
    include_nmap: bool = True,
    nuclei_subset: tuple[str, ...] = ("http/exposures/configs",),
    workflow_profiles: Sequence[str] = (),
    oracle_path: Path | None = None,
) -> EvaluationRun:
    """Run the full oracle plan against a fresh (or provided) lab instance.

    ``workflow_profiles`` additionally runs production jobs (``jobs.
    run_assessment``) for those profiles against the same lab. Those exercise
    the orchestration path — adapter selection, coverage accounting, finding
    de-duplication — which per-adapter calls cannot cover. Workflow findings
    join the same scoring pool; their job states are reported separately.
    """
    started = time.monotonic()
    oracle = load_oracle(oracle_path)
    notes: list[str] = []
    tools: dict[str, str] = {}
    findings: list[Finding] = []
    ran: set[str] = set()
    unavailable: dict[str, str] = {}
    workflows: list[dict[str, Any]] = []

    owns_lab = lab is None
    lab = lab or lab_target.LabTarget()
    try:
        if owns_lab:
            lab.__enter__()
        base_url = lab.base_url
        if configure_scope:
            scope.configure(
                program="strix detection lab",
                authorized_by="local evaluation",
                authorization_ref=f"strix-lab-oracle-{oracle.get('oracle_version', '0')}",
                include=["127.0.0.1"],
                authorized_networks=["127.0.0.0/8", "::1/128"],
            )

        for adapter, paths, timeout in (
            (HTTPAdapter(), _HTTP_TARGETS, _HTTP_TIMEOUT),
            (DynamicValidationAdapter(), _DYNAMIC_TARGETS, _DYNAMIC_TIMEOUT),
            (GitExposureAdapter(), ("/",), _HTTP_TIMEOUT),
            (TCPPortAdapter(), ("/",), _NMAP_TIMEOUT),
        ):
            adapter_findings, adapter_notes = _assess(
                adapter,
                base_url,
                paths,
                timeout=timeout,
                ran=ran,
                unavailable=unavailable,
            )
            findings.extend(adapter_findings)
            notes.extend(adapter_notes)

        if include_nuclei:
            nuclei = NucleiAdapter()
            ok, detail = nuclei.available()
            if not ok:
                unavailable[nuclei.id] = detail
                notes.append(f"nuclei skipped: {detail}")
            else:
                nuclei.TEMPLATE_SUBSET = (
                    nuclei_subset  # bounded sweep, like the e2e test
                )
                ok, detail = nuclei.available()
                ran.add(nuclei.id)
                tools["nuclei"] = detail.removeprefix("nuclei ").strip() or detail
                result = nuclei.assess(
                    f"{base_url}/", timeout=_NUCLEI_TIMEOUT, cancel=threading.Event()
                )
                findings.extend(result.findings)
                notes.extend(result.notes)

        if include_nmap:
            nmap = NmapAdapter()
            ok, detail = nmap.available()
            if not ok:
                unavailable[nmap.id] = detail
                notes.append(f"nmap skipped: {detail}")
            else:
                version = _NMAP_VERSION.search(detail)
                ran.add(nmap.id)
                tools["nmap"] = version.group(1) if version else detail
                result = nmap.assess(
                    f"{base_url}/", timeout=_NMAP_TIMEOUT, cancel=threading.Event()
                )
                findings.extend(result.findings)
                notes.extend(result.notes)

        for profile in workflow_profiles:
            job, job_notes = _run_workflow(profile, base_url)
            notes.extend(job_notes)
            if job is None:
                continue
            findings.extend(job.findings)
            workflows.append(
                {
                    "profile": profile,
                    "state": job.state.value,
                    "verdict": job.verdict,
                    "coverage": job.coverage(),
                    "findings": len(job.findings),
                }
            )
            # Credit exactly the adapters the job actually executed; adapters
            # it found unavailable are reported as unmeasured, not as passing.
            for run in job.runs:
                if run.state.value in ("ok", "partial"):
                    ran.add(run.adapter)
                elif run.state.value == "unavailable":
                    unavailable.setdefault(run.adapter, run.detail)
    finally:
        if owns_lab:
            lab.__exit__(None, None, None)

    assigned, unmatched = match_findings(findings, oracle)
    metrics = score(
        assigned,
        len(unmatched),
        oracle,
        detectors_run=ran,
        detectors_unavailable=set(unavailable),
    )
    return EvaluationRun(
        oracle_version=str(oracle.get("oracle_version", "0")),
        duration_s=time.monotonic() - started,
        tools=tools,
        assigned=assigned,
        unmatched=unmatched,
        metrics=metrics,
        notes=notes,
        detectors_run=sorted(ran),
        detectors_unavailable=unavailable,
        workflows=workflows,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m strix.lab",
        description="Evaluate Strix's real adapters against the loopback "
        "detection lab and score them against the versioned oracle.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="write the full JSON report to this path",
    )
    parser.add_argument("--min-precision", type=float, default=1.0)
    parser.add_argument("--min-recall", type=float, default=1.0)
    parser.add_argument(
        "--no-nuclei",
        action="store_true",
        help="skip the nuclei adapter (offline runs)",
    )
    parser.add_argument("--no-nmap", action="store_true", help="skip the nmap adapter")
    parser.add_argument(
        "--nuclei-subset",
        default="http/exposures/configs",
        help="comma-separated template subset relative to the "
        "nuclei-templates root (default: %(default)s)",
    )
    parser.add_argument(
        "--workflow",
        default="",
        help="comma-separated profiles to also run as production "
        "jobs (e.g. web,network); empty disables workflow scans",
    )
    parser.add_argument(
        "--allow-unmeasured",
        action="store_true",
        help="exit 0 even when some oracle cases could not be "
        "measured (an unavailable detector); the report "
        "still marks coverage incomplete",
    )
    args = parser.parse_args(argv)

    subset = tuple(s.strip() for s in args.nuclei_subset.split(",") if s.strip())
    workflows = tuple(s.strip() for s in args.workflow.split(",") if s.strip())
    try:
        run = run_evaluation(
            include_nuclei=not args.no_nuclei,
            include_nmap=not args.no_nmap,
            nuclei_subset=subset,
            workflow_profiles=workflows,
        )
    except AdapterError as exc:
        print(f"evaluation could not run: {exc}", file=sys.stderr)
        return 2

    print(run.human_summary())
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(run.to_dict(), indent=2) + "\n", encoding="utf-8"
        )
        print(f"report written to {args.report}")

    metrics = run.metrics
    if not metrics.get("coverage_complete", True) and not args.allow_unmeasured:
        # Exit 2 means "the evaluation could not answer the question", which is
        # exactly what an unmeasured case is. It is never a pass.
        print(
            "INCOMPLETE: "
            + ", ".join(metrics.get("unmeasured_cases") or [])
            + " could not be measured (detector unavailable); use "
            "--allow-unmeasured to accept a partial benchmark"
        )
        return 2
    failures = []
    if metrics["precision"] < args.min_precision:
        failures.append(f"precision {metrics['precision']} < {args.min_precision}")
    if metrics["recall"] < args.min_recall:
        failures.append(f"recall {metrics['recall']} < {args.min_recall}")
    if metrics["verification_violations"]:
        failures.append(
            f"{len(metrics['verification_violations'])} verification "
            "level violation(s)"
        )
    if failures:
        print("FAILED: " + "; ".join(failures))
        return 1
    print("PASSED: oracle satisfied at the configured thresholds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
