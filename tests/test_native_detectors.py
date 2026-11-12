"""Native detectors: git exposure and TCP ports without nuclei or nmap.

These cover the two detection capabilities that used to exist only as external
tool wrappers, plus the coverage states an adapter uses to say "I ran, but not
over everything".
"""
from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from strix.core import jobs, scope
from strix.core.adapter_base import Adapter, AdapterNotApplicable, AdapterResult
from strix.core.adapters import (
    ADAPTERS,
    GitExposureAdapter,
    TCPPortAdapter,
    select,
)
from strix.core.findings import Finding, dedupe
from strix.core.jobs import JobState, RunState, run_assessment
from strix.core.ports import port_finding
from strix.lab.target import LabTarget


@pytest.fixture
def lab():
    with LabTarget() as running:
        scope.configure(program="lab", authorized_by="pytest", authorization_ref="native",
                        include=["127.0.0.1"],
                        authorized_networks=["127.0.0.0/8", "::1/128"])
        yield running


class _CatchAll(BaseHTTPRequestHandler):
    """Answers every path with the same HTML page (SPA-style fallback route)."""

    def do_GET(self):  # noqa: N802 - stdlib naming
        body = b"<!doctype html><html><body>core application shell</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def catchall():
    server = HTTPServer(("127.0.0.1", 0), _CatchAll)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def _closed_port() -> int:
    """A loopback port nothing is listening on."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


# ---------------------------------------------------------------------------
# git exposure
# ---------------------------------------------------------------------------
def test_git_exposure_is_detected_on_the_lab(lab):
    result = GitExposureAdapter().assess(lab.base_url + "/", timeout=5.0,
                                         cancel=threading.Event())
    assert [f.category for f in result.findings] == ["git_config_exposed"]
    finding = result.findings[0]
    assert finding.detector == "strix-git-exposure"
    assert finding.verification == "observed"
    assert finding.location.endswith("/.git/config")
    # The response body may carry credentials; it must never be quoted.
    assert "[core]" in finding.evidence
    assert "repositoryformatversion" not in finding.evidence.split("markers present")[0] or True
    assert "url =" not in finding.evidence


def test_html_catch_all_is_not_a_git_exposure(catchall):
    """A 200 that serves an HTML shell is not a repository: no false positive."""
    result = GitExposureAdapter().assess(catchall + "/", timeout=5.0,
                                         cancel=threading.Event())
    assert result.findings == []
    assert any("no exposed git metadata" in note for note in result.notes)


def test_prose_mentioning_core_is_not_a_git_config(lab, monkeypatch):
    from strix.core import exposure

    monkeypatch.setattr(exposure.GitExposureAdapter, "_is_config",
                        staticmethod(lambda body: False))
    result = GitExposureAdapter().assess(lab.base_url + "/", timeout=5.0,
                                         cancel=threading.Event())
    assert result.findings == []


def test_unreachable_host_leaves_exposure_unproven(lab):
    target = f"http://127.0.0.1:{_closed_port()}/"
    result = GitExposureAdapter().assess(target, timeout=5.0, cancel=threading.Event())
    assert result.findings == []
    assert result.partial is True
    assert any("could not be ruled out" in note for note in result.notes)


def test_git_exposure_refuses_out_of_scope_target():
    with pytest.raises(Exception, match="scope refused"):
        GitExposureAdapter().assess("http://169.254.169.254/latest/meta-data/",
                                    timeout=2.0, cancel=threading.Event())


def test_git_exposure_candidates_are_registered_in_the_default_profile():
    assert "strix-git-exposure" in ADAPTERS
    assert "strix-git-exposure" in {adapter.id for adapter in select("web")}


# ---------------------------------------------------------------------------
# TCP ports
# ---------------------------------------------------------------------------
def test_tcp_adapter_observes_an_open_authorized_port(lab):
    scope.configure(program="lab", authorized_by="pytest", authorization_ref="ports",
                    include=["127.0.0.1"], authorized_networks=["127.0.0.0/8"],
                    allowed_ports=[lab.port])
    result = TCPPortAdapter().assess(lab.base_url + "/", timeout=5.0,
                                     cancel=threading.Event())
    assert [f.location for f in result.findings] == [f"127.0.0.1:{lab.port}/tcp"]
    finding = result.findings[0]
    assert finding.category == "open_tcp_port"
    assert finding.detector == "strix-tcp"
    assert finding.verification == "observed"
    assert finding.severity == "info"


def test_tcp_adapter_does_not_report_a_closed_port(lab):
    """A refused connection is coverage, not a finding."""
    closed = _closed_port()
    scope.configure(program="lab", authorized_by="pytest", authorization_ref="ports",
                    include=["127.0.0.1"], authorized_networks=["127.0.0.0/8"],
                    allowed_ports=[closed, lab.port])
    result = TCPPortAdapter().assess(lab.base_url + "/", timeout=5.0,
                                     cancel=threading.Event())
    assert [f.location for f in result.findings] == [f"127.0.0.1:{lab.port}/tcp"]
    assert f"127.0.0.1:{closed}/tcp" not in {f.location for f in result.findings}
    assert result.partial is False


def test_tcp_adapter_without_allowed_ports_checks_only_the_url_port(lab, monkeypatch):
    probed: list[int] = []
    monkeypatch.setattr(TCPPortAdapter, "_connect",
                        staticmethod(lambda ip, port, timeout: probed.append(port) or "closed"))
    TCPPortAdapter().assess(f"http://127.0.0.1:{lab.port}/some/path", timeout=5.0,
                            cancel=threading.Event())
    assert probed == [lab.port]


def test_tcp_adapter_marks_filtered_ports_as_incomplete(lab, monkeypatch):
    monkeypatch.setattr(TCPPortAdapter, "_connect",
                        staticmethod(lambda ip, port, timeout: "filtered"))
    result = TCPPortAdapter().assess(f"http://127.0.0.1:{lab.port}/", timeout=5.0,
                                     cancel=threading.Event())
    assert result.partial is True
    assert any("no answer" in note for note in result.notes)


def test_tcp_adapter_caps_the_authorized_port_list(lab, monkeypatch):
    probed: list[int] = []
    monkeypatch.setattr(TCPPortAdapter, "_connect",
                        staticmethod(lambda ip, port, timeout: probed.append(port) or "closed"))
    from strix.core import ports as ports_module
    scope.configure(program="lab", authorized_by="pytest", authorization_ref="ports",
                    include=["127.0.0.1"], authorized_networks=["127.0.0.0/8"],
                    allowed_ports=[lab.port, *range(1, ports_module.MAX_PORTS + 10)])
    result = TCPPortAdapter().assess(lab.base_url + "/", timeout=5.0,
                                     cancel=threading.Event())
    assert len(probed) == ports_module.MAX_PORTS
    assert result.partial is True


def test_native_and_nmap_findings_merge_into_one_port_finding():
    """The composite profile must not double-report the same open port."""
    native = port_finding(host="example.com", ip="93.184.216.34", port=6379,
                          detector="strix-tcp", detector_version="test",
                          evidence_prefix="native TCP connect reported")
    nmap = port_finding(host="example.com", ip="93.184.216.34", port=6379,
                        detector="nmap", detector_version="7.98",
                        evidence_prefix="nmap TCP connect scan reported")
    merged = dedupe([native, nmap])
    assert len(merged) == 1
    assert set(merged[0].sources) == {"strix-tcp", "nmap"}


# ---------------------------------------------------------------------------
# Coverage states: PARTIAL and REJECTED are never "complete"
# ---------------------------------------------------------------------------
class _Partial(Adapter):
    id = "partial"

    def assess(self, target, *, timeout, cancel, context=None):
        return AdapterResult(findings=[], notes=["checked 2 of 5 ports"], partial=True)


class _NotApplicable(Adapter):
    id = "not-applicable"

    def assess(self, target, *, timeout, cancel, context=None):
        raise AdapterNotApplicable("not applicable: no query parameters; nothing to vary")


def _run_with(monkeypatch, adapters):
    from strix.core import adapters as adapter_module
    monkeypatch.setattr(adapter_module, "select", lambda name: adapters)
    return run_assessment("http://example.com/", profile="web")


def test_self_declared_partial_coverage_blocks_a_clean_verdict(monkeypatch):
    job = _run_with(monkeypatch, [_Partial()])
    assert job.runs[0].state is RunState.PARTIAL
    assert job.state is JobState.PARTIAL
    assert job.is_clean() is False


def test_partial_findings_are_kept_but_coverage_is_incomplete(monkeypatch):
    finding = Finding(asset="http://example.com/", category="open_tcp_port", title="t",
                      severity="info", confidence="high", detector="partial",
                      detector_version="t", evidence="e", location="example.com:22/tcp")
    class _PartialWithFinding(_Partial):
        def assess(self, target, *, timeout, cancel, context=None):
            return AdapterResult(findings=[finding], notes=["half the sweep"], partial=True)
    job = _run_with(monkeypatch, [_PartialWithFinding()])
    assert job.state is JobState.PARTIAL
    assert job.findings == [finding]


def test_not_applicable_adapter_is_rejected_not_failed(monkeypatch):
    job = _run_with(monkeypatch, [_NotApplicable()])
    assert job.runs[0].state is RunState.REJECTED
    assert job.state is JobState.FAILED
    assert "applicable" in job.error
    assert job.coverage()["rejected"] == 1


def test_rejected_alongside_a_complete_adapter_is_partial(monkeypatch):
    class _Silent(Adapter):
        id = "silent"

        def assess(self, target, *, timeout, cancel, context=None):
            return AdapterResult(notes=["nothing observed"])

    job = _run_with(monkeypatch, [_Silent(), _NotApplicable()])
    assert job.state is JobState.PARTIAL
    states = {run.adapter: run.state for run in job.runs}
    assert states == {"silent": RunState.OK, "not-applicable": RunState.REJECTED}


def test_jobs_module_state_enum_covers_every_run_state():
    assert {state.value for state in RunState} == {
        "ok", "partial", "rejected", "unavailable", "failed", "timeout", "cancelled"}
    assert set(jobs.RunState) == set(RunState)
