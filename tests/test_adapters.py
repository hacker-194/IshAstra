"""Adapter framework and job lifecycle: real execution, honest failure states."""
import json
import os
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from strix.core import adapters as adapter_module
from strix.core import scope
from strix.core.adapters import (
    Adapter,
    AdapterError,
    HTTPAdapter,
    NmapAdapter,
    NucleiAdapter,
    _run_tool,
)
from strix.core.jobs import Job, JobState, RunState, run_assessment

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


# ---------------------------------------------------------------------------
# HTTP adapter
# ---------------------------------------------------------------------------
def test_http_adapter_emits_observed_findings(local_target):
    result = HTTPAdapter().assess(f"{local_target.url}/?q=hello", timeout=5.0,
                                  cancel=threading.Event())
    categories = {finding.category for finding in result.findings}
    assert {"missing_csp", "xss"} <= categories
    xss = next(f for f in result.findings if f.category == "xss")
    assert xss.verification == "unverified"
    assert xss.severity == "info"
    assert "q" in xss.evidence
    assert "execution context was not tested" in xss.evidence
    assert xss.cwe == "CWE-79"


def test_http_adapter_refuses_out_of_scope_target():
    with pytest.raises(AdapterError):
        HTTPAdapter().assess("http://169.254.169.254/latest/meta-data/", timeout=2.0,
                             cancel=threading.Event())


def test_no_response_is_not_reported_as_missing_headers(local_target):
    # Point at a closed port on the same host: nothing was observed, so no
    # header findings may be invented.
    result = HTTPAdapter().assess("http://127.0.0.1:1/", timeout=2.0,
                                  cancel=threading.Event())
    assert not {f.category for f in result.findings} & {"missing_csp", "missing_hsts"}
    assert any("no HTTP response" in note for note in result.notes)


# ---------------------------------------------------------------------------
# nmap adapter
# ---------------------------------------------------------------------------
def test_nmap_parses_ports_and_flags_risky_services(monkeypatch):
    adapter = NmapAdapter()
    adapter._version = "7.98"
    monkeypatch.setattr(adapter, "available", lambda: (True, "stubbed"))
    monkeypatch.setattr(scope, "destination", lambda target: ("", "", scope.Destination(
        scheme="http", host="example.com", port=80, ip="93.184.216.34")))
    monkeypatch.setattr(adapter_module, "_run_tool", lambda *a, **k: (0, NMAP_XML, ""))

    result = adapter.assess("http://example.com", timeout=5.0, cancel=threading.Event())
    by_location = {finding.location: finding for finding in result.findings}
    assert set(by_location) == {"example.com:22/tcp", "example.com:6379/tcp"}
    assert by_location["example.com:6379/tcp"].severity == "info"
    assert by_location["example.com:22/tcp"].severity == "info"
    assert by_location["example.com:22/tcp"].verification == "observed"
    assert "OpenSSH 9.6" in by_location["example.com:22/tcp"].evidence
    assert "closed" not in str([f.location for f in result.findings])


def test_redirect_observation_is_not_mislabeled_as_open_redirect(local_target):
    result = HTTPAdapter().assess(f"{local_target.url}/redirect", timeout=5.0,
                                  cancel=threading.Event())
    assert "open_redirect" not in {finding.category for finding in result.findings}
    assert any("redirects are not followed" in note for note in result.notes)


def test_nmap_uses_pinned_ip_and_explicit_authorized_ports(monkeypatch):
    adapter = NmapAdapter()
    adapter._version = "7.98"
    scope.configure(program="ports", authorized_by="pytest", authorization_ref="ports",
                    include=["example.com"], allowed_ports=[443, 8443])
    monkeypatch.setattr(scope, "destination", lambda target: ("", "", scope.Destination(
        scheme="https", host="example.com", port=443, ip="93.184.216.34")))
    monkeypatch.setattr(adapter, "available", lambda: (True, "stubbed"))
    captured = {}
    def run(argv, **kwargs):
        captured["argv"] = argv
        return 0, NMAP_XML, ""
    monkeypatch.setattr(adapter_module, "_run_tool", run)
    adapter.assess("https://example.com/", timeout=5.0, cancel=threading.Event())
    argv = captured["argv"]
    assert argv[argv.index("-p") + 1] == "443,8443"
    assert argv[-1] == "93.184.216.34"
    assert "example.com" not in argv


def test_nmap_defaults_to_only_the_target_url_port(monkeypatch):
    adapter = NmapAdapter()
    adapter._version = "7.98"
    monkeypatch.setattr(scope, "destination", lambda target: ("", "", scope.Destination(
        scheme="https", host="example.com", port=8443, ip="93.184.216.34")))
    monkeypatch.setattr(adapter, "available", lambda: (True, "stubbed"))
    captured = {}
    def run(argv, **kwargs):
        captured["argv"] = argv
        return 0, NMAP_XML, ""
    monkeypatch.setattr(adapter_module, "_run_tool", run)
    adapter.assess("https://example.com:8443/", timeout=5.0, cancel=threading.Event())
    argv = captured["argv"]
    assert argv[argv.index("-p") + 1] == "8443"
    assert "--top-ports" not in argv
    assert argv[-1] == "93.184.216.34"


def test_nmap_rejects_unparseable_output(monkeypatch):
    adapter = NmapAdapter()
    adapter._version = "7.98"
    monkeypatch.setattr(scope, "destination", lambda target: ("", "", scope.Destination(
        scheme="http", host="example.com", port=80, ip="93.184.216.34")))
    monkeypatch.setattr(adapter_module, "_run_tool", lambda *a, **k: (0, "not xml", ""))
    with pytest.raises(AdapterError):
        adapter.assess("http://example.com", timeout=5.0, cancel=threading.Event())


def test_nmap_nonzero_exit_is_an_error_not_an_empty_result(monkeypatch):
    adapter = NmapAdapter()
    adapter._version = "7.98"
    monkeypatch.setattr(scope, "destination", lambda target: ("", "", scope.Destination(
        scheme="http", host="example.com", port=80, ip="93.184.216.34")))
    monkeypatch.setattr(adapter_module, "_run_tool",
                        lambda *a, **k: (1, "", "nmap: permission denied"))
    with pytest.raises(AdapterError):
        adapter.assess("http://example.com", timeout=5.0, cancel=threading.Event())


def test_external_tool_drains_stdout_and_stderr_without_deadlock():
    # Both streams exceed typical pipe-buffer capacity. They must be drained
    # concurrently, not read only after the child exits.
    code, stdout, stderr = _run_tool(
        [sys.executable, "-c",
         "import sys; sys.stdout.write('x'*200000); sys.stdout.flush(); "
         "sys.stderr.write('y'*200000); sys.stderr.flush()"],
        timeout=5, cancel=threading.Event())
    assert code == 0
    assert len(stdout) == 200000 and set(stdout) == {"x"}
    assert len(stderr) == 200000 and set(stderr) == {"y"}


def test_external_tool_output_is_capped(monkeypatch):
    monkeypatch.setattr(adapter_module, "MAX_TOOL_OUTPUT_BYTES", 1024)
    with pytest.raises(AdapterError, match="output exceeded"):
        _run_tool([sys.executable, "-c", "print('x'*10000)"],
                  timeout=5, cancel=threading.Event())


def test_tool_timeout_kills_the_process():
    with pytest.raises(adapter_module.AdapterTimeout):
        _run_tool([sys.executable, "-c", "import time; time.sleep(10)"],
                  timeout=0.3, cancel=threading.Event())


def test_tool_cancellation_kills_the_process():
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(adapter_module.AdapterCancelled):
        _run_tool([sys.executable, "-c", "import time; time.sleep(10)"],
                  timeout=10, cancel=cancel)


@pytest.mark.skipif(shutil.which("nmap") is None, reason="nmap is not installed")
def test_nmap_really_executes_against_loopback(monkeypatch):
    monkeypatch.setattr(scope, "check", lambda url: ("", ""))
    result = NmapAdapter().assess("http://127.0.0.1/", timeout=60.0,
                                  cancel=threading.Event())
    # Real run: it must produce a coverage note even when nothing is exposed
    assert any("open" in note for note in result.notes)
    assert all(f.detector == "nmap" for f in result.findings)


# ---------------------------------------------------------------------------
# nuclei adapter (fixture-tested; the real binary is exercised by the
# end-to-end test at the bottom of this file when it is installed)
# ---------------------------------------------------------------------------
NUCLEI_JSONL = "\n".join([
    json.dumps({
        "template-id": "CVE-2021-44228",
        "info": {"name": "Apache Log4j RCE", "severity": "critical",
                 "description": "JNDI injection", "remediation": "Upgrade log4j",
                 "classification": {"cwe-id": ["CWE-502", "CWE-400"], "cvss-score": 10.0}},
        "host": "https://example.com",
        "matched-at": "https://example.com/api?x=1",
        "matcher-name": "word",
    }),
    json.dumps({
        "template-id": "tech-detect",
        "info": {"name": "Technology Detection", "severity": "info",
                 "classification": {"cwe-id": []}},
        "host": "https://example.com",
        "matched-at": "https://example.com/",
    }),
    "not-json-at-all",
])


def _nuclei(monkeypatch, tmp_path, stdout="", code=0, stderr=""):
    adapter = NucleiAdapter()
    adapter._version = "3.1.0"                 # version already resolved: no -version call
    monkeypatch.setattr(adapter_module.shutil, "which", lambda name: "/usr/local/bin/nuclei")
    def fake_destination(target):
        parsed = adapter_module.parse_url(target)
        if parsed is None or parsed.hostname is None:
            return "invalid_target", "invalid URL", None
        current = scope.active()
        if current is None:
            return "out_of_scope", "no authorized scope", None
        denial, reason, host, port = current._gate(target)
        if denial:
            return denial, reason, None
        resolved_port = port or (443 if parsed.scheme == "https" else 80)
        return "", "", scope.Destination(parsed.scheme, host, resolved_port, "93.184.216.34")
    monkeypatch.setattr(scope, "destination", fake_destination)
    # Hermetic templates dir: the availability gate must not depend on the
    # machine this suite runs on.
    for subset in adapter.TEMPLATE_SUBSET:
        (tmp_path / subset).mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(adapter, "templates_dir", lambda: tmp_path)
    captured = {}

    def fake_run(argv, *, timeout, cancel):
        captured["argv"] = argv
        return code, stdout, stderr

    monkeypatch.setattr(adapter_module, "_run_tool", fake_run)
    return adapter, captured


def test_nuclei_normalizes_jsonl_results(monkeypatch, tmp_path):
    adapter, _ = _nuclei(monkeypatch, tmp_path, stdout=NUCLEI_JSONL)
    result = adapter.assess("http://example.com", timeout=10, cancel=threading.Event())

    by_category = {finding.category: finding for finding in result.findings}
    assert set(by_category) == {"CVE-2021-44228", "tech-detect"}
    severe = by_category["CVE-2021-44228"]
    assert severe.severity == "critical"
    assert severe.cwe == "CWE-502"          # list form flattened
    assert severe.verification == "observed"
    assert "matched at https://example.com/api?x=1" in severe.evidence
    assert severe.detector == "nuclei"
    assert by_category["tech-detect"].severity == "info"
    assert any("unparseable" in note for note in result.notes)


def test_nuclei_argument_list_is_bounded_and_shell_free(monkeypatch, tmp_path):
    adapter, captured = _nuclei(monkeypatch, tmp_path, stdout=NUCLEI_JSONL)
    hostile = "http://example.com/?q=1;rm${IFS}-rf${IFS}/`id`$(id)|cat"
    adapter.assess(hostile, timeout=10, cancel=threading.Event())
    argv = captured["argv"]

    assert isinstance(argv, list)                     # never a shell string
    assert argv[1] == "-u" and argv[2].startswith("http://93.184.216.34:80/")
    assert argv[argv.index("-H") + 1] == "Host: example.com"
    assert argv[argv.index("-sni") + 1] == "example.com"
    assert "-dr" in argv
    # Template set is explicitly bounded: the full sweep cannot finish inside
    # a job deadline at a conservative rate.
    assert argv[argv.index("-t") + 1].endswith("http/exposures")
    assert "-no-interactsh" in argv                   # no out-of-band callbacks
    assert argv[argv.index("-rate-limit") + 1] == "25"
    assert argv[argv.index("-concurrency") + 1] == "10"
    assert "-jsonl" in argv


def test_nuclei_all_unparseable_output_is_an_error(monkeypatch, tmp_path):
    adapter, _ = _nuclei(monkeypatch, tmp_path, stdout="garbage\nmore garbage")
    with pytest.raises(AdapterError):
        adapter.assess("http://example.com", timeout=10, cancel=threading.Event())


def test_nuclei_failure_without_results_is_an_error(monkeypatch, tmp_path):
    adapter, _ = _nuclei(monkeypatch, tmp_path, code=2, stderr="no templates found")
    with pytest.raises(AdapterError) as excinfo:
        adapter.assess("http://example.com", timeout=10, cancel=threading.Event())
    assert "exited 2" in str(excinfo.value)


def test_nuclei_present_but_missing_is_reported_unavailable(monkeypatch):
    monkeypatch.setattr(adapter_module.shutil, "which", lambda name: None)
    available, detail = NucleiAdapter().available()
    assert available is False
    assert "not installed" in detail


def test_nuclei_without_templates_is_reported_unavailable(monkeypatch, tmp_path):
    # Binary present, templates absent: must say so — never pretend readiness.
    monkeypatch.setattr(adapter_module.shutil, "which", lambda name: "/usr/local/bin/nuclei")
    adapter = NucleiAdapter()
    monkeypatch.setattr(adapter, "templates_dir", lambda: tmp_path / "nowhere")
    available, detail = adapter.available()
    assert available is False
    assert "-update-templates" in detail


def test_job_marks_absent_nuclei_as_unavailable_not_clean(monkeypatch):
    monkeypatch.setattr(adapter_module.shutil, "which", lambda name: None)
    job = _run_with(monkeypatch, [NucleiAdapter()])
    assert job.state is JobState.FAILED
    assert job.runs[0].state is RunState.UNAVAILABLE
    assert job.is_clean() is False


# ---------------------------------------------------------------------------
# Job lifecycle: empty findings are not a clean verdict without coverage
# ---------------------------------------------------------------------------
class Silent(Adapter):
    id = "silent"
    asset_types = ("web",)

    def assess(self, target, *, timeout, cancel, context=None):
        return adapter_module.AdapterResult(findings=[], notes=["nothing observed"])


class Broken(Adapter):
    id = "broken"
    asset_types = ("web",)

    def assess(self, target, *, timeout, cancel, context=None):
        raise AdapterError("tool crashed")


def _run_with(monkeypatch, adapters, *, profile="web", cancel=None):
    monkeypatch.setattr(adapter_module, "select", lambda name: adapters)
    return run_assessment("http://example.com/", profile=profile, cancel=cancel)


def test_complete_silent_coverage_is_clean(monkeypatch):
    job = _run_with(monkeypatch, [Silent()])
    assert job.state is JobState.COMPLETED
    assert job.is_clean() is True
    assert "complete coverage" in job.verdict


def test_one_failed_adapter_makes_empty_findings_inconclusive(monkeypatch):
    job = _run_with(monkeypatch, [Silent(), Broken()])
    assert job.state is JobState.PARTIAL
    assert job.findings == []
    assert job.is_clean() is False
    assert "inconclusive" in job.verdict
    states = {run.adapter: run.state for run in job.runs}
    assert states == {"silent": RunState.OK, "broken": RunState.FAILED}
    assert "tool crashed" in job.coverage()["adapters"][1]["detail"]


def test_unavailable_tool_is_reported_not_skipped(monkeypatch):
    class Missing(Adapter):
        id = "missing"

        def available(self):
            return False, "binary not installed"

    job = _run_with(monkeypatch, [Missing()])
    assert job.state is JobState.FAILED
    assert job.runs[0].state is RunState.UNAVAILABLE
    assert "no usable coverage" in job.verdict
    assert job.is_clean() is False


def test_unknown_adapter_exception_becomes_failed_run(monkeypatch):
    class Exploding(Adapter):
        id = "exploding"

        def assess(self, target, *, timeout, cancel, context=None):
            raise RuntimeError("unexpected")

    job = _run_with(monkeypatch, [Exploding()])
    assert job.state is JobState.FAILED
    assert job.runs[0].state is RunState.FAILED
    assert "RuntimeError" in job.runs[0].detail


def test_preset_cancellation_stops_before_any_adapter(monkeypatch):
    cancel = threading.Event()
    cancel.set()
    job = _run_with(monkeypatch, [Silent()], cancel=cancel)
    assert job.state is JobState.CANCELLED
    assert job.runs[0].state is RunState.CANCELLED
    assert job.is_clean() is False
    assert "do not treat as clean" in job.verdict


def test_out_of_scope_job_never_runs_an_adapter():
    job = run_assessment("http://victim.example.net/", profile="web")
    assert job.state is JobState.FAILED
    assert job.runs == []
    assert "out_of_scope" in job.error
    assert job.policy["authorization_ref"] == "local-tests"


def test_job_serializes_policy_and_coverage():
    job = Job(target="http://example.com/", profile="web", actor="analyst",
              policy={"authorization_ref": "ENG-1"})
    data = job.to_dict()
    assert data["actor"] == "analyst"
    assert data["policy"]["authorization_ref"] == "ENG-1"
    assert data["coverage"]["total"] == 0
    assert data["findings"] == []


# ---------------------------------------------------------------------------
# nuclei end-to-end: runs only when the real binary and templates are present
# ---------------------------------------------------------------------------
def _nuclei_e2e_ready() -> bool:
    binary = Path(__file__).resolve().parents[2] / "tools" / "nuclei"
    templates = (Path(os.environ.get("HOME", "")) / "nuclei-templates"
                 / "http" / "exposures")
    return binary.is_file() and os.access(binary, os.X_OK) and templates.is_dir()


class _GitConfigBait(BaseHTTPRequestHandler):
    """Serves the content the official `git-config` exposure template matches."""

    def do_GET(self):
        if self.path.startswith("/.git/config"):
            body = (b"[core]\n\trepositoryformatversion = 0\n"
                    b"\tfilemode = true\n\tbare = false\n")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *args):
        pass


@pytest.mark.skipif(not _nuclei_e2e_ready(),
                    reason="nuclei binary (tools/) or templates not installed")
def test_nuclei_end_to_end_against_authorized_local_target(monkeypatch):
    """Real binary, real HTTP, real JSONL → normalized findings.

    The template set is narrowed to the directory holding the bait so the sweep
    stays inside the deadline; argv construction, execution, exit-status
    handling and JSONL parsing are the production code paths.
    """
    tools_dir = Path(__file__).resolve().parents[2] / "tools"
    monkeypatch.setenv("PATH", f"{tools_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    adapter = NucleiAdapter()
    monkeypatch.setattr(adapter, "TEMPLATE_SUBSET", ("http/exposures/configs",))

    server = ThreadingHTTPServer(("127.0.0.1", 0), _GitConfigBait)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        ok, detail = adapter.available()
        assert ok, detail
        assert "unknown" not in detail           # version parsed from real output

        result = adapter.assess(f"http://127.0.0.1:{server.server_port}/",
                                timeout=90.0, cancel=threading.Event())
    finally:
        server.shutdown()
        server.server_close()

    # A real template really matched, and every finding is normalized.
    assert any(f.category == "git-config" for f in result.findings), result.notes
    for finding in result.findings:
        assert finding.detector == "nuclei"
        assert finding.detector_version not in ("", "unknown", "0")
        assert finding.verification == "observed"
        assert finding.evidence
    assert any("nuclei" in note and "template profile" in note
               for note in result.notes)


def test_gate_refuses_targets_with_whitespace_before_any_tool_runs(monkeypatch, tmp_path):
    adapter, captured = _nuclei(monkeypatch, tmp_path, stdout=NUCLEI_JSONL)
    with pytest.raises(adapter_module.AdapterError, match="scope refused"):
        adapter.assess("http://example.com/?q=1; rm -rf / #", timeout=10,
                       cancel=threading.Event())
    assert "argv" not in captured                     # nothing was executed


# ---------------------------------------------------------------------------
# Process containment and "no answer" honesty
# ---------------------------------------------------------------------------
def test_tool_timeout_kills_the_whole_process_group(tmp_path):
    """A scanner that forks workers must not leave them running after a timeout."""
    import time

    ticks = tmp_path / "ticks"
    worker = (
        "import pathlib, sys, time\n"
        "path = pathlib.Path(sys.argv[1])\n"
        "while True:\n"
        "    size = path.stat().st_size if path.exists() else 0\n"
        "    path.write_text('x' * (size + 1))\n"
        "    time.sleep(0.02)\n"
    )
    script = (
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, '-c', {worker!r}, {str(ticks)!r}])\n"
        "time.sleep(60)\n"
    )
    with pytest.raises(adapter_module.AdapterTimeout):
        _run_tool([sys.executable, "-c", script], timeout=1.0, cancel=threading.Event())
    # Give the grandchild a moment to be killed, then prove it stopped writing.
    time.sleep(0.3)
    before = len(ticks.read_text()) if ticks.exists() else 0
    time.sleep(0.5)
    after = len(ticks.read_text()) if ticks.exists() else 0
    assert after == before, "a forked worker kept running after the tool was killed"


def test_nmap_output_without_port_elements_is_not_a_clean_scan(monkeypatch):
    adapter = NmapAdapter()
    adapter._version = "7.98"
    monkeypatch.setattr(adapter, "available", lambda: (True, "stubbed"))
    monkeypatch.setattr(adapter_module, "_run_tool",
                        lambda *a, **k: (0, "<nmaprun></nmaprun>", ""))
    with pytest.raises(AdapterError, match="no port results"):
        adapter.assess("http://example.com/", timeout=5.0, cancel=threading.Event())


def test_nmap_error_element_fails_the_run(monkeypatch):
    adapter = NmapAdapter()
    adapter._version = "7.98"
    monkeypatch.setattr(adapter, "available", lambda: (True, "stubbed"))
    payload = ('<nmaprun><host><ports><port portid="80" protocol="tcp">'
               '<state state="closed"/></port></ports></host>'
               '<runstats><finished errormsg="could not resolve"/></runstats></nmaprun>')
    monkeypatch.setattr(adapter_module, "_run_tool", lambda *a, **k: (0, payload, ""))
    with pytest.raises(AdapterError, match="nmap reported an error"):
        adapter.assess("http://example.com/", timeout=5.0, cancel=threading.Event())


def test_nmap_filtered_port_marks_coverage_partial(monkeypatch):
    adapter = NmapAdapter()
    adapter._version = "7.98"
    monkeypatch.setattr(adapter, "available", lambda: (True, "stubbed"))
    payload = ('<nmaprun><host><ports>'
               '<port portid="80" protocol="tcp"><state state="filtered"/></port>'
               '</ports></host></nmaprun>')
    monkeypatch.setattr(adapter_module, "_run_tool", lambda *a, **k: (0, payload, ""))
    result = adapter.assess("http://example.com/", timeout=5.0, cancel=threading.Event())
    assert result.partial is True
    assert any("no answer" in note for note in result.notes)


def test_nuclei_strings_are_bounded_and_control_characters_removed(monkeypatch, tmp_path):
    payload = {"template-id": "t" * 400, "matched-at": "http://example.com/x",
               "info": {"name": "bad\x00title" * 100, "severity": "HIGH",
                        "classification": {"cwe-id": "79"}}}
    adapter, _captured = _nuclei(monkeypatch, tmp_path, stdout=json.dumps(payload) + "\n")
    result = adapter.assess("http://example.com", timeout=10, cancel=threading.Event())
    finding = result.findings[0]
    assert len(finding.category) <= 120
    assert "\x00" not in finding.title and len(finding.title) <= 200
    assert finding.severity == "high"
    assert finding.cwe == "CWE-79"
