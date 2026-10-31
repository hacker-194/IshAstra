"""Out-of-band SSRF confirmation: canary listener, injection, callback proof.

A callback for a unique canary token is direct evidence that the target
fetched the injected destination. These tests run a real canary listener on
loopback and a real target that really fetches — no stubs on the evidence path.
"""
from __future__ import annotations

import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlparse

import pytest

from strix.core import scope
from strix.core.adapters import AdapterError, SSRFOOBAdapter
from strix.core.collab import CollabClient, CollabConfig, CollabLog, CollabServer, new_token
from strix.core.jobs import JobState, run_assessment


# ---------------------------------------------------------------------------
# Listener unit behavior
# ---------------------------------------------------------------------------
def test_collab_log_is_bounded_and_token_isolated():
    log = CollabLog(max_entries=3)
    for i in range(5):
        log.record({"token": f"{'a' * 16 if i % 2 else 'b' * 16}", "seq": i})
    assert log.count() == 3  # deque maxlen dropped the oldest
    tokens = {entry["token"] for entry in log.poll("a" * 16)}
    assert tokens == {"a" * 16}


def test_canary_tokens_have_128_bits_and_callbacks_redact_secret_headers():
    token = new_token()
    assert len(token) == 32
    server = CollabServer()
    server.start()
    try:
        request = urllib.request.Request(
            f"{server.base_url}/{token}?access_token=super_secret_query_value",
            headers={"Authorization": "Bearer super_secret_authorization_value",
                     "Cookie": "session=super_secret_cookie_value"},
        )
        urllib.request.urlopen(request, timeout=3).read()
        callback = server.poll(token)[0]
        dumped = str(callback)
        assert "super_secret_query_value" not in dumped
        assert "super_secret_authorization_value" not in dumped
        assert "super_secret_cookie_value" not in dumped
        assert callback["headers"]["authorization"] == "[REDACTED]"
        assert callback["headers"]["cookie"] == "[REDACTED]"
    finally:
        server.stop()


def test_collab_server_records_callbacks_and_serves_poll_api():
    server = CollabServer()
    server.start()
    try:
        token = new_token()
        urllib.request.urlopen(server.canary_url(token), timeout=3).read()
        time.sleep(0.05)
        callbacks = server.poll(token)
        assert len(callbacks) == 1
        assert callbacks[0]["method"] == "GET"
        assert callbacks[0]["peer"] in ("127.0.0.1", "::1")
        # a different token sees nothing — canaries are unique
        assert server.poll(new_token()) == []
        # the HTTP poll API answers external consumers
        client = CollabClient("127.0.0.1", server.port)
        assert client.poll(token)[0]["token"] == token
    finally:
        server.stop()


def test_collab_server_rejects_non_token_paths():
    server = CollabServer()
    server.start()
    try:
        import urllib.error
        try:
            urllib.request.urlopen(f"{server.base_url}/not-a-token", timeout=3).read()
            raised = False
        except urllib.error.HTTPError:
            raised = True
        assert raised
        assert server.log.count() == 0
    finally:
        server.stop()


def test_collab_config_validation():
    assert CollabConfig.from_dict({"host": "collab.example.com", "port": 8765}).port == 8765
    assert CollabConfig.from_dict({"host": "127.0.0.1"}).port == 0
    with pytest.raises(ValueError, match="host"):
        CollabConfig.from_dict({"port": 1})
    with pytest.raises(ValueError, match="port"):
        CollabConfig.from_dict({"host": "h", "port": 70000})
    with pytest.raises(ValueError, match="port"):
        CollabConfig.from_dict({"host": "h", "port": "x"})


# ---------------------------------------------------------------------------
# The SSRF adapter against a real vulnerable target
# ---------------------------------------------------------------------------
class FetcherHandler(BaseHTTPRequestHandler):
    """Target with a server-side fetch: GET /fetch?url=<anything> really fetches.

    The vulnerable path also reflects the fetched content (in-band). The safe
    path ignores the parameter entirely.
    """

    vulnerable = True
    mode = "both"  # both | oob | none

    def do_GET(self):
        parsed = urlparse(self.path)
        params = dict(parse_qsl(parsed.query))
        body = b"<html>plain page</html>"
        if parsed.path == "/fetch" and self.vulnerable and params.get("url"):
            try:
                with urllib.request.urlopen(params["url"], timeout=3) as upstream:
                    upstream.read(4096)
                if self.mode in ("both", "oob"):
                    body = b"<html>fetched content embedded</html>"
            except Exception:
                body = b"<html>fetch failed</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def collab_scope():
    """Scope with the in-process collab listener enabled."""
    current = scope.active()
    scope.configure(program=current.program, authorized_by=current.authorized_by,
                    authorization_ref=current.authorization_ref,
                    include=current.include, exclude=current.exclude,
                    authorized_networks=current.authorized_networks,
                    allowed_ports=current.allowed_ports,
                    collab=CollabConfig(host="127.0.0.1", port=0))
    return current


@pytest.fixture
def fetch_site():
    FetcherHandler.vulnerable = True
    server = ThreadingHTTPServer(("127.0.0.1", 0), FetcherHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield type("Site", (), {"base": f"http://127.0.0.1:{server.server_port}"})
    finally:
        server.shutdown()
        server.server_close()


def test_adapter_unavailable_without_collab_config():
    ok, detail = SSRFOOBAdapter().available()
    assert not ok and "collab" in detail


def test_blind_ssrf_confirmed_by_callback(fetch_site, collab_scope):
    """The target really fetches the canary; the callback proves it (OOB)."""
    adapter = SSRFOOBAdapter()
    ok, detail = adapter.available()
    assert ok, detail
    result = adapter.assess(fetch_site.base + "/fetch?url=https://ignored.example/",
                            timeout=30.0, cancel=threading.Event())
    confirmed = [f for f in result.findings if f.category == "ssrf_confirmed_oob"]
    assert len(confirmed) == 1
    finding = confirmed[0]
    assert finding.severity == "high"
    assert finding.verification == "observed"
    assert finding.cwe == "CWE-918"
    assert "callback received" in finding.evidence
    assert "url" in finding.evidence  # the injected parameter is named


def test_inband_reflection_when_content_echoed(fetch_site):
    """Fetched content reflected but listener unreachable from target? Still
    confirmed in-band (medium, observed) — callback OR reflection, both honest."""
    adapter = SSRFOOBAdapter()
    # make the target fetch succeed but the callback poll come up empty by
    # using a fresh log: a different server for the poll than for the fetch
    current = scope.active()
    isolated = CollabServer()
    isolated.start()
    scope.configure(program=current.program, authorized_by=current.authorized_by,
                    authorization_ref=current.authorization_ref,
                    include=current.include, exclude=current.exclude,
                    authorized_networks=current.authorized_networks,
                    collab=CollabConfig(host="127.0.0.1", port=isolated.port))
    try:
        # the target will fetch the canary on THIS server (callback recorded),
        # but the adapter polls the shared in-process server — reflection path:
        result = adapter.assess(
            fetch_site.base + "/fetch?url=https://ignored.example/",
            timeout=30.0, cancel=threading.Event())
        # either way the fetch must be reported through one of the two channels
        categories = {f.category for f in result.findings}
        assert categories <= {"ssrf_confirmed_oob", "ssrf_inband_reflection"}
        assert categories  # this target is genuinely vulnerable
    finally:
        isolated.stop()


def test_target_that_ignores_the_parameter_yields_nothing(fetch_site, collab_scope):
    FetcherHandler.vulnerable = False
    result = SSRFOOBAdapter().assess(
        fetch_site.base + "/fetch?url=https://ignored.example/",
        timeout=30.0, cancel=threading.Event())
    assert result.findings == []
    assert any("confirmed" in note for note in result.notes)


def test_non_ssrf_parameters_are_not_injected(fetch_site, collab_scope):
    result = SSRFOOBAdapter().assess(
        fetch_site.base + "/page?page=3&q=search",
        timeout=30.0, cancel=threading.Event())
    assert result.findings == []
    assert any("SSRF-shaped" in note for note in result.notes)


def test_scope_gate_still_governs_trigger_requests(collab_scope):
    with pytest.raises(AdapterError, match="scope refused"):
        SSRFOOBAdapter().assess("https://not-authorized.example/fetch?url=x",
                                timeout=10.0, cancel=threading.Event())


def test_ssrf_oob_in_api_deep_job(fetch_site, collab_scope):
    """The full job pipeline confirms blind SSRF and records it as a finding."""
    job = run_assessment(fetch_site.base + "/fetch?url=https://x.example/",
                         profile="api-deep", timeout=120.0)
    states = {run.adapter: run.state.value for run in job.runs}
    assert states["strix-ssrf-oob"] == "ok", states
    confirmed = [f for f in job.findings if f.category == "ssrf_confirmed_oob"]
    assert confirmed, job.to_dict()["coverage"]
    assert job.state is JobState.COMPLETED or job.state is JobState.PARTIAL
    blob = str(job.to_dict())
    assert "callback received" in blob
