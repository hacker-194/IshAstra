"""Monitor: baseline first, alert only on new high-severity findings, safe webhooks."""
import asyncio

import pytest

from strix.audit import AuditChain, AuditLog
from strix.core import jobs
from strix.core.findings import Finding
from strix.monitor import AlertSink, Monitor, validate_webhook_url


class Collect(AlertSink):
    def __init__(self):
        super().__init__("collect")
        self.alerts = []

    async def send(self, alert):
        self.alerts.append(alert)


def _finding(category, severity="high", location="/"):
    return Finding(asset="http://example.com", category=category, title=category,
                   severity=severity, confidence="high", detector="t", detector_version="1",
                   evidence="seen", location=location)


def _job(findings, state=jobs.JobState.COMPLETED):
    job = jobs.Job(target="http://example.com", profile="web", actor="system", policy={})
    job.state, job.findings = state, findings
    return job


@pytest.fixture
def monitor():
    m = Monitor(audit_chain=AuditChain())
    m.alert_sinks = [Collect()]
    return m


def _run(m, job):
    asyncio.run(m._evaluate("http://example.com", job))
    return m.alert_sinks[0].alerts


def test_first_cycle_is_a_baseline_and_never_alerts(monitor):
    assert _run(monitor, _job([_finding("sqli", "critical")])) == []


def test_new_high_severity_finding_alerts_once(monitor):
    _run(monitor, _job([_finding("xss", "low")]))
    alerts = _run(monitor, _job([_finding("xss", "low"), _finding("sqli", "critical")]))
    assert [a["rule_name"] for a in alerts] == ["new_finding"]
    assert alerts[0]["severity"] == "critical"
    # Unchanged on the next cycle: no repeat alert
    assert len(_run(monitor, _job([_finding("xss", "low"), _finding("sqli", "critical")]))) == 1


def test_low_severity_changes_do_not_alert(monitor):
    _run(monitor, _job([]))
    assert _run(monitor, _job([_finding("missing_csp", "low")])) == []


def test_failed_run_alerts_and_does_not_reset_the_baseline(monitor):
    _run(monitor, _job([_finding("sqli", "critical")]))
    alerts = _run(monitor, _job([], state=jobs.JobState.FAILED))
    assert alerts[-1]["rule_name"] == "assessment_incomplete"
    # The failed run said nothing about findings, so the known issue is not "new"
    assert len(_run(monitor, _job([_finding("sqli", "critical")]))) == 1


@pytest.mark.parametrize("url", [
    "http://example.com/hook",            # not https
    "https://user:pw@example.com/hook",   # embedded credentials
    "https://127.0.0.1/hook",             # loopback
    "https://169.254.169.254/latest",     # cloud metadata
    "https://10.0.0.5/hook",              # private range
    "https://hooks.example.com/hook?access_token=secret",  # credential in query
])
def test_webhook_urls_must_be_https_and_public(url):
    assert validate_webhook_url(url) is not None


def test_audit_chain_detects_tampering():
    chain = AuditChain()
    for i in range(3):
        chain.append({"event": "e", "n": i})
    assert chain.verify() == (True, None)
    chain._entries[1]["n"] = 99
    assert chain.verify()[0] is False


def test_audit_log_is_bounded_redacted_and_tenant_filtered():
    log = AuditLog(max_entries=3)
    for i in range(5):
        log.record({"event": "e", "tenant": "a" if i % 2 else "b", "n": i})
    assert [e["n"] for e in log.entries()] == [2, 3, 4]
    assert {e["tenant"] for e in log.entries(tenant="a")} == {"a"}
    log.record({"event": "x", "note": "password=hunter2"})
    assert "hunter2" not in str(log.entries()[-1])
