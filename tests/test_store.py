"""SQLite persistence: restart survival, tenant scoping, migrations, redaction."""
import sqlite3

from strix.core import jobs, store
from strix.core.findings import Finding


def make_finding(**overrides):
    base = dict(
        asset="http://example.com/", category="xss", title="Reflected XSS",
        severity="high", confidence="high", detector="strix-http",
        detector_version="3.1.0", evidence="marker reflected verbatim for q",
        location="http://example.com/?q", remediation="Encode output.", cwe="CWE-79",
    )
    base.update(overrides)
    return Finding(**base)


def make_job(tenant="acme", *, findings=None, state=jobs.JobState.COMPLETED, error=""):
    job = jobs.Job(target="http://example.com/", profile="web", actor=tenant,
                   policy={"authorization_ref": "ENG-1", "profile": "web"})
    job.state = state
    job.started_at, job.finished_at = 100.0, 102.5
    job.findings = findings if findings is not None else [make_finding()]
    job.error = error
    job.runs = [jobs.AdapterRun("strix-http", jobs.RunState.OK, "completed",
                                findings=len(job.findings), elapsed_ms=12.5)]
    return job


def test_job_round_trip_preserves_findings_and_coverage():
    job = make_job()
    store.save_job(job, tenant="acme")
    loaded = store.get_job(job.id, tenant="acme")

    assert loaded["id"] == job.id
    assert loaded["state"] == "completed"
    assert loaded["policy"]["authorization_ref"] == "ENG-1"
    assert loaded["duration_ms"] == 2500.0
    assert loaded["coverage"]["ok"] == 1
    finding = loaded["findings"][0]
    assert finding["evidence"] == "marker reflected verbatim for q"
    assert finding["verification"] == "observed"
    assert finding["fingerprint"] == make_finding().fingerprint
    assert finding["sources"] == ["strix-http"]


def test_job_survives_an_application_restart():
    job = make_job()
    store.save_job(job, tenant="acme")
    database = store.current_path()

    # Simulate a restart: fresh configuration over the same file
    store.configure(database)
    assert store.schema_version() == store.MIGRATIONS[-1][0]
    assert store.get_job(job.id, tenant="acme") is not None
    assert [item["id"] for item in store.list_jobs(tenant="acme")] == [job.id]


def test_store_enforces_tenant_isolation():
    job = make_job(tenant="acme")
    store.save_job(job, tenant="acme")

    assert store.get_job(job.id, tenant="other-co") is None
    assert store.get_job(job.id) is not None          # administrator view
    assert store.list_jobs(tenant="other-co") == []
    assert store.get_findings(job.id, tenant="other-co") == []
    assert len(store.get_findings(job.id, tenant="acme")) == 1


def test_failed_and_partial_states_are_preserved():
    failed = make_job("acme", findings=[], state=jobs.JobState.FAILED, error="no adapter could run")
    store.save_job(failed, tenant="acme")
    loaded = store.get_job(failed.id, tenant="acme")
    assert loaded["state"] == "failed"
    assert loaded["error"] == "no adapter could run"
    assert loaded["clean"] is False
    assert loaded["findings"] == []

    partial = make_job("acme", findings=[], state=jobs.JobState.PARTIAL)
    store.save_job(partial, tenant="acme")
    assert store.get_job(partial.id, tenant="acme")["state"] == "partial"


def test_duplicate_findings_do_not_multiply_on_resave():
    job = make_job()
    job.findings = [make_finding(), make_finding(evidence="second observation")]
    store.save_job(job, tenant="acme")
    store.save_job(job, tenant="acme")
    assert len(store.get_job(job.id, tenant="acme")["findings"]) == 1


def test_migrations_are_versioned_and_idempotent():
    versions = [version for version, _ in store.MIGRATIONS]
    assert versions == sorted(versions)
    assert len(versions) == len(set(versions))

    database = store.current_path()
    store.configure(database)
    first = store.schema_version()
    store.configure(database)          # re-running migrations must be a no-op
    assert store.schema_version() == first == versions[-1]


def test_evidence_is_redacted_at_rest():
    job = make_job(findings=[make_finding(category="secret",
                                          evidence="found api_key=sk_live_deadbeef in query")])
    store.save_job(job, tenant="acme")

    with sqlite3.connect(store.current_path()) as connection:
        blob = " ".join(str(value) for row in connection.execute("SELECT * FROM findings")
                        for value in row)
    assert "sk_live_deadbeef" not in blob
    assert "[REDACTED]" in blob
