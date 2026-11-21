# Ishastra Security Audit

Date: 2026-11-13. Method: source inspection, route/schema inventory, and targeted
test runs. This is **not** an independent penetration test, code audit or
certification. It records what was verified, what was found, and what remains
unverified.

> **Post-audit status (2026-11-14).** Findings F1, F3, F4, F6, F7 and F8 are
> fixed in the current working tree: the queue is selected by routers,
> cancellation is persisted and checked by the Celery worker, tenant roles and
> member keys are implemented, assets/finding events/remediation are implemented,
> live nmap/Nuclei run in CI against a loopback lab, and the OpenTelemetry
> duplicate declaration is resolved. F5 (SQLite unencrypted at rest) remains an
> operator responsibility. Organizations and OIDC/SAML SSO were added after this
> review and are covered by `test_organizations.py` and `test_sso_auth.py`. The original
> findings are kept below for traceability; this is still not an independent audit.

## 1. Scope

In scope: API authentication and tenant isolation, scope enforcement, policy
binding, finding lifecycle, redaction, audit chain, proof verification, request
body handling, worker/queue selection, report/export paths, AI analyst
boundaries.

Out of scope: live exploitation testing, infrastructure penetration testing,
third-party dependency code review, WeasyPrint/nmap/nuclei internals, legal
compliance certification.

## 2. Controls verified in code and tests

| Control | Evidence |
|---|---|
| Default-deny scope gate with URL, DNS/IP and pinned-destination layers | `core/scope.py`; `tests/unit/test_scope.py` (the test suite passes) |
| Policy version binding and re-validation before execution | `core/jobs.py`, `core/policies.py`; policy/API tests |
| Tenant derived from validated key, never headers | `api/security.py` `resolve_identity` |
| Cross-tenant reads return 404 | `_get_job_or_404`, tenant-filtered store queries |
| Audit chain verification at startup and on demand | `audit.py`, `/api/audit/verify`, `/api/ready` cached check |
| Redaction at output boundaries | `core/redaction.py`; finding/SARIF/report tests |
| Request body size and JSON depth limits | `api/body_depth.py`; the test suite passes after correction |
| Proof signature, chain, scope and time-window verification | `proof.py`; the test suite passes |
| AI cannot change findings or execute tools | `analyst.py`; triage accepts only existing fingerprints and output is sanitized; 96 analyzer tests pass |
| Admin-only policy and key administration | `require_admin`; policies/tenant routers |

## 3. Findings from this audit

### Fixed

**F1 — Distributed queue was not used by API routers (high).**
`api/app.py` started the queue selected by `ISHASTRA_QUEUE_MODE`, but the
assessment and policy routers imported the concrete in-process
`worker.assessment_worker`. In Celery mode, submissions and policy-revocation
cancellations therefore stayed in the API process while the Celery worker
listened on Redis. Routers now obtain the queue through
`core.queue.get_assessment_worker()`; the in-process singleton was removed.
Tests continue to patch the router attribute. Verified by import checks and the
assessment/queue tests.

**F2 — Two body-depth tests asserted the wrong semantics (low, assurance).**
`json_depth` counts every object and array container, consistent with its other
tests. The mixed-nesting case is five containers, not four, and `{"a": 1}` is
depth one, not two, so a "reject at depth 2 with limit 1" test was not testing
rejection. Assertions corrected; middleware behavior unchanged. This is a test
integrity fix, not a weakened assertion.

### Open

**F3 (fixed 2026-11-14) — Celery cancellation did not cross process boundaries (medium).**
`CeleryAssessmentQueue.cancel()` set a flag on a `Job` object in the API process,
while the Celery task rehydrated a different object. Cancellation is now a
durable database flag; the worker polls it, revokes queued task IDs and stops
running jobs cooperatively. Validated for running and queued jobs on one host.
Multi-node scheduling and crash recovery remain experimental.

**F4 — One key per tenant, read/write scope only (medium; fixed 2026-11-14).**
Tenants now support multiple member keys with `admin`, `analyst` and `viewer`
roles. Viewers are read-only, analysts can assess, and tenant admins manage
members and risk-exception decisions. Per-project/per-endpoint scopes and
organization-level roles remain future work.

**F5 — SQLite is unencrypted at rest (medium, deployment-dependent).**
Webhook destinations, findings, audit entries and metadata live in the database
file. File permissions are owner-only, but disk/volume encryption and database
access control are the operator's responsibility. Secret material is hashed or
redacted, but target and evidence data remain.

**F6 (fixed 2026-11-14) — No per-finding history or ownership (medium, compliance).**
Finding events are now immutable per-job/fingerprint records, and remediation
stores owner, deadline, exception expiry/reason and an approver string. Asset
inventory is derived from assessments, and `/api/findings` aggregates stable
fingerprints across jobs with first/last seen, tenant remediation and
coverage-checked resolution against a later job. Risk exceptions now use an
audited request/administrator-decision workflow with computed expiry. There is
still no notification or background expiry sweep.

**F7 — Live-tool integration test is environment-dependent (low).**
The nmap integration test fails when no scannable service is present; it took
~49 seconds and blocked a full-suite run. It should skip with an explicit reason
unless a fixture target is running. Stubbed ingestion tests remain valid but do
not prove a live engine finding.

**F8 — Dependency duplication (low).**
The OpenTelemetry package set is listed both in core dependencies and in the
`otel` extra. This increases maintenance and audit surface; resolve to one
declaration with a documented install path.

## 4. Threat model summary

| Threat | Current posture |
|---|---|
| Unauthorized scanning | Blocked by default-deny gate + policy binding; residual: operator misconfiguration |
| DNS rebinding / TOCTOU | Pinned destination after validation |
| Tenant data leakage | Key-derived tenant, filtered queries, 404 semantics; residual: admin keys are cross-tenant by design |
| Secret leakage in findings/reports | Redaction at boundaries; residual: novel secret formats and operator-authored evidence |
| Forged audit history | HMAC-keyed chain when configured; without the key, only naive tampering is detected |
| Malicious target content | Treated as untrusted; bounded parsing; AI output sanitized, no tool execution |
| Supply chain | pip-audit/Bandit in CI; optional tools not vendored; residual: live scanner binaries are operator-supplied |
| Denial of service | Body/rate limits; residual: expensive scans are bounded by worker concurrency, not per-tenant quotas |

## 5. Framework mapping (evidence support, not certification)

- **OWASP Top 10 / ASVS**: findings carry CWE and evidence; ASVS coverage is
  partial and must be assessed per engagement. No ASVS conformance claim.
- **CWE**: findings accept CWE identifiers; built-in rules map a subset.
- **CVSS**: a score field exists and SARIF emits severity bands. The internal
  risk heuristic is not a CVSS calculator; do not label it as such.
- **SARIF 2.1.0**: per-job and code-scan export.
- **NIST CSF / CIS Controls / OWASP SAMM**: only as report references where a
  finding supplies `compliance_refs`; no organizational maturity assessment.
- **SOC 2 / ISO 27001 / PCI DSS**: no certification or attestation. Ishastra can
  produce evidence that may support an audit; an auditor decides relevance.

## 6. Recommended security backlog

1. Scoped/read-only API keys — **implemented** as read/write scopes; per-project
   and per-endpoint scopes remain future work.
2. Tenant RBAC and member keys — **implemented**; organizations, teams and
   OIDC/SAML SSO — **implemented**.
3. Resolution evidence and an exception/approval workflow — **implemented**;
   notification and background expiry sweep remain future work.
4. Independent security review before any hosted-production claim.
5. Multi-node Celery/PostgreSQL soak, failover and crash-recovery testing before
   either is called production-ready.
6. Periodic backup/restore and key-rotation drills with recorded results.
