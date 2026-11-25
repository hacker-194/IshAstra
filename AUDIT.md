# Phase 0 — Baseline Audit

**Repository:** `hacker-194/IshAstra`
**Commit audited:** `a6360d1` (`main`, 2026-11-25)
**Audit date:** 2026-11-25
**Method:** read the repository, run the shipped checks locally, query the
GitHub security APIs, and trace the enforcement path in the adapters. Nothing
in this document is inferred from marketing copy; each claim names its evidence.

---

## 1. Baseline results (real output)

Local environment: Python 3.14.4 virtualenv, SQLite default database.
CI additionally runs SQLite and PostgreSQL on Python 3.12, 3.13 and 3.14.

| Check | Command | Result |
|-------|---------|--------|
| Lint | `ruff check src tests scripts` | **pass** — "All checks passed!" |
| Format | `ruff format --check src tests scripts` | **pass** — 256 files already formatted |
| Types | `mypy src/` | **pass** — no issues in 143 source files |
| Tests | `pytest -q` | **pass** — 1874 passed, 24 skipped, 42 warnings in 84.6 s |
| Bandit | `bandit -r src -f json` | 134 findings: **0 HIGH**, 48 MEDIUM, 86 LOW |
| pip-audit | `pip-audit -f json` | **4 vulnerable packages**, 30 advisory entries |
| Grype | CI-only report | **not generated locally** (binary absent) |
| Security gate | `python scripts/security_gate.py` | **fail** — "30 HIGH/blocking finding(s)", "required report not found: grype-results/grype-results.json" |

The 24 local skips are PostgreSQL-dependent integration tests
(`tests/integration/test_pg_queue.py`, `test_pg_job_transitions.py`,
`test_verifier_read_only.py`, `tests/test_rls.py`) that require
`ISHASTRA_TEST_PG_DSN`. The CI PostgreSQL matrix sets it and those jobs pass.

### Vulnerable packages (pip-audit)

| Package | Version | Notes |
|---------|---------|-------|
| `fastmcp` | 0.4.1 | only reachable through the optional `hexstrike` extra |
| `in-toto` | 1.4.0 | only reachable through the optional `slsa` extra |
| `pip` | 25.1.1 | build/install tool, not a runtime dependency |
| `tornado` | 6.5.10 | transitive dependency |

The gate fails closed on all of them by design. Severity triage is Phase 2.

---

## 2. GitHub security inventory (real counts)

Queried with `gh api` on 2026-11-25.

**Open code-scanning alerts: 400**

| Tool | Error | Warning | Note | Total |
|------|-------|---------|------|-------|
| CodeQL | 47 | 37 | 138 | 222 |
| Trivy | 18 | 41 | 67 | 126 |
| Scorecard | 52 | 0 | 0 | 52 |

Top rules:

- `Scorecard / PinnedDependenciesID` — 39
- `CodeQL / py/empty-except` — 33
- `CodeQL / py/unused-global-variable` — 23
- `CodeQL / py/unused-import` — 19
- `CodeQL / py/import-and-import-from` — 19
- `CodeQL / py/log-injection` — 18
- `CodeQL / py/path-injection` — 9
- `Trivy / KSV-0125`, `KSV-0104`, `KSV-0021` — Kubernetes/Helm misconfigurations

**Open secret-scanning alerts: 2**, both Amazon AWS *example* access-key IDs
(`ASIAIOSFODNN7EXAMPLE`, `ASIA4M7Q7UWXAMPLEKEY`) in
`tests/security/test_redaction_fuzzing.py`. These are redaction test fixtures,
not live credentials. They still need an explicit dismissal with a written
reason (Phase 2).

**Dependabot alerts:** could not be read — the current `gh` token lacks the
required scope. This is an audit limitation, not evidence of zero alerts.

---

## 3. What works end to end (with evidence)

| Capability | Evidence |
|------------|----------|
| Scope Gate: URL/host, DNS/IP and pinned-destination checks | `tests/unit/test_scope_gate.py`, `tests/security/test_scope_gate_adversarial.py` |
| Signed scope documents, key rotation, break-glass dual approval | `tests/unit/test_scope_signing.py`, `test_scope_breakglass.py`, `test_scope_jti.py` |
| Assessment API and CLI (`/api/assess`, `assess run/status/list/submit`) | `tests/test_api_routes.py`, `tests/unit/test_assessments.py` |
| Queue modes: in-process, SQLite, Redis Streams, PostgreSQL | `tests/unit/test_queue.py`, `test_redis_queue.py`, `tests/integration/test_pg_queue.py` |
| Proof packs, signed evidence bundles, offline verification | `tests/unit/test_proof.py`, `test_bundle.py`, `test_evidence_signing.py` |
| Findings, assets, trends, SLA and remediation tracking | `tests/test_api_routes.py`, `tests/unit/test_store.py` |
| SBOM, release signing and PyPI trusted publishing workflows | `.github/workflows/release.yml`, `.github/workflows/publish.yml` |
| Helm chart renders and lints | `helm lint deploy/helm/ishastra` (pass), `helm template` (pass) |
| TLA+ claim of 21,458,641 states | committed run output in `docs/tla/model-check-results.txt` |

## 4. Experimental, optional or stubbed

| Area | Status |
|------|--------|
| `k8s-jobs` queue | Experimental, labelled as such in README; one Kubernetes Job per assessment |
| Kubernetes operator/CRDs | Shipped, but not exercised by the default test suite |
| `hexstrike` extra (`fastmcp`, Selenium, mitmproxy…, angr) | Optional, heavy, carries the vulnerable `fastmcp` pin |
| `advise` command | Local model, off by default |
| Consent policy (`docs/consent-policy.md`) | Explicitly "Draft — not yet implemented" |
| Plugin template and `tcp_port_scanner` | `enforcement = "none"` (in-process only) |
| MSSP/partner model | Removed from architecture; organization/team model remains |

---

## 5. Enforcement reality (the Phase 1 problem)

The README headline says the gate validates "before any connection is made".
That is true for in-process HTTP adapters, which use the scoped HTTP client, but
it is **not unconditionally true for external tools**:

| Adapter | Declared enforcement | Actual behaviour |
|---------|----------------------|------------------|
| `HTTPAdapter`, `CrawlerAdapter`, `OpenAPIAdapter`, `DynamicValidationAdapter`, `SSRFOOBAdapter`, `AuthorizationDiffAdapter` | in-process scope checks | outbound requests use the scoped client |
| `NmapAdapter` | `proxy` | adds `--proxies <gateway>` **only when a gate context is supplied**; otherwise runs against the resolved IP directly |
| `NiktoAdapter` | `proxy` | adds `-useproxy` **only when a gate context is supplied**; otherwise runs directly |
| `SqlmapAdapter` | `proxy` | adds `--proxy` **only when a gateway URL is present**; otherwise runs directly |
| `TcpPortScanner` | `none` | direct socket connection, no proxy mode |
| Plugin template | `none` (default) | whatever the plugin author implements |

Code references: `src/ishastra/core/adapters.py` lines 1153, 1238–1239, 1335,
1547, 1624–1625, 1703, 1843–1845; `src/ishastra/plugins/tcp_port_scanner.py`
line 80; `src/ishastra/plugins/template.py` line 91.

So the accurate statement today is: **the gate decides before the action and
records it; in-process HTTP paths are pinned to the authorized destination, and
external tools are proxied only when the caller supplies a gateway context.**
Phase 1 must either make the proxy mandatory (fail closed when it is missing) or
reword the claim.

---

## 6. Documentation that disagrees with the code

| Location | Claim | Reality |
|----------|-------|---------|
| `README.md` headline | "before any connection is made" | external tools fall back to direct connections without a gateway context (section 5) |
| `README.md` footer | "Free forever" | `free`, `pro` and `enterprise` tiers and a pricing API exist |
| `README.md` capability table | capability tokens are "Unforgeable" | they are Ed25519-signed; forgery requires the private key, not impossible |
| `README.md`, `docs/index.md` | "compliance-ready" | mappings and evidence packs exist; there is no certification or audit opinion |
| `docs/security/audit-report.md` | queue accepts `inprocess`, `redis-streams`, `k8s-jobs` | code also supports `sqlite` and `postgres` |
| `docs/compliance/*.md` | implies SOC 2 / NIST / ISO / PCI evidence export | the CLI generates NRB, NTA and NCSP packs only; the docs now say so |
| `docs/consent-policy.md` | consent API routes | labelled draft; no consent router exists |
| `README.md` | "not yet published to PyPI" | true today; the trusted-publishing workflow exists but has never run |

Claims that **are** backed and should stay: the TLA+ state count, default-deny
scope validation, signed evidence bundles, offline proof verification, and the
single-writer database lease.

---

## 7. Phase 1 priorities (proposed)

1. Make `enforcement == "proxy"` fail closed: refuse to execute nmap, nikto or
   sqlmap when no gateway URL is supplied, instead of connecting directly.
2. Add per-adapter integration tests that assert denial plus an audit receipt
   for out-of-scope host, out-of-scope IP, rebinding hostname, redirect, and
   private/link-local address.
3. Add the gate-bypass suite (IPv6/mapped IPv6, decimal/octal/hex, trailing
   dots, userinfo, punycode, ports, TOCTOU).
4. Add the TLA+ invariant → test mapping table to `docs/scope-gate/`.

## 8. Audit limitations

- Dependabot alert count could not be retrieved with the current token.
- Grype and the container scans run only in CI, not in this local environment.
- The PostgreSQL integrations were exercised by CI, not this local run.
- No third-party security review has been performed; none is claimed.
