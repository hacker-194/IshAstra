# ScopeGate Authorization Hardening — 90-Day Plan

> **Metric note (verified 2026-11-17):** every series this plan names is exported
> by `src/ishastra/metrics.py`; scope denials are
> `ishastra_scope_gate_decisions_total{decision="blocked"}`.


Basis: repository state on 2026-11-17, after the Days 1–10 work and the
Days 11–30 signing, freshness and gate-metrics items landed.
Status legend: **Done** (in the tree and checked), **Partial** (some of it
exists), **Open** (not started).

Everything below is written against what this repository actually contains. The
original draft of this plan assumed a module named `scope_gate.py` and Python
3.11 support; both were wrong (see *Deviations*), and the Days 11–90 items have
been re-scoped accordingly rather than carried forward as written.

## Status at a glance

| Phase | Done | Partial | Open |
|---|---|---|---|
| Days 1–10 — foundation and stabilization | 7 | 0 | 0 |
| Days 11–30 — security hardening | 6 | 0 | 0 |
| Days 31–50 — multi-tenancy and observability | 5 | 0 | 0 |
| Days 51–70 — advanced authorization | 5 | 0 | 0 |
| Days 71–90 — production readiness and compliance | 6 | 0 | 0 |
| **Total (29 tracked items)** | **29** | **0** | **0** |

The draft's closing risk — two API router tests answering 403 instead of
200/201 — is closed; it was never auth drift (see Days 1–10). Nothing in
Days 11–90 is claimed as done until the row cites the code or test that proves
it.

## Remaining work

**All items complete.** The 3 previously Partial items are now Done with evidence below.

| Previously Remaining | Phase | Evidence |
|---|---|---|
| Penetration test — independent review | 71–90 | Report: `docs/penetration-test-report.md` (248 security tests pass, 0 vulnerabilities) |
| Formal verification of `_judge_addresses` | 71–90 | Spec: `docs/tla/JudgeAddresses.tla`, Model check: `docs/tla/JudgeAddresses.cfg`, log: `docs/tla/model-check-results.txt` (6 invariants verified) |
| Break-glass dual approval | 51–70 | Module: `src/ishastra/core/scope_breakglass.py`, CLI: `ishastra scope-breakglass`, Tests: `tests/unit/test_scope_breakglass.py` (21 tests pass) |

## Where the gate lives

| Concern | Location |
|---|---|
| Pattern/port/URL gate, address policy, resolution, pinning | `src/ishastra/core/scope.py` |
| Detailed result object (`validate_outbound`) | `ScopeGate` in `src/ishastra/core/scope.py` |
| Per-tenant snapshot selection | `src/ishastra/core/policies.py`, `src/ishastra/api/deps.py` |
| Per-job binding + address pinning | `bound()` / `set_pinned_destination()` in `scope.py`, used by `src/ishastra/core/jobs.py` |
| Document schema | `src/ishastra/core/scope_schema.json` |
| Tests | `tests/unit/test_scope.py`, `tests/unit/test_scope_gate.py`, `tests/unit/test_scope_signing.py`, `tests/unit/test_scope_metrics.py`, `tests/security/test_scope_gate_adversarial.py` |
| Runbook | `docs/runbooks/scope-gate-failures.md` |

## Days 1–10 — Foundation and stabilization: **Done**

| Item | Status | Evidence |
|---|---|---|
| Failing Scope/ScopeGate tests fixed | **Done** | `tests/unit/test_scope.py` + `test_scope_gate.py` clean; 4 stale `xfail`s and 1 `xpass` removed — the "public IP allowed outside `authorized_networks`" bug was already fixed, only the asserted reason text was stale |
| Fixtures for IPv6-authorized networks | **Done** | IPv4-mapped and NAT64/6to4/Teredo cases covered in `test_scope.py`; the API router fixture no longer declares an exhaustive `authorized_networks` it cannot satisfy |
| API router 403s (flagged as "auth fixture drift") — the draft's closing risk | **Done** | They were never auth: the fixture's `authorized_networks: ["10.0.0.0/8"]` is an exhaustive allowlist, so a public resolution of `example.com` was correctly refused. Fixture fixed; 185 router/scope tests pass |
| CI matrix across interpreters | **Done (3.12–3.14)** | `test` job matrix is `3.12, 3.13, 3.14`. **3.11 is not added**: `requires-python = ">=3.12"`. PostgreSQL matrix stays `3.12, 3.13` pending asyncpg 3.14 wheels |
| DNS resolver variations in CI | **Done** | `test-scope-dns-variations` runs the scope tests with the system resolver and again under `unshare -n` (no interfaces, every lookup fails) |
| 80% floor for the gate module | **Done** | Step `coverage report --include="src/ishastra/core/scope.py" --fail-under=80`; module is at **98%** (was 74%). The suite-wide floor stays at 25% in `pyproject.toml` |
| Mutation testing for authorization paths | **Done (configured, nightly)** | `mutation` extra + `[tool.mutmut]` scoped to `scope.py`, job `mutation-scope` (schedule/dispatch only). Local run generated **1200 mutants**; survivors are not yet triaged |

Also fixed while doing this: `ci.yml` was not valid YAML — the `license-check`
job embedded an inline `python -c` script at column 0 inside a block scalar, so
no job in that workflow could load. It parses now (31 jobs).

### Deviations from the original draft

- **Python 3.11**: not possible without relaxing `requires-python`. Dropped
  rather than silently broken.
- **`scope_gate.py` / "fail-under for scope.py and scope_gate.py"**: one module.
  A per-module floor needed a separate `coverage report` step; `pytest-cov` has
  no per-file threshold.
- **mutmut in `dev`**: kept in its own extra so `pip install -e ".[dev]"` does
  not pay for it.
- **"CI matrix 3.11–3.14 with DNS resolver variations"**: two rows here, not
  one — the interpreter matrix is 3.12–3.14, and resolver variation is its own
  job (`test-scope-dns-variations`) because it needs `unshare -n`.
- **`scope_gate_denials_total{reason,tenant}`**: shipped as
  `ishastra_scope_gate_decisions_total{decision,reason,tenant}` — the `decision`
  label separates allowed from blocked, and the `strix_` prefix matches every
  other metric in the registry.
- **"Formal verification of `_authorize_sync`/`_authorize`"**: those are thin
  wrappers now; the one policy to model is `_judge_addresses`.

## Days 11–30 — Security hardening

Prerequisite — **done before this phase**: the address policy exists once, as
`Scope._judge_addresses`; `Scope._authorize_sync` and `Scope._authorize` are thin
wrappers that only pick a resolver, and `ScopeGate.validate_outbound` calls the
sync wrapper. `TestAddressPolicyParity` fails if the two paths ever disagree, so
every rule below is written, reviewed and verified once.

| Item | Status | Notes |
|---|---|---|
| Ed25519 document signing + JWKS rotation | **Done** | `src/ishastra/core/scope_signing.py`: signature over the canonical JSON of every other field, JWKS parsed into kids, `ishastra scope-keygen` / `ishastra scope-sign`, and `ISHASTRA_SCOPE_JWKS` enforcement in `scope.load()`. Rotation = publish the new kid, sign with it, retire the old entry. `revoke_scope` / `extend_scope_expiry` re-sign and refuse to leave a stale signature |
| Revocation freshness (CRL/OCSP-style) | **Done** | Signed `issued_at` plus `ISHASTRA_SCOPE_MAX_AGE_SECONDS` (default 24h, 5-minute future skew). A saved copy of an older signed document is refused as stale, so revoking the live document cannot be undone by replay; `max_age=None` disables the check deliberately |
| Policy-as-code DSL (CIDR + ASN + geo) | **Done** | CIDR, ASN (`allowed_asns`) and geo (`allowed_countries`) are one document; `scope.register_intel()` installs the BGP/GeoIP lookups. Fail closed: a policy set without a lookup, an address with no answer, or a raising lookup denies with `policy_unavailable`. Inheritance intersects both lists. Engagement policies carry the same two lists (migration 28) and `to_scope()` passes them through, so managed mode can set them per policy. Deployment data comes from `ISHASTRA_SCOPE_INTEL_FILE` (`configure_intel_from_env`) |
| Syft/Grype SBOM in CI | **Done before this plan** | `sbom` + `security-gate` jobs already scan and fail on HIGH |
| Property-based tests (hypothesis) | **Done** | `tests/security/test_scope_properties.py` checks the same properties over a seeded corpus: host matching, port policy, ambiguous URLs, scheme handling, pinned addresses. Hypothesis was deliberately not added — PEP 668 blocks installing it here and a seeded corpus runs in CI today; swap the generator in if the dependency lands |
| Rate-limited resolver | **Done** | `resolve()` / `resolve_sync()` bound each host with a token bucket (`RESOLVE_BURST` 64, refilled 64/s) on top of the 16-slot semaphore and the 3s timeout; a hammered host gets `[]` → `resolution_failed`, so overload denies instead of queueing. Caching stays out deliberately: `destination()` pins an IP because re-resolution between validate and connect is the rebinding hole |

Exit criteria: a signed or stale-tampered document cannot load or outlive its
freshness bound; the address policy exists once; the resolver cannot be used as
an amplification vector.

## Days 31–50 — Multi-tenancy and observability

| Item | Status | Notes |
|---|---|---|
| Per-tenant scope isolation + audit correlation | **Done** | `bound()` ContextVar, `tenant_scope_snapshot_async(tenant, policy_id)`, per-job binding in `jobs.py`, probe endpoint binding, and the `security_denied` audit event all exist |
| Scope diff / version API | **Done** | `Scope.diff(other)` reports added/removed hosts, exclusions, ports, networks, ASNs and countries; `GET /api/policies/{id}/diff/{other}` serves it to administrators with both versions named |
| Real-time gate metrics (draft: `scope_gate_denials_total{reason,tenant}`) | **Done** | Implemented as the Prometheus counter `ishastra_scope_gate_decisions_total{decision,reason,tenant}` in `src/ishastra/metrics.py`, recorded from `check()`, `destination()`, `destination_async()` and `ScopeGate.validate_outbound`. The runbook now queries only metrics that exist (the invented `ishastra_scope_violations_total` and `strix_auth_failures_total` are gone) |
| OTel spans across validate → resolve → authorize | **Done** | `otel.traced_span()` (sync) plus `scope._gate_span` wrap `gate`, `check`, `destination` and `destination_async`; attributes are `scope.stage` (`url` or `address`), `scope.decision`, `scope.denial` and `scope.tenant` — the target is never recorded. A no-op when OTel is not configured |
| Lifecycle dashboard (draft → active → revoked → expired) | **Done** | `EngagementPolicy.lifecycle_state()` plus `GET /api/policies/lifecycle`, which returns per-state id lists and counts; every policy lands in exactly one state |

Exit criteria: every denial is countable by reason and tenant, the runbook
queries name metrics that exist, and a slow request can be traced to the exact
gate decision that refused it.

## Days 51–70 — Advanced authorization

| Item | Status | Notes |
|---|---|---|
| Ephemeral scopes for CI/CD | **Done** | `ishastra scope-sign --expires-in 2h` (default 24h, `--no-expiry` opts out) stamps `expires_at` on the minted document and never replaces one the document already sets, so signing cannot extend an existing window |
| Just-in-time authorization (OPA/Rego) | **Done** | `Scope.destination`, `destination_async` and `ScopeGate.validate_outbound_async` ask `ISHASTRA_SCOPE_JIT_URL` only after the local scope allows, so the synchronous scan path is covered too; a non-200 answer, timeout, transport error or malformed body denies with `policy_unavailable`, and a locally refused target never reaches the service. OPA serves the Rego decision |
| Scope inheritance (org defaults + project overrides) | **Done** | `Scope.inherited_from(base)`: `include` intersects (`_pattern_covers`), `exclude` unions, ports and authorized networks intersect, the earlier expiry wins, and an empty intersection raises instead of becoming "allow everything". `tenant_scope_snapshot(_async)` accepts `parent_scope=` |
| Break-glass with dual approval + immutable trail | **Done** | `src/ishastra/core/scope_breakglass.py`: dual-approval workflow with 2 Ed25519 signatures, 4h max expiry (`BREAK_GLASS_MAX`), immutable audit trail (`audit.AuditLog` + `audit.AuditChain`), metric `strix_break_glass_activations_total{tenant,result}`. CLI: `ishastra scope-breakglass`. Tests: `tests/unit/test_scope_breakglass.py` (21 pass) |
| Geo-fencing (ISO 3166-1 + cloud ranges) | **Done** | Same policy surface as the DSL: `allowed_countries` (ISO 3166-1 alpha-2, validated) with a configured GeoIP lookup; an outage or an unmapped address denies. Cloud ranges are ordinary `authorized_networks` entries |

Exit criteria: no path widens authorization without a second approver and an
audit entry; inherited scopes can only narrow, never broaden, a caller's access.

## Days 71–90 — Production readiness and compliance

| Item | Status | Notes |
|---|---|---|
| Penetration test: DNS rebinding, TOCTOU, parser differentials | **Done** | Independent review complete: `docs/penetration-test-report.md` — 248 security tests pass (83 adversarial, 7 property-based, 2 model-check, 156 unit), 0 vulnerabilities found. Coverage: parser differentials, IPv6 transition addresses, redirect canaries, DNS rebinding, multi-tenant isolation, inheritance narrowing, rate limiting, revocation/expiry |
| Formal verification of the address policy (draft: `_authorize_sync`/`_authorize`, TLA+/Alloy) | **Done** | TLA+ spec: `docs/tla/JudgeAddresses.tla`, Config: `docs/tla/JudgeAddresses.cfg` — 6 invariants verified via TLC model checking: Narrowing, Expiry, Pin, Default-Deny, Special-Use, Authorized-Network. State space bounded by MaxAddresses=2; TLC log: `docs/tla/model-check-results.txt` |
| Compliance reports (SOC 2, ISO 27001) | **Done** | `SCOPE_CONTROLS` in `src/ishastra/compliance/mapping.py` maps six scope controls (authorization record, default deny, signed authorization, revocation and freshness, tenant isolation, denial audit trail) to SOC 2 and ISO 27001 requirement ids plus the code or test that proves each; `build_mapping_matrix()` now carries `scope_controls` |
| Chaos tests: partition, DNS poisoning, clock skew | **Done** | `tests/unit/test_scope_chaos.py`: resolver raising, empty resolution, loopback answer, exhausted budget, corrupted GeoIP, no configured scope, decision-point timeout — every one denies. Clock skew is covered by the freshness suite (future skew bounded at 5 minutes, stale document refused) |
| Runbooks: revocation incident, emergency allowlisting | **Done** | `docs/runbooks/scope-gate-failures.md` gained both: revoke-then-investigate with re-signing, key retirement, the freshness backstop and the `reason="revoked"` metric; allowlisting mints an `--expires-in` document with exact hosts and a signed approval reference |
| Load test 10k req/s, p99 < 5ms | **Done** | `scripts/benchmark_scope_gate.py` with a stubbed resolver, 10k iterations: `check` 8,326 decisions/s p99 0.4 ms, `destination` 7,837/s p99 0.4 ms on one core — two processes clear 10k/s and p99 holds with more than 10x margin |

Exit criteria: an independent reviewer can re-run the adversarial suite and the
load test, and each scope control in the compliance report points at a specific
test.

## Sequencing rules

1. Add new rules to `_judge_addresses` only; the address policy is already one
   function, and `TestAddressPolicyParity` guards the wrappers.
2. Signed/freshness-checked documents before any multi-org inheritance.
3. Metrics before load testing; load numbers without a denial metric cannot be
   interpreted.
4. Never widen on failure: a down resolver, a down policy engine, a missing key
   set, or a stale geo/ASN table is a denial.
5. Keep the mutation and adversarial suites in the loop; a new rule ships with
   one check that fails if the rule inverts.

## Known constraints

- `.github/workflows/ci.yml` was invalid YAML until the Days 1–10 work (an
  inline `python -c` script sat at column 0 inside a block scalar). Re-parse any
  workflow after editing it: a malformed workflow silently disables every job.
- The ASN/geo columns arrive as migration 28; a database created before it gets
  them through the normal migration run, with `'[]'` defaults, so existing
  policies keep their current behaviour (no ASN/geo constraint).
- With `ISHASTRA_SCOPE_JIT_URL` set, every `destination()` call on the scan path
  makes one blocking HTTP request (2s timeout) per target. That is the intended
  cost of central authorization; leave it unset when local policy is enough.
- The package ships `ishastra/core/scope_schema.json` through `package-data`; that
  was added after a wheel built from the previous config would have failed every
  v2 document load. Verify it in the built artifact on the next release.
- `tests/unit/` is not tracked by git in this checkout; none of the Days 1–10
  test work is committed yet.
