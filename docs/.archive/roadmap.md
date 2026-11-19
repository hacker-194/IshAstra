# Strix Implementation Roadmap

Basis: repository state on 2026-11-14. Releases are ordered by trust dependency,
not feature appeal. Do not start a later release while an earlier exit criterion
is unmet.

## Release 1 — Trust and stability (current)

Goal: a consultancy can run one authorized engagement end to end and defend the
result.

| Task | Status |
|---|---|
| Scope gate hardening and tests | Done; 46 scope tests pass |
| Proof verification and offline checks | Done; 49 proof tests pass |
| Tenant isolation and audit chain | Done; API/auth and asset-isolation tests pass |
| Finding integrity, redaction, SARIF | Done; model + export tested |
| Distributed queue actually selected by API routers | Done; k8s-jobs mode dispatches submissions and policy revocations |
| Durable cross-process cancellation | Done; persisted flag stops running jobs and cancels queued jobs; policy revoke sets it |
| Deterministic test suite | Done; 1426 passed / 0 failed / 14 skipped (64.97% coverage) |
| Remove duplicate/dead code and stale docs | Lint/format clean; readiness docs updated |
| Community files: code of conduct, issue/PR templates, changelog | Done |
| Backup/restore drill recorded | Done; 14 tables match, integrity ok, HMAC audit chain verified |
| Live nmap + Nuclei tests against deterministic loopback lab | Done locally (4 passed); CI installs nmap, pinned Nuclei v3.11.1 and templates |
| Dependency duplicates and Kubernetes Jobs compatibility | Done; OTel is opt-in, `redis>=6.1,<7.0` for Kubernetes Jobs 5.7 |
| Production fail-closed mode | Done; `STRIX_ENV=production` requires bootstrap, audit, and encryption keys; rejects debug mode and disabled rate limits; and disables API docs |
| CI valid and running on the default branch | Workflows parse locally; first GitHub run not yet observed |

Exit criteria:

- CI green on a clean checkout with no external scanner binaries.
- Live-tool tests skip with a clear reason when tools/services are absent.
- A backup → restore → verify-audit-chain rehearsal is recorded. **Done**
  (`scripts/operational_check.py --hmac-key`).
- Known limitations are documented and visible in the UI where relevant.
- No router path can bypass the selected queue or the scope gate.

## Release 2 — Team security platform

Goal: repeated work is manageable, not just possible.

| Capability | State |
|---|---|
| Asset inventory: identity, type, owner, criticality, first/last seen, finding counts | **Implemented** from persisted jobs/findings; no explicit registration or policy linkage yet |
| Finding history: immutable created/status-changed events | **Implemented** per job/finding; assigned/reopened events add status changes, not a separate assignment event |
| Remediation model: owner, deadline | **Implemented** at tenant level (`finding_records`), with the legacy per-job endpoint mirroring into it |
| Remediation exceptions/risk acceptance with expiry and approver | **Implemented** as request → administrator decision, audited and sealed. Expiry is computed on read; notifications/background sweep remain out of scope |
| Resolution evidence against a later scan | **Implemented** via `POST /api/findings/{fingerprint}/resolve`; requires complete detector coverage and refuses partial jobs |
| Cross-job finding identity (stable asset+category+location) | **Implemented** as `GET /api/findings` and `/api/findings/{fingerprint}`: aggregate first/last seen, occurrence count, remediation and per-job history |
| Finding trends | **Implemented** as `GET /api/findings/trends` with day/week/month buckets and an inline chart |
| Distinguish confirmed resolved / not observed / incomplete / failed / accepted | Partial; job verdict distinguishes coverage, and explicit resolution is coverage-checked, but accepted/exception state is not an approval workflow |
| UI: asset list, finding detail with timeline | **Implemented** (asset inventory/detail, owner/deadline, timeline) |
| Scoped/read-only API keys for CI and readers | **Implemented** as read/write scopes; read keys are limited to safe HTTP methods. |
| Multiple users per tenant and RBAC | **Implemented** as `admin`/`analyst`/`viewer` member keys. Organizations (`/api/v2/orgs`), OIDC/SAML SSO and SCIM 2.0 are implemented; organization-level billing does not exist (Phase 1 is free). |
| Developer workflow: repository identity and GitHub/GitLab checks | Missing |
| Tests for each workflow, including tenant isolation on assets/history | **Implemented** for store and API asset/history paths; broader workflow tests remain |

Exit criteria: a customer can answer "what is open on this asset, who owns it,
when is it due, and what changed since last month" without SQL. Owner, deadline,
cross-job identity, first/last seen and bounded date-range trends are answerable.

## Release 3 — Security intelligence

- Historical trends and coverage trends per asset/tenant.
- Finding correlation across detectors and jobs.
- Risk prioritization using validated inputs, with provenance.
- AI analyst providers: configurable local/hosted providers, explicit data
  handling, prompt-injection tests, no tool execution, advisory-only output.
- Evidence analysis summaries that cite fingerprints and never alter findings.

Exit criteria: every intelligence output is traceable to stored evidence and
degrades cleanly when no provider is configured.

## Release 4 — Open-source ecosystem

- Public adapter and connector plugin interfaces with versioned contracts.
- Contribution templates, code of conduct, changelog, release automation.
- Third-party license and dependency policy enforced in CI.
- Adapter conformance tests and a registry with support status.
- Public roadmap and security advisory process.

Exit criteria: an external contributor can add and test an adapter without
maintainer intervention, and a release can be produced from a tagged commit.

## Release 5 — Community scale, fully open source

Prerequisites: tenant roles, organizations/teams and OIDC/SAML SSO are implemented;
cross-job asset and finding history and a tested multi-node deployment remain. All work remains in the MIT repository:

- Advanced roles and organization-level policy defaults (base organization administration and SSO are implemented).
- Multi-user engagement and evidence workflows.
- Extended retention and compliance reporting.
- Centralized multi-organization management for agencies.
- Tested multi-node/HA deployment and operational runbooks.
- Community support and integration ownership.

There is no paid edition, billing system, seat metering or feature gated behind
a commercial plan. Exit criteria: independent security review, operational
runbooks exercised, and every feature still available under MIT.

## Next five engineering tasks (in order)

1. Commission an independent security review of scope enforcement, tenant
   isolation, Proof, redaction, cancellation and secret handling.
2. Harden organization administration (org-level policy defaults, invitations,
   team-scoped keys); organizations, multi-user roles and SSO are implemented.
3. Add an exception/risk-acceptance approval workflow with notifications and an
   expiry sweep on top of the tenant finding records.
4. Observe the first green GitHub Actions run and resolve any environment-only
   failures; keep live scanners pinned and skippable.
5. Run a representative multi-worker soak on SQLite and PostgreSQL, including
   cancellation and crash/restart, before making any availability or capacity
   commitment.

## Sequencing rules

- No paid edition or feature gating: every feature remains available under MIT.
- No PostgreSQL production claim before multi-node/HA and soak testing; the
  single-host worker path is now tested and remains experimental.
- No Kubernetes Jobs production claim before multi-node scheduling, idempotency and
  crash recovery are tested; cross-process cancellation is now implemented.
- No AI feature that can change findings or execute tools.
- No new detector before coverage and evidence semantics are correct.
