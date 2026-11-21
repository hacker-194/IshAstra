# Ishastra Customer Workflows

Status: verified against the current working tree on 2026-11-14. Each step is
marked **Implemented**, **Partial** or **Missing**. "Partial" means a real
mechanism exists but a customer-facing requirement is unmet; it is not a claim
of completeness.

## Workflow A — First-time organization setup

| Step | Status | How it works today |
|---|---|---|
| Create organization | Implemented | `POST /api/v2/orgs`; organizations group tenants and support member management, OIDC/SAML SSO and SCIM 2.0. Phase 1 has no billing. |
| Configure administrator | Implemented | `ISHASTRA_API_KEY` bootstraps an admin key at startup. |
| Create tenant | Implemented | `POST /api/keys/create` (admin), raw key shown once. |
| Configure authorization policy | Implemented | `POST /api/policies` (admin, managed mode). |
| Register authorized assets | Partial | Authorization still lives in the policy's hosts/networks. Assessments now populate a tenant-scoped asset inventory with owner, criticality and last-seen; there is no explicit asset-registration or policy-linkage step yet. |
| Verify scope | Implemented | `GET /api/scope` shows the caller only its own policy; `POST /api/probe` for a single check. |
| Run initial assessment | Implemented | `POST /api/assess` with `web`, `api` or `network` profile. |
| Review findings | Implemented | `GET /api/assess/{id}`, triage via `PATCH .../findings/{fingerprint}`. |
| Export security report | Implemented | `POST /api/report`, `GET .../report.html`, `GET .../report.pdf`, `GET .../sarif`. |

Blocking gap for a first-time organization: onboarding multiple humans into one
organization, assigning roles, and seeing the organization (not one key) as the
unit of ownership.

## Workflow B — Application security assessment

| Step | Status | How it works today |
|---|---|---|
| Register an application | Partial | Add its host to an engagement policy. No application record, owner or metadata. |
| Verify authorization | Implemented | Policy validity/window and gate checks; job binds policy id + version. |
| Discover permitted endpoints | Implemented | `web-crawl` crawler and `api`/`api-deep` OpenAPI discovery, bounded to same origin and scope. |
| Run selected profiles | Implemented | `web`, `web-crawl`, `web-deep`, `api`, `api-deep`, `ports`, `network`. |
| Normalize findings | Implemented | `core/findings.py`; dedupe by asset/category/location; CWE/CVSS/impact fields. |
| Calculate risk | Implemented (model, not validated) | Severity × asset criticality × exploitability with documented thresholds. Treat as a prioritization heuristic, not a certified CVSS implementation. |
| Generate evidence | Implemented | Coverage-aware job record, redacted evidence, audit chain, reports. |
| Export SARIF | Implemented | Per-job SARIF 2.1.0; code scanning has its own SARIF output. |
| Track remediation | Implemented (no notifications) | Status lifecycle plus tenant-level owner, deadline, an immutable timeline, and coverage-checked resolution against a later job. Risk exceptions use an audited request → administrator decision workflow; expiry is computed on read. |

## Workflow C — Continuous security monitoring

| Step | Status | How it works today |
|---|---|---|
| Register an authorized asset | Partial | `POST /api/monitor/configure` with validated targets; assessments derive an asset inventory, but monitoring configuration is not itself an asset-onboarding record. |
| Configure a schedule | Implemented | `POST /api/schedules` with cron expression and timezone. |
| Reassess within approved scope | Implemented | Scheduler submits jobs; each run re-validates authorization. |
| Compare with history | Implemented | Cross-job finding records show first/last seen and occurrence history; `/api/findings/trends` reports bounded day/week/month counts. Monitor baseline detects newly appeared high findings. |
| Identify new findings | Implemented | Baseline diff for alerting. |
| Alert responsible teams | Implemented | Log sink and signed webhook sink; Slack/Teams connectors exist. |
| Track resolution | Implemented | Explicit resolution verification requires a later completed job on the same asset, no matching fingerprint, and an `ok` run for every detector that observed it. Partial coverage is refused. |
| Produce security trends | Partial | `/api/findings/trends` plus an inline 30-day chart in the Assets tab. No long-term compliance dashboard. |

## Workflow D — Developer security

| Step | Status | How it works today |
|---|---|---|
| Connect an authorized repository | Missing | Only a local checkout path is supported; remote repository acquisition is not implemented. |
| Perform local code/dependency analysis | Implemented | `ishastra-code-scan PATH` with packaged Semgrep rules, Bandit and Trivy. |
| Generate SARIF | Implemented | `ishastra-code-scan --sarif`. |
| Integrate with CI/CD | Partial | CI/CD connectors can format/send payloads; no verified end-to-end GitHub App or GitLab pipeline workflow. |
| Report findings in pull requests | Missing | No PR comment/check-run integration. |
| Track remediation | Partial | Status lifecycle, owner/deadline and timeline in the platform; code-scan findings are not automatically linked to a repository identity. |
| Verify fixes | Partial | A re-scan can show the issue absent, but "not observed" is not distinguished from "scan incomplete" in a code-scan history because there is no history store. |

Do not market remote repository scanning, PR annotations or automatic fix
verification until these exist and are tested against real providers.

## Workflow E — Security consultant engagement (strongest today)

| Step | Status | How it works today |
|---|---|---|
| Create engagement | Partial | Engagement = versioned policy + optional Proof grant. No engagement record with client, dates, scope history or status beyond the policy. |
| Record client authorization | Implemented | Policy fields (authorized_by, authorization_ref, program, validity) and signed Proof grants. |
| Define permitted targets | Implemented | Policy hosts/networks/ports; broad-network override is explicit and auditable. |
| Execute assessment | Implemented | API or CLI under the policy/grant; worker re-validates before scanning. |
| Collect evidence | Implemented | Normalized findings, coverage, redacted evidence, sealed audit chain. |
| Review findings | Implemented | Triage lifecycle with audited transitions. |
| Generate professional reports | Implemented | JSON evidence bundle, self-contained HTML, PDF (WeasyPrint). |
| Produce verifiable Proof package | Implemented | `ishastra proof` / `POST /api/proof/verify`, offline verification, pinned issuer key. |

This is the workflow to validate first: it is the only one that is
substantially complete end to end today.

## Cross-workflow truth table

| Requirement | State |
|---|---|
| Authorization before every connection | Yes |
| Tenant isolation on reads/writes | Yes (tested) |
| Coverage-aware verdicts | Yes |
| Per-finding history | Yes (per job/finding; cross-job records at `GET /api/findings`) |
| Finding owner/deadline | Yes |
| Finding exception/risk acceptance | Fields only (API; no approval workflow) |
| Asset inventory | Yes (derived from assessments; no explicit registration) |
| Scoped/read-only API keys | Yes for read/write; read keys are limited to safe HTTP methods. Tenants also support multiple member keys with admin/analyst/viewer roles. |
| Production fail-closed startup | Yes (`ISHASTRA_ENV=production`) |
| Organization/RBAC/SSO | No |
| Billing/paid tiers | Not planned; all features are MIT |
| Remote repository onboarding | No |
| Long-term trend analytics | Partial (366-day API; no compliance dashboard) |

## Recommended next workflow investment

1. **Organization and roles** before any multi-user deployment; today a tenant
   is still one API key.
2. **Verified resolution**, using the existing cross-job record and stable
   fingerprint so a clean later job can prove a finding was fixed rather than
   hidden by incomplete coverage.
3. **Exception/risk-acceptance workflow** (approval, notifications, expiry
   sweep) and date-range trend reporting.
