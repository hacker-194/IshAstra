# Strix Product Strategy

Status: working draft for validation. Date: 2026-11-14. Basis: repository
inspection of the current working tree (v3.5.0). Everything in "Validated" is
observable in code; hypotheses are labelled and must not be presented as market
fact. Strix is a fully open-source MIT project, not a commercial product plan.

## 1. The problem

A small security team or consultancy doing authorized application assessments
has four tools, four exports and no defensible answer to one question: **was
this action authorized, and can we prove what was tested?**

- Scanners produce findings in incompatible formats.
- Authorization lives in an email, a PDF or a ticket, not in the tool.
- "No findings" is indistinguishable from "the scan did not run".
- Clients and auditors cannot verify a report offline.
- Larger vulnerability platforms are priced and operated for large teams.

## 2. Who it is for (hypothesis)

Primary users: **5–50 person security consultancies and software agencies** that
run authorized web/API assessments and need repeatable evidence.

Secondary users: **internal application-security teams at SMEs** that need a
self-hosted, auditable assessment workflow without a large platform contract.

Tertiary users: **regional regulated environments** where in-country,
self-hosted assessment is a requirement. The repository already carries
Nepal-focused evidence templates and deployment notes.

This is an open-source project. There is no buyer, paid seat, sales motion or
commercial edition. Anyone may adopt, modify or redistribute it under MIT.

## 3. What Strix can do today (validated)

| Capability | Evidence in repository |
|---|---|
| Default-deny scope gate (URL, DNS/IP, pinned destination) | `src/strix/core/scope.py`, tested by `tests/unit/test_scope.py` |
| Versioned per-tenant engagement policies | `src/strix/core/policies.py`, `/api/policies` |
| Normalized findings with CWE, CVSS, impact, exploitability, compliance refs | `src/strix/core/findings.py` |
| Finding lifecycle and audited triage | `/api/assess/{id}/findings/{fingerprint}` |
| Asset inventory and per-finding history | `assets`, `finding_events`, `/api/assets`; derived from assessments |
| Cross-job finding records | Stable fingerprints aggregated by `/api/findings`, with first/last seen, occurrence history, tenant remediation and resolution |
| Finding trends | `GET /api/findings/trends` with day/week/month buckets and a 30-day inline chart |
| Remediation owner, deadline and risk-exception fields | `finding_records`, `/api/findings/{fingerprint}/remediation` and the legacy per-assessment path |
| Coverage-checked resolution | `/api/findings/{fingerprint}/resolve` requires a later completed job and `ok` detector coverage |
| SARIF 2.1.0 export | `/api/assess/{id}/sarif`, `strix-code-scan --sarif` |
| Signed grants, hash-chained receipts, offline proof packs | `src/strix/proof.py`, `strix grant/gate/proof/verify` |
| JSON, HTML and PDF evidence reports | `/api/report`, `/report.html`, `/report.pdf` |
| Recurring assessments and new-finding alerts | `src/strix/core/scheduler.py`, `/api/schedules`, monitor webhooks |
| Multi-tenant API keys, rotation, expiry, read/write scope, audit chain | `src/strix/api/security.py`, `/api/audit` |
| Multiple users per tenant with `admin`/`analyst`/`viewer` roles | `tenant_users`, `/api/users`; the legacy tenant key remains |
| Local SAST/SCA/secret scanning | `src/strix/code_scan.py` (Semgrep, Bandit, Trivy) |
| Advisory AI triage with no tool execution | `src/strix/analyst.py`, `/api/assess/{id}/triage` |
| SIEM/ticketing/chat/CI connectors | `src/strix/integrations/` |
| Single-node self-hosted deployment | `Dockerfile`, `docker-compose.yml`, `DEPLOYMENT.md` |

Read/write API key scopes are implemented; a read key is limited to safe HTTP
methods. Still absent (validated by schema and route inventory): an organization
entity, per-project/per-endpoint key scopes, organization-level role
inheritance, SSO, remote repository onboarding, pull-request comments,
long-term compliance dashboards and multi-node HA. Fail-closed `STRIX_ENV=production` startup is
implemented.

## 4. Differentiation

1. **Authorization is the product, not a settings page.** Every outbound
   connection is gated, policies are versioned and revocable, jobs are bound to
   the policy version they ran under, and Strix Proof produces signed grants and
   receipt chains that a third party can verify offline.
2. **Evidence over verdicts.** Coverage-aware job states, explicit verification
   levels, redaction at output boundaries, sealed audit history and portable
   reports. A failed or partial scan can never be presented as clean.
3. **One normalized model from scan to SARIF to report.** Built-in scanners,
   external tools and local code scanning land in the same finding schema.
4. **Operable by one team on one node.** SQLite and a single process by default;
   no mandatory SaaS, no mandatory Redis, no microservices.
5. **No open-core trap.** Every feature in the repository is MIT; security
   controls cannot be bought.

Not differentiators: detector count, template library size, SAST language
coverage or enterprise fleet scale. Do not market on those axes.

## 5. Open-source commitment

- License: MIT, with no proprietary edition and no feature gating.
- No billing, subscription, seat metering or paid support requirement.
- Anyone may host Strix, including as part of an independent service; that is a
  right under MIT, not an offering of this project.
- API tier names are technical rate-limit profiles only.

## 6. MVP definition

The MVP is the current single-node product, hardened:

1. Create an admin key and register a tenant key.
2. Authorize targets through a policy (managed mode) or scope document.
3. Run `web`, `api` or `network` assessments.
4. Review normalized findings, owners, deadlines and lifecycle state.
5. Export SARIF, JSON, HTML/PDF and, where required, a Proof pack.
6. Schedule a repeat assessment and receive a new-finding alert.

MVP exit criterion: a consultancy completes one real authorized engagement,
including an evidence pack a client accepts, without reading source code or
editing the database.

Not in the MVP: long-term compliance dashboards, remote repository connection, PR
comments and multi-node HA. Organizations, teams and OIDC/SAML SSO shipped after
this draft and are part of the current build.

## 7. Adoption plan (non-commercial)

1. Publish the open-source repository with a reproducible demo and detection lab.
2. Recruit design partners from consultancies and agencies for feedback; no
   payment or commercial conversion is involved.
3. Run supervised pilots and publish case studies with permission.
4. Add the highest-friction missing workflow revealed by users, expected to be
   organization/engagement management, not more detectors.
5. Grow contributors and integrations through public issues and documentation.

Distribution: GitHub, adapter/rule contributions, security-community talks and
regional public-interest deployments. **Phase 1 is free**: no paid tier, no
hosted offering, no pilot fee. Paid services, if any, are gated on the exit
criteria in [`commercialization.md`](commercialization.md) and never withhold a
feature.

## 8. Product metrics

Activation: first authorized assessment completed within 30 minutes of install.
Value: percentage of engagements with an exported evidence pack; repeat scans
per asset per month.
Trust: jobs with partial/failed coverage correctly labelled; Proof verification
success rate; zero cross-tenant incidents.
Community: external pull requests merged, time to first review and active
deployments.

Avoid vanity metrics: number of adapters, number of findings, lines of code and
download counts alone.

## 9. Risks

- Scope-gate bugs are existential; any bypass destroys the trust thesis.
- Detector breadth will always lose to Nuclei/Semgrep/Trivy; integrate, do not
  imitate.
- Single-node SQLite limits large multi-tenant hosting; the project does not
  operate a hosted service.
- AI features can erode trust if they appear to alter findings; keep the analyst
  advisory and visibly optional.
- Compliance language must remain evidence-oriented, never certification claims.

## 10. Validation plan (next 30 days)

1. Ten structured interviews with consultancies/agencies; record current tools,
   authorization workflow and report acceptance criteria.
2. Three supervised pilots on the current build.
3. Measure time-to-first-report and report acceptance.
4. Decide the next highest-friction workflow from pilot evidence, not revenue.
