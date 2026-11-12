# Strix Startup Execution Plan — 12 Weeks to Pilot-Ready SaaS

**Goal:** Transform Strix from a hardened CLI/library into a multi-tenant SaaS platform that 2-3 design partners can pilot and pay for.

---

## Week 1-2: Foundation Hardening (Unblock Everything Else)

### Must-Do (P0)
| Task | Owner | Done When |
|------|-------|-----------|
| Built-in forward migrations in `strix.core.store` (no Alembic dependency) | Backend | Fresh SQLite DB reaches schema v9 at startup |
| **PostgreSQL** for the threaded worker (shared queue required first) | Backend | `STRIX_DATABASE_URL=postgresql://...` runs jobs cleanly |
| Add **OIDC/SSO** (Authlib + Starlette) — support Auth0, Azure AD, Okta, Google | Backend | `STRIX_OIDC_*` env vars → login flow works |
| Add **RBAC** model: Org → Workspace → Project → Role (admin/member/viewer) | Backend | API enforces roles on all endpoints |
| **API versioning** (`/api/v1/...`) + OpenAPI spec generation | Backend | `GET /api/openapi.json` valid |

### Should-Do (P1)
| Task | Owner | Done When |
|------|-------|-----------|
| Replace single-process worker with **Celery + Redis** (broker + result backend) | Backend | Multiple workers consume from queue |
| Add **Alembic** migration for Celery task metadata (job_id, status, result) | Backend | Schema versioned |
| Structured **audit log** for admin actions (user invite, role change, policy CRUD) | Backend | Queryable via API |

### Exit Criteria Week 2
- [ ] `docker compose up` → PostgreSQL + Redis + API + Worker all healthy
- [ ] `pytest -x` passes (all existing tests green)
- [ ] Can create org, invite user via OIDC, assign role, create scope, run scan via API

---

## Week 3-4: Continuous Scanning & Asset Inventory

### Must-Do (P0)
| Task | Owner | Done When |
|------|-------|-----------|
| **Target Registry** CRUD API: `POST /targets`, `GET /targets`, `PATCH /targets/{id}`, `DELETE` | Backend | Targets persist, scoped to project |
| **Schedule** model: cron expression, profile, enabled, next_run_at | Backend | Scheduler enqueues jobs on cron |
| **APScheduler** (or Celery beat) integration for schedule execution | Backend | Jobs fire on schedule, visible in UI |
| **Finding State Machine**: `new → triaged → in_progress → fix_verified → closed` (with `reopened` and `deferred` branches) | ✅ Complete | Backend | State transitions audited, API enforces valid moves |
| **Finding Deduplication** across runs (fingerprint-based) | Backend | Re-scan doesn't create duplicate `new` findings |

### Should-Do (P1)
| Task | Owner | Done When |
|------|-------|-----------|
| **Asset Change Detection**: new subdomain, new port, tech stack change | Backend | Diff findings between runs, flag deltas |
| **Cloud Asset Sync** (MVP): AWS EC2/ALB → targets (read-only, tagged) | Backend | `strix sync aws --profile prod` creates targets |
| **SLA Tracking** by severity (configurable per org) | Backend | Dashboard shows overdue findings |

### Exit Criteria Week 4
- [ ] Create target → schedule daily `web-deep` → findings appear with state `new`
- [ ] Re-run → existing findings move to `verified`/`regressed`, new ones are `new`
- [ ] SLA dashboard shows correct overdue counts

---

## Week 5-6: Vulnerability Management & Integrations

### Must-Do (P0)
| Task | Owner | Done When |
|------|-------|-----------|
| **Jira Integration** (OAuth 2.0): push findings as issues, sync status back | Backend | Finding `in_progress` ↔ Jira `In Progress` bidirectional |
| **GitHub Issues Integration** (GitHub App): same as Jira | Backend | Finding ↔ GitHub Issue bidirectional |
| **Slack Alerts**: webhook per workspace, configurable severity threshold | Backend | P1 finding → Slack message in < 30s |
| **Suppression/Exception Workflow**: create, expiry, audit trail | Backend | Suppressed findings hidden from SLA, auto-expire |

### Should-Do (P1)
| Task | Owner | Done When |
|------|-------|-----------|
| **Risk Scoring**: CVSS + exploitability + asset criticality | ✅ Complete | `risk_score` on every finding, sortable |
| **Bulk Operations**: multi-select findings → change state, assign, suppress | API + UI | 50 findings → bulk triage in one request |

### Exit Criteria Week 6
- [ ] Finding triaged in Strix → Jira issue created → Jira status change → Strix finding state updates
- [ ] P1 finding triggers Slack alert with link to finding
- [ ] Suppression with 90-day expiry auto-reopens finding

---

## Week 7-9: SAST/SCA Integration (Unified Platform)

### Must-Do (P0)
| Task | Owner | Done When |
|------|-------|-----------|
| **Semgrep Adapter**: run Semgrep OSS rules + custom rule packs | Backend | `strix assess --profile sast` runs Semgrep, outputs SARIF |
| **Dependency Scanning Adapter**: OSV.dev + GitHub Advisory DB | Backend | `strix assess --profile sca` finds vulnerable deps |
| **Unified Finding Model**: normalize SAST/DAST/SCA into single `Finding` schema | Backend | All three adapters produce compatible findings |
| **Cross-Engine Deduplication**: same CWE + location + fingerprint → one finding | Backed | DAST XSS + SAST XSS on same line = 1 finding |

### Should-Do (P1)
| Task | Owner | Done When |
|------|-------|-----------|
| **IaC Scanning Adapter**: checkov or tfsec for Terraform/K8s/Helm | Backend | `strix assess --profile iac` works |
| **Reachability Analysis** (MVP): call graph from finding to public entrypoint | Backend | SAST finding tagged `reachable`/`unreachable` |

### Exit Criteria Week 9
- [ ] Single scan runs DAST + SAST + SCA → unified SARIF → unified HTML report
- [ ] Finding shows `detection_methods: ["dast", "sast"]` when both engines agree
- [ ] Semgrep custom rule pack loads and executes

---

## Week 10-11: Compliance & Enterprise Polish

### Must-Do (P0)
| Task | Owner | Done When |
|------|-------|-----------|
| **Compliance Pack Framework**: pluggable (SOC2, PCI-DSS, ISO 27001, HIPAA) | Backend | `strix evidence --framework soc2` works |
| **Executive Dashboard**: risk trend, SLA compliance, coverage, top findings | Frontend + API | `/dashboard` shows actionable metrics |
| **API Keys per Project** (scoped, rotatable, auditable) | Backend | CI/CD uses project key, not org admin key |
| **Terraform Provider** (read-only: targets, findings, schedules) | Backend | `terraform plan` shows Strix resources |

### Should-Do (P1)
| Task | Owner | Done When |
|------|-------|-----------|
| **SCIM Provisioning** (Okta/Azure AD) | Backend | User sync works |
| **Custom Report Builder** (drag-drop sections, export PDF) | Frontend | Non-technical stakeholder can build report |

### Exit Criteria Week 11
- [ ] SOC2 evidence pack generates with control mappings
- [ ] Dashboard loads in < 2s for 10k findings
- [ ] Terraform provider reads targets/findings

---

## Week 12: Pilot Hardening & Launch Prep

### Must-Do (P0)
| Task | Owner | Done When |
|------|-------|-----------|
| **Load Test**: 50 concurrent scans, 10k findings, verify no deadlocks | Backend | P95 latency < 5s, zero data loss |
| **Security Review**: pen test scope gate, authZ, redaction, audit chain | Security | No CRITICAL/HIGH findings |
| **Documentation**: API reference, integration guides, admin runbook | Docs | New user can onboard in < 30 min |
| **Billing Integration** (Stripe): subscription, usage-based overages | Backend | `strix billing portal` works |

### Should-Do (P1)
| Task | Owner | Done When |
|------|-------|-----------|
| **Onboarding Wizard**: create org → connect SSO → add target → first scan | Frontend | 5-click first scan |
| **Status Page** (uptime, incident history) | Infra | Public status page |

### Exit Criteria Week 12 (PILOT READY)
- [ ] **Design Partner A** (50 devs): onboarded, scanning daily, findings in Jira
- [ ] **Design Partner B** (200 devs): SAST+DAST unified, compliance pack for SOC2
- [ ] **Design Partner C** (agency): multi-client, project isolation, white-label reports
- [ ] All three paying (even $1) or signed LOI

---

## Parallel Tracks (Run Throughout)

| Track | Weeks | Owner |
|-------|-------|-------|
| **Frontend Dashboard** (React/Next.js + shadcn/ui) | 1-12 | Frontend |
| **Automated Tests** (unit + integration + contract) | 1-12 | QA/Backend |
| **CI/CD Pipeline** (GitHub Actions → staging → prod) | 1-2 | DevOps |
| **Observability** (OpenTelemetry → Grafana/Loki/Tempo) | 3-4 | DevOps |
| **Customer Conversations** (2-3 calls/week) | 1-12 | Founder |

---

## Resource Plan (Solo Founder + 1 Contractor)

| Role | Weeks 1-4 | Weeks 5-8 | Weeks 9-12 |
|------|-----------|-----------|------------|
| **Founder** | Backend core (DB, auth, worker) | Integrations (Jira, GitHub, Slack) | SAST/SCA, compliance, pilot onboarding |
| **Contractor (Frontend)** | Dashboard scaffolding, auth UI | Finding management UI, Jira sync UI | Dashboard, report builder, onboarding wizard |
| **Contractor (DevOps, part-time)** | CI/CD, staging, observability | Load testing, security hardening | Production deploy, status page |

---

## Success Metrics (Week 12)

| Metric | Target |
|--------|--------|
| Scan success rate | > 99% |
| API P95 latency | < 500ms |
| Finding deduplication accuracy | > 95% (manual spot-check) |
| Design partners active | 3 |
| Design partners paying/LOI | 3 |
| Time to first scan (new org) | < 15 min |
| Test coverage (core) | > 80% |

---

## Risk Mitigation

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| SAST/SCA integration scope creep | High | High | Fix Semgrep + OSV scope; defer reachability, IaC to post-pilot |
| OIDC edge cases (enterprise IdP quirks) | Medium | High | Test against Auth0, Azure AD, Okta, Google in Week 1-2 |
| Celery worker reliability at scale | Medium | High | Load test Week 12; use Redis Streams as backup queue |
| Competitor launches similar feature | Low | Medium | Focus on *authorized-first* + *audit chain* differentiators |
| Founder bandwidth | High | High | Contractor handles frontend; ruthless scope cutting |

---

## Post-Pilot (Week 13+) — Full Priority Backlog

### Phase 2: Vulnerability Management & Scale (Weeks 13-20)
| Priority | Item | Source |
|----------|------|--------|
| P0 | **Jira Integration** (OAuth 2.0) bidirectional sync | Priority #3 |
| P0 | **GitHub Issues Integration** (GitHub App) bidirectional sync | Priority #3 |
| P0 | **Slack/Teams/PagerDuty Alerts** configurable thresholds | Priority #3 |
| P0 | **Suppression/Exception Workflow** with expiry & audit trail | Priority #3 |
| P0 | **Risk Scoring**: CVSS + EPSS + asset criticality | ✅ Complete |
| P0 | **Bulk Operations** on findings (state, assign, suppress) | Priority #3 |
| P1 | **ServiceNow Integration** (enterprise req) | Priority #5 |
| P1 | **Linear/Asana/ClickUp** connectors | Priority #5 |
| P1 | **SIEM Export**: Splunk, Elastic, Datadog, Sentinel (CEF/JSON) | Priority #5 |
| P1 | **SCIM Provisioning** (Okta/Azure AD) | Priority #5 |
| P1 | **Terraform Provider** (full CRUD) | Priority #5 |
| P1 | **OpenAPI SDK** (Python/TypeScript) | Priority #5 |

### Phase 3: SAST/SCA/IaC Unified Platform (Weeks 20-32)
| Priority | Item | Source |
|----------|------|--------|
| P0 | **Semgrep Adapter** (OSS rules + custom packs) | Priority #4 |
| P0 | **Dependency Scanning** (OSV.dev + GitHub Advisory) | Priority #4 |
| P0 | **Unified Finding Model** (SAST/DAST/SCA normalized) | Priority #4 |
| P0 | **Cross-Engine Deduplication** (fingerprint-based) | Priority #4 |
| P1 | **IaC Scanning** (checkov/tfsec for TF/K8s/Helm) | Priority #4 |
| P1 | **Reachability Analysis** (call graph to entrypoint) | Priority #4 |
| P1 | **SBOM Generation** (CycloneDX/SPDX) | Priority #4 |
| P1 | **License Compliance** scanning | Priority #4 |

### Phase 4: Cloud/Infra & Compliance Expansion (Weeks 32-44)
| Priority | Item | Source |
|----------|------|--------|
| P0 | **CSPM-lite**: AWS/GCP/Azure posture checks | Priority #4 (cloud/infra) |
| P0 | **Kubernetes Admission Controller** integration | Priority #4 |
| P0 | **Container Image Scanning** (Trivy/Gryp) | Priority #4 |
| P1 | **PCI-DSS Evidence Pack** | Priority #4 (compliance) |
| P1 | **ISO 27001 Evidence Pack** | Priority #4 |
| P1 | **HIPAA Evidence Pack** | Priority #4 |
| P1 | **FedRAMP/NIST 800-53** mappings | Priority #4 |
| P1 | **Custom Compliance Framework Builder** | Priority #4 |

### Phase 5: Enterprise Platform (Week 44+)
| Priority | Item | Source |
|----------|------|--------|
| P0 | **SSO/SAML/OIDC** (beyond Auth0) | Priority #1 |
| P0 | **Advanced RBAC** (resource-level, conditions) | Priority #1 |
| P0 | **Audit Log Streaming** (to SIEM, S3, GCS) | Priority #1 |
| P1 | **On-prem / Air-gapped Deployment** | Priority #5 |
| P1 | **Custom Detector SDK** (customer-written adapters) | Priority #5 |
| P1 | **ML-based Finding Prioritization** | Priority #4 |

---

## Refactor/Remove Track (Continuous)

| Item | Reason | Target |
|------|--------|--------|
| **SQLite single-process worker** | Won't scale | Week 1-2 (Celery) |
| **Nepal-only compliance packs** | Too narrow | Extract to plugin (Week 13) |
| **In-process collab listener** | Single-host only | Replace with managed service (Week 13) |
| **Hardcoded Nuclei template subset** | Users need control | Profile-driven selection (Week 20) |
| **No migration system** | Schema changes break | Built-in migrations (done) |
| **Single API key auth** | Enterprise requires SSO | OIDC (Week 1-2) |

---

## Launch Sequence (Revenue Gates)

| Gate | Criteria | Target Date |
|------|----------|-------------|
| **Alpha** | 1 design partner scanning daily, findings in GitHub Issues | Week 8 |
| **Beta** | 3 design partners, SOC2 pack, Stripe billing, Streamlit dashboard | Week 12 |
| **Public Launch** | 10 paying customers, $5k MRR, public docs, status page | Week 20 |
| **Series A Ready** | $100k ARR, 3 logos, net revenue retention > 110% | Week 44 |

---

## Original 12-Week Pilot Plan (Unchanged)
*See sections above for Weeks 1-12 detail.*