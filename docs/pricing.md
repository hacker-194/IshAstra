# Pricing & Design Partner Program

## Design Partner Program

We are recruiting 3-5 design partners for the v4.0 GA release (Q1 2027). Design partners get:

- **Free lifetime PRO tier** (up to 50 concurrent assessments)
- **Direct engineering access** — Slack channel with core team
- **Roadmap influence** — Priority on features you need
- **Co-marketing** — Joint case study, logo on site (with approval)
- **Early access** — Pre-release builds, new adapter betas

### Who qualifies

| Profile | Example |
|---------|---------|
| Internal security team | 50-500 employee company running continuous assessments |
| Pentest boutique | 5-20 consultants delivering client engagements |
| MSSP / MDR provider | Managed detection & response needing assessment automation |
| Compliance team | SOC 2 / ISO 27001 evidence automation |

### Commitment

- Weekly 30-min sync during onboarding (first 4 weeks)
- Monthly 30-min sync thereafter
- Run ≥ 5 assessments/month on authorized targets
- Share sanitized feedback (no customer data)

### Apply

Email: `design-partners@ishastra.io` with:
1. Company & team size
2. Current assessment workflow
3. Top 3 pain points with existing tools
4. Authorized target scope (internal, client, or both)

---

## Pricing Tiers (v4.0 GA — Subject to Change)

| Feature | FREE | STARTER | PRO | ENTERPRISE |
|---------|------|---------|-----|------------|
| **Monthly assessments** | 10 | 100 | 500 | Unlimited |
| **Concurrent jobs** | 1 | 3 | 10 | 50+ |
| **Queue mode** | In-process | In-process | Redis Streams | Redis + K8s Jobs |
| **Database** | SQLite | SQLite | PostgreSQL | PostgreSQL HA |
| **Tenants** | 1 | 3 | 10 | Unlimited |
| **Organizations / Teams** | ❌ | ❌ | ✅ | ✅ |
| **RBAC (Admin/Analyst/Viewer)** | ❌ | ❌ | ✅ | ✅ |
| **SSO (OIDC/SAML)** | ❌ | ❌ | ❌ | ✅ |
| **SLSA Provenance** | ❌ | ✅ | ✅ | ✅ |
| **Evidence bundles (NRB/NTA/NCSP)** | ✅ | ✅ | ✅ | ✅ |
| **Audit chain verification** | ✅ | ✅ | ✅ | ✅ |
| **Scope Gate (TLA+ verified)** | ✅ | ✅ | ✅ | ✅ |
| **Capability tokens / Egress gateway** | ❌ | ❌ | ✅ | ✅ |
| **Disaster recovery runbooks** | ✅ | ✅ | ✅ | ✅ |
| **Warm standby promotion** | ✅ | ✅ | ✅ | ✅ |
| **Plugin framework** | ✅ | ✅ | ✅ | ✅ |
| **Template allowlist (Nuclei/NSE)** | ✅ | ✅ | ✅ | ✅ |
| **Support** | Community | Email (48h) | Email (24h) | Slack + Phone (4h) |
| **SLA** | ❌ | 99.5% | 99.9% | 99.95% |

**FREE tier** is self-hosted only (your infrastructure, your data). No cloud account required.

**STARTER/PRO/ENTERPRISE** available as:
- Self-hosted (your cloud, your keys)
- Managed cloud (IshAstra-hosted, dedicated tenancy) — contact sales

---

## FAQ

**Is the FREE tier really free forever?**
Yes. No credit card, no trial expiry, no telemetry. Apache-2.0 license.

**Can I upgrade from self-hosted to managed later?**
Yes. Export/import assessment data via `ishastra export` / `ishastra import-sarif`.

**What counts as an "assessment"?**
One job execution against an authorized target. A 500-page web app scan = 1 assessment.

**Do you charge per finding?**
No. Unlimited findings per assessment.

**Is there a volume discount?**
Enterprise tier includes volume pricing. Contact sales.

**What payment methods?**
Annual invoice (net-30), credit card via Stripe. No crypto.

---

## Contact Sales

`pricing@ishastra.io` — response within 1 business day.