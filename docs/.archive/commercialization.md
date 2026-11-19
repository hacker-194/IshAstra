# Commercialization: Phase 1 is free

Status: current policy. Date: 2026-11-16.

Phase 1 of Strix charges nobody. The repository is MIT, every feature is
included, and pilots are free. This document records that decision, what it
costs, and the conditions that would have to be met before any paid phase is
considered. It is a policy statement, not a price list and not an offer.

## Phase 1 (now): free

- **All features, no gating.** Scope enforcement, adapters, findings, Proof,
  reports, monitoring, API, UI, SSO/SCIM and deployment tooling are MIT.
- **Free pilots.** Design partners and pilot deployments pay nothing: no fee,
  no card, no trial countdown, no usage metering. Evidence packs produced during
  a pilot belong to the pilot client.
- **No billing code.** There is no subscription, seat metering, invoice,
  entitlement check or plan-based feature flag in the codebase.
- **Support is best-effort.** GitHub issues and documentation only. There is no
  SLA, no on-call rotation and no hosted service operated by the project.
- **Honest limits.** Single-node SQLite is the supported pilot deployment;
  PostgreSQL and Kubernetes Jobs are experimental single-host paths; there is no HA.

Free is a deliberate choice for this phase: the product needs real engagements
and accepted evidence packs far more than it needs revenue.

## Exit criteria for Phase 1

Phase 1 ends only when all of these are true. No date is promised.

1. At least three supervised pilots complete a real authorized engagement and
   the client accepts the evidence pack.
2. An independent security review covers the scope gate, tenant isolation, the
   Proof chain, redaction, cancellation and secret handling.
3. The detection benchmark in `docs/detection-benchmark.md` is reproducible by a
   third party and published alongside the release.
4. A support runbook exists (triage, escalation, backup/restore, key rotation)
   and has been exercised at least once.
5. A legal and support structure exists that can sign a contract in the target
   jurisdiction (initially Nepal).

## Phase 2 (not started): optional paid layer, still MIT

Any future revenue comes from services around the software, never from
withholding a feature.

| Candidate | What is sold | What stays free |
|---|---|---|
| Support retainer | Response times, named maintainer, upgrade reviews | The software and every feature |
| Deployment and audit sprint | In-country setup, hardening, evidence-pack review | The software and every feature |
| Training | Assessment and Proof workflow training | Documentation and the software |
| Managed hosting | Operated instance (deferred; not planned for Phase 1 or 2a) | Self-hosting under MIT |

Rules that do not change in Phase 2:

- No open-core split, no paid edition, no feature gated by plan.
- MIT remains the license for everything in the repository.
- A paid layer may not weaken the authorization, tenant-isolation or Proof
  invariants.
- Tier names (`free`, `pro`, `enterprise`) remain rate-limit profiles, not
  prices.

## Pricing hypothesis (unvalidated, for planning only)

These are ranges to test with design partners, not commitments. They are
included because investors asked for a pricing hypothesis; nothing here is
charged in Phase 1.

| Segment | Hypothesis | Basis |
|---|---|---|
| 5-50 person consultancy | $5k-15k/year support retainer | Replaces ad-hoc consulting hours; priced per firm, not per seat |
| Regulated enterprise / bank | $25k-50k/year retainer + one-time deployment sprint | Compliance evidence and in-country deployment carry real support load |
| Deployment/audit sprint | $10k-25k one-time | 1-2 weeks of engineering plus evidence review |
| Hosted SaaS | Deferred | Would require HA, multi-node and an independent review first |

Validation gates before publishing any price: ten structured design-partner
interviews, three accepted evidence packs, one independent security review, and
a support runbook that has been used at least once.

## What Phase 1 will not do

- Charge for pilots, seats, scans, evidence packs or API access.
- Add billing, entitlement or metering code.
- Claim an ARR figure, a customer count or a conversion rate it cannot show.
- Operate a hosted service for third parties.
- Present compliance mappings as certifications.

## Status summary for diligence

- License: MIT, all features.
- Revenue in Phase 1: zero by design.
- Paid contracts in Phase 1: none.
- Phase 1 exit: gated on pilots, an independent review, a reproducible
  benchmark and a support runbook, in that order.
