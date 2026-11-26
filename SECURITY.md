# Security Policy

**Version:** 3.5.x · **Last updated:** 2026-11-19

IshAstra runs security tools, so the platform itself is held to the same standard:
default-deny authorization, tamper-evident audit, and no silent failure paths.
This page states what is supported, how to report a problem, and what we do and
do not claim.

## Supported versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 3.5.x | Yes | Active fixes |
| 3.4.x | Critical fixes only | Upgrade path is a restore-tested upgrade, see `DEPLOYMENT.md` |
| < 3.4 | No | — |

Only the latest release on `master` receives security fixes.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Use GitHub's private advisory flow:

1. Open <https://github.com/hacker-194/IshAstra/security/advisories/new>.
2. Describe the impact, affected version/commit, and a minimal reproduction.
3. If the report involves a live target, use only targets you are authorized to
   test.

There is **no paid bug bounty program** at this time. Reports are handled on a
best-effort basis by the maintainers; this is a community project, not a vendor
with a contractual SLA.

### What to expect

| Step | Target |
|------|--------|
| Acknowledgment | 5 business days |
| Triage and severity assessment | 10 business days |
| Fix or documented mitigation | 90 days for high/critical, or a public advisory if longer |
| Credit | Named in the advisory unless you ask otherwise |

If a report is not handled within those windows, you may disclose publicly after
coordinating with the maintainers.

## Scope

In scope:

- `src/ishastra/` (API, scope gate, adapters, audit chain, crypto, redaction)
- Shipped container image and Helm chart defaults
- Scope-document handling, signing, and break-glass flow
- Authentication and tenant isolation in the API

Out of scope:

- Operator infrastructure (cluster, cloud IAM, TLS termination, DNS)
- Findings produced by scanners against third-party targets
- Denial of service that requires unbounded resources
- Missing hardening headers on endpoints that are unauthenticated by design
  (`/api/health`, `/api/ready`)

## Security model (summary)

| Control | Implementation |
|---------|----------------|
| Default deny | Every outbound connection passes `scope.check()`/`scope.destination()`; adapters re-check |
| DNS rebinding | Validation returns a pinned `Destination` (scheme, host, port, IP); adapters connect to that IP |
| Tenant identity | Derived from a validated API key (SHA-256 at rest), never from a request header |
| Audit integrity | Append-only HMAC-sealed chain (`ISHASTRA_AUDIT_HMAC_KEY`), verified after restore |
| Secrets at rest | AES-GCM envelope encryption (`ISHASTRA_ENCRYPTION_KEY`) |
| Output hygiene | Redaction at every boundary (findings, SARIF, reports, logs, webhooks) |
| Container | Non-root `ishastra` user, read-only-friendly runtime, healthcheck |

Details: [`docs/scope-gate/concepts.md`](docs/scope-gate/concepts.md),
[`ARCHITECTURE.md`](ARCHITECTURE.md),
[`docs/quickstart/production.md`](docs/quickstart/production.md).

## Limitations

These are stated so nobody builds against guarantees that do not exist. The full list lives in CLAIMS.md.

- **Single writer per database.** One worker lease holder; no clustering or automated failover.
- **SQLite is the pilot backend.** PostgreSQL is supported single-host, not as a multi-node database.
- **No third-party audit or certification.** The TLA+ model and adversarial tests are evidence, not a penetration test.
- **Compliance pages are mappings.** `docs/compliance/*` is not a SOC 2, ISO 27001 or PCI DSS certificate.
- **External tools require the egress gateway.** nmap, nikto and sqlmap refuse to run without it; plugin adapters may declare `enforcement="none"`.
- **Performance figures are single-machine baselines.** See `docs/reliability.md`; no soak or multi-node numbers.
- **k8s-jobs is experimental.** The default and pilot queue is inprocess or a durable single-host mode.
- **Not on PyPI yet.** Install from the repository or build the wheel.

## Hardening checklist for operators

- [ ] `ISHASTRA_ENV=production` (refuses placeholder keys, disables `/docs`)
- [ ] TLS terminated by a reverse proxy; `ISHASTRA_TRUSTED_PROXIES` set
- [ ] `ISHASTRA_API_KEY`, `ISHASTRA_AUDIT_HMAC_KEY`, `ISHASTRA_ENCRYPTION_KEY` from a
      secret manager, rotated after bootstrap
- [ ] Signed scope document loaded; unsigned/expired documents rejected
- [ ] Host-level egress filtering behind the scope gate
- [ ] Backups off-host and **one restore rehearsed**
- [ ] `/api/ready` probed by the load balancer; alert routed to a human
- [ ] Image pinned by digest

See [`docs/quickstart/production.md`](docs/quickstart/production.md) for the
full go-live checklist.
