# License and Cost

IshAstra is free and open source. There is no paid edition, no license key,
and no feature gated behind a purchase.

## What you get

- **Apache-2.0 license.** Use, modify, and redistribute it, including
  commercially, under the terms in [LICENSE](../LICENSE).
- **Every feature in the repository.** The API, workers, egress gateway,
  scope gate, RBAC, SSO, reports, evidence bundles, and adapters are all in the
  same source tree. Nothing is withheld for a commercial tier.
- **No telemetry.** The software does not phone home. Optional outbound calls
  (for example an external scanner or an identity provider) happen only when an
  operator configures them.
- **Self-hosted by default.** You run it on your infrastructure and keep your
  data.

## What you pay for

Only the infrastructure you choose: compute, PostgreSQL, Redis, object storage,
DNS, and any managed services. The [zero-cost deployment guide](quickstart/free-tier.md)
describes one way to run it on free-tier infrastructure.

## What is not offered

- No hosted/managed IshAstra service.
- No commercial support contract or response-time SLA.
- No certification (SOC 2, ISO 27001, PCI DSS, etc.). The compliance pages map
  controls; they are not certificates.
- No uptime guarantee. See [Production deployment](quickstart/production.md)
  for the supported topology and its limits.

Support is community-based through the repository issue tracker. See
[SUPPORT.md](../SUPPORT.md).

## API compatibility

`/api/pricing/*` endpoints exist for older clients. They report a single
`free` tier with unlimited limits and no gating; they are not a storefront.
