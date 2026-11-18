# Strix Open-Source Policy

Status: current. Date: 2026-11-14. This is an engineering and community policy,
not legal advice.

## 1. License

Strix is **fully open source under the MIT License** (`LICENSE`, "Copyright (c)
2026 Strix contributors").

- Every feature in this repository — scope enforcement, assessment engine,
  adapters, findings, Proof, reports, monitoring, API, UI, integrations and
  deployment tooling — is available under MIT.
- There is **no open-core split, paid edition, proprietary add-on, billing
  system, metering plan or feature reserved for a commercial customer.**
- The project does not sell a hosted or paid edition.
- MIT permits anyone to use, copy, modify, distribute, sublicense or sell the
  software. That permission belongs to every user; it is not a project business
  plan.
- API tier names (`free`, `pro`, `enterprise`) are technical rate-limit
  profiles. They are not prices or paid plans.

Optional external scanners (nmap, Nuclei, Semgrep, Bandit, Trivy) remain
optional because of installation and operational cost, not because a Strix
feature is paywalled. Third-party dependencies keep their own licenses; a
release must not claim compatibility without checking them.

## 2. No edition gating

Security controls and evidence features are never withheld:

- default-deny scope enforcement and engagement policies;
- assessment profiles and built-in adapters;
- normalized findings, lifecycle, asset inventory and remediation fields;
- SARIF, JSON, HTML and PDF evidence;
- Strix Proof grants, receipts and offline verification;
- monitoring, scheduling, alerts and integrations;
- the CLI, REST API, web UI and self-hosted deployment.

There is no "community vs enterprise" feature matrix. If a capability is in the
repository, it is in the MIT project.

## 3. Contributions

1. Issues describe a problem, reproduction and expected behavior.
2. Pull requests are small, include tests for changed behavior, and preserve the
   scope, tenant-isolation, coverage-honesty and Proof invariants.
3. Security-sensitive changes require review by a maintainer with security
   ownership.
4. Adapters and connectors are the preferred contribution surface.
5. Contributions are accepted under the repository's MIT license. There is no
   contributor license agreement and no copyright assignment.

## 4. Governance

- Maintainers review changes in public and document security-sensitive
  decisions.
- The roadmap is public and derived from user problems, not revenue targets.
- No feature vote, sponsorship or payment changes the security model.
- Security reports follow `SECURITY.md`; credit is given unless a reporter asks
  otherwise.

## 5. Releases

- Semantic Versioning; the project stays `0.x` until the HTTP API, finding
  schema and Proof format are declared stable.
- Every release includes a changelog, migration notes, test evidence, container
  image, checksums and rollback guidance.
- A release is blocked by failing authorization, tenant-isolation or Proof
  tests.
- Deprecations are announced one minor release ahead with a documented
  replacement.

## 6. Dependencies and third-party tools

- Standard library and existing dependencies first. A new dependency needs a
  named problem, license check, security review and an optional fallback where
  practical.
- Keep optional scanners optional and degrade to explicit partial coverage,
  never a clean verdict.
- Pin production constraints and document known CVEs and upgrade paths.
- Do not vendor or relicense third-party code without its compatible license.

## 7. Community health

Measure adoption, contribution and trust: successful first assessments, active
deployments, external pull requests merged, time to first review, disclosed
vulnerabilities, time to fix and Proof verification failures.

Do not measure or optimize for revenue conversion, paid seats or commercial
upsells. The project has no such conversion goal.

## 8. Legal and brand cautions

- Do not claim certification (ISO 27001, SOC 2, PCI DSS) from using Strix.
- Do not use competitor trademarks in product naming or imply endorsement.
- Keep "authorized testing only" language visible in the README, UI and reports.
- Changing the license requires a deliberate public decision; it is not a
  maintainer-side commercial lever.
