# Security policy

Strix is a security tool: the boundaries it enforces (scope gate, tenant
isolation, secret redaction, audit chain) are the product, so a defect there is
a vulnerability even when it "only" affects our own metadata.

## Reporting

Report privately through GitHub's **Security → Report a vulnerability** form for
this repository. Do not open a public issue, and do not test against systems you
are not authorized to test — including instances belonging to other users.

Please include the version (`strix --version` or `GET /api/version`), the mode
(`STRIX_SCOPE_MODE`), and the smallest reproduction you can manage. A Docker
`--read-only` container with a temporary `STRIX_DB` is the easiest target.

We will acknowledge within 5 working days, tell you whether we consider it a
vulnerability, and credit you in the fix unless you ask otherwise. There is no
bug bounty at this time.

## In scope

- Escaping the scope gate: any target, redirect, webhook or adapter invocation
  that reaches a host or network the authorization document does not name.
- Cross-tenant access to jobs, findings, keys, policies, audit entries or
  metrics.
- Authentication or authorization bypass (`/api/*` without a valid key, or an
  action above the caller's tier).
- Reading secrets that should have been redacted (evidence, SARIF, HTML report,
  audit trail, webhook payload, error text).
- Forging or silently breaking the audit chain.
- Denial of service against the API process from an unauthenticated caller.

## Out of scope

- Findings produced by the assessment profiles themselves (a missed or wrong
  vulnerability) — that is a detection quality issue, please open a normal issue
  with the case from `strix.lab`.
- Anything that requires the attacker to already hold an administrator key or
  control of the database file, unless it escapes the documented threat model in
  `README.md` § Security notes.
- `src/hunt`, which is an unreleased scaffold.

## Supported versions

The latest tagged release receives fixes. Pin `constraints.txt` and upgrade
deliberately; `pip-audit` runs in CI so a new advisory against the pinned set
fails the build.
