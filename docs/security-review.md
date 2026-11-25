# Security Review Process

IshAstra is a community project. This page describes the reviews that actually
happen in the repository; it is not a claim of a staffed security team, a paid
bug bounty, or an independent audit.

## Review types

### Every pull request

- Authentication and authorization changes require a second reviewer.
- Scope Gate changes require a second reviewer and must keep the adversarial,
  property, and TLA+ checks green.
- New adapters must call `checked_destination()` before any network operation
  and must not resolve a target independently of the gate.
- Crypto, secret handling, and redaction changes require a reviewer familiar
  with those modules.

### Before a release

CI is the evidence, not a separate attestation:

- `ruff`, `mypy`, and the SQLite/PostgreSQL test suites
- Scope Gate unit, adversarial, property, DNS-variation, and mutation tests
- TLA+ model checking (bounded state exploration, not a proof)
- `bandit`, `semgrep`, `safety`, and `pip-audit`
- container image scans and dependency review
- Helm lint and kubeconform validation

The exact commands and thresholds are in `.github/workflows/ci.yml` and
`.github/workflows/security-scan.yml`.

## Review checklist

### Authentication and authorization

- [ ] Every non-public endpoint uses `require_auth` or `require_admin`.
- [ ] Write requests require a write-scoped key; read-only keys cannot mutate.
- [ ] Tenant identity comes from a validated API key, never a request header.
- [ ] Every outbound adapter path goes through `checked_destination()`.
- [ ] External scanners receive the pinned IP, not a hostname they can resolve
      independently; redirects are disabled or ignored.
- [ ] Background jobs re-check that the bound policy is still valid.

### Data protection

- [ ] Tenant predicates are present on every application query.
- [ ] PostgreSQL RLS is enabled only with a non-superuser application role; see
      `DEPLOYMENT.md`.
- [ ] Secrets and credentials never appear in logs, findings, or SARIF.
- [ ] Encryption keys and HMAC keys come from the environment/secret manager.
- [ ] Backups are verified and one restore is rehearsed.

### Input and execution

- [ ] API bodies are bounded by size and nesting depth.
- [ ] SQL is parameterized.
- [ ] External tools run with argument arrays, a minimal environment, a
      deadline, and process-group termination.
- [ ] Tool output is size-bounded and parsed defensively (for example,
      `defusedxml` for nmap XML).

## Vulnerability reporting

Use GitHub's private advisory flow described in [`SECURITY.md`](https://github.com/hacker-194/IshAstra/blob/master/SECURITY.md).
There is no paid bounty and no contractual response SLA. Do not send reports to
an address that is not listed there.

## Compliance pages

`docs/compliance/*` contains control mappings. It is **not** a certification,
attestation, or independent audit. MFA, TLS termination, and high availability
are deployment responsibilities, not features IshAstra implements itself.
