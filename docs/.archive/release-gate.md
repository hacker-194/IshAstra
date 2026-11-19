# Release gate: what is verified before calling this ready

Status: verified 2026-11-16 against this working tree. Only facts that were
observed by running the software are listed. Nothing here is a certification.

## One command

```bash
python scripts/readiness_check.py
```

It starts the API in production mode against a throwaway database, runs a real
assessment against a loopback HTTP target, and proves the trust layer end to
end. Exit 0 means every check passed; any failure prints the check and exits 1.
Add `--keep` to keep the temporary artifacts.

Checks in the gate:

| Area | Check |
|---|---|
| Startup | Production mode starts, `/api/health` 200, `/api/ready` 200, UI 200 |
| Fail-closed | `/docs` 404 in production; unauthenticated reads 401; metrics require admin |
| Assessment | Authorized target accepted, terminal state reached, coverage recorded |
| Honesty | A partial job is not reported as clean; out-of-scope target refused with 403 |
| Evidence | SARIF export 200; audit chain verifies 200 |
| Recovery | SQLite backup/restore with matching tables, integrity ok, HMAC chain ok |
| Proof | Grant signs; gate allows in-scope and denies out-of-scope; pack builds; offline verify passes |
| Tampering | A modified proof is rejected; a missing proof exits non-zero |

## Independently observed results (2026-11-16)

| Check | Measured result |
|---|---|
| Full suite with coverage | 1426 passed, 14 skipped, 64.97% coverage |
| Ruff 0.17.2 + CI-pinned 0.6, check and format | Clean |
| mypy | Clean across `src/strix` |
| Wheel build | `strix-3.5.0-py3-none-any.whl`, 473,887 bytes |
| Container build | `docker build` succeeded; container runs as UID 10001 with a read-only rootfs, `/api/health` and `/api/ready` 200, `/docs` 404 |
| Detection lab (real nmap) | 6/6 true positives, 0 false positives, precision/recall 1.0 |
| Backup/restore drill | 27 tables, integrity ok, counts match, audit chain ok |
| Proof tamper test | exit 1 (NOT VERIFIED); missing pack exit 3 |

## Publish checklist

1. `python scripts/readiness_check.py` exits 0 on a clean checkout.
2. CI (lint, types, tests, live nmap/Nuclei, container, security) is green on the
   commit being released. The first GitHub Actions run must be observed, not
   assumed from local parsing.
3. `python scripts/check_secrets.py` is clean and no `.env*`, `*.db`, `*.db-*`
   or `scope.json` is tracked.
4. `python scripts/operational_check.py` passes against a real backup with the
   production HMAC key.
5. The independent security review of scope enforcement, tenant isolation,
   Proof, redaction, cancellation and secret handling is complete. Until it is,
   do not claim "production-ready" or "audited"; the review package is
   `docs/security-audit-prep.md` and the status is tracked in `docs/roadmap.md`.

## Pilot contract language

State these in writing before the first engagement:

- **Single node only.** One Strix process per SQLite database; a second process
  is refused by the worker lease. No HA, no failover, no multi-node scheduling.
  PostgreSQL and Kubernetes Jobs are experimental single-host paths.
- **`partial` is not clean.** A partial job means at least one selected detector
  could not complete. Only `completed` with full coverage may be read as
  "no findings from the selected coverage".
- **Not a penetration test.** Authorized, non-destructive DAST/SAST-style
  coverage; it does not exploit, and it does not replace manual review.
- **Optional scanners.** nmap, Nuclei, Semgrep, Bandit and Trivy are optional;
  missing tools reduce coverage and are reported as such.
- **No SLA in Phase 1.** Best-effort support; Phase 1 is free.

## SCIM behaviour worth telling identity-provider admins

- Group membership changes go through `PATCH /scim/v2/Groups/{id}` with
  `add`/`remove` operations on `members`; they are persisted.
- `PATCH /scim/v2/Users/{id}` accepts `displayName`, `userName`, `active`,
  `role`, `emails` and `name`. Operations that target the read-only `groups`
  attribute are ignored rather than rejected, because SCIM declares
  `User.groups` as `readOnly`.
- Organization email invitations are not implemented. The endpoint returns
  `501`; add members directly with `POST /api/v2/orgs/{org_id}/members`.
