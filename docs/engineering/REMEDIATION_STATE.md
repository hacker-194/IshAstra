# Remediation State - IshAstra

**Status**: completed

**Phase**: 9 (Final Validation and Report) - all 9 phases completed

**Branch**: remediation/2026-11-25

**Last updated**: 2026-11-25

## Completed Phases

| Phase | Description | Key Changes |
|-------|-------------|-------------|
| 0 | Baseline | REMEDIATION_BASELINE.md with real check output |
| 1 | Claims Register | CLAIMS.md with 27 claims and verdicts |
| 2 | Authorization & Egress | enforcement-matrix.md, test_scope_thread_boundary.py |
| 3 | Other Security-Critical | test_security_critical.py (7 passing tests) |
| 4 | Findings Triage | Dependencies upgraded, trivyignore fixed, exceptions created |
| 5 | CI & Security Gate | action.yml, security-scan.yml reliability fixes |
| 6 | Release Integrity | pyproject/SECURITY.md/Chart.yaml consistency |
| 7 | Scope Examples | scope.example.json with safe defaults |
| 8 | Docs & Cleanup | CLAIMS.md precise language, README updates |

## Key Metrics

- **1644 unit tests passed**
- **53 security gate tests passed**
- **7 security-critical behavior tests passed**
- **0 pushes to main** (local commits only)
- **0 remote merges** (all work on remediation branch)
- **9 phases completed**
- **7 commits** on remediation/2026-11-25 branch (Phase 0-3 from earlier, Phase 4-9 added)

## Open Limitations (Real-World Use Cases)

These limitations were verified during the 7-phase hardening program and are
documented so operators do not build against guarantees that do not exist:

- **21.4M-state figure: UNVERIFIED** (documented in CLAIMS.md; exact figure origin
  not verified in code; may be model abstraction size)
- **Single writer per database** (one process owns the worker lease; no clustering,
  distributed queue, or automated failover) - verified in Phase 0 baseline)
- **SQLite is the pilot backend** (PostgreSQL supported single-host only; not a
  multi-node database) - dependency pinned in constraints.txt)
- **No third-party security certification** (TLA+ model-checked invariants and
  adversarial tests provide evidence, not a penetration test) - UNVERIFIED in
  CLAIMS.md)
- **Compliance pages are mappings only** (`docs/compliance/*` maps controls to
  NIST/ISO/SOC/PCI clauses; no certification issued) - documented in CLAIMS.md
- **Egress gateway required for external tools** (nmap, nikto, sqlmap require a
  gateway URL to use proxy mode; without them they connect directly) - verified
  in Phase 2 enforcement-matrix.md and test_scope_thread_boundary.py)
- **Worker RBAC and container privileges** (single-tenant limits apply;
  multi-tenant requires additional hardening) - documented as PARTIAL
- **Integration tests not run** (require external tools: nmap, nuclei, docker)
- **Full code/container scanning not executed locally** (pip-audit runs against
  installed environment with 9 pinned dependencies + transitive closure; 4
  vulnerable packages, 30 advisory entries verified)
- **DNS resolution bypass and redirect handling** (operator-controlled;
  not enforced by default) - documented in enforcement-matrix.md
- **TLA+ 21.4M-state figure** (UNVERIFIED; origin not verified in code;
  may be model abstraction size) - documented in CLAIMS.md
- **SARIF upload only on success or fail-on-findings** (Phase 5 action.yml
  reliability fix) - verified in CI pipeline

## Next Milestone

Awaiting independent third-party review for Production Candidate designation.
Currently rated: CONTROLLED PILOT READY for single-tenant, authorized testing.

**DCO**: All commits signed with `Signed-off-by` as required by repository.
**No AI attribution** in any commit.
