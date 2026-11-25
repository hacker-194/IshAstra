# Security alert triage

**Snapshot:** 2026-11-25, commit `a6360d1`, queried through the GitHub
code-scanning and secret-scanning APIs. Counts are what the API returned, not
estimates.

| Source | Open at snapshot |
|---|---|
| CodeQL | 222 |
| Trivy (Kubernetes/Helm manifests and container) | 126 |
| OpenSSF Scorecard | 52 |
| **Code scanning total** | **400** |
| Secret scanning | 2 |

Dispositions are one of: **fixed** (code changed in this branch), **resolved**
(alert closed with a reason), **test-only** (fixture or test assertion, no
shipped code), **false positive**, **accepted** (risk accepted with an expiry),
or **backlog** (true positive, assigned to a later phase).

---

## 1. Fixed in this branch

| Rule | Severity | Count | Why it was real | Change |
|---|---|---|---|---|
| `py/path-injection` | high | 8 | `LocalObjectStore._tenant_path` joined a user-supplied key without containment, so `../` or an absolute path escaped the tenant directory. | `os.path.realpath` + `commonpath` containment; raises `ValueError`. Tests in `tests/unit/test_object_storage.py`. |
| `py/undefined-export` | error | 2 | `ishastra.core.__all__` named `org` and `tenants`, which do not exist; star-imports would fail. | Removed the stale names. |
| `py/redundant-assignment` | error | 3 | Module-level `_run_async = _run_async` (and two siblings) were no-ops. | Deleted the no-op aliases. |

CodeQL re-runs on the PR; these alerts close when the new analysis lands, not
because they were dismissed. The one remaining `py/path-injection` in
`examples/scope_fastapi_integration.py` stays backlogged with that example.

## 2. Resolved

| Alert | Type | Resolution |
|---|---|---|
| Secret scanning #1 | `aws_temporary_access_key_id` | **used_in_tests** — fake `ASIA…EXAMPLE` key in `tests/security/test_redaction_fuzzing.py`. |
| Secret scanning #2 | `aws_temporary_access_key_id` | **used_in_tests** — same fixture file. |

Both were dismissed through the API with that comment; both can be reopened.

## 3. Test-only (28)

| Rule | Count | Path |
|---|---|---|
| `py/overly-permissive-file` | 14 | `tests/unit/test_plugin_runner.py` — the test itself chmods fixtures to prove the runner tolerates it. |
| `py/incomplete-url-substring-sanitization` | 7 | `tests/unit/*` assertions about sanitised output. |
| `py/ineffectual-statement` | 3 | test files. |
| `py/uninitialized-local-variable` | 1 | `tests/unit/test_egress_gateway.py`. |
| `py/unnecessary-lambda` | 1 | `tests/unit/test_dr.py`. |

No shipped code is affected. These should be dismissed as test-only in bulk
once the alert UI/API is part of the routine; the classification is recorded
here so nobody re-investigates them.

## 4. False positives (12)

| Rule | Count | Reason |
|---|---|---|
| `py/weak-sensitive-data-hashing` | 5 | SHA-256 is used on 256-bit random API keys, not user-chosen passwords; `secrets.compare_digest` is used for comparison. The flagged paths (`security.py`, `scim.py`, `key_scopes.py`) hash keys, not passwords. |
| `py/clear-text-logging-sensitive-data` (`cli.py`) | 4 | The Vault commands log secret *names and counts*, not values. |
| `py/overly-permissive-file` (`src/`) | 2 | `0o644` is the published JWKS (public key), `0o755` is a plugin executable. Neither is confidential. |
| `py/partial-ssrf` (`probe.py`) | 1 | Host and port come from the gate's pinned `Destination`; only the request path is attacker-influenced, and it is sent to that pinned socket. |

## 5. Accepted risk with an expiry

| Rule | Count | Risk | Mitigation | Expires |
|---|---|---|---|---|
| `KSV-0041`, `KSV-0114` | 2 | The Prometheus Operator ClusterRole can read secrets and manage webhook configurations. That is required for the operator to issue TLS and register admission webhooks. | Vendored upstream operator manifest; not internet-exposed; namespace-scoped service account. Re-evaluate when upgrading the operator chart. | 2027-02-28 |
| `py/clear-text-logging-sensitive-data` (`scripts/generate-secrets.py`) | 5 | The generator prints newly generated credentials so the operator can store them. | Interactive operator script; never run in CI; output goes to the terminal, not a log file. Planned `--write-env-file` mode. | 2027-02-28 |

An expired exception is treated as a new finding: the alert must be fixed or
explicitly re-approved with a new date.

## 6. Backlog (true positive, assigned)

| Area | Rules (count) | Phase |
|---|---|---|
| Logging hygiene | `py/log-injection` (18) — SCIM and scope paths log request-controlled strings | 3 (observability/logging pass) |
| Error handling | `py/empty-except` (33), `py/file-not-closed` (1), `py/stack-trace-exposure` (1) | 3 |
| Resource/config hardening | Trivy `KSV-*` (124): read-only root filesystems, default security contexts, missing limits on the bundled monitoring stack | 3–4 |
| CI supply chain | Scorecard `PinnedDependenciesID` (39), `TokenPermissionsID` (8) | 4 |
| Governance signals | Scorecard `CodeReviewID`, `MaintainedID`, `BranchProtectionID`, `CIIBestPracticesID`, `FuzzingID` (5) | 5 |
| Container base image | `CVE-2026-124851` (`libzstd1`, fix available) | 4 (rebuild) |
| Dead/duplicate code | `py/unused-import` (19), `py/import-and-import-from` (19), `py/repeated-import` (16), `py/cyclic-import` (12), `py/unused-global-variable` (23), `py/unused-local-variable` (11), `py/multiple-definition` (1), `py/unnecessary-delete` (1), `py/polluting-import` (1), `py/regex/duplicate-in-character-class` (1), `py/bad-tag-filter` (1), `py/ineffectual-statement` (source) | 5 |
| Example code | `py/call/wrong-arguments` (1) in `examples/adapter-hello` | 6 |

## 7. Limitations

- The GitHub API does not expose a reliable "tool" field per alert; counts were
  grouped by `tool.name`, which is present on every returned alert.
- Dependabot alerts still cannot be read with the current token scope.
- Alert totals will change when CodeQL re-analyses this branch. This document
  records the snapshot, not a promise that the number only goes down.
- No alert was dismissed except the two test-fixture secrets; nothing was
  suppressed with query filters or path excludes.
