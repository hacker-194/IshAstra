# Security and Readiness Audit — 2026-11-21

Branch: `audit/security-readiness`  
Scope: repository documentation, outbound network paths, authentication,
tenant isolation, queue/reliability claims, CI, and deployment configuration.

This report records what was inspected, what was changed, and what remains
unresolved. It is an internal review, not an independent penetration test.

## Findings

### H-1 — PostgreSQL RLS is not wired into API requests

- **Files:** `src/ishastra/api/app.py`, `src/ishastra/api/middleware/rls.py`,
  `src/ishastra/core/store.py`
- **Evidence:** `RLSTenantMiddleware` is defined and exported but never added in
  `create_app()`; the only registered identity middleware is
  `TenantStateMiddleware`. `PostgreSQLDatabase.transaction()` never calls
  `set_app_current_tenant()`, and the middleware uses a thread-local
  `_tenant_context` on a shared database object.
- **Actual behaviour:** the database-layer RLS policies are tested by
  `tests/test_rls.py`, but API requests do not set the tenant session variable.
  Under a non-superuser role, RLS-protected reads can return no rows (fail
  closed) and the API relies entirely on application-level tenant predicates.
- **Expected behaviour:** the authenticated tenant is applied to every
  PostgreSQL transaction, so RLS is defense-in-depth behind the application
  filters and cannot be raced by concurrent async requests.
- **Recommended fix:** register the middleware so it runs after
  `TenantStateMiddleware`, replace the thread-local tenant with a `ContextVar`,
  and apply/reset `set_app_current_tenant()` in `transaction()`. Add a
  two-tenant API integration test against PostgreSQL.
- **Status:** unresolved. No unsafe workaround was added.

### H-2 — Nikto and SQLMap could resolve the hostname independently

- **Files:** `src/ishastra/core/adapters.py`
- **Evidence:** Nikto was invoked with `-host <hostname>`; SQLMap was invoked
  with `-u <original URL>`. Both tools perform their own DNS resolution and can
  follow redirects outside the gate's pinned destination.
- **Actual behaviour:** a DNS rebinding or redirect between the gate check and
  the scanner connection could reach an address the scope gate did not authorize.
- **Expected behaviour:** external scanners receive the pinned IP, preserve the
  authorized Host header, and do not follow redirects.
- **Fix:** Nikto now uses `-host <pinned IP> -vhost <authorized Host>`; SQLMap
  uses the pinned-IP URL, `--host`, and `--ignore-redirects`, and `--force-ssl`
  for HTTPS targets.
- **Regression test:** `tests/unit/test_adapters.py::TestExternalScannerPinning`.

### M-1 — SQLMap TLS/SNI remains best-effort

- **File:** `src/ishastra/core/adapters.py`
- **Evidence:** SQLMap connects to an IP URL with a Host header; the TLS
  certificate/SNI is presented for the IP, not the original hostname.
- **Actual behaviour:** HTTPS SQLMap scans can fail certificate validation or
  use a different SNI than the authenticated target.
- **Expected behaviour:** an in-process egress proxy that pins the destination
  while preserving Host/SNI.
- **Status:** unresolved trade-off. The pinning prevents DNS rebinding, but the
  TLS identity mismatch must be fixed with a proxy before claiming full
  HTTPS coverage.

### M-2 — Documentation claimed features the code does not provide

- **Files:** `README.md`, `docs/security-review.md`,
  `docs/api/authentication.md`, `docs/architecture/overview.md`,
  `docs/compliance/*`
- **Evidence:** claims of MFA, API-key-to-JWT exchange, JWT rotation, mTLS,
  Cloudflare WAF, SPIFFE, an annual third-party penetration test, a bug bounty,
  and a 48-hour security SLA.
- **Actual behaviour:** authentication is API keys plus optional OIDC/SAML
  browser sessions; there is no MFA implementation, no JWT exchange, and no
  staffed security team or bounty.
- **Fix:** rewrote the security-review and authentication pages, corrected the
  architecture overview and README, and added a non-certification/non-MFA
  notice to the compliance mappings. Compliance tables still describe target
  controls; treat them as mappings only.

### M-3 — Queue-mode documentation contradicted the code

- **Files:** `ARCHITECTURE.md`, `docs/architecture/overview.md`
- **Evidence:** the docs said only `inprocess` and `k8s-jobs` exist; the code
  accepts `inprocess`, `redis-streams`, and `k8s-jobs`.
- **Fix:** documented all three modes and marked `k8s-jobs` experimental.

### L-1 — Wrong repository and image URLs

- **Files:** README, SECURITY, issue templates, `pyproject.toml`, Helm chart,
  Argo CD, mkdocs, SARIF metadata, monitoring runbook links.
- **Fix:** replaced `ishastra/ishastra`, `useishastra/ishastra`, and
  `your-org/ishastra` with `hacker-194/IshAstra` / `ghcr.io/hacker-194/ishastra`.

### L-2 — Backup helper name and artifact mismatch

- **Files:** `deploy/cron/strix-backup`, `DEPLOYMENT.md`
- **Evidence:** docs referenced `deploy/cron/ishastra-backup`; the file was
  `strix-backup`, used the `strix` binary, and pruned `strix-*.db` while
  `create_backup()` writes `ishastra-*.db`.
- **Fix:** renamed to `deploy/cron/ishastra-backup`, uses the `ishastra` binary,
  and prunes the correct artifacts.

## Positive controls verified

- HTTP probe disables redirects and scope-checks any `Location` header.
- Crawler uses `checked_destination()` and filters links to http/https.
- nmap receives `-n` and the pinned IP.
- nuclei receives the pinned IP URL, Host header, SNI, and `-dr` (disable
  redirects).
- Form-login authentication resolves and pins the destination before opening a
  socket.
- Tenant identity is derived from the validated key, not a request header.
- External tool output is bounded, deadlined, and nmap XML uses `defusedxml`.
- Scope signing supports operator-driven key rotation; this is not JWT rotation.

## Unresolved risks

1. PostgreSQL RLS API wiring (H-1).
2. SQLMap HTTPS SNI/certificate identity (M-1).
3. No MFA, no independent security audit, no bug bounty, no HA/failover.
4. Plugin adapters execute in-process and are trusted code; they can open
   sockets without `checked_destination()`. Only install plugins you trust.
5. Compliance tables still contain target-state control language; they are
   mappings, not evidence of certification.
6. Local validation did not run the PostgreSQL suite (no test DSN) or
   kubeconform (not installed).

## Reproduce

```bash
python3 -m pytest -q tests/unit/test_adapters.py --no-cov
python3 -m pytest -q tests/security/test_scope_gate_adversarial.py --no-cov
python3 -m pytest -q --no-cov
ruff check src tests
ruff format --check src tests
mypy src/ishastra
helm lint ./deploy/helm/ishastra -f ./deploy/helm/ishastra/values-prod.yaml
docker compose config
```
