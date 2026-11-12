# Strix

Authorized security assessment platform. You describe what you are *permitted* to
test; Strix refuses everything else, runs real tools against what remains, and
records the results as normalized findings you can export (SARIF) or file
(evidence report).

## What it does

- **Scope gate** – every request is checked against an authorization document
  (`include`/`exclude` hosts, explicitly authorized networks, and optional
  `allowed_ports`). Private, loopback and metadata addresses are denied unless
  the document authorizes them. Built-in HTTP, Nmap and Nuclei connections use
  the validated destination IP; external redirects are disabled or never followed.
- **Assessments** – `web`, `web-deep`, `api`, `api-deep` and `network` profiles
  run the appropriate adapters as background jobs. `web-deep` adds bounded,
  non-destructive GET validation for redirect handling and database error
  leakage; `api` discovers same-origin OpenAPI/Swagger documents and checks
  documented protected GET endpoints without credentials. A result is only
  called clean if the selected adapter coverage completed.
- **Local source/dependency analysis** – `strix-code-scan` makes a bounded
  snapshot of a local repository and optionally normalizes Semgrep, Bandit and
  Trivy results. It does not execute project code or send requests to a live
  target. Missing tools or unavailable vulnerability databases result in a
  partial/inconclusive report, never a clean verdict.
- **Findings** – one normalized model (severity, confidence, verification,
  evidence, CWE, remediation), enriched with defensive security fields
  (CVSS score, business impact, asset criticality, risk rating, exploit availability,
  user impact, compliance references, remediation status, discovery/report/resolution dates),
  deduplicated across tools, credentials redacted, persisted in SQLite,
  exportable as SARIF 2.1.0. Findings have an enforced client lifecycle
  (`new → triaged → in_progress → fix_verified → closed`, plus deferred/reopened)
  with audited, tenant-scoped status changes.
- **Strix Proof** – a signed authorization *grant*, a hash-chained receipt for
  every gate decision taken under it, and a portable proof pack anyone can
  verify offline. See [Strix Proof](#strix-proof).
- **Monitoring** – re-assesses registered targets and alerts (log / webhook) on
  *newly appeared* high-severity findings.
- **Multi-tenant API** – bearer keys (hashed, persisted), per-tenant data
  isolation, rate limiting by tier, persistent audit trail.
- **Web UI** – served at `/`.

## Quick start

```bash
pip install -e ".[dev]"
cp scope.example.json scope.json            # edit: what you are authorized to test
export STRIX_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
strix serve --host 0.0.0.0 --port 8000      # UI at http://127.0.0.1:8000
# `strix --host 0.0.0.0 --port 8000` also works as the default serve mode.
```

```bash
curl -H "Authorization: Bearer $STRIX_API_KEY" -H 'Content-Type: application/json' \
     -d '{"target": "https://app.example.com/", "profile": "web"}' \
     http://127.0.0.1:8000/api/assess          # 202 + job id; poll /api/assess/{id}

# Triage one finding (same controls are in the web UI). The fingerprint is
# returned with each finding; illegal transitions are refused with 409.
curl -X PATCH -H "Authorization: Bearer $STRIX_API_KEY" -H 'Content-Type: application/json' \
     -d '{"status": "triaged"}' \
     http://127.0.0.1:8000/api/assess/$JOB_ID/findings/$FINGERPRINT
```

Interactive API docs: `/docs`. Without a scope document **and** without an
engagement policy, **every assessment is refused**.

### Authorization modes

- **Global (single organization).** One `scope.json` authorizes the whole
  deployment. Simple, and appropriate when one team owns every assessment.
- **Managed (multi-tenant).** Every assessment is bound to an *engagement
  policy* — a versioned authorization record for one tenant with its own hosts,
  networks, ports, validity window (`effective_at`/`expires_at`) and status.
  Policies are created, updated and revoked **by administrators only** via
  `/api/policies`; customers can never authorize their own targets. Each job
  records the policy id and version it ran under; the worker re-validates the
  binding before execution and revoking a policy also cancels its queued or
  running assessments. `GET /api/scope` shows a tenant only its own policy.

The mode is explicit (`STRIX_SCOPE_MODE=global|managed|auto`). In `auto` — the
default — the deployment behaves as a single organization until the first
policy is created, then every tenant needs its own policy.

Network ranges in `authorized_networks` (or a policy's equivalent field) that
are broader than a `/8` are refused unless the record sets
`allow_broad_networks: true` — a deliberate, auditable override. IPv4-mapped
IPv6 network syntax (`::ffff:0:0/96`) is always refused; authorize the IPv4
CIDR directly.

## Strix Proof

Whoever runs a scan can produce findings. Strix Proof answers the question a
client, auditor or insurer actually asks: **was that action authorized, and can
you show it?**

```bash
# 1. The asset owner signs what may be tested, for how long.
strix grant --program "nrb annual assessment" \
            --authorized-by "Example Bank Ltd" --ref "PO-2026-0417" \
            --include app.example.com --include '*.example.com' \
            --port 443 --days 14 --out grant.json --key-out issuer.key

# 2. Any agent asks the gate before acting; every decision is receipted.
strix gate --grant grant.json --ledger receipts.jsonl --gate-key gate.key
curl -H 'Content-Type: application/json' \
     -d '{"url": "https://app.example.com/login", "method": "GET"}' \
     http://127.0.0.1:8787/v1/authorize

# 3. Bundle the grant and receipts, then verify anywhere, offline.
strix proof  --grant grant.json --ledger receipts.jsonl --out proof.json
strix verify proof.json --issuer-key issuer.key
```

The same verification is available over HTTP for parties who have no Strix
install and no account: `POST /api/proof/verify` with
`{"proof": <pack>, "trusted_issuer": <public key>}` returns the same report.
That endpoint is unauthenticated and stateless — it stores nothing from the
request.

A Strix scan can be run under the same grant, receipting each decision it
makes:

```bash
strix assess --grant grant.json --target https://app.example.com/ \
             --profile web --proof-out proof.json --proof-ledger receipts.jsonl
```

**What the artifacts are.** A grant is JSON signed with Ed25519 over a
canonical encoding of who authorized what, which hosts/networks/ports, and the
validity window. A receipt is `{seq, grant_id, url, decision, reason, …}`
chained by `previous` and `hash` and signed by the gate, so altering, dropping
or reordering one breaks the chain. A proof pack is grant + receipts + the gate
public key + a summary.

**Verification is not trust.** `strix verify` reports each check
(`grant_signature`, `issuer_trusted`, `chain`, `scope_compliance`, `gate_key`).
Pin the issuer with `--issuer-key`: a grant verifies cryptographically even
when someone else signed it, so an unpinned proof proves integrity, not
authority. Verification also re-checks every allowed action against the grant
(hosts, ports, networks) and against the grant's time window — an action taken
after expiry fails even though the receipt's own chain is intact.

**Scope of enforcement.** The gate cannot stop an agent that ignores it; it is
an authorization service, not a packet filter. What it does provide: every
decision it was asked for is receipted, and any action absent from a complete
ledger was never presented for authorization. Strix's own adapters enforce the
same grant through the scope gate, which pins the resolved address it
validated, so a scan cannot drift outside the grant between DNS lookup and
connect.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `STRIX_API_KEY` | – | Bootstrap admin key (≥16 chars). Required to use the API. |
| `STRIX_SCOPE_FILE` | `scope.json` | Authorization document (global mode). |
| `STRIX_SCOPE_MODE` | `auto` | `global` (single scope document), `managed` (per-tenant engagement policies), or `auto` (managed as soon as a policy exists in the database, global before that). |
| `STRIX_DB` | `strix.db` | SQLite file (jobs, findings, policies). |
| `STRIX_WORKERS` / `STRIX_QUEUE_MAX` | `1` / `32` | Concurrent jobs / queue depth. |
| `STRIX_CORS_ORIGINS` | none | Comma-separated origins. The bundled UI needs none. |
| `STRIX_TRUSTED_PROXIES` | none | Peers whose `X-Forwarded-For` is honored. |
| `STRIX_AUDIT_MAX_ENTRIES` | `10000` | Audit entries kept in memory (all are also stored in SQLite). |
| `STRIX_AUDIT_HMAC_KEY` | – | Secret that keys the audit hash chain (see Security notes). Set it in production. |
| `STRIX_WEBHOOK_SECRET` | – | HMAC key that signs alert webhook deliveries. Set it when webhooks are configured. |
| `STRIX_RETENTION_DAYS` | `0` | `0` keeps everything forever. A positive value prunes finished jobs/findings and plain audit entries older than that many days; the sealed audit chain is never pruned. |
| `STRIX_MAX_BODY_BYTES` | `1048576` | Hard cap on request bodies (413 above it). |
| `STRIX_LOG_FORMAT` | `text` | `json` for one structured log object per line. |
| `STRIX_LOG_LEVEL` | `INFO` | Python log level. |
| `STRIX_RATE_LIMIT_DISABLED` | – | `1` disables limits (local development only). |
`nmap` and `nuclei` are optional external binaries; `GET /api/adapters` reports
which are usable. Missing tools reduce coverage and the job says so. The API
profile is built in and does not require external tools.

### Measuring detection: the built-in lab

Detection claims are measured, not asserted. `strix.lab` ships a deterministic,
deliberately vulnerable loopback target, a versioned oracle mapping every route
to the finding an honest scanner should (or must not) produce — including the
verification level it may claim — and a runner that scores the real adapters
against that oracle:

```bash
python -m strix.lab --report lab-eval.json   # precision / recall / F1 / FP rate
python -m strix.lab.target --port 8765       # serve the lab for inspection
```

The lab binds to `127.0.0.1` only and serves static bait; no request content is
executed or persisted. Exit status is `0` only when the configured
`--min-precision` / `--min-recall` thresholds (default 1.0) are met and no
verification-level violation remains. `DETECTION_BENCHMARK.md` records the
measured results (per-case provenance, the honesty contract the oracle
enforces, and a real-world run) and `DETECTION_READINESS.md` what those numbers
do and do not prove.

### Local code and dependency scan

Install the optional tools appropriate for the repository (`semgrep`, `bandit`,
`trivy`) and run the scanner against a local checkout you are authorized to
review:

```bash
strix-code-scan ./path/to/repository --output strix-code-report.json
# Or emit SARIF for supported CI/code-scanning consumers:
strix-code-scan ./path/to/repository --sarif --output strix-code.sarif
```

Strix uses its packaged, local Semgrep ruleset (no remote rule download), Bandit
for Python checks and Trivy for dependency, secret and misconfiguration checks.
Trivy database updates are disabled by this invocation; prepare/update its DB
separately under your organization's approved process. The snapshot excludes
symlinks, common vendor/build directories, files above 2 MiB, and excess files
or bytes. Such omissions are recorded. This command provides SAST/SCA indicators,
not proof that code paths are exploitable; review and validate findings.


| | |
|---|---|
| `GET /api/health`, `/api/ready` | liveness, readiness (no auth) |
| `GET /api/metrics` | Prometheus exposition (admin key required) |
| `POST /api/assess` · `GET /api/assess[/{id}]` · `POST /api/assess/{id}/cancel` | jobs (`wait=true` runs inline, max 120 s) |
| `GET /api/assess/{id}/sarif` | SARIF export |
| `PATCH /api/assess/{id}/findings/{fingerprint}` | triage a finding; invalid transitions return 409 |
| `POST /api/report` | evidence report for a target's latest finished job |
| `POST /api/probe` | one request, graded on security headers |
| `GET /api/scope`, `/api/adapters`, `/api/overview` | context |
| `GET /api/audit`, `/api/audit/verify` | audit trail, chain verification |
| `GET /api/tenants`, `POST /api/keys/create`, `POST /api/keys/rotate/{tenant}` (optional `ttl_days`), `POST /api/keys/revoke/{tenant}` | keys |
| `GET /api/policies`, `POST /api/policies`, `PATCH /api/policies/{id}`, `POST /api/policies/{id}/revoke` | versioned engagement policies (admin) |
| `GET /api/monitor/status`, `POST /api/monitor/configure` (`replace` to remove targets), `POST /api/alerts/webhook` | monitoring (admin; targets and webhook sinks persist across restarts) |

## Development

```bash
ruff check .
mypy
python scripts/check_secrets.py .
pytest
```

Layout: `src/strix/core` (scope gate, adapters, jobs, worker, store, findings,
probe, policies, redaction, crawler), `src/strix/api` (app factory, routers,
security middleware, static UI), `src/strix/lab` (detection lab, oracle,
evaluation runner), `src/strix/rules` (bundled Semgrep ruleset), the modules
sitting directly under `src/strix` (`cli.py`, `config.py`, `code_scan.py`,
`analyst.py`, `monitor.py`, `audit.py`, `metrics.py`, `report_html.py`,
`retention.py`) and `tests/`, which mirrors that layout.

## Deploying

`DEPLOYMENT.md` is the full operator runbook: container/systemd install, reverse
proxy and TLS, first-run checklist, backups, key rotation, retention, scaling
limits and troubleshooting. For a Nepal-focused pilot (NRB/NTA/NCSP evidence,
in-country hosting, legal and commercial gates), see
[`NEPAL_LAUNCH_READINESS.md`](NEPAL_LAUNCH_READINESS.md).

- Put Strix behind a TLS-terminating reverse proxy; it speaks plain HTTP and binds
  to `127.0.0.1` unless told otherwise. List the proxy in `STRIX_TRUSTED_PROXIES`
  so rate limits count real client addresses (this setting is the only
  place forwarded addresses are trusted).
- Set `STRIX_API_KEY` (bootstrap admin) and a separate random `STRIX_AUDIT_HMAC_KEY`;
  do not use the example placeholders. Known placeholders and API keys shorter than 16
  characters are rejected. Generate secrets with `python -c 'import secrets; print(secrets.token_urlsafe(32))'`
  and keep both out of the repository and database host's reach. A startup without
  `STRIX_AUDIT_HMAC_KEY` still serves, but logs a warning: the audit chain then only
  detects accidental or naive tampering.
- If you restore a SQLite database created under a different HMAC key, startup will
  fail closed until the operator explicitly clears the stale chain. Use
  `strix serve --reset-audit-chain` only after a deliberate recovery decision; this
  discards the old sealed chain intentionally.
- The database grows with every assessment and audit event. Set `STRIX_RETENTION_DAYS`
  to a positive value to prune finished jobs/findings and plain audit entries that old
  (a sweep runs at startup and every 6 hours); the sealed audit chain is always kept.
- `SIGTERM` is handled gracefully and is bounded: in-flight requests get up to
  30 seconds, running assessments are cancelled and marked
  `failed — interrupted by process restart` (never left looking live), so
  systemd or a container runtime is never left waiting on a wedged connection.
- Back up the SQLite file (`STRIX_DB`): it holds jobs, findings, key hashes and
  the audit trail. Use `sqlite3 strix.db ".backup out.db"` for a consistent copy.
- Container: `docker build -t strix .` (CI's `docker` job builds the image and
  asserts `/api/health`, `/api/ready` and a 401 on unauthenticated metrics).

## Security notes

- API keys are stored only as SHA-256 hashes; issuing a new key for a tenant
  retires the previous one. Raw keys are shown once.
- **Secret redaction is applied at every output boundary.** Credential-shaped
  values (passwords, tokens, bearer headers, JWTs, AWS keys, private key
  material, session ids, signed-URL parameters, `user:pass@` strings) are
  removed from evidence, job targets, errors, audit and chain entries, API
  responses, SARIF, HTML reports and webhook payloads. Sensitive *query
  parameter values* in stored targets are redacted while the host and path stay
  identifiable; non-sensitive parameters are kept so evidence remains
  reproducible. `Set-Cookie` values in probe responses are redacted while the
  flags are kept for grading.
- Key lifecycle, authorization denials, webhook and monitor changes, assessments
  and reports are sealed in a hash chain. **With `STRIX_AUDIT_HMAC_KEY` set, the
  chain cannot be recomputed by someone who can only edit the database;**
  without it the chain detects accidental or naive tampering only. Neither
  protects against an attacker who controls the running process and its secrets.
- Request bodies are capped and JSON nesting is limited before authentication.
- Targets are refused if different URL parsers could read their host differently
  (backslashes, userinfo, whitespace, percent-encoded hosts), so the scope check
  and the external tools agree on the destination being tested. Nmap is passed
  the validated IP; Nuclei is passed that IP with the original Host header/TLS SNI
  and redirects disabled. Keep host-level egress filtering enabled as defense in depth.
- Set `allowed_ports` in `scope.json` to enumerate authorized service ports (the
  example limits to `[80, 443]`). Without an explicit list, host authorization does
  not broaden Nmap to a top-port sweep: network discovery is limited to the port
  named by the target URL. The URL's explicit port is still subject to the target
  host allowlist and address policy; enumerate approved ports for broader scans.
- URL signatures and reflected markers are reported as low-confidence, unverified
  indicators. The reflection checker records an HTML context when it can, but does
  not claim JavaScript execution. The opt-in `web-deep` checks use only existing
  query parameters, GET requests and a reserved `.invalid` redirect canary; redirects
  are never followed and database error signatures remain indicators, not confirmed
  SQL injection. Port exposure is informational until service authentication and
  configuration are independently verified; ordinary redirects are not findings.
- The `api` profile treats OpenAPI security declarations as hints, checks at most
  30 documented protected GET operations without credentials, and reports successes
  as unverified authorization mismatch indicators. It does not test writes, all
  API methods, authenticated roles, BOLA/IDOR, business logic or mutation safety.
- Webhooks require HTTPS and public addresses, connect to the validated IP, and reject
  URLs with embedded user-info or credential-bearing query parameters. Existing unsafe
  query-bearing destinations are removed on reload. Because arbitrary path segments cannot
  reliably be distinguished from opaque tokens, do not embed webhook secrets in URL paths:
  the webhook destination is persisted in SQLite for restart recovery, and SQLite is not
  encrypted by Strix. Restrict database/volume access and use host or volume encryption.
- Hostnames must be valid DNS names or IP literals (no leading hyphen, `*`, `$`, or
  non-punycode IDNs), and `nmap` receives its target after `--`, so a target can
  never be interpreted as a tool option.
- `nmap` output is parsed with `defusedxml`; error text from tools is kept
  server-side, so clients see tool names, not filesystem paths.
- The CSP forbids inline and third-party scripts, form posts to other origins,
  framing and `<base>` changes. Request IDs from clients are accepted only if
  they are short and printable.
- `/api/ready` is unauthenticated, so it uses a result cached for 30 s instead of
  re-verifying the whole audit chain per request.
- The SQLite files are created owner-only (0600).
- `starlette>=1.3.1` is required: older versions allow unauthenticated CPU
  exhaustion through `StaticFiles` (CVE-2025-62727) and trust the `Host` header
  when rebuilding `request.url`.

## Known limitations

- **Single process.** The job queue and rate-limit buckets live in memory; run one
  process. Jobs left running by a dead process are marked `failed` at startup,
  never "success". Scaling out needs a shared queue and limiter.
- **SQLite.** Fine for one node and moderate volume; not for a multi-node setup.
  PostgreSQL is not a supported backend yet: the worker runs threaded adapters
  on separate event loops and asyncpg pools are loop-bound.
- **Per-key scopes are not modeled.** A tenant has one key and one tier; expiry
  (`ttl_days`) and rotation exist, but fine-grained scopes do not.
- **URL-signature findings are inferences**, labelled as such. The additional
  dynamic checks can observe redirect behavior or database error leakage, but do
  not perform destructive exploitation or data extraction. OpenAPI coverage is
  read-only and unauthenticated. Neither feature replaces authenticated, stateful
  DAST or a full API authorization test suite.
- `strix-code-scan` relies on optional tools. A missing tool or Trivy DB causes a
  partial result. Local Semgrep rules are deliberately small and need organization-
  specific rules; do not interpret a successful scan as proof that code is secure.
- The `nmap`/`nuclei` adapters are covered by stubbed tests, not by running the
  real binaries in CI. The stub writes real upstream-shaped artifacts, so finding
  ingestion is schema- and fixture-verified only; a live engine-filed finding has
  not been demonstrated. A remote Git repository is not an authorized asset in
  this platform's scope model; use `strix-code-scan` for local checkouts.
- **`src/hunt` is a design scaffold**, not a second product. The Rust crates
  (`mesh`, `killchain`, `chain`, `zk_scope`, `zk_fingerprint`) compile and expose
  types, but the CLI refuses every subcommand because no engine, prover or mesh
  loop is wired up yet, and there are no tests. Do not present it as working.
