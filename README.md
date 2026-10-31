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
  run the appropriate adapters as background jobs. The optional `agent` profile
  instead runs the upstream autonomous engine (`strix-agent`) as an external,
  scope-gated process — see *Autonomous AI engine*. `web-deep` adds bounded,
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
  evidence, CWE, remediation), deduplicated across tools, credentials redacted,
  persisted in SQLite, exportable as SARIF 2.1.0.
- **Evidence reports** – scope authorization + findings, sealed in a hash chain.
- **Monitoring** – re-assesses registered targets and alerts (log / webhook) on
  *newly appeared* high-severity findings.
- **Multi-tenant API** – bearer keys (hashed, persisted), per-tenant data
  isolation, rate limiting by tier, persistent audit trail.
- **Web UI** – served at `/`.

## Quick start

```bash
pip install -e ".[dev]"
cp config/scope.example.json scope.json     # edit: what you are authorized to test
export STRIX_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
strix --port 8000                           # UI at http://127.0.0.1:8000
```

```bash
curl -H "Authorization: Bearer $STRIX_API_KEY" -H 'Content-Type: application/json' \
     -d '{"target": "https://app.example.com/", "profile": "web"}' \
     http://127.0.0.1:8000/api/assess          # 202 + job id; poll /api/assess/{id}
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
| `STRIX_AGENT_BIN` | – | Path to the installed `strix-agent` CLI. Unset disables the `agent` profile (it reports the adapter as unavailable, never clean). |
| `STRIX_AGENT_SCAN_MODE` | `quick` | Engine scan mode: `quick`, `standard` or `deep`. |
| `STRIX_AGENT_WORKDIR` | system temp | Where per-run engine artifacts are written and kept. |
| `STRIX_AGENT_MAX_TURNS` | engine default | Per-agent turn ceiling passed to the engine. |
| `STRIX_AGENT_MAX_BUDGET_USD` | engine default | Stop the engine run at this LLM spend. |
| `STRIX_LLM` | – | The *engine's* model. Forwarded by name, never the platform's whole environment. |
| `LLM_API_KEY` / `OPENAI_API_KEY` | – | The engine's provider key (it accepts either name). |
| `LLM_API_BASE` / `OPENAI_API_BASE` / `OPENAI_BASE_URL` / `OLLAMA_API_BASE` | – | The engine's provider endpoint (any OpenAI-compatible server, including a local open-source model). |
| `STRIX_IMAGE` | upstream default | Sandbox image the engine runs its agents in — point it at a mirror for air-gapped hosts. |

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

### Autonomous AI engine (optional)

The `agent` profile delegates an assessment to the upstream open-source engine
[`usestrix/strix`](https://github.com/usestrix/strix) (`strix-agent`, Apache-2.0):
autonomous AI pentesting agents that use their own tools inside a sandbox. Strix
integrates it as an **external process** — nothing from upstream is vendored
here, the engine is never imported, and it can be upgraded or replaced on its
own schedule. What this platform adds around it is the authorization boundary,
the job lifecycle and the normalized finding model; the full record (decisions,
component mapping, licence notes and remaining work) is in
`INTEGRATION_STRIX_AGENT.md`.

Prerequisites (on the assessment host, not in this package):

- **Docker, running** — the engine executes its agents in a sandbox container.
- **An LLM provider of the engine's own**: `STRIX_LLM` (for example
  `openrouter/your-model`, or an open-source model served locally through Ollama
  or vLLM behind any OpenAI-compatible endpoint) plus its `LLM_API_KEY` and,
  when needed, `LLM_API_BASE`. These are the engine's variables; the adapter
  forwards those three by name and passes nothing else of the platform's
  environment to the engine.
- **The engine itself, pinned**: `pipx install strix-agent==1.7.0` (verified
  against 1.7.0, upstream commit `ef5d810`), then point `STRIX_AGENT_BIN` at the
  installed binary. A `PATH` lookup is deliberately not used: both projects ship
  a console script named `strix`, so the setting must name the engine explicitly
  and the adapter refuses any binary whose `--version` does not report a `strix`
  version.

```bash
export STRIX_AGENT_BIN="$HOME/.local/bin/strix-agent"
export STRIX_LLM="openrouter/your-model"     # the engine's provider
export LLM_API_KEY="..."                     # the engine's key
export STRIX_AGENT_SCAN_MODE=quick            # quick | standard | deep
curl -H "Authorization: Bearer $STRIX_API_KEY" -H 'Content-Type: application/json' \
     -d '{"target": "https://app.example.com/", "profile": "agent", "timeout": 900}' \
     http://127.0.0.1:8000/api/assess
```

How it runs: the target passes the same scope gate as every other engine — a
refused target never reaches the engine, and no LLM call is spent on it — then
`strix-agent --target <authorized url> --non-interactive --scan-mode <mode>` runs
in a private working directory under the job's deadline and cancellation switch,
and the run artifacts it wrote (`strix_runs/<run-name>/run.json` and
`vulnerabilities.json`) are read back. Headless exit status `0` (no findings) and
`2` (findings reported) are normal completions; anything else is a failed run, so
a broken engine can never look like a clean target.

Honesty rules applied to its output:

- **Its findings are `unverified`**: they are the engine's own claims, recorded
  with a provenance line (run id, engine agent, its severity/confidence claims,
  its evidence, PoC and remediation text). Strix did not reproduce them.
- **A finding naming any asset outside the engagement is dropped**, not imported
  — an agent does not get to widen its own scope — and the run becomes partial
  as a result.
- **Coverage is claimed only when the engine's own record says `completed`.** Any
  other status keeps the findings but reports partial coverage, so the verdict
  reads "inconclusive — do not treat as clean".
- Ingestion is bounded (first 200 reports, bounded text, control characters
  stripped) and the cap is stated in the job's coverage detail.

Know before you enable it: the engine drives a browser, an interception proxy
and a shell inside its own sandbox, so its connections **cannot be pinned to the
address this gate validated** the way the nmap and nuclei adapters pin theirs
(keep host-level egress filtering on). Run artifacts are kept on the assessment
host for inspection (`STRIX_AGENT_WORKDIR` chooses where) and are never deleted
by the platform, and only `quick` fits the API's 900 s request ceiling —
`standard` and `deep` need a longer deadline than the API currently accepts.

Verified against the real engine, not only against its documentation. With
`strix-agent` 1.7.0, its own sandbox image and a real container, an `agent` job
took ~12 s to complete scoped, clean and artifact-parsed; a provider failure
produced a `failed` job carrying the engine's own error. Five behaviours are
worth knowing in advance, each now handled or documented:

- **The first run pulls a multi-gigabyte sandbox image** (~5.9 GB for 1.7.0)
  before anything else. Pre-pull it (`docker pull ghcr.io/usestrix/strix-sandbox:1.3.0`)
  or set `STRIX_IMAGE`; a job whose deadline is shorter than the pull is a
  `timeout`, not a clean target.
- **A provider failure is fast and loud**: the engine preflights the LLM
  connection, exits `1` and writes no run directory. The platform reports the
  job as `failed` with the engine's own message.
- **A run that files nothing writes no finding index**, and still completes: the
  job is `completed` with zero findings, never a failure.
- **The engine rewrites a loopback target for its sandbox** (`127.0.0.1` becomes
  `host.docker.internal`). Findings filed against that rewrite are matched back
  to the asset you authorized; findings naming anything else are dropped.
- **The engine persists the provider configuration it was handed** into
  `~/.strix/cli-config.json` for the account running it — treat that file as a
  secret, and note that a value it cannot parse there breaks every later run
  until it is fixed (`INTEGRATION_STRIX_AGENT.md` §8).

## API

| | |
|---|---|
| `GET /api/health`, `/api/ready` | liveness, readiness (no auth) |
| `POST /api/assess` · `GET /api/assess[/{id}]` · `POST /api/assess/{id}/cancel` | jobs (`wait=true` runs inline, max 120 s) |
| `GET /api/assess/{id}/sarif` | SARIF export |
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

`DEPLOYMENT.md` is the full operator runbook: systemd unit, reverse proxy,
first-run checklist, backups, key rotation, retention and troubleshooting.

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
  real binaries in CI. The `agent` profile's engine is the same in CI — its
  tests drive a stub that writes real upstream-shaped artifacts — but it has
  additionally been run live once against the real engine, as described above;
  what that run did not prove is a live engine-filed finding, so finding
  ingestion remains schema- and fixture-verified only.
- **The `agent` profile's engine is not address-pinned.** Its agents resolve and
  contact the target from inside their own sandbox container. The scope gate
  validates the target and findings naming other assets are dropped, but the
  platform cannot re-check a name that resolves differently inside the sandbox.
  Cancelling or timing out a run kills the engine process; whether its sandbox
  container is removed depends on the engine and is not verified here, so check
  `docker ps` after a killed run.
- The `agent` profile accepts URLs and hosts only. A local source directory is
  not an authorized asset in this platform's scope model; use
  `strix-code-scan` for local repositories.
