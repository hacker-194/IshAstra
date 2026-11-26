# IshAstra Architecture

IshAstra is an **authorized security assessment platform** that enforces authorization before every outbound connection. It runs real security tools against authorized targets, normalizes findings into a common model, and exports results as SARIF or evidence reports.

## High-Level Architecture (IshAstra 4.0)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           IshAstra Platform (v4.0)                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐          │
│  │   REST API   │    │   Job Queue  │    │   Assessment Worker  │          │
│  │  (FastAPI)   │───▶│ (In-Memory/  │───▶│  (Threaded Pool)     │          │
│  └──────────────┘    │  Redis/      │    └──────────┬───────────┘          │
│       │              │  k8s-jobs)   │               │                      │
│       │              └──────────────┘               │                      │
│       │                       │                     │                      │
│       │                       ▼                     ▼                      │
│       │  ┌────────────────────────────────────────────────────────────┐   │
│       │  │                   CAPABILITY ISSUER                          │   │
│       │  │  Ed25519 JWT (TTL ≤900s) — tenant, engagement, targets,     │   │
│       │  │  pinned_ips, allowed_ports/protocols/tools, budget, RoE     │   │
│       │  └────────────────────────────────────────────────────────────┘   │
│       │                       │                     │                      │
│       ▼                       ▼                     ▼                      │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                    SCOPE GATE (Authorization)                          │ │
│  │  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌──────────────────────────┐  │ │
│  │  │ Layer 1 │ │ Layer 2 │ │  Layer 3 │ │    Observer (IshAstra    │  │ │
│  │  │ URL/Host│ │  DNS/IP │ │ Pinned   │ │    Proof)                │  │ │
│  │  │  Gate   │ │ Policy  │ │ Dest.    │ │                          │  │ │
│  │  └─────────┘ └─────────┘ └──────────┘ └──────────────────────────┘  │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│       │                       │                      │            │      │
│       │                       │                      │            │      │
│       ▼                       ▼                      ▼            ▼      │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                      PHASE 2: SECURITY SPINE                          │ │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐   │ │
│  │  │  EGRESS GATEWAY  │  │  WORKER MANAGER  │  │ EVIDENCE SIGNING │   │ │
│  │  │  (CONNECT Proxy) │  │  (Disposable     │  │  (Ed25519 Manifest│   │ │
│  │  │  Enforces Cap    │  │   Containers)    │  │   + SHA-256 Pins)│   │ │
│  │  │  Allow/Deny rcpts│  │  --read-only     │  │  Offline Verify  │   │ │
│  │  └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘   │ │
│  └───────────┼─────────────────────┼─────────────────────┼──────────────┘ │
│              │                     │                     │               │
│              ▼                     ▼                     ▼               │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                     ADAPTER FRAMEWORK                                 │ │
│  │  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌──────────────────────────┐  │ │
│  │  │  HTTP   │ │ Crawler │ │ Dynamic  │ │    External              │  │ │
│  │  │ Probe   │ │         │ │ Validate │ │  (nmap, nuclei, SQLMap,  │  │ │
│  │  │(proxy)  │ │ (proxy) │ │ (proxy)  │ │   Nikto)                 │  │ │
│  │  └─────────┘ └─────────┘ └──────────┘ └──────────────────────────┘  │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│       │                       │                      │            │      │
│       ▼                       ▼                      ▼            ▼      │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                    FINDINGS ENGINE                                    │ │
│  │  Normalize ▶ Dedupe ▶ Redact ▶ Persist (SQLite/PG) ▶ Export (SARIF,  │ │
│  │  Evidence Bundle, Compliance Reports)                                 │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Queue Modes** (`ISHASTRA_QUEUE_MODE`): `inprocess` (thread pool inside API), `redis-streams` (durable Redis Stream), `k8s-jobs` (one K8s Job per assessment, experimental). See `docs/architecture/jobs.md`.

## Core Components

### 1. Scope Gate (`src/ishastra/core/scope.py`)

**Purpose**: Default-deny authorization layer. Every outbound request is validated against an authorization document before any network contact.

**Three-Layer Validation**:
- **Layer 1 (URL/Host)**: Validates URL structure, host against `include`/`exclude` lists, port against `allowed_ports` — no DNS
- **Layer 2 (DNS/IP)**: Resolves hostname, validates every returned IP against `authorized_networks`, denies special-use addresses (loopback, link-local, private, multicast, etc.) unless explicitly authorized
- **Layer 3 (Pinned Destination)**: Returns a single `Destination` (scheme, host, port, IP) that adapters MUST connect to — prevents DNS rebinding between validation and connection

**Features**:
- ContextVar-based per-task scope binding for multi-tenant isolation (`bound` context manager)
- Observer pattern for IshAstra Proof receipting every gate decision
- Atomic configuration reload — invalid documents never replace active policy
- Signed documents: Ed25519 over canonical JSON, verified against a JWKS key set
  (`configure_signing`), plus a signed `issued_at` freshness bound
  (`ISHASTRA_SCOPE_MAX_AGE_SECONDS`) so a revoked document cannot be replayed
- Optional network intelligence: `allowed_asns` and `allowed_countries` looked up
  through `register_intel()` / `ISHASTRA_SCOPE_INTEL_FILE`; an unset, missing or
  failing lookup denies with `policy_unavailable`
- Just-in-time authorization: with `ISHASTRA_SCOPE_JIT_URL` set, `destination()` and
  `destination_async()` consult the decision point after the local policy allows;
  any non-apply answer, timeout or transport error is a denial
- Inheritance: `Scope.inherited_from(base)` intersects includes, ports, networks,
  ASNs and countries, unions exclusions and takes the earlier expiry — it can only
  narrow an authorization
- Observability: every decision increments
  `ishastra_scope_gate_decisions_total{decision,reason,tenant}` and emits a
  `scope.{url|address}` span carrying `scope.stage`, `scope.decision`,
  `scope.denial` and `scope.tenant` — never the target

### 2. Job Orchestration (`src/ishastra/core/jobs.py`)

**Purpose**: Manages assessment lifecycle from submission to completion with coverage tracking.

**Job States**: `queued → running → completed | partial | failed | cancelled`

**Run States per Adapter**: `ok | partial | rejected | unavailable | failed | timeout | cancelled`

**Coverage Model**: A job is only "clean" (`no findings (complete coverage)`) when **every** selected adapter ran to completion (`RunState.OK`). Partial, failed, or unavailable adapters make the result inconclusive.

**Execution Flow**:
1. `prepare()` — captures scope snapshot, binds engagement policy (id + version)
2. `execute()` — re-validates policy hasn't been revoked/changed, pins destination, runs adapters sequentially
3. Each adapter runs with deadline, cancellation token, and shared context (crawler → HTTP probe → dynamic validation)

### 3. Adapter Framework (`src/ishastra/core/adapter_base.py`, `src/ishastra/core/adapters.py`)

**Purpose**: One capability = one adapter = one tool. Adapters re-check scope gate internally.

**Base Contract** (`Adapter`):
- `available()` → `(bool, str)` — tool presence check
- `assess(target, timeout, cancel, context)` → `AdapterResult(findings, notes, partial)`
- `info()` → capability metadata for `/api/adapters`

**AdapterResult**:
- `findings: list[Finding]` — normalized findings
- `notes: list[str]` — operational details (coverage gaps, deadlines)
- `partial: bool` — adapter admits incomplete coverage

**Built-in Adapters** (always available):
- `ishastra-http` — HTTP probe + header analysis + reflection checks
- `ishastra-crawl` — bounded same-origin crawl, publishes URLs to context
- `ishastra-dynamic-validation` — redirect canaries (.invalid) + DB error indicators (GET only)
- `ishastra-openapi` — discovers OpenAPI specs, checks declared protected GETs
- `ishastra-authz` — cross-principal authorization diff testing (requires `auth.users` in scope)
- `ishastra-ssrf-oob` — blind SSRF confirmation via collab listener (requires `collab` in scope)
- `ishastra-git-exposure` — `.git` exposure checks
- `ishastra-tcp` — native TCP port scan (no external tool)

**External Tool Adapters**:
- `nmap` — TCP connect scan limited to `allowed_ports` or target URL port
- `nuclei` — template-based checks (`http/exposures` subset), pinned IP + Host header, no redirects

**Profiles** (ordered adapter sequences):
| Profile | Adapters |
|---------|----------|
| `web` | http, git-exposure |
| `web-crawl` | crawl, http, git-exposure |
| `web-deep` | crawl, http, dynamic-validation, git-exposure, nuclei |
| `api` | http, openapi, git-exposure |
| `api-deep` | crawl, http, openapi, authz, ssrf-oob, dynamic-validation, git-exposure, nuclei |
| `ports` | tcp, nmap |
| `network` | http, tcp, nmap, git-exposure |

### 4. Findings Engine (`src/ishastra/core/findings.py`)

**Finding Model**: Normalized across all adapters with:
- Severity: `critical | high | medium | low | info`
- Confidence: `high | medium | low`
- Verification: `observed | inferred | unverified`
- Defensive fields: CVSS, business impact, asset criticality, risk rating, exploit availability, user impact, compliance refs
- Lifecycle: `new → triaged → in_progress → fix_verified → closed` (+ `deferred`, `reopened`)

**Deduplication**: By `(asset, category, location)` — nmap and native TCP findings merge on same open port.

**Redaction**: Credential-shaped values removed at every output boundary (evidence, job targets, errors, audit, SARIF, HTML, webhooks).

### 5. Persistence (`src/ishastra/core/store.py`)

**Backend**: SQLite by default (async via aiosqlite) — single-process, owner-only files (0600). PostgreSQL is supported with `ISHASTRA_DB=postgresql://...` and the `postgres` extra; it remains experimental (see Deployment Constraints).

**Tables**:
- `jobs` — job records with coverage JSON
- `findings` — normalized findings with full lifecycle
- `api_keys` — tenant keys (SHA-256 hashed), tiers, rotation
- `audit_log` + `audit_chain` — hash-chained audit trail
- `policies` — engagement policies (managed mode)
- `monitor_targets` + `settings` — monitoring config

### 6. Multi-Tenant Authorization (`src/ishastra/core/policies.py`)

**EngagementPolicy**: Versioned, revocable authorization per tenant.
- Fields mirror `Scope` plus `effective_at`, `expires_at`, `status` (active/revoked)
- Created/updated/revoked by administrators only
- Worker re-validates binding at job dequeue + execution start
- Revoking cancels queued/running jobs for that policy

**Scope Modes** (`ISHASTRA_SCOPE_MODE`):
- `global` — single `scope.json` for entire deployment
- `managed` — per-tenant engagement policies required
- `auto` (default) — global until first policy created, then managed

### 7. API Layer (`src/ishastra/api/`)

**Framework**: FastAPI with:
- Bearer token auth (admin + tenant keys, hashed storage)
- Rate limiting (in-memory single-worker, Redis multi-worker)
- Request ID, security headers, body size/depth limits
- CORS only when explicitly configured
- Static UI at `/` (served from `src/ishastra/api/static/`)

**Key Routers**:
- `assessments` — job submission, polling, SARIF export, finding triage
- `policies` — admin-only engagement policy CRUD
- `monitoring` — target registration, scheduler, webhook alerts
- `proof` — IshAstra Proof grant/verify endpoints
- `probe` — single-request security header grading

### 8. IshAstra Proof (`src/ishastra/proof.py`)

**Artifacts**:
- **Grant** — Ed25519-signed authorization record (who authorized what, hosts/networks/ports, validity window)
- **Receipt** — hash-chained record of every gate decision (`{seq, grant_id, url, decision, reason, previous, hash}`)
- **Proof Pack** — grant + receipts + gate public key + summary

**Verification** (offline, no IshAstra install):
- `grant_signature` — grant signed by issuer
- `issuer_trusted` — pinned issuer key
- `chain` — receipts hash-chain intact
- `scope_compliance` — every allowed action within grant (hosts, ports, networks, time window)
- `gate_key` — receipts signed by gate key

## Data Flow: Assessment Request

```
POST /api/assess {target, profile}
       │
       ▼
┌──────────────────┐
│ Validate scope   │  (gate.check(target) — Layer 1 only)
│ Check tenant key │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Create Job       │  prepare(): capture scope snapshot, bind policy
│ Enqueue          │
└────────┬─────────┘
         │
         ▼ (worker dequeues)
┌──────────────────┐
│ execute()        │
│ 1. Re-validate   │  policy exists, active, same version, tenant matches
│    binding       │
│ 2. scope.check() │  Layer 1 + Layer 2 (DNS)
│ 3. destination() │  Layer 3 → pinned Destination
│ 4. Run adapters  │  sequential, shared context, deadline/cancel
│ 5. Dedupe        │  findings across adapters
│ 6. Persist       │  job + findings → SQLite
└────────┬─────────┘
         │
         ▼
GET /api/assess/{id} → coverage, findings, verdict
```

## Phase 2: Security Spine

### 9. Capability Tokens (`src/ishastra/security/capabilities/`)

**Purpose**: Ed25519-signed JWTs (TTL ≤ 900s) that authorize every outbound action. Tokens carry tenant, engagement, targets, pinned IPs, allowed ports/protocols/tools, budget, and Rules of Engagement hash.

- **Issuer** (`issuer.py`): Generates tokens, registers them for revocation tracking, supports key rotation
- **Verifier** (`verifier.py`): Offline verification — signature, expiration, issuer, scope compliance
- **Revocation** (`revocation.py`): SQLite/PostgreSQL-backed revocation list; revoke by token, job, engagement, or tenant

### 10. Egress Gateway (`src/ishastra/security/egress/gateway.py`)

**Purpose**: CONNECT proxy that enforces capability tokens on every outbound TCP connection.

- Accepts `CONNECT host:port HTTP/1.1` with `Authorization: Bearer <capability-token>`
- Validates token via `CapabilityVerifier`; checks `pinned_ips`, `allowed_ports`, `allowed_protocols`
- Emits `GatewayDecision` receipts (allow/deny with reason) to audit chain
- Default-deny: unauthorized ports/IPs/protocols are rejected at the network layer

**Firewall** (`firewall.py`): Renders nftables deny-by-default ruleset from `FirewallPlan` for host-level enforcement.

### 11. Worker Manager (`src/ishastra/execution/worker_manager.py`)

**Purpose**: Launches disposable containers with hardened defaults for each assessment task.

- `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges:true`, `--user 10001:10001`
- Per-task capability token injected via `--env-file` (never in image or env defaults)
- Automatic cleanup on completion/cancellation/timeout; `docker stop --time=5` then `docker rm -f`

### 12. Evidence Signing Service (`src/ishastra/security/signing/service.py`)

**Purpose**: Produces tamper-evident evidence bundles for compliance.

- Canonical JSON serialization (sorted keys, no whitespace)
- Ed25519 signature over manifest; every member SHA-256 pinned
- `EvidenceManifest` + `ArtifactRef` model; offline verification via `ishastra bundle --verify`

## Security Boundaries

| Boundary | Enforcement |
|----------|-------------|
| **Authorization → Network** | Scope gate validates every connection; pinned destination prevents TOCTOU |
| **Tenant A → Tenant B** | Per-task `bound` ContextVar swaps engagement policy; job carries policy_id+version |
| **Operator → Database** | Audit chain HMAC (`ISHASTRA_AUDIT_HMAC_KEY`) — unforgeable without key |
| **Tool Output → Findings** | Bounded output (16MB), defusedxml parsing, control char stripping |
| **Secrets → Output** | Redaction at every boundary (passwords, tokens, JWTs, AWS keys, private keys) |
| **External Tools** | Minimal env, argument arrays, process group kill, deadline enforcement |
| **Capability → Egress** | CONNECT proxy enforces token on every TCP connection; allow/deny receipted |
| **Worker → Host** | Disposable containers: read-only fs, no caps, no new privileges, non-root user |
| **Evidence → Auditor** | Ed25519 manifest + SHA-256 pins; any tampering detected offline |

## Deployment Constraints

- **Single host by default** — SQLite is the supported pilot backend; one worker lease per database
- **In-process queue by default** — `redis-streams` adds a durable queue shared by workers; `k8s-jobs` adds one Job per assessment and durable cancellation, but remains experimental
- **PostgreSQL is experimental** — loop-aware pools and a single-host worker path are tested; no HA or multi-node support
- **No multi-node guarantee** — multi-node scheduling, exactly-once execution and automated failover are not supported
- **TLS termination** — IshAstra speaks HTTP; put behind reverse proxy, set `ISHASTRA_TRUSTED_PROXIES`
