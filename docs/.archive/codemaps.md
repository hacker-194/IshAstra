# CODEMAPS — Core Module Reference

Quick-reference map of key modules, their responsibilities, and entry points.

---

## `src/ishastra/core/scope.py` — Authorization Gate

**Purpose**: Default-deny scope validation for every outbound connection.

### Key Types
| Name | Purpose |
|------|---------|
| `Scope` | Frozen authorization record (program, include/exclude, networks, ports, policy binding) |
| `Destination` | Single connectable address (scheme, host, port, pinned IP) |
| `AuthConfig` / `CollabConfig` | Test principals + out-of-band listener (from scope doc) |

### Public API
| Function | Purpose |
|----------|---------|
| `configure(...)` | Install global scope (atomic: validates before install) |
| `load(path)` | Load scope.json — returns Scope or None; raises ValueError on invalid doc |
| `check(url)` | Layer 1+2 gate: returns `(denial, reason)` or `("", "")` |
| `destination(url)` | Layer 1+2+3: returns pinned `Destination` for connection |
| `current()` | Active scope for this task (job-bound or global) |
| `bound(scope)` | Context manager: swap scope for this task (multi-tenant) |
| `set_observer(fn)` | Install receipt callback `(url, denial, reason)` for Ishastra Proof |

### Validation Layers
1. **Layer 1** (`_gate`): URL syntax, host in `include`/not in `exclude`, port in `allowed_ports` — no DNS
2. **Layer 2** (`_authorize/_authorize_sync`): DNS resolve → every IP must be global or in `authorized_networks`
3. **Layer 3** (`destination`): Returns `Destination` with first resolved IP — caller MUST connect to this IP only

### Special-Use Address Handling
- `is_special_use()` denies: loopback, link-local, multicast, private, reserved, unspecified, site-local
- IPv6 transition addresses (NAT64, 6to4, Teredo, IPv4-mapped) judged by **embedded IPv4**
- `authorized_networks` can explicitly allow internal ranges (e.g., `10.0.0.0/8`)

### Multi-Tenant
- `_bound: ContextVar[Scope]` — per-task engagement policy
- `bound(snapshot)` used by job executor and probe endpoint
- Observer callback receipts every gate decision for Proof

---

## `src/ishastra/core/jobs.py` — Assessment Orchestration

**Purpose**: Job lifecycle, coverage tracking, adapter execution.

### Key Types
| Name | Purpose |
|------|---------|
| `Job` | Assessment record: target, profile, actor, policy, runs, findings, state |
| `AdapterRun` | Per-adapter result: adapter id, state, detail, findings count, elapsed |
| `RunState` | `OK \| PARTIAL \| REJECTED \| UNAVAILABLE \| FAILED \| TIMEOUT \| CANCELLED` |
| `JobState` | `QUEUED \| RUNNING \| COMPLETED \| PARTIAL \| FAILED \| CANCELLED` |

### Public API
| Function | Purpose |
|----------|---------|
| `prepare(target, profile, actor, policy, scope_snapshot)` | Create job, bind scope snapshot + policy metadata |
| `execute(job)` | Run job against bound scope: re-validate policy, pin destination, run adapters |
| `run_assessment(...)` | Convenience: prepare + execute (wait=True) |

### Execution Flow (`execute()`)
1. Bind job's `scope_snapshot` via `scope.bound()`
2. Re-validate target against bound scope (`scope_snapshot.check()`)
3. Pin destination via `scope.destination()` → `set_pinned_destination()`
4. **Re-validate policy binding**:
   - Policy exists in registry
   - Policy `is_valid()` (active, not expired, effective)
   - Policy version matches job's `policy_version`
   - Job actor matches policy `tenant_id`
5. Select adapters for profile (`adapters.select(profile)`)
6. For each adapter:
   - `adapter.available()` → `UNAVAILABLE` if false
   - `adapter.assess(target, timeout, cancel, context)` with auth principal
   - Handle `AdapterCancelled`, `AdapterTimeout`, `AdapterNotApplicable`, `AdapterError`
   - Track `partial` if any adapter reports incomplete coverage
7. Dedupe findings across adapters
8. Determine job state:
   - All adapters `OK` + findings → `COMPLETED`
   - Any `PARTIAL`/`TIMEOUT`/`FAILED` → `PARTIAL` or `FAILED`
   - No adapter ran → `FAILED` ("no usable coverage")

### Coverage Model
```python
job.coverage() → {
    "total": N,
    "ok": N, "partial": N, "rejected": N, "unavailable": N, "failed": N, "timeout": N, "cancelled": N,
    "adapters": [...]
}
```
- `job.is_clean()` = `COMPLETED` + zero findings + all runs `OK`
- `job.verdict` = human-readable claim

---

## `src/ishastra/core/adapter_base.py` — Adapter Primitives

**Purpose**: Base classes shared by all adapters (built-in + external).

### Key Types
| Name | Purpose |
|------|---------|
| `Adapter` | Base class: `id`, `version`, `asset_types`, `requires`, `available()`, `assess()`, `info()` |
| `AdapterResult` | `findings: list[Finding]`, `notes: list[str]`, `partial: bool` |
| `AdapterError` / `AdapterTimeout` / `AdapterCancelled` / `AdapterNotApplicable` | Exception hierarchy |

### Critical Helper
```python
def checked_destination(target: str) -> Destination:
    """MANDATORY first call in every adapter.assess().
    Returns pinned destination from job context, or runs scope.destination().
    Raises AdapterError if scope refuses."""
```

### Adapter Contract
| Method | Required Behavior |
|--------|-------------------|
| `available()` | Check tool presence; return `(True, "version")` or `(False, "reason")` |
| `assess(target, timeout, cancel, context)` | Must call `checked_destination(target)` first; respect `timeout` (wall clock) and `cancel` (threading.Event); return `AdapterResult` |
| `info()` | Metadata for `/api/adapters` |
| `net_boundary_state()` | Override if adapter enforces network boundary (e.g., "pinned", "none") |

### Context Passing
- `context: dict` shared across adapters in one job
- Crawler publishes: `context["discovered_urls"]`, `context["crawl_pages"]`
- Auth principal: `context["auth_principal"]` (set by job executor)

---

## `src/ishastra/core/adapters.py` — Built-in Adapter Registry

**Purpose**: All scanner adapters + profile definitions.

### Adapter Registry
```python
ADAPTERS: dict[str, Adapter] = {a.id: a for a in (...)}

PROFILES: dict[str, tuple[str, ...]] = {
    "web": ("ishastra-http", "ishastra-git-exposure"),
    "web-crawl": ("ishastra-crawl", "ishastra-http", "ishastra-git-exposure"),
    "web-deep": ("ishastra-crawl", "ishastra-http", "ishastra-dynamic-validation", "ishastra-git-exposure", "nuclei"),
    "api": ("ishastra-http", "ishastra-openapi", "ishastra-git-exposure"),
    "api-deep": ("ishastra-crawl", "ishastra-http", "ishastra-openapi", "ishastra-authz", "ishastra-ssrf-oob", "ishastra-dynamic-validation", "ishastra-git-exposure", "nuclei"),
    "ports": ("ishastra-tcp", "nmap"),
    "network": ("ishastra-http", "ishastra-tcp", "nmap", "ishastra-git-exposure"),
}
```

### Built-in Adapters (always available)
| ID | Purpose | Key Logic |
|----|---------|-----------|
| `ishastra-http` | HTTP probe + headers + reflection | `EndpointProbe`, `match_url_signatures`, header checks (CSP, HSTS) |
| `ishastra-crawl` | Bounded same-origin crawl | `WebCrawler` → publishes `discovered_urls` to context |
| `ishastra-dynamic-validation` | Redirect canaries (.invalid) + DB error indicators | GET only, bounded, no data extraction |
| `ishastra-openapi` | Discover OpenAPI, check protected GETs | Same-origin spec discovery, 30 endpoint limit |
| `ishastra-authz` | Cross-principal auth diff | Requires `auth.users` in scope; compares responses |
| `ishastra-ssrf-oob` | Blind SSRF via collab listener | Requires `collab` in scope; unique canary per param |
| `ishastra-git-exposure` | `.git` exposure checks | Two bounded requests |
| `ishastra-tcp` | Native TCP port scan | No external tool; connects to pinned IP |

### External Tool Adapters
| ID | Tool | Key Constraints |
|----|------|-----------------|
| `nmap` | nmap | `-sT -Pn -n`, pinned IP via `--`, ports = `allowed_ports` or target URL port only |
| `nuclei` | nuclei | `-dr` (no redirects), pinned IP + Host header + SNI, `http/exposures` templates only, rate 25/s |

### Tool Execution (`_run_tool`)
- Argument array (no shell), minimal env (`PATH`, `LC_ALL`, `HOME`)
- Process group kill (`os.killpg`) + `proc.kill()`
- Bounded output (16MB/stream), continuous drain threads
- Deadline enforcement via `time.monotonic()` + cancel event
- defusedxml for nmap XML parsing

### Selecting Adapters
```python
from ishastra.core.adapters import select
adapters = select("web-deep")  # returns list[Adapter] in profile order
```

---

## `src/ishastra/core/policies.py` — Engagement Policies (Multi-Tenant)

**Purpose**: Versioned, revocable authorization per tenant.

### Key Types
| Name | Purpose |
|------|---------|
| `EngagementPolicy` | Frozen policy record (extends Scope fields + lifecycle: status, version, effective_at, expires_at) |
| `PolicyRegistry` | Thread-safe SQLite-backed registry |
| `PolicyError` | Validation/persistence errors |

### Policy Lifecycle
```
create() → active v1
    │
    ├─ update() → active v2, v3, ... (scope fields only; status via revoke)
    │
    └─ revoke() → revoked vN+1 (cancels queued/running jobs)
```

### Registry API
| Method | Purpose |
|--------|---------|
| `create_async(...)` | Validate + persist new policy (builds Scope to validate) |
| `update_async(policy_id, **changes)` | New version with field changes |
| `revoke_async(policy_id)` | Mark revoked, increment version |
| `get_async(policy_id)` | Fetch by ID |
| `list_async(tenant_id?)` | All or tenant-filtered |
| `resolve_async(tenant_id, policy_id?, now?)` | Get usable policy for tenant (newest valid active) |

### Job Binding Validation
```python
def validate_job_binding(job) -> str:
    """Returns refusal reason or ''.
    Checks: policy exists, belongs to job.actor, is_valid(), version matches."""
```
Called at worker dequeue + adapter boundaries via bound snapshot.

### Scope Modes (`ISHASTRA_SCOPE_MODE`)
- `global`: Single `scope.json` for all
- `managed`: Per-tenant policies required
- `auto`: Global until first policy created, then managed

---

## `src/ishastra/core/store.py` — Persistence

**Purpose**: Async SQLite (aiosqlite) + optional PostgreSQL (asyncpg) persistence.

### Key Tables
| Table | Purpose |
|-------|---------|
| `jobs` | Job records + coverage JSON |
| `findings` | Normalized findings with lifecycle fields |
| `api_keys` | Tenant keys (SHA-256 hash), tier, admin flag, rotation |
| `audit_log` | Event log (tenant, event, ts, data JSON) |
| `audit_chain` | Hash chain (sequence, previous_hash, hash, data) |
| `policies` | EngagementPolicy rows |
| `monitor_targets` | Registered monitoring targets |
| `settings` | Key-value settings |

### Async API (canonical)
| Function | Purpose |
|----------|---------|
| `configure(db_path)` | Initialize connection pool |
| `save_job(job)` | Persist job + findings |
| `load_job(job_id)` | Load job with findings |
| `save_finding(finding)` | Upsert finding |
| `load_findings(job_id)` | All findings for job |
| `transition_finding(job_id, fingerprint, new_status, actor)` | Enforced lifecycle transition |
| `save_policy(policy_row)` | Persist EngagementPolicy |
| `load_policies()` | All policies for registry load |
| `save_audit_entry(...)` | Append to log + chain |
| `verify_audit_chain()` | Verify HMAC chain integrity |

### Sync Wrappers
All `*_async` functions have synchronous wrappers (e.g., `save_job_sync`) that run via `asyncio.run()` for non-async callers (CLI, worker threads).

---

## `src/ishastra/core/findings.py` — Finding Model

**Purpose**: Normalized finding schema across all adapters.

### Finding Fields
```python
@dataclass
class Finding:
    asset: str                    # target host/URL
    category: str                 # adapter-specific category (e.g., "missing_csp")
    title: str                    # human-readable
    severity: str                 # critical|high|medium|low|info
    confidence: str               # high|medium|low
    verification: str             # observed|inferred|unverified
    detector: str                 # adapter id
    detector_version: str
    evidence: str                 # redacted
    location: str                 # specific URL/port/path
    description: str
    remediation: str
    cwe: str                      # CWE-XXX
    # Defensive fields:
    cvss_score: str
    business_impact: str          # critical|high|medium|low
    asset_criticality: str        # critical|high|medium|low
    risk_rating: str              # critical|high|medium|low
    exploit_available: int        # 0/1
    user_impact: str              # none|low|medium|high|critical
    compliance_refs: list[str]
    remediation_status: str       # pending|in_progress|fix_verified|deferred|wont_fix
    discovered_date: str
    reported_date: str
    resolved_date: str
    sources: list[str]            # adapter ids that produced this
```

### Key Functions
| Function | Purpose |
|----------|---------|
| `dedupe(findings)` | Merge by `(asset, category, location)` — keep highest severity |
| `validate_transition(current, new)` | Enforce lifecycle: `new → triaged → in_progress → fix_verified → closed` (+ `deferred`, `reopened`) |
| `allowed_transitions` | Dict of valid next states |
| `to_sarif(findings)` | Export SARIF 2.1.0 |
| `fingerprint(finding)` | Stable hash for deduplication/triage |

### Lifecycle Transitions
```
new → triaged → in_progress → fix_verified → closed
  ↘ deferred ↗
       ↘ reopened → triaged
```
Invalid transitions raise `ValueError` (API returns 409).

---

## `src/ishastra/api/` — REST API Layer

### Structure
```
src/ishastra/api/
├── app.py              # FastAPI factory, lifespan, middleware stack
├── dependencies.py     # DI: settings, auth, rate limiter, redis, http client
├── security.py         # Middleware: rate limit, headers, request ID, tenant state
├── schemas.py          # Pydantic request/response models
├── routers/
│   ├── assessments.py  # POST/GET /api/assess, SARIF, finding triage
│   ├── policies.py     # Admin: CRUD engagement policies
│   ├── monitoring.py   # Targets, scheduler, webhooks
│   ├── proof.py        # Grant/verify Ishastra Proof
│   ├── probe.py        # Single-request header grading
│   ├── system.py       # Health, ready, metrics, scope, adapters
│   ├── tenants.py      # Key management
│   └── scheduler.py    # Scheduled assessments
└── static/             # Bundled UI (index.html, JS, CSS)
```

### Middleware Order (outermost first)
1. `MetricsMiddleware` — Prometheus metrics
2. `TenantStateMiddleware` — Binds tenant from API key
3. `BodyLimitMiddleware` — Max bytes + JSON nesting depth
4. `RedisRateLimitMiddleware` / `RateLimitMiddleware` — Per-tier limits
5. `RequestIDMiddleware` — X-Request-ID propagation
6. `SecurityHeadersMiddleware` — CSP, HSTS, frame options
7. `CORSMiddleware` — Only if `ISHASTRA_CORS_ORIGINS` set

### Auth
- `require_admin` — Bootstrap admin key (ISHASTRA_API_KEY)
- `require_tenant` — Tenant API key (hashed lookup)
- Keys stored as SHA-256; raw key shown once on creation

---

## `src/ishastra/proof.py` — Ishastra Proof

**Purpose**: Cryptographic authorization evidence.

### Artifacts
| Artifact | Description |
|----------|-------------|
| `Grant` | Ed25519-signed authorization (program, authorized_by, ref, include, networks, ports, validity) |
| `Receipt` | Hash-chained gate decision `{seq, grant_id, url, decision, reason, previous, hash}` |
| `Proof` | Grant + receipts + gate public key + summary |

### CLI Commands
```bash
ishastra grant --program "..." --authorized-by "..." --ref "..." --include host --port 443 --days 14 --out grant.json --key-out issuer.key
ishastra gate --grant grant.json --ledger receipts.jsonl --gate-key gate.key
ishastra proof --grant grant.json --ledger receipts.jsonl --out proof.json
ishastra verify proof.json --issuer-key issuer.key
```

### Verification Checks
1. `grant_signature` — Grant signed by issuer
2. `issuer_trusted` — Pinned issuer public key
3. `chain` — Receipt hash chain intact
4. `scope_compliance` — Every allowed action within grant (hosts, ports, networks, time)
5. `gate_key` — Receipts signed by gate key

---

## Cross-Module Data Flow

```
scope.json / EngagementPolicy
       │
       ▼
Scope (gate) ──► Job.prepare() ──► Job (with scope_snapshot)
       │                          │
       │                          ▼
       │                   Job.execute()
       │                          │
       │                          ▼
       │                   scope.bound(snapshot)
       │                          │
       │                          ▼
       │                   checked_destination()
       │                          │
       │                          ▼
       │                   Adapter.assess()
       │                          │
       │                          ▼
       │                   Finding → dedupe()
       │                          │
       ▼                          ▼
store.save_job() ◄──────────── Job (completed)
       │
       ▼
GET /api/assess/{id} → coverage, findings, verdict
       │
       ▼
to_sarif() / render_pdf_report()
```