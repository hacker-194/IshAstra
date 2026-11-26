# Architecture Overview

High-level system design and data flows.

## System Context (IshAstra 4.0)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            External Systems                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Target     │  │  Identity    │  │   Ticketing  │  │    SIEM      │   │
│  │  Applications│  │  Providers   │  │  (Jira,      │  │  (Splunk,    │   │
│  │              │  │  (OIDC/SAML) │  │   GitHub)    │  │   Sentinel)  │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘   │
└─────────┼─────────────────┼─────────────────┼─────────────────┼───────────┘
          │                 │                 │                 │
          ▼                 ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              IshAstra Platform (v4.0)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        API Gateway (FastAPI)                          │  │
│  │  Auth │ Rate Limit │ RBAC │ Multi-tenant │ OpenAPI │ Webhooks       │  │
│  └────────────────────────────────┬─────────────────────────────────────┘  │
│                                   │                                        │
│           ┌───────────────────────┼───────────────────────┐               │
│           ▼                       ▼                       ▼               │
│  ┌───────────────┐       ┌───────────────┐       ┌───────────────┐      │
│  │  Assessment   │       │   Job Queue   │       │  Scheduler    │      │
│  │  Service      │◀─────▶│ (In-Memory/   │◀─────▶│  (Cron +      │      │
│  │               │       │  Redis/k8s)   │       │   Interval)   │      │
│  └───────┬───────┘       └───────┬───────┘       └───────┬───────┘      │
│          │                       │                       │              │
│          └───────────────────────┼───────────────────────┘              │
│                                  ▼                                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │              CAPABILITY ISSUER (Phase 2)                          │  │
│  │  Ed25519 JWT (TTL ≤900s) — tenant, engagement, targets,          │  │
│  │  pinned_ips, allowed_ports/protocols/tools, budget, RoE hash     │  │
│  └────────────────────────────────┬────────────────────────────────┘  │
│                                   │                                    │
│           ┌───────────────────────┼───────────────────────┐           │
│           ▼                       ▼                       ▼           │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Scope Gate (Authorization)                     │  │
│  │  ┌─────────┐  ┌─────────┐  ┌──────────┐  ┌──────────────────┐   │  │
│  │  │ Layer 1 │  │ Layer 2 │  │ Layer 3  │  │    Observer      │   │  │
│  │  │URL/Host │  │ DNS/IP  │  │ Pinned   │  │ (IshAstra Proof)    │   │  │
│  │  └─────────┘  └─────────┘  └──────────┘  └──────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│           │                      │                      │             │
│           ▼                      ▼                      ▼             │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                   PHASE 2: SECURITY SPINE                         │  │
│  │  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐   │  │
│  │  │  EGRESS GATEWAY  │  │  WORKER MANAGER  │  │EVIDENCE SIGN │   │  │
│  │  │  (CONNECT Proxy) │  │ (Disposable      │  │  (Ed25519    │   │  │
│  │  │ Enforces Cap     │  │  Containers)     │  │  Manifest)   │   │  │
│  │  │ Allow/Deny rcpts │  │ --read-only      │  │ Offline Ver  │   │  │
│  │  └────────┬─────────┘  └────────┬─────────┘  └──────┬───────┘   │  │
│  └───────────┼─────────────────────┼─────────────────────┼───────────┘  │
│              │                     │                     │              │
│              ▼                     ▼                     ▼              │
│           ┌──────────────────────────────────────────────────────┐    │
│           │              ADAPTER FRAMEWORK                        │    │
│           │  ┌──────────┐ ┌─────────┐ ┌──────────┐ ┌──────────┐  │    │
│           │  │ HTTP     │ │Crawler  │ │Dynamic   │ │ External │  │    │
│           │  │ Probe    │ │ Adapter │ │Validate  │ │(nmap,    │  │    │
│           │  │ (proxy)  │ │ (proxy) │ │ (proxy)  │ │ nuclei,  │  │    │
│           │  └──────────┘ └─────────┘ └──────────┘ │ SQLMap,  │  │    │
│           │                                         │ Nikto)   │  │    │
│           │                                         └──────────┘  │    │
│           └──────────────────────────────────────────────────────┘    │
│                                  │                                      │
│                                  ▼                                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Findings Engine                                │  │
│  │  Normalize ▶ Dedupe ▶ Redact ▶ Enrich ▶ Persist ▶ Export        │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                  │                                      │
│           ┌──────────────────────┼──────────────────────┐               │
│           ▼                      ▼                      ▼               │
│  ┌───────────────┐      ┌───────────────┐      ┌───────────────┐      │
│  │  PostgreSQL   │      │    Redis      │      │ Object Store  │      │
│  │  (Primary)    │      │  (Queue/Cache)│      │  (Reports)    │      │
│  └───────────────┘      └───────────────┘      └───────────────┘      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. API Gateway (`src/ishastra/api/`)
- **FastAPI** with async request handling
- **Authentication**: API keys; OIDC/SAML browser sessions (no mTLS in the app)
- **Authorization**: RBAC with org/partner/tenant hierarchy
- **Rate Limiting**: Token bucket per tenant
- **Multi-tenancy**: application-level tenant filters on every backend; PostgreSQL RLS is defense-in-depth where tenant context is set
- **Observability**: OpenTelemetry, Prometheus metrics, structured logging

### 2. Scope Gate (`src/ishastra/core/scope.py`)
The **authorization engine** — default-deny for every outbound connection.

**Three-Layer Validation:**
| Layer | Checks | DNS Required |
|-------|--------|--------------|
| 1. URL/Host | Structure, include/exclude hosts, allowed ports | No |
| 2. DNS/IP | Resolution, every IP vs authorized_networks, special-use detection | Yes |
| 3. Pinned Destination | Returns single immutable Destination | No (cached) |

**Key Properties:**
- **ContextVar isolation**: Per-task scope binding prevents cross-tenant leakage
- **Observer pattern**: Every decision receipted for IshAstra Proof audit chain
- **TLA+ model-checked**: 6 invariants, 21.4M states verified (`docs/tla/model-check-results.txt`); this is not a formal proof

### 3. Job Orchestration (`src/ishastra/core/scheduler.py`, `worker.py`)
- **In-process queue** (default), **Redis Streams** (durable), or **Kubernetes Jobs** (experimental)
- **Threaded worker pool** with configurable concurrency
- **Priority queues**: Critical > High > Normal > Low
- **Retries with backoff** in the supported queue paths; no claim of exactly-once execution
- **Scheduler**: Cron + interval triggers in the single writer process

### 4. Adapter Framework (`src/ishastra/core/adapters.py`)
**Built-in Adapters:**
| Adapter | Purpose | Scope Gate Re-check |
|---------|---------|---------------------|
| HTTP Probe | Header analysis, security headers, tech detection | Yes |
| Crawler | Link discovery, form extraction, JS analysis | Yes |
| Dynamic Validation | Runtime behavior, auth flows, business logic | Yes |

**External Tool Adapters:**
- nmap (port/service discovery)
- Nuclei (template-based vuln scanning)
- SQLMap (SQL injection)
- Nikto (web server issues)

**SDK**: Custom adapter development with automatic Scope Gate integration.

### 5. Findings Engine (`src/ishastra/core/findings.py`)
Pipeline: `Raw Finding → Normalize → Dedupe → Redact → Enrich → Persist → Export`

**Output Formats:** SARIF 2.1, JSON, PDF, HTML, Jira, GitHub Issues

### 6. IshAstra Proof (`src/ishastra/core/proof.py`)
Cryptographic audit chain for every gate decision:
```
Grant (scope doc signed) → Gate (decision) → Proof (receipt) → Verify (offline)
```
- Ed25519 signatures; scope-signing keys can be rotated by the operator
- Tamper-evident Merkle tree
- Offline verification capability

## Data Flow: Assessment Lifecycle

```
1. CREATE SCOPE
   User POST /api/v1/scopes {version, authorized_networks, include_hosts...}
   → Stored in PostgreSQL, signed with Ed25519

2. SUBMIT ASSESSMENT
   POST /api/v1/assessments {scope_id, targets, adapters}
   → Validated, queued, returns assessment_id

3. WORKER PICKS JOB
   Worker dequeues, binds scope via ContextVar
   → Scope Gate active for this task only

4. ADAPTER EXECUTES
   For each target:
   a) Scope Gate Layer 1: URL structure + host allowlist
   b) Scope Gate Layer 2: DNS resolve + IP allowlist + special-use check
   c) Scope Gate Layer 3: Returns pinned Destination
   d) Adapter connects ONLY to pinned Destination
   e) Every connection re-validated by Scope Gate

5. FINDINGS COLLECTED
   Raw findings → Normalize → Dedupe → Redact PII → Enrich (CVE, CWE)
   → Persist to PostgreSQL → Export SARIF/PDF

6. AUDIT CHAIN
   Each gate decision → Proof receipt → Signed → Stored
   → Verifiable offline via `ishastra proof verify`

7. COMPLETION
   Assessment marked complete → Webhook fired → Report available
```

## Multi-Tenancy Model

```
Organization (Customer)
  ├── Project A (Team 1)
  │    ├── Assessment 1
  │    └── Assessment 2
  └── Project B (Team 2)
       └── Assessment 3
```

**Isolation Mechanisms:**
- **Database**: application filters on every backend; PostgreSQL RLS policies are defense-in-depth (SQLite has no RLS)
- **Runtime**: ContextVar-bound scope per worker task
- **API**: Tenant-scoped endpoints, org-admin/partner-admin roles
- **Secrets**: Per-tenant encryption keys

## Security Boundaries

| Boundary | Protection |
|----------|------------|
| Internet → API | Operator-provided TLS reverse proxy, rate limiting, auth |
| API → Workers | Same process by default; network policy when deployed separately |
| Workers → Targets | Scope Gate (default-deny), Pinned destinations |
| Workers → DB | Parameterized SQL, tenant filters, optional PostgreSQL RLS |
| Workers → Redis | Operator-provided ACLs/TLS; logical separation only where configured |
| Inter-service | Kubernetes network policies; no SPIFFE/mTLS implementation |

## Deployment Topologies

| Integration | Status | Notes |
|-------------|--------|-------|
| **In-process library** | Supported | Adapters call `checked_destination()`; the only supported integration |
| **Sidecar proxy** | Not implemented | No sidecar image or proxy protocol exists |
| **DaemonSet / eBPF** | Not implemented | No eBPF component exists |

## Scaling Characteristics

IshAstra is single-writer by design. These are the real limits, not aspirational
capacity numbers:

| Component | Scaling approach | Tested |
|-----------|------------------|--------|
| API + worker | Vertical: more CPU/RAM, `ISHASTRA_WORKERS` threads | Single host |
| Job queue | In-process by default; durable `redis-streams`, `sqlite` and `postgres` queues; `k8s-jobs` one Job per assessment (experimental) | 10-job soak |
| PostgreSQL | Single writer against a managed instance | Single host |
| Redis | Shared rate-limit counters | Single node |
| Scope gate check | In-process, sub-millisecond on pinned destinations | 95% covered, TLA+-checked |

## Failure Modes & Mitigations

| Failure | Detection | Mitigation |
|---------|-----------|------------|
| Scope Gate misconfig | Startup validation, health check | Fail-fast, default-deny |
| DNS rebinding | Layer 2/3 mismatch | Pinned destinations, TTL=0 |
| Cross-tenant leak | Tenant-filter tests, optional PostgreSQL RLS | Integration tests, static analysis |
| Worker OOM | Memory limits, metrics | Chunked processing, backpressure |
| DB overload | Connection pool exhaustion | Slow down submissions, add CPU/RAM; no PgBouncer or read replicas in the supported topology |
| Redis loss | Rate-limit backend errors | Rate limiting fails closed; Redis holds counters only, not jobs |

## Related Documentation

- [Scope Gate Deep Dive](../scope-gate/concepts.md)
- [Adapters](../adapters/built-in.md)
- [Deployment](../deployment/kubernetes.md)
- [API Reference](../api/authentication.md)