# Architecture Overview

# Architecture Overview

High-level system design and data flows.

## System Context

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
│                              Strix Platform                                  │
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
│  │  Service      │◀─────▶│  (In-Memory/  │◀─────▶│  (Cron +      │      │
│  │               │       │   Redis)      │       │   Interval)   │      │
│  └───────┬───────┘       └───────┬───────┘       └───────┬───────┘      │
│          │                       │                       │              │
│          └───────────────────────┼───────────────────────┘              │
│                                  ▼                                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    Scope Gate (Authorization)                     │  │
│  │  ┌─────────┐  ┌─────────┐  ┌──────────┐  ┌──────────────────┐   │  │
│  │  │ Layer 1 │  │ Layer 2 │  │ Layer 3  │  │    Observer      │   │  │
│  │  │URL/Host │  │ DNS/IP  │  │ Pinned   │  │ (Strix Proof)    │   │  │
│  │  └─────────┘  └─────────┘  └──────────┘  └──────────────────┘   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                  │                                      │
│           ┌──────────────────────┼──────────────────────┐               │
│           ▼                      ▼                      ▼               │
│  ┌───────────────┐      ┌───────────────┐      ┌───────────────┐      │
│  │  HTTP Probe   │      │   Crawler     │      │  Dynamic Val  │      │
│  │  Adapter      │      │   Adapter     │      │  Adapter      │      │
│  └───────┬───────┘      └───────┬───────┘      └───────┬───────┘      │
│          │                      │                      │              │
│          └──────────────────────┼──────────────────────┘              │
│                                  ▼                                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    External Tool Adapters                         │  │
│  │  nmap │ Nuclei │ SQLMap │ Nikto │ Custom (SDK)                   │  │
│  └──────────────────────────────────────────────────────────────────┘  │
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

### 1. API Gateway (`src/strix/api/`)
- **FastAPI** with async request handling
- **Authentication**: API keys, OIDC, mTLS
- **Authorization**: RBAC with org/partner/tenant hierarchy
- **Rate Limiting**: Token bucket per tenant
- **Multi-tenancy**: Row-level security via PostgreSQL RLS
- **Observability**: OpenTelemetry, Prometheus metrics, structured logging

### 2. Scope Gate (`src/strix/core/scope.py`)
The **authorization engine** — default-deny for every outbound connection.

**Three-Layer Validation:**
| Layer | Checks | DNS Required |
|-------|--------|--------------|
| 1. URL/Host | Structure, include/exclude hosts, allowed ports | No |
| 2. DNS/IP | Resolution, every IP vs authorized_networks, special-use detection | Yes |
| 3. Pinned Destination | Returns single immutable Destination | No (cached) |

**Key Properties:**
- **ContextVar isolation**: Per-task scope binding prevents cross-tenant leakage
- **Observer pattern**: Every decision receipted for Strix Proof audit chain
- **TLA+ verified**: 6 invariants, 21.4M states model-checked

### 3. Job Orchestration (`src/strix/core/scheduler.py`, `worker.py`)
- **In-memory queue** (dev) / **Redis queue** (prod)
- **Threaded worker pool** with configurable concurrency
- **Priority queues**: Critical > High > Normal > Low
- **Retry with exponential backoff** + dead letter queue
- **Scheduler**: Cron + interval triggers in the single writer process

### 4. Adapter Framework (`src/strix/core/adapters.py`)
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

### 5. Findings Engine (`src/strix/core/findings.py`)
Pipeline: `Raw Finding → Normalize → Dedupe → Redact → Enrich → Persist → Export`

**Output Formats:** SARIF 2.1, JSON, PDF, HTML, Jira, GitHub Issues

### 6. Strix Proof (`src/strix/core/proof.py`)
Cryptographic audit chain for every gate decision:
```
Grant (scope doc signed) → Gate (decision) → Proof (receipt) → Verify (offline)
```
- Ed25519 signatures with JWKS rotation
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
   → Verifiable offline via `strix proof verify`

7. COMPLETION
   Assessment marked complete → Webhook fired → Report available
```

## Multi-Tenancy Model

```
Partner (MSSP)
  └── Organization (Customer)
       ├── Project A (Team 1)
       │    ├── Assessment 1
       │    └── Assessment 2
       └── Project B (Team 2)
            └── Assessment 3
```

**Isolation Mechanisms:**
- **Database**: Row-Level Security (RLS) policies on all tables
- **Runtime**: ContextVar-bound scope per worker task
- **API**: Tenant-scoped endpoints, org-admin/partner-admin roles
- **Secrets**: Per-tenant encryption keys

## Security Boundaries

| Boundary | Protection |
|----------|------------|
| Internet → API | Cloudflare WAF, TLS 1.3, Rate limiting, Auth |
| API → Workers | Internal network, mTLS, Scope Gate sidecar |
| Workers → Targets | Scope Gate (default-deny), Pinned destinations |
| Workers → DB | RLS, Prepared statements, Connection pooling |
| Workers → Redis | ACLs, TLS, Separate databases per tenant |
| Inter-service | Network policies, mTLS, SPIFFE identities |

## Deployment Topologies

| Topology | Use Case | Scope Gate |
|----------|----------|------------|
| **Sidecar** | K8s pods | Per-pod, shared config |
| **Init Container** | Short-lived jobs | Pre-fetch + cache |
| **Library** | Embedded in adapters | In-process, zero latency |
| **DaemonSet** | Node-level gate | Host-network, eBPF |

## Scaling Characteristics

| Component | Scaling Trigger | Max Observed |
|-----------|-----------------|--------------|
| API Pods | CPU > 70%, RPS > 1000 | 50 replicas |
| Workers | Queue depth > 50 | 100 replicas |
| Scope Gate Check | < 1ms p99 | 12k ops/s |
| PostgreSQL | Connections > 80% | 5000 conn (PgBouncer) |
| Redis | Memory > 70% | Cluster mode |

## Failure Modes & Mitigations

| Failure | Detection | Mitigation |
|---------|-----------|------------|
| Scope Gate misconfig | Startup validation, health check | Fail-fast, default-deny |
| DNS rebinding | Layer 2/3 mismatch | Pinned destinations, TTL=0 |
| Cross-tenant leak | RLS policy test, ContextVar audit | Integration tests, static analysis |
| Worker OOM | Memory limits, metrics | Chunked processing, backpressure |
| DB overload | Connection pool exhaustion | PgBouncer, read replicas, circuit breaker |
| Redis failover | Sentinel/Cluster health | Multi-AZ, persistent queues |

## Related Documentation

- [Scope Gate Deep Dive](../scope-gate/concepts.md)
- [Adapters](../adapters/built-in.md)
- [Deployment](../deployment/kubernetes.md)
- [API Reference](../api/authentication.md)