# Changelog

## 0.1.0 — 2026-11-12

First tagged release. The assessment core was already in place; this release
adds the proof-of-authorization layer and freezes a installable baseline.

### Strix Proof (new)

- **Signed grants** (`strix grant`): an Ed25519-signed document naming the
  program, the authorizing person, the reference, the hosts/CIDRs and the
  validity window. Expired, tampered or out-of-scope grants are refused.
- **Receipt ledger**: every allow/deny decision is appended to a hash-chained
  JSONL ledger that resumes safely across restarts and detects reordering,
  deletion and edits.
- **Gate service** (`strix gate`): `POST /v1/authorize` for tools and agents,
  plus `/v1/grant`, `/v1/receipts` and `/v1/proof`. Refuses a non-loopback bind
  without a token.
- **Verification**: `strix verify` offline, or `POST /api/proof/verify` over
  HTTP with no account. Trust requires pinning the issuer key
  (`--issuer-key` / `trusted_issuer`); an unpinned pack reports
  `issuer_trusted: false`.
- **`strix assess --grant`** derives the assessment scope from a grant and
  records gate decisions into the pack.

### Assessment platform

- Fail-closed scope gate with DNS pinning, engagement policies, tenant
  isolation, HMAC audit chain, redaction in logs/SARIF/evidence, and
  retention.
- Adapters for HTTP, Nuclei, Nmap and agent profiles; SARIF, JSON, CSV, OSCAL
  and printable HTML reports.
- Docker Compose stack (Strix + Redis + nginx), Prometheus/Grafana overlay,
  and a tag-driven release workflow.

### Known limits

- Single writer, SQLite only; no horizontal scaling or automatic failover.
- The gate authorizes and records; it is not a packet filter.
- No grant revocation list yet, and no external timestamp authority.
