# Nepal launch readiness

This is the operator checklist for running Strix as a Nepal-focused,
non-commercial security assessment deployment. It separates what the repository
now does from what only a local operator, lawyer and regulator can establish.

> Not legal advice. NRB, NTA, NCSP and privacy obligations change; confirm every
> claim below with Nepali counsel and the relevant regulator before running a
> pilot. The Strix project is fully open source under MIT and does not sell a
> hosted, paid or enterprise edition.

## 1. Engineering status

Ready for a **single-node pilot** (one host, one Strix process, SQLite WAL):

- Fail-closed authorization: no scope document or managed policy means every
  scan/probe is refused; scope reloads are atomic and never widen silently.
- Tamper-evident audit chain (set `STRIX_AUDIT_HMAC_KEY`), redaction at rest and
  in logs/SARIF, owner-only database permissions, and per-request scope checks.
- Nepal evidence packs: NRB, NTA and NCSP 2080 control mappings, JSON/CSV/OSCAL/
  SARIF exports. `--format pdf` writes printable HTML (use Print to PDF).
- Sector scope starters: `strix scope-template bank|telco|gov|global
  --domain client.com.np`; they authorize only a placeholder client domain and
  **no** shared ISP ranges. Add the client's own hosts/CIDRs from the signed
  authorization letter.
- Production stack: `docker compose` (Strix + Redis + nginx), required secrets,
  loopback admin port, TLS example, health check that requires a loaded scope,
  optional Prometheus/Grafana overlay.
- Verified locally: ruff, format and mypy clean, `pytest tests/unit tests/security` passes
  (14 skips: IPv6 and opt-in live scanners), live nmap/Nuclei against a loopback lab, a verified
  backup/restore with audit-chain verification, and fresh-database migrations.

Known limits to state honestly in a pilot contract:

- **Single writer.** The worker lease refuses a second process; no horizontal
  scaling, no automated HA/failover. Backups + restore are the recovery path.
- **SQLite is the supported pilot backend.** PostgreSQL and Kubernetes Jobs have tested
  single-host worker paths but are experimental, with no HA or multi-node
  failover.
- Detection is authorized, non-destructive DAST/SAST-style coverage; it is not a
  penetration test, does not exploit, and does not replace manual review.
- JavaScript-rendered apps, authenticated business-logic testing and custom
  client workflows are limited; scope them explicitly.

## 2. In-country deployment profile

Recommended for banks, ISPs and government pilots:

| Item | Recommended |
|---|---|
| Hosting | Nepal-based VPS/private cloud or client on-prem; keep evidence in-country unless the client approves otherwise |
| Domain/TLS | `*.com.np` / client domain, HTTPS only; enable `deploy/nginx/conf.d/tls.conf.example` |
| DNS | Set `STRIX_TRUSTED_PROXIES` to the actual proxy CIDR only |
| Backups | Encrypted nightly SQLite `.backup`, copied to a second Nepali location; quarterly restore test |
| Time | NTP enabled (audit timestamps and chain ordering) |
| Power/net | UPS on-prem; redundant uplink for hosted pilots |
| Access | Admin API only over VPN/SSH tunnel or the loopback port; no public admin UI |
| Secrets | Generated per deployment, stored outside git; rotate API keys and the audit HMAC key on a schedule |
| Monitoring | Optional Prometheus/Grafana overlay; alert on readiness, disk, failed jobs |
| Retention | Set `STRIX_RETENTION_DAYS` to the client's contractual period; the sealed chain is kept |

Start:

```bash
cp .env.production.example .env.production
# Generate each secret with: python -c 'import secrets; print(secrets.token_urlsafe(32))'
docker compose --env-file .env.production run --rm strix strix scope-wizard --output /etc/strix/scope.json
# OR manually: cp config/scope.example.json config/scope.json   # replace with signed scope
docker compose --env-file .env.production up -d --build
curl -s http://127.0.0.1:8000/api/ready
```

## 3. Authorization and evidence (non-negotiable)

Before any packet leaves the host:

1. A signed engagement letter or rules-of-engagement names the client entity,
   the exact hosts/CIDRs, ports, time window, contacts, and emergency stop.
2. The scope document references that authorization
   (`authorized_by`, `authorization_ref`) and excludes production-only or
   third-party systems the client did not authorize.
3. The client confirms it owns or is authorized to test every included host.
   Shared hosting, ISP ranges and `*.com.np` are never acceptable defaults.
   Restart Strix after changing the global scope file; managed-mode policies
   apply through the API without a restart.
4. Findings, evidence and the audit chain are handled as client confidential
   data; share only through the agreed channel.
5. Incident/breach notification duties are agreed in writing before testing.

## 4. Regulatory mapping (verify with counsel)

Strix ships control mappings, not certifications. Treat an evidence pack as
input to the client's compliance process.

| Framework | What the pack covers | What it does not establish |
|---|---|---|
| **NRB** (Nepal Rastra Bank IT/cyber guidance) | Control-level observations mapped to NRB-style controls: access, crypto/TLS, logging, segmentation, backups/DR, vendor risk, incident handling | NRB approval, audit certification, or a legal opinion |
| **NTA** (telecom bylaws/MIS security expectations) | Network exposure, management-plane and signaling-adjacent checks, logging/monitoring, incident reporting gaps | NTA licence compliance or sign-off |
| **NCSP 2080** (National Cyber Security Policy) | CII protection, incident reporting, supply chain, resilience and awareness control evidence | Government accreditation or CII designation |

Practical rules:

- Prefer **in-country hosting** and client-controlled evidence. Confirm data
  residency, cross-border transfer and breach-notification duties with counsel.
- Do not enable an external AI/LLM triage provider for client data unless the
  contract and the client expressly allow that transfer. Keep it off by default.
- Retain evidence only as long as the engagement requires; the audit chain is
  append-only, so agree its retention in the contract.

## 5. Non-commercial pilot readiness

These are outside the codebase. A pilot may be free of charge, but authorization,
data handling and legal review still apply:

- [ ] Confirm the deploying organization has authority to run the pilot and that
      every target is covered by written authorization.
- [ ] Sign data-processing/confidentiality terms and a clear limitation of
      liability; even a free pilot needs agreed data handling.
- [ ] Confirm the legal basis for providing security testing in Nepal; retain
      counsel's written view.
- [ ] Define an incident-response and client-escalation runbook, including who
      contacts NRB/NTA/the client and within what time.
- [ ] Keep tester identity/authorization records for every engagement.
- [ ] Do not charge a fee or describe the project as a paid/hosted edition. If a
      deploying organization independently funds a pilot, keep that arrangement
      separate from the open-source project and disclose it.
- [ ] If another party independently offers hosting or services under MIT, do
      not present that as an official Strix offering.

## 6. Pilot go-live gates

Do not start a client scan until all are true:

- [ ] `docker compose ps` shows healthy Strix/nginx/Redis, or systemd is active.
- [ ] `/api/ready` returns `ready=true` and `scope_configured=true`.
- [ ] `STRIX_ENV=production`, and `STRIX_API_KEY`, `STRIX_AUDIT_HMAC_KEY` and
      (if used) `STRIX_WEBHOOK_SECRET` are unique random values, not examples.
- [ ] `GET /api/scope` returns exactly the signed hosts/CIDRs/ports.
- [ ] Out-of-scope target submission returns 403 and is never contacted.
- [ ] A loopback assessment smoke run passes:
  `python scripts/assessment_load_check.py --jobs 1 --workers 1`.
- [ ] Backups and a restore test are complete.
- [ ] The client has the stop contact and knows how to halt the engagement.
- [ ] TLS is enabled and the admin port is not publicly reachable.
- [ ] The signed authorization letter is stored with the engagement record.

## 7. What to build next (in order)

1. **Organizations/RBAC/SSO** before any multi-user deployment. Today a tenant
   is one API key and the honest ceiling is one host.
2. **Cross-job finding records and verified resolution**, building on the stable
   per-asset fingerprint, for repeat-engagement evidence.
3. **Authenticated scanning** (session/role support) for bank and telecom apps.
4. **Independent security review** and a multi-node/HA soak before any
   availability commitment.
5. **Nepali-language report templates** and local currency/date formatting for
   client-facing deliverables.
