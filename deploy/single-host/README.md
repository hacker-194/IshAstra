# Single-host deployment

One Docker host, one application process, SQLite on a named volume, Caddy in
front for TLS. This is the topology `docs/quickstart/production.md` supports:
**one writer, no replicas**. It fits Oracle Cloud Always Free Arm (2 OCPU / 12 GB)
and other 2 vCPU / 4+ GB VMs, and it does not need PostgreSQL, Redis or object
storage.

Use this when you want the platform running on a host that survives longer than
5 minutes (no Fly auto-stop).

## 1. Prerequisites

- A Linux host with Docker Engine 24+ and the Compose plugin, 2 vCPU and 4 GB
  RAM minimum (8 GB if you run deep crawls and nuclei).
- Ports 80 and 443 reachable from the internet if you want automatic TLS.
- A DNS name pointing at the host, or use `SITE_ADDRESS=:80` for plain HTTP.
- [Oracle Cloud Always Free](https://www.oracle.com/cloud/free/) Arm instance:
  2 OCPU, 12 GB RAM, ARM64. No credit card needed after the June 2026 halving.
- If using an x86 Oracle instance, the amd64 image is the default; for Arm add
  `--build-arg TARGETARCH=arm64` to the Docker build.

## 2. Configure

```bash
cd deploy/single-host
cp .env.example .env
chmod 600 .env
openssl rand -base64 48   # run three times: API key, audit HMAC key, encryption key
$EDITOR .env              # set SITE_ADDRESS and the three values
```

`ISHASTRA_ENV=production` is fail-closed: short or placeholder keys abort
startup, and `/docs`, `/redoc` and `/openapi.json` are disabled.

## 3. Start

```bash
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1/api/health   # through Caddy
```

First build takes a few minutes: it installs nmap, sqlmap, nikto and pinned
nuclei with templates. The Dockerfile is `TARGETARCH`-aware (default amd64;
pass `TARGETARCH=arm64` for Oracle Arm).

## 4. Restore an existing deployment

The database lives on the `ishastra_data` volume at
`/var/lib/ishastra/ishastra.db`, next to the signed scope document.

```bash
# 1. Copy the files in (the container writes as the ishastra user)
docker compose cp /path/to/ishastra.db        ishastra:/var/lib/ishastra/ishastra.db
docker compose cp /path/to/scope.json         ishastra:/var/lib/ishastra/scope.json

# 2. Fix ownership, then restart
docker compose exec -u root ishastra chown -R ishastra:ishastra /var/lib/ishastra
docker compose restart ishastra

# 3. Prove the restore worked
docker compose exec ishastra ishastra backup --verify /var/lib/ishastra/ishastra.db
curl -fsS http://127.0.0.1/api/ready | jq
```

`/api/ready` must report `database`, `audit_chain`, `monitoring` and
`scope_configured` all true. If `audit_chain` is false, the
`ISHASTRA_AUDIT_HMAC_KEY` does not match the key the chain was sealed with — do
not "fix" it by resetting the chain, copy the original key.

Keep `ISHASTRA_ENCRYPTION_KEY` from the old deployment as well: values
encrypted with the old key cannot be read with a new one.

### Keys that cannot be recovered

Secret stores such as `fly secrets` are write-only: once the old host is gone,
the values are gone with it. Record `ISHASTRA_API_KEY`,
`ISHASTRA_AUDIT_HMAC_KEY` and `ISHASTRA_ENCRYPTION_KEY` somewhere you control
before decommissioning anything.

- Wrong audit key: the app **refuses to start** in production mode with
  `Audit chain tampered: Hash mismatch at sequence N`. That is fail-closed by
  design. `ishastra serve --reset-audit-chain` discards the history and is only
  for a deliberate recovery, never for a key mismatch.
- Wrong encryption key: existing encrypted values cannot be decrypted.


[read_files: showing lines 1-80 of 103. Use code_search to locate the part you need and read a window around it, or call read_files again with offset=81 to continue.]
## 2. Configure

```bash
cd deploy/single-host
cp .env.example .env
chmod 600 .env
openssl rand -base64 48   # run three times: API key, audit HMAC key, encryption key
$EDITOR .env              # set SITE_ADDRESS and the three values
```

`ISHASTRA_ENV=production` is fail-closed: short or placeholder keys abort
startup, and `/docs`, `/redoc` and `/openapi.json` are disabled.

## 3. Start

```bash
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1/api/health   # through Caddy
```

First build takes a few minutes: it installs nmap, sqlmap, nikto and pinned
nuclei with templates, for both amd64 and arm64 images upstream.

## 4. Restore an existing deployment

The database lives on the `ishastra_data` volume at
`/var/lib/ishastra/ishastra.db`, next to the signed scope document.

```bash
# 1. Copy the files in (the container writes as the ishastra user)
docker compose cp /path/to/ishastra.db        ishastra:/var/lib/ishastra/ishastra.db
docker compose cp /path/to/scope.json         ishastra:/var/lib/ishastra/scope.json

# 2. Fix ownership, then restart
docker compose exec -u root ishastra chown -R ishastra:ishastra /var/lib/ishastra
docker compose restart ishastra

# 3. Prove the restore worked
docker compose exec ishastra ishastra backup --verify /var/lib/ishastra/ishastra.db
curl -fsS http://127.0.0.1/api/ready | jq
```

`/api/ready` must report `database`, `audit_chain`, `monitoring` and
`scope_configured` all true. If `audit_chain` is false, the
`ISHASTRA_AUDIT_HMAC_KEY` does not match the key the chain was sealed with — do
not "fix" it by resetting the chain, copy the original key.

Keep `ISHASTRA_ENCRYPTION_KEY` from the old deployment as well: values
encrypted with the old key cannot be read with a new one.

### Keys that cannot be recovered

Secret stores such as `fly secrets` are write-only: once the old host is gone,
the values are gone with it. Record `ISHASTRA_API_KEY`,
`ISHASTRA_AUDIT_HMAC_KEY` and `ISHASTRA_ENCRYPTION_KEY` somewhere you control
before decommissioning anything.

- Wrong audit key: the app **refuses to start** in production mode with
  `Audit chain tampered: Hash mismatch at sequence N`. That is fail-closed by
  design. `ishastra serve --reset-audit-chain` discards the history and is only
  for a deliberate recovery, never for a key mismatch.
- Wrong encryption key: existing encrypted values cannot be decrypted.

The Kubernetes manifests in this repository use the `ISHASTRA_*` variable
names the runtime reads. Drop `ISHASTRA_DATABASE_URL` entirely — this stack is
SQLite-only, and pointing it at PostgreSQL makes startup fail while parsing
the DSN.

## 5. Operate

```bash
docker compose logs -f ishastra          # JSON logs
docker compose exec ishastra ishastra backup -o /var/lib/ishastra/backups
docker compose restart ishastra          # after a .env change
```

Back up the volume, not just the database file: `ishastra_data` also holds the
signed scope and any evidence you generated in place.

## 6. What this does not give you

No high availability and no horizontal scale. Do not run more than one
`ishastra` replica against the same volume; the database is single-writer by
design. If you need availability, the supported path is the warm-standby
promotion in `docs/runbooks/failover.md`, not a second writer.
