# Fly.io Deployment Guide for Ishastra (Testing)

Deploy Ishastra to Fly.io for free testing — no credit card required.

## Prerequisites

- Fly.io account: `fly auth signup` (email only)
- GitHub repo with Ishastra code
- Domain name (optional, for custom domain)

---

## Quick Deploy (5 minutes)

### 1. Install flyctl & Login
```bash
# Linux/Mac/WSL
curl -L https://fly.io/install.sh | sh

# Or download binary directly
# https://github.com/superfly/flyctl/releases

fly auth signup  # Opens browser, email only
```

### 2. Prepare Repository
```bash
git clone https://github.com/<YOUR_USER>/ishastra.git
cd ishastra

# Create fly.toml (see below)
# Create scope.json (see below)
```

### 3. Create `fly.toml` (App Config)
```toml
# fly.toml
app = "ishatra"
primary_region = "lax"

[build]
  dockerfile = "Dockerfile"

[env]
  ISHASTRA_WORKERS = "1"
  ISHASTRA_LOG_FORMAT = "json"
  ISHASTRA_LOG_LEVEL = "INFO"
  # Lives on the mounted volume, NOT in the image (scope.json is gitignored,
  # and a COPY in the Dockerfile would break CI builds from a clean checkout).
  ISHASTRA_SCOPE_FILE = "/var/lib/ishastra/scope.json"
  # These will be set via fly secrets (not in git):
  # ISHASTRA_API_KEY
  # ISHASTRA_DATABASE_URL
  # ISHASTRA_REDIS_URL
  # ISHASTRA_ENCRYPTION_KEY
  # ISHASTRA_AUDIT_HMAC_KEY

[http_service]
  internal_port = 8000
  force_https = true
  auto_stop_machines = false  # Keep running for worker
  auto_start_machines = true
  min_machines_running = 1

  [[http_service.checks]]
    interval = "30s"
    timeout = "5s"
    grace_period = "20s"
    method = "GET"
    path = "/api/health"

[[vm]]
  memory = "1gb"
  cpu_kind = "shared"
  cpus = 1

# Volume for SQLite fallback (if not using managed PG)
[mounts]
  source = "ishastra_data"
  destination = "/var/lib/ishastra"
```

### 4. Launch App (Creates fly.toml if missing)
```bash
fly launch --name ishatra --dockerfile Dockerfile --region lax --no-deploy
# Say "No" to PostgreSQL/Redis here — we'll create managed ones separately
```

### 5. Create Managed PostgreSQL (Free Tier)
```bash
# 1GB RAM, 3GB disk, shared CPU — free within allowance
fly postgres create \
  --name ishatra-db \
  --region lax \
  --vm-size shared-cpu-1x \
  --volume-size 3 \
  --initial-cluster-size 1

# Output: connection string like:
# postgresql://postgres:<PASS>@ishatra-db.flycast:5432
```

### 6. Create Managed Redis (Free Tier)
```bash
fly redis create \
  --name ishatra-redis \
  --region lax \
  --vm-size shared-cpu-1x \
  --volume-size 1

# Output: connection string like:
# redis://default:<PASS>@ishatra-redis.flycast:6379
```

### 7. Attach & Get Connection Strings
```bash
# Attach DB (sets DATABASE_URL secret automatically)
fly postgres attach ishatra-db

# Attach Redis (sets REDIS_URL secret automatically)
fly redis attach ishatra-redis

# View what was set
fly secrets list
```

### 8. Set Required Secrets

The API key is the one you are missing most often: without it the server starts
fine but **refuses every authenticated request**, so the UI loads and every
panel stays empty (all API calls return 401).

```bash
# Generate keys locally
API_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')
ENC_KEY=$(openssl rand -base64 32)
HMAC_KEY=$(openssl rand -base64 32)

fly secrets set \
  ISHASTRA_API_KEY="$API_KEY" \
  ISHASTRA_ENCRYPTION_KEY="$ENC_KEY" \
  ISHASTRA_AUDIT_HMAC_KEY="$HMAC_KEY"

# You will need this again to sign in to the UI — save it in your password manager.
echo "ISHASTRA_API_KEY=$API_KEY"
```

`fly secrets set` triggers a release, so the new key is live once the machine
restarts.

### 9. Deploy (First Boot)
```bash
fly deploy

# Watch logs
fly logs -f
```

The app serves immediately, but with no scope document yet every scan and probe
is refused — that is the intended default-deny behaviour.

### 10. Upload `scope.json` to the Volume

`scope.json` is gitignored on purpose (it is an authorization record, not source),
so it is **not** baked into the image. Put it on the mounted volume instead; the
file survives redeploys, and image builds stay reproducible in CI.

```bash
# Create locally — v2 requires version/program/authorized_by/authorization_ref/include.
# List only hosts you are authorized to test; wildcards cover subdomains only.
cat > scope.json << 'EOF'
{
  "version": 2,
  "program": "Ishastra Test Program",
  "authorized_by": "Your Name",
  "authorization_ref": "TEST-2026-001",
  "include": ["ishatra.fly.dev"],
  "exclude": [],
  "authorized_networks": [],
  "allowed_ports": [443, 80],
  "allow_broad_networks": false
}
EOF

# Upload to /var/lib/ishastra (the ishastra_data volume from fly.toml).
# base64 avoids any stdin/quoting trouble over fly ssh.
B64=$(base64 -w0 scope.json)
fly ssh console -a ishatra -C "sh -c 'printf %s $B64 | base64 -d > /var/lib/ishastra/scope.json'"

# Restart so the server loads it on startup
fly apps restart ishatra
```

To change scope later, re-run the upload and restart. If a deploy ever recreates
the volume, the file is gone — re-upload it.

### 11. Verify
```bash
# Health + readiness (readiness also reports scope_configured)
curl -s https://ishatra.fly.dev/api/health
curl -s https://ishatra.fly.dev/api/ready
# -> "scope_configured":true

# Authentication: 401 without the key, 200 with it
curl -s -o /dev/null -w '%{http_code}\n' https://ishatra.fly.dev/api/overview
curl -s -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $ISHASTRA_API_KEY" https://ishatra.fly.dev/api/overview

# Loaded scope
curl -s -H "Authorization: Bearer $ISHASTRA_API_KEY" https://ishatra.fly.dev/api/scope

# Open UI and paste ISHASTRA_API_KEY into the API-key field in the top bar
open https://ishatra.fly.dev
```

---

## Custom Domain (Optional)

```bash
# Add certificate
fly certs create ishatra.yourdomain.com

# In Cloudflare/your DNS provider, add CNAME:
# Type: CNAME
# Name: ishatra (or @)
# Target: ishatra.fly.dev
# Proxy: ON (orange cloud)

# Verify
fly certs show ishatra.yourdomain.com
curl https://ishatra.yourdomain.com/api/health
```

---

## Running Assessments

1. Open `https://ishatra.fly.dev` (or your custom domain)
2. Paste `ISHASTRA_API_KEY` into the API-key field in the top bar and click Save
   (there is no OIDC provider configured, so this is the sign-in)
3. Dashboard → Assessments → New Assessment:
   - Target: `https://httpbin.org` (or your test target)
   - Profile: `web-deep`
   - Run!
4. Watch findings populate in real-time

---

## Scaling for Heavier Tests

```bash
# Scale API memory (default 1GB)
fly scale memory 2048

# Add a second machine for worker (separate app recommended)
fly apps create ishatra-worker
# Configure worker-only Dockerfile or entrypoint
```

---

## Monitoring & Debugging

```bash
# Live logs
fly logs -f

# SSH into running container
fly ssh console

# Check secrets
fly secrets list

# Check status
fly status

# Restart
fly apps restart ishatra
```

---

## Free Tier Limits (Fly.io)

| Resource | Limit |
|----------|-------|
| Shared CPU VMs | 3 (total across apps) |
| Memory | 1GB per VM (configurable up to 2GB free) |
| Bandwidth | 160GB/mo outbound |
| IPv4 | 1 free (shared), dedicated $2/mo |
| PostgreSQL | 1 shared instance (3GB disk) |
| Redis | 1 shared instance (1GB disk) |
| Build minutes | Unlimited (GitHub Actions) |

**Note:** Bandwidth is the main constraint for security scanning. Heavy scans may exceed 160GB/mo.

---

## Common Issues

| Issue | Fix |
|-------|-----|
| UI loads but every panel is empty; API returns 401 | `ISHASTRA_API_KEY` is not set as a Fly secret, or was not pasted into the UI's API-key field |
| `No Authorized Scope` / `/api/ready` says `scope_configured:false` | `scope.json` is missing from `/var/lib/ishastra` on the volume — re-run step 10 |
| `fly deploy` hangs | `fly scale count 0 && fly scale count 1` |
| Database connection refused | Check `fly postgres attach` output; ensure `DATABASE_URL` secret set |
| Redis connection refused | Check `fly redis attach`; ensure `REDIS_URL` secret set |
| Scope gate blocks scans | Verify `scope.json` includes target; `allow_broad_networks: true` for testing |
| OOM kills | Increase memory: `fly scale memory 2048` |
| Cold starts | Set `auto_stop_machines = false` in fly.toml |

---

## Cleanup (When Done Testing)

```bash
# Destroy everything
fly apps destroy ishatra --yes
fly postgres destroy ishatra-db --yes
fly redis destroy ishatra-redis --yes
fly volumes list  # Delete any remaining volumes
```

---

## Next Steps for Production

When ready for 24/7 production with heavier workloads:
1. **Upgrade Fly.io** (paid plan) — more bandwidth, dedicated CPU, larger DB
2. **Migrate to Hetzner CX22 (€4.50/mo)** — guaranteed resources, no bandwidth limits
3. **Use Oracle Cloud Free Tier** — if you get a virtual card for verification

The Fly.io deployment validates the architecture. Production hardening = more resources.
