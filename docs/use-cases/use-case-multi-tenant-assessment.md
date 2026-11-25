# Use case: multi-tenant assessment

## Goal

Run independent assessments per tenant, each with its own capability token,
tenant context, and isolated evidence.

## Preconditions

- Operator manages multiple tenants, each with a signed capability token.
- IshAstra deployment supports org hierarchy and per-tenant scope keys.
- Each tenant's assessment is scoped to that tenant's targets only.

## Steps

1. **Generate per-tenant tokens** — Each JWT carries `tenant: "<tenant-id>"`,
   `targets: ["<tenant-targets>"]`, allowed tools, TTL ≤ 900s.
2. **Run assessment per tenant**:

   ```bash
   ISHASTRA_ENV=production \
   ISHASTRA_GATEWAY_URL=http://localhost:8080 \
   ishastra scope-assess \
     --token <tenant-jwt> \
     --targets "<comma-separated>" \
     --output <tenant-id>.evidence.zip
   ```
3. **Verify evidence independently** — Each bundle's manifest is signed with
   the private key corresponding to the token's Ed25519 key ID.

## CI job snippet (GitHub Actions)

```yaml
name: Multi-tenant assessment
on:
  workflow_dispatch:
    inputs:
      tenant_tokens:
        description: 'JSON map of tenant_id -> JWT'
        required: true
      targets:
        description: 'JSON map of tenant_id -> target URLs'
        required: true
jobs:
  assess:
    runs-on: ubuntu-latest
    env:
      ISHASTRA_ENV: production
      ISHASTRA_GATEWAY_URL: http://127.0.0.1:8080
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v1
      - name: Install IshAstra
        run: pip install -e .[dev]
      - name: Run assessments per tenant
        env:
          TOKENS: '${{ github.event.inputs.tenant_tokens }}'
          TARGETS: '${{ github.event.inputs.targets }}'
        run: |
          python - <<'PY'
import json, os, subprocess
tokens = json.loads(os.environ["TOKENS"])
targets = json.loads(os.environ["TARGETS"])
for tid, jwt in tokens.items():
    tgt = targets.get(tid, "")
    out = f"{tid}.evidence.zip"
    r = subprocess.run(
        ["ishastra", "scope-assess",
         "--token", jwt,
         "--target", tgt,
         "--output", out],
        env={**os.environ, "ISHASTRA_ENV": "production",
             "ISHASTRA_GATEWAY_URL": "http://127.0.0.1:8080"})
    assert r.returncode == 0, f"tenant {tid} failed"
    # verify
    subprocess.run(["ishastra", "verify", out], check=True)
PY
      - name: Verify all evidence
        run: echo "All tenants verified"
```