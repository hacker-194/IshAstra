# Use case: authorized scope assessment

## Goal

Run a bounded, authorized assessment of a single target within a defined
scope, producing signed evidence.

## Preconditions

- Operator holds a valid capability token for the engagement.
- The target has been authorized with explicit permission (see
  [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md)).
- IshAstra deployment has `ISHASTRA_ENV=production` set (refuses placeholder
  keys, disables `/docs`).
- Egress gateway is running if external tools (nmap, nikto, sqlmap, nuclei)
  are needed.

## Steps

1. **Obtain or generate a capability token** — Ed25519-signed JWT with
   `scope: assessment`, `targets: ["https://example.com"]`, `ports: [443]`,
   `tools: ["nuclei"]`, `ttl: 900`.
2. **Run IshAstra** against the authorized target:

   ```bash
   ISHASTRA_ENV=production \
   ISHASTRA_GATEWAY_URL=http://localhost:8080 \
   ishastra scope-assess \
     --token <JWT> \
     --target https://example.com \
     --output evidence.zip
   ```

3. **Verify the signed evidence** — `ishastra verify evidence.zip` checks the
   Ed25519 manifest hash chain and reports `OK`.

## CI job snippet (GitHub Actions)

```yaml
name: Authorized assessment
on:
  workflow_dispatch:
    inputs:
      target:
        description: 'Target URL (authorized)'
        required: true
      token:
        description: 'Ed25519 JWT token'
        required: true
jobs:
  assess:
    runs-on: ubuntu-latest
    env:
      ISHASTRA_ENV: production
      ISHASTRA_GATEWAY_URL: http://127.0.0.1:8080
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v1  # or python setup
      - name: Install IshAstra
        run: pip install -e .[dev]
      - name: Run assessment
        run: |
          echo "${{ github.event.inputs.token }}" > token.jwt
          ISHASTRA_ENV=production \
            ISHASTRA_GATEWAY_URL=http://127.0.0.1:8080 \
            ishastra scope-assess \
              --token token.jwt \
              --target "${{ github.event.inputs.target }}" \
              --output evidence.zip
      - name: Verify evidence
        run: |
          ishastra verify evidence.zip
```