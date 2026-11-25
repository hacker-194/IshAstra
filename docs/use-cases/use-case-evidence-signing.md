# Use case: evidence signing and verification

## Goal

Collect findings, sign them as a canonical JSON bundle, and verify the signature
offline without depending on any external service.

## Preconditions

- IshAstra deployment has an Ed25519 key pair configured (`ISHASTRA_ENCRYPTION_KEY`
  for the signing key).
- Evidence has been collected from one or more assessments.

## Steps

1. **Collect evidence** — Run an assessment and produce a `findings.json` file.
2. **Sign the evidence**:

   ```bash
   ishastra evidence-sign \
     --input findings.json \
     --output evidence.zip
   ```
   This writes canonical JSON + Ed25519 manifest, SHA-256-pinned members.
3. **Verify the signature offline** — No internet, no IshAstra process needed:

   ```bash
   ishastra verify evidence.zip
   ```

   The command checks the manifest hash chain and reports `OK` or fails if
   any member hash has been altered.

## CI job snippet (GitHub Actions)

```yaml
name: Evidence signing
on:
  workflow_dispatch:
    inputs:
      findings:
        description: 'Base64-encoded findings JSON'
        required: true
jobs:
  sign:
    runs-on: ubuntu-latest
    env:
      ISHASTRA_ENV: production
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v1
      - name: Install IshAstra
        run: pip install -e .[dev]
      - name: Sign evidence
        env:
          FINDINGS_B64: '${{ github.event.inputs.findings }}'
        run: |
          python - <<'PY'
import base64, json, subprocess, os
findings = json.loads(base64.b64decode(os.environ["FINDINGS_B64"]))
with open("findings.json", "w") as f:
    json.dump(findings, f, sort_keys=True)
r = subprocess.run(["ishastra", "evidence-sign",
                    "--input", "findings.json",
                    "--output", "evidence.zip"],
                       env={**os.environ, "ISHASTRA_ENV": "production"})
assert r.returncode == 0, "signing failed"
PY
      - name: Verify evidence
        run: |
          ishastra verify evidence.zip
```