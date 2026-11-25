# Use case: compliance control mapping

## Goal

Map IshAstra controls and evidence to selected compliance frameworks for
documentation purposes. This is **not** a certification or audit opinion.

## Preconditions

- IshAstra deployment with evidence collection enabled (`ISHASTRA_ENV=production`).
- Control inventory lives in `docs/compliance/*`; each file maps one framework's
  controls to IshAstra capabilities, findings or evidence-collection points.
- Operator has collected signed evidence bundles from real assessments.

## Steps

1. **Select a framework** — Choose from the mappings in `docs/compliance/`,
   currently covering NIST SP 800‑53 Rev. 5, ISO 27001:2022, SOC 2 Type II
   control families, and PCI DSS v4.1.
2. **Inspect the mapping** — Each `docs/compliance/<framework>.md` lists
   controls, the IshAstra feature or evidence type that addresses it, and
   whether the mapping is *direct* (evidence exists today) or *indirect* (process
   or policy gap).
3. **Extract supporting evidence** — Use `ishastra verify <bundle>` to prove
   the chain of each signed finding, then cite the relevant control number.
4. **Report** — Assemble a markdown or PDF table that lists each control, the
   IshAstra evidence referenced, the mapping type, and any gaps. Attach the
   signed evidence bundles as appendices.

## CI job snippet (GitHub Actions)

```yaml
name: Compliance mapping snapshot
on:
  workflow_dispatch:
jobs:
  map:
    runs-on: ubuntu-latest
    env:
      ISHASTRA_ENV: production
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v1
      - name: Install IshAstra
        run: pip install -e .[dev]
      - name: Collect and verify latest evidence
        run: |
          python - <<'PY'
import json, subprocess, os
os.environ.update({"ISHASTRA_ENV": "production"})
# run a bounded assessment and sign it
subprocess.run(["ishastra", "scope-assess",
                "--token", "PLACEHOLDER_JWT",
                "--target", "https://example.com",
                "--output", "evidence.zip"],
               env=os.environ, check=True)
subprocess.run(["ishastra", "verify", "evidence.zip"], check=True)
PY
      - name: List control mappings
        run: |
          for f in docs/compliance/*.md; do
            echo "=== $(basename $f) ==="
            cat "$f"
          done
      - name: Archive verified evidence
        uses: actions/upload-artifact@v4
        with:
          name: verified-evidence
          path: evidence.zip
```