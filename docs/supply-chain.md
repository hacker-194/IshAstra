# Supply chain and release

What is verified about how IshAstra is built, signed, and published — and what
is not. All commands below were run on 2026-11-25 against the Phase 4 branch.

## Versions

| Source | Value |
|---|---|
| `pyproject.toml` | `4.0.0rc1` |
| Built wheel/sdist | `ishastra-4.0.0rc1-py3-none-any.whl`, `ishastra-4.0.0rc1.tar.gz` |
| Installed clean venv | `ishastra.__version__ == "4.0.0rc1"` |

`ishastra.__version__` reads installed distribution metadata rather than a
hard-coded string, so it cannot drift from the built artifact.

## Reproducible build

```bash
SOURCE_DATE_EPOCH=1700000000 python -m build --outdir /tmp/dist1
SOURCE_DATE_EPOCH=1700000000 python -m build --outdir /tmp/dist2
```

| Artifact | Result |
|---|---|
| Wheel | **byte-identical**: `ab20544dbabe808eb1777b479ccec643cf3f8ec8eff9fcfd4c1b006ac3a8aade` in both builds |
| sdist (extracted) | **content-identical**: `diff -r` reports no differences |
| sdist (archive) | hash differs (`df7484…` vs `d76d64…`): gzip stores a container timestamp |

`twine check` passes for both artifacts.

So the installable wheel is reproducible byte-for-byte; the sdist is
reproducible in content but not in archive bytes. The release publishes a
`SHA256SUMS` file over the exact artifacts it built and signed — that file, not
a promise of identical bytes, is the verification anchor.

## SBOM

```bash
python scripts/generate_sbom.py --output dist/ishastra.spdx.json
```

Produces SPDX-2.3 JSON. A local run reported **293 packages**. The release job
regenerates it from the built environment. It is an environment SBOM, not a
hermetic build-time SBOM: it describes what is installed, not a rebuild recipe.

## Release pipeline

`.github/workflows/release.yml`, triggered by a `v*` tag:

1. Run the test suite on the tagged commit.
2. Build sdist and wheel.
3. Install the wheel in a clean venv and run `ishastra --version`.
4. Generate the SPDX SBOM and `SHA256SUMS`.
5. Sign `SHA256SUMS` with `cosign sign-blob` (keyless, OIDC).
6. Emit a build-provenance attestation (`actions/attest-build-provenance`).
7. Upload the `dist` artifact and create/update the GitHub release.

The separate `publish-pypi` job uses **trusted publishing** (no stored API
token): `id-token: write`, environment `pypi`, and `skip-existing: true`. It
publishes the exact artifacts produced and signed by the release job.

**Not verified here:** no tag-triggered release was executed during this work,
and `ishastra` has never been published to PyPI. The workflow configuration was
read and YAML-validated; the publish path itself remains unexercised.

## Workflow permissions

Eight Scorecard `TokenPermissionsID` findings were fixed by moving write scopes
from workflow level to the single job that needs them:

| Workflow | Before (top level) | Now |
|---|---|---|
| `security-scan.yml` | `security-events: write` | write on `security-scan` and `container-security-scan` only |
| `scorecard.yml` | `security-events`, `id-token` write | on the `scorecard` job only |
| `codeql.yml` | `security-events: write` | on the `analyze` job only |
| `ishastra-scan.yml` | `security-events: write` | on the `assess` job only |
| `assess.yml` | `security-events: write` | removed — the workflow uploads an artifact, not SARIF |
| `nuclei-template-refresh.yml` | `packages: write` | on the `build` job only |
| `release.yml` | `contents`, `id-token`, `attestations` write | on the `release` job only; publish job keeps `id-token` |
| `docker-security.yml` | already job-scoped | unchanged |

All workflow YAML parses after the edits.

## Pinning

- Every `uses:` action is pinned to a commit SHA with a version comment; a scan
  for `@vN` references finds none.
- Both Docker stages are now pinned to the `python:3.12-slim` manifest digest
  `sha256:191083cd…f51b4b`.
- The remaining Scorecard `PinnedDependenciesID` findings are `pip install`,
  `curl | sh`, and container-image pulls without hashes. `constraints.txt`
  pins every direct dependency to an exact version and documents why a
  platform-specific hash lock is not used. Hash-pinning the CI downloads is not
  done in this phase.

## Container CVE

The pinned base still shipped `libzstd1 1.5.7+dfsg-1`, affected by
`CVE-2026-124851`. A one-off container check confirmed that
`apt-get install libzstd1` from the image's own archive upgrades it to
`1.5.7+dfsg-1+deb13u1`, so `libzstd1` was added to the runtime stage's install
list. A local `docker build --target runtime` was then run: the resulting image
reports `libzstd1 1.5.7+dfsg-1+deb13u1` and `ishastra --version` prints
`ishastra 4.0.0rc1`. The CI-published image still has to be rebuilt for the
alert to close.

## Limits

- The local reproducibility check ran on Python 3.14.4; the release builds on
  3.12. Cross-interpreter byte-identity is not claimed.
- Cosign and the provenance attestation were not executed locally (no release
  run, no OIDC identity).
- No Postgres/Redis services are involved in these checks.
