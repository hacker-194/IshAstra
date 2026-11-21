# Good first issues

Ten self-contained tasks, each under a day, each with an observable acceptance
criterion. Copy one into a GitHub issue (title + body) when the repository is
public. None of them require understanding the whole platform.

---

### 1. Machine-readable output for bundle verification

`ishastra bundle --verify` prints one human-readable line, which makes it
awkward in CI. Add `--json` that prints the verified manifest (job id, file
count, `created_at`, key id) as a single JSON object, and document the exit
codes.

- Files: `src/ishastra/cli.py` (`_run_bundle`), `tests/unit/test_bundle.py`
- Done when: a test asserts the JSON keys on a valid bundle and that a tampered
  bundle still exits non-zero with no JSON on stdout.

### 2. Teams payload next to the Slack blocks

`notify_job_finished` builds `text` + `blocks` for Slack, which other receivers
ignore. Add a `MessageCard`-style `sections` array for Microsoft Teams in the
same body, following the same pattern.

- Files: `src/ishastra/monitor.py`, `tests/unit/test_job_notifications.py`
- Done when: the payload keeps the existing fields untouched and the test
  asserts the Teams section renders target, job, verdict and finding count.

### 3. Pre-commit configuration

There is no `.pre-commit-config.yaml`, so contributors discover formatting rules
only after CI fails.

- Files: new `.pre-commit-config.yaml`
- Done when: `pre-commit run --all-files` passes locally and pins ruff and mypy
  to the same versions CI uses.

### 4. Devcontainer

Make "clone and run the tests" one click without installing Python 3.12 or the
scanner binaries.

- Files: new `.devcontainer/devcontainer.json`
- Done when: the container builds from the repo `Dockerfile`, runs `pytest -q`
  out of the box, and the README dev section links to it.

### 5. Replace placeholder docs metadata

`mkdocs.yml` ships a placeholder analytics id (`G-XXXXXXXXXX`) and social links
that may not exist. Either wire real values or remove them, so the published
site does not look abandoned.

- Files: `mkdocs.yml`
- Done when: `mkdocs build --strict` passes and no placeholder strings remain.

### 6. Property test: inheritance can only narrow

`Scope.inherited_from` intersects includes and unions exclusions, so it must
never widen an authorization. That invariant is asserted only by example tests.

- Files: `tests/unit/test_scope*.py` (hypothesis is already a dev dependency)
- Done when: a property test generates scopes and asserts every destination
  allowed by the child is also allowed by the parent.

### 7. Document verification exit codes

Operators scripting against the CLI need to distinguish "invalid signature" from
"member tampered" from "key unknown" without parsing prose.

- Files: `docs/api/*`, `src/ishastra/cli.py` help text
- Done when: each `BundleError` path maps to a documented exit code and a test
  covers at least two of them.

### 8. `make docs`

The Makefile builds and tests the code but not the documentation, so a broken
nav is only discovered in CI.

- Files: `Makefile`
- Done when: `make docs` builds the site with the same command as
  `.github/workflows/docs.yml`.

### 9. Minimal third-party adapter example

The plugin entry-point contract is documented but there is no runnable example
package.

- Files: new `examples/adapter-hello/` (pyproject + module + README)
- Done when: installing it into a demo venv makes the adapter appear in
  `/api/adapters`, and the README shows the exact install and run commands.

### 10. Helm resources for the real free tier

Oracle halved the Always Free Arm allowance to 2 OCPU / 12 GB, but the chart's
default requests still assume the old 4 OCPU / 24 GB shape.

- Files: `deploy/helm/ishastra/values.yaml`
- Done when: the default requests fit one 2 OCPU / 12 GB node and
  `helm template` renders with the documented `docs/deployment/free-tier.md`
  sizing.
