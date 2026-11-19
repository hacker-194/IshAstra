# Release Process

# Release Process

Strix release workflow from development to production.

## Versioning

**Semantic Versioning** (MAJOR.MINOR.PATCH)

| Type | When | Example |
|------|------|---------|
| MAJOR | Breaking API changes, architecture changes | 3.0.0 → 4.0.0 |
| MINOR | New features, backward compatible | 3.5.0 → 3.6.0 |
| PATCH | Bug fixes, security patches | 3.5.0 → 3.5.1 |

Pre-release: `-alpha`, `-beta`, `-rc` (e.g., `3.6.0-rc.1`)

## Release Branches

```
main ──────────────────────────────────────────────▶
  │                    │                    │
  ▼                    ▼                    ▼
 v3.5.0             v3.6.0              v4.0.0
  │                    │                    │
  ▼                    ▼                    ▼
release/v3.5       release/v3.6       release/v4.0
```

- `main`: Latest development, unstable
- `release/vX.Y`: Stabilization branch for minor version
- Tags: `v3.5.0`, `v3.5.1`, etc.

## Release Checklist

### Pre-Release (2 weeks before)

- [ ] Create release branch: `git checkout -b release/v3.6 main`
- [ ] Update version in `pyproject.toml`, `Cargo.toml`, `package.json`
- [ ] Update `CHANGELOG.md` with release notes
- [ ] Run full test suite: `make test-all`
- [ ] Security scan: `make security-scan`
- [ ] Dependency audit: `make dep-audit`
- [ ] Update documentation version references
- [ ] Create release PR to `release/v3.6`

### Release Candidate (1 week before)

- [ ] Tag RC: `git tag v3.6.0-rc.1`
- [ ] Build and publish RC images to GHCR
- [ ] Deploy to staging: `make deploy-staging VERSION=v3.6.0-rc.1`
- [ ] Run E2E tests against staging
- [ ] Collect feedback, fix critical issues
- [ ] Repeat RC if needed: `v3.6.0-rc.2`, etc.

### Final Release

- [ ] Tag release: `git tag v3.6.0`
- [ ] Push tag: `git push origin v3.6.0`
- [ ] GitHub Actions builds and publishes:
  - [ ] Docker images (multi-arch) to GHCR
  - [ ] Python package to PyPI
  - [ ] Rust crates to crates.io
  - [ ] Helm charts to OCI registry
  - [ ] SBOM (SPDX) to GitHub Releases
  - [ ] Cosign signatures
- [ ] Create GitHub Release with notes
- [ ] Update `latest` Helm chart pointer
- [ ] Deploy to production (canary → full)
- [ ] Verify health checks
- [ ] Announce: Discord, Twitter, mailing list

## Automated Release (GitHub Actions)

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:
    inputs:
      version:
        description: 'Version to release (e.g., v3.6.0)'
        required: true

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build multi-arch images
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: |
            ghcr.io/strix/strix:${{ github.ref_name }}
            ghcr.io/strix/strix:latest
          platforms: linux/amd64,linux/arm64
      - name: Build Python package
        run: make build-python
      - name: Build Rust crates
        run: make build-rust
      - name: Build Helm chart
        run: make build-helm
      - name: Generate SBOM
        run: make sbom
      - name: Sign artifacts
        run: make sign

  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            dist/*.whl
            dist/*.tar.gz
            target/*.crate
            helm/*.tgz
            sbom/*.spdx.json
          generate_release_notes: true
  
  deploy:
    needs: release
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Deploy to production
        run: make deploy-production
```

## Manual Release Commands

```bash
# Prepare release branch
git checkout main
git pull
git checkout -b release/v3.6

# Update versions
sed -i 's/version = "3.5.0"/version = "3.6.0"/' pyproject.toml
sed -i 's/version = "3.5.0"/version = "3.6.0"/' src/strix-rust/Cargo.toml

# Update changelog
# Edit CHANGELOG.md - move "Unreleased" to "3.6.0 - YYYY-MM-DD"

# Commit
git add pyproject.toml src/strix-rust/Cargo.toml CHANGELOG.md
git commit -m "chore(release): prepare v3.6.0"

# Push and create PR
git push origin release/v3.6
gh pr create --base main --title "Release v3.6.0" --body "Release PR for v3.6.0"

# After PR merged, tag
git checkout main
git pull
git tag v3.6.0
git push origin v3.6.0
```

## Hotfix Process

For critical production fixes:

```bash
# From latest release branch
git checkout release/v3.5
git checkout -b hotfix/v3.5.1

# Fix issue
# Update version to 3.5.1
# Update CHANGELOG.md

git commit -am "fix: critical security patch"
git push origin hotfix/v3.5.1

# Create PR to release/v3.5
# After merge, tag v3.5.1
# Backport to main if needed
git checkout main
git merge release/v3.5
```

## Rollback Procedure

```bash
# Helm rollback (immediate)
helm rollback strix -n strix

# Or specific revision
helm rollback strix 3 -n strix

# Kubernetes rollback
kubectl rollout undo deployment/strix-api -n strix
kubectl rollout undo deployment/strix-worker -n strix

# Database rollback (if migration)
alembic downgrade -1  # or specific revision

# Verify
curl https://api.strix.dev/health
```

## Release Artifacts

| Artifact | Location | Signature |
|----------|----------|-----------|
| Docker Images | `ghcr.io/strix/strix:v3.6.0` | Cosign |
| Python Wheel | PyPI `strix-3.6.0-py3-none-any.whl` | Cosign |
| Rust Crates | crates.io `strix-core-3.6.0.crate` | Cargo sign |
| Helm Chart | `oci://ghcr.io/strix/charts/strix-3.6.0.tgz` | Cosign |
| SBOM | GitHub Releases `sbom-v3.6.0.spdx.json` | Cosign |

## Verification

```bash
# Verify Docker image
cosign verify ghcr.io/strix/strix:v3.6.0 \
  --certificate-identity-regexp ".*" \
  --certificate-oidc-issuer-regexp ".*"

# Verify Python package
cosign verify-blob strix-3.6.0-py3-none-any.whl \
  --signature strix-3.6.0-py3-none-any.whl.sig \
  --certificate strix-3.6.0-py3-none-any.whl.pem

# Verify Helm chart
cosign verify oci://ghcr.io/strix/charts/strix:v3.6.0
```

## Communication Template

```markdown
# Strix v3.6.0 Released 🎉

## Highlights
- ✨ New feature: Custom adapter SDK
- 🔒 Security: Updated Scope Gate with IPv6 support
- 🐛 Fixed: Webhook retry logic

## Breaking Changes
- API: `callback_url` now requires HTTPS
- Config: `dns_timeout` default changed from 5s to 10s

## Upgrade Guide
1. Update Helm values: `image.tag: v3.6.0`
2. Run migrations: `helm upgrade strix ... --set migrate=true`
3. Verify: `kubectl get pods -n strix`

## Full Changelog
https://github.com/strix/strix/releases/tag/v3.6.0
```

## Related

- [Development Guide](development.md)
- [Code Style Guide](code-style.md)
- [Testing Guide](testing.md)
- [Deployment Guides](../deployment/kubernetes.md)