## What changed

<!-- One or two sentences. Link the issue this closes, if any. -->

## Why

<!-- The user-visible or security reason for the change. -->

## Verification

<!-- Commands you ran and their results. Do not claim checks you did not run. -->

- [ ] `ruff check src/`
- [ ] `mypy`
- [ ] `pytest`
- [ ] Documentation updated for behavior or configuration changes

## Security review

- [ ] The default-deny scope gate is still the only outbound authorization path.
- [ ] Tenant isolation and audit/redaction boundaries are preserved.
- [ ] No credentials, tokens, local databases or `.env` files are included.
