# GitHub PR Template
# Supersedes: No previous PR template existed
# Linked from: GitHub UI when creating new PR
# User instruction: "update all"

## Description

<!-- Describe your changes -->

## Type of Change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Refactoring
- [ ] Performance improvement
- [ ] Test improvement
- [ ] CI/CD change

## Component(s) Affected

- [ ] Scope Gate (`src/strix/core/scope.py`)
- [ ] API (`src/strix/api/`)
- [ ] Adapters (`src/strix/core/adapters.py`)
- [ ] Workers (`src/strix/core/worker.py`)
- [ ] Scheduler (`src/strix/core/scheduler.py`)
- [ ] CLI (`src/strix/cli.py`)
- [ ] Helm Chart (`deploy/helm/strix/`)
- [ ] Documentation (`docs/`)
- [ ] Tests (`tests/`)
- [ ] Other: _____

## Testing

- [ ] Unit tests pass (`pytest tests/unit/`)
- [ ] Integration tests pass (`pytest tests/integration/`)
- [ ] Manual testing done (describe):
- [ ] New tests added for changes

## Checklist

- [ ] Code follows project style (ruff, mypy pass)
- [ ] Self-reviewed the code
- [ ] Comments added for complex logic
- [ ] Documentation updated if needed
- [ ] No secrets or credentials committed
- [ ] CHANGELOG.md updated (if user-facing)
- [ ] Migration script added (if DB schema changed)

## Screenshots/Logs (if applicable)

<!-- Add screenshots or relevant logs -->

## Related Issues

Fixes #<!-- issue number -->