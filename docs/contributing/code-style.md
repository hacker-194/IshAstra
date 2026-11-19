# Code Style Guide

# Code Style Guide

Consistent code style across all Strix components.

## General Principles

1. **Consistency** - Follow existing patterns in the codebase
2. **Readability** - Code is read more than written
3. **Type Safety** - Use type hints everywhere (Python) / strict typing (Rust)
4. **Documentation** - Public APIs must have docstrings/comments
5. **Testing** - New code requires tests

## Python Style

### Formatting

```bash
# Auto-format
make format-python
# or
black src/ tests/
isort src/ tests/
```

### Type Hints

```python
# Required for all public functions
async def create_assessment(
    scope_id: str,
    targets: list[str],
    adapters: list[str],
    options: dict[str, Any] | None = None,
    priority: Priority = Priority.NORMAL,
) -> Assessment:
    """Create a new assessment.
    
    Args:
        scope_id: Scope document identifier
        targets: List of target URLs to assess
        adapters: Adapter names to execute
        options: Per-adapter configuration
        priority: Execution priority
        
    Returns:
        Created assessment object
        
    Raises:
        ScopeNotFoundError: If scope doesn't exist
        ValidationError: If targets/adapters invalid
    """
    ...
```

### Imports

```python
# Standard library first
import asyncio
from datetime import datetime
from typing import Any

# Third-party
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

# Local
from strix.core.scope_gate import ScopeGate
from strix.models.assessment import Assessment
```

### Naming

| Type | Convention | Example |
|------|------------|---------|
| Classes | PascalCase | `ScopeGate`, `AssessmentService` |
| Functions/Methods | snake_case | `create_assessment`, `validate_target` |
| Constants | UPPER_SNAKE_CASE | `DEFAULT_TIMEOUT`, `MAX_TARGETS` |
| Variables | snake_case | `scope_id`, `target_url` |
| Private | _leading_underscore | `_internal_cache` |
| Type Variables | PascalCase + `_T` | `ModelType_T` |

### Async Patterns

```python
# Always use async for I/O
async def fetch_scope(scope_id: str) -> ScopeDocument:
    async with db.session() as session:
        result = await session.execute(
            select(ScopeDocument).where(ScopeDocument.id == scope_id)
        )
        return result.scalar_one()

# Use asyncio.gather for parallelism
async def run_adapters(target: str, adapters: list[str]) -> list[Finding]:
    tasks = [run_single_adapter(target, a) for a in adapters]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in results if not isinstance(r, Exception)]
```

### Error Handling

```python
# Custom exceptions with context
class ScopeGateError(StrixError):
    def __init__(self, target: str, layer: int, reason: str):
        self.target = target
        self.layer = layer
        self.reason = reason
        super().__init__(f"Scope Gate layer {layer} denied {target}: {reason}")

# Use specific exceptions, not generic Exception
try:
    dest = await scope_gate.validate(url)
except ScopeGateError as e:
    logger.warning("Scope denied", target=url, layer=e.layer, reason=e.reason)
    raise HTTPException(422, "Target not authorized by scope") from e
```

### Pydantic Models

```python
from pydantic import BaseModel, Field, field_validator
from typing import Annotated

class CreateAssessmentRequest(BaseModel):
    scope_id: Annotated[str, Field(min_length=1, max_length=100)]
    targets: Annotated[list[HttpUrl], Field(min_length=1, max_length=100)]
    adapters: Annotated[list[str], Field(min_length=1)]
    options: dict[str, dict] = Field(default_factory=dict)
    priority: Priority = Priority.NORMAL
    callback_url: HttpUrl | None = None
    
    @field_validator("adapters")
    @classmethod
    def validate_adapters(cls, v: list[str]) -> list[str]:
        known = get_registered_adapters()
        unknown = set(v) - set(known)
        if unknown:
            raise ValueError(f"Unknown adapters: {unknown}")
        return v
```

## Rust Style

### Formatting

```bash
# Auto-format
make format-rust
# or
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
```

### Naming

| Type | Convention | Example |
|------|------------|---------|
| Structs/Enums/Traits | PascalCase | `ScopeGate`, `ValidationResult` |
| Functions/Methods | snake_case | `validate_target`, `compute_proof` |
| Constants | UPPER_SNAKE_CASE | `DEFAULT_TTL`, `MAX_DEPTH` |
| Modules | snake_case | `scope_gate`, `strix_proof` |
| Type Parameters | PascalCase | `T`, `TargetType` |

### Error Handling

```rust
// Use thiserror for library errors
#[derive(Debug, thiserror::Error)]
pub enum ScopeGateError {
    #[error("Layer {layer} denied {target}: {reason}")]
    Denied { layer: u8, target: String, reason: String },
    
    #[error("DNS resolution failed for {host}: {source}")]
    DnsResolution { host: String, #[source] source: hickory_resolver::error::ResolveError },
    
    #[error("Invalid CIDR: {0}")]
    InvalidCidr(#[from] cidr::CidrError),
}

// Result type alias
pub type Result<T> = std::result::Result<T, ScopeGateError>;

// Use ? operator
pub async fn validate(&self, target: &Url) -> Result<Destination> {
    let layer1 = self.layer1_check(target)?;
    let layer2 = self.layer2_check(&layer1).await?;
    let layer3 = self.layer3_check(&layer2).await?;
    Ok(layer3)
}
```

### Async Patterns

```rust
// Use tokio for async
use tokio::task;

// Parallel execution
pub async fn run_all(&self, targets: Vec<Url>) -> Vec<Result<Destination>> {
    let futures = targets.into_iter().map(|t| self.validate(t));
    futures::future::join_all(futures).await
}

// Timeout
use tokio::time::{timeout, Duration};

pub async fn validate_with_timeout(&self, target: &Url) -> Result<Destination> {
    timeout(Duration::from_secs(30), self.validate(target))
        .await
        .map_err(|_| ScopeGateError::Timeout)?
}
```

### Documentation

```rust
/// Validates a target URL through the 3-layer Scope Gate.
///
/// # Arguments
/// * `target` - The URL to validate
///
/// # Returns
/// * `Ok(Destination)` - Validated and pinned destination
/// * `Err(ScopeGateError)` - Validation failed at any layer
///
/// # Examples
/// ```
/// let gate = ScopeGate::new(scope_document);
/// let dest = gate.validate(&"https://api.example.com".parse()?).await?;
/// ```
pub async fn validate(&self, target: &Url) -> Result<Destination> {
    ...
}
```

## SQL Style

### Migrations

```sql
-- Use descriptive names
-- 20240115_add_finding_status_index.sql

CREATE INDEX IF NOT EXISTS idx_findings_status_severity 
ON findings (status, severity);

-- Always include down migration
-- DROP INDEX IF EXISTS idx_findings_status_severity;
```

### Queries

```python
# Use SQLAlchemy ORM, avoid raw SQL
query = (
    select(Finding)
    .where(Finding.assessment_id == assessment_id)
    .where(Finding.severity.in_(["critical", "high"]))
    .order_by(Finding.discovered_at.desc())
    .limit(100)
)

# For complex queries, use CTEs with clear names
from sqlalchemy import cte

finding_cte = (
    select(Finding.id, Finding.severity, func.count().label("count"))
    .where(Finding.assessment_id == assessment_id)
    .group_by(Finding.id, Finding.severity)
    .cte("finding_counts")
)
```

## API Design

### REST Endpoints

```python
# Resource-oriented URLs
GET    /api/v1/scopes              # List scopes
POST   /api/v1/scopes              # Create scope
GET    /api/v1/scopes/{id}         # Get scope
PATCH  /api/v1/scopes/{id}         # Update scope
POST   /api/v1/scopes/{id}/activate # Activate scope (action)

# Nested resources
GET    /api/v1/scopes/{id}/versions
GET    /api/v1/assessments/{id}/findings
GET    /api/v1/assessments/{id}/report
```

### Response Format

```python
# Success
{
  "data": {...},
  "meta": {"request_id": "req_abc123"}
}

# List with pagination
{
  "data": [...],
  "pagination": {
    "total": 100,
    "limit": 50,
    "offset": 0,
    "has_more": true
  },
  "meta": {"request_id": "req_abc123"}
}

# Error
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request",
    "details": {"field_errors": {"targets": "At least one required"}}
  },
  "meta": {"request_id": "req_abc123"}
}
```

## Documentation Style

### Docstrings (Python)

```python
def validate_scope(scope: ScopeDocument) -> ValidationResult:
    """Validate a scope document configuration.
    
    Performs comprehensive validation including:
    - CIDR syntax and overlap detection
    - Host suffix format validation
    - Port range validation
    - DNS resolver configuration
    - Break-glass configuration
    
    Args:
        scope: Scope document to validate
        
    Returns:
        ValidationResult with valid flag, warnings, and errors
        
    Raises:
        ValidationError: If scope is None
    """
```

### Comments

```python
# Good: explains WHY, not WHAT
# Use exponential backoff to avoid overwhelming target services
# and respect rate limits imposed by external APIs
async def fetch_with_backoff(url: str, max_retries: int = 3) -> Response:
    ...

# Bad: explains WHAT (redundant with code)
# Loop 3 times with increasing delays
async def fetch_with_backoff(url: str, max_retries: int = 3) -> Response:
    ...
```

## Git Commit Messages

```bash
# Format: <type>(<scope>): <subject>
# Types: feat, fix, docs, style, refactor, test, chore, perf, ci

feat(scope-gate): add IPv6 support to layer 3 pinning
fix(api): handle null callback_url in assessment creation
docs(compliance): add PCI DSS 4.0.1 mapping
refactor(adapters): extract base adapter class
test(core): add TLA+ invariant tests for break-glass
perf(db): add composite index for finding queries
ci: add rust clippy to CI pipeline
```

## Code Review Checklist

- [ ] Type hints on all public functions
- [ ] Tests for new functionality
- [ ] Documentation updated
- [ ] No hardcoded secrets/config
- [ ] Error handling with context
- [ ] Logging at appropriate levels
- [ ] Performance considerations noted
- [ ] Security implications reviewed
- [ ] Backward compatibility maintained
- [ ] Changelog entry added

## Related

- [Development Guide](development.md)
- [Testing Guide](testing.md)
- [Architecture Overview](../architecture/overview.md)
- [Assessments API](../api/assessments.md)
- [API Reference](../api/authentication.md)