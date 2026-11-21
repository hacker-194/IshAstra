# Break-Glass Dual Approval

# Break-Glass Dual Approval

Emergency authorization workflow requiring dual approval for exceptional access.

## Overview

Break-Glass provides controlled emergency access when legitimate targets fall outside normal scope policies.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        Break-Glass Workflow                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. REQUEST                                                                  │
│     User requests emergency access to unauthorized target                   │
│     → Creates BreakGlassRequest with target, reason, duration               │
│                                                                              │
│  2. APPROVAL (Dual)                                                         │
│     Two designated approvers must approve                                   │
│     → Both must authenticate with MFA                                       │
│     → Approval recorded with timestamp, identity                            │
│                                                                              │
│  3. GRANT                                                                    │
│     Temporary scope extension created                                       │
│     → Signed with break-glass key                                           │
│     → Time-bounded (max 4h default)                                         │
│     → Audited in Ishastra Proof chain                                          │
│                                                                              │
│  4. USE                                                                      │
│     Worker uses extended scope                                              │
│     → All decisions marked as break-glass                                   │
│     → Metrics: break_glass_activations_total                                │
│                                                                              │
│  5. EXPIRY / REVOKE                                                         │
│     Automatic expiry at max_duration                                        │
│     → Or manual revoke by any approver                                      │
│     → Revocation propagates within 5 minutes                                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Configuration

### Scope Document

```json
{
  "version": 2,
  "metadata": {
    "name": "Production Assessment",
    "owner": "security@example.com"
  },
  "authorized_networks": ["10.0.0.0/8"],
  "break_glass": {
    "enabled": true,
    "approvers": [
      "security-lead@example.com",
      "cto@example.com",
      "ciso@example.com"
    ],
    "max_duration": "4h",
    "require_mfa": true
  }
}
```

### Approver Requirements

| Requirement | Description |
|-------------|-------------|
| Minimum approvers | 2 (configured in scope) |
| MFA | Required if `require_mfa: true` |
| Identity | Must match email in approvers list |
| Availability | At least 2 must be available |

---

## Request Flow

### 1. Create Request

```bash
# API
curl -X POST https://api.ishastra.dev/api/v1/break-glass \
  -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "scope_id": "scope-prod-123",
    "target": "https://169.254.169.254/latest/meta-data/",
    "reason": "Incident response: need AWS metadata for compromised instance",
    "duration": "2h"
  }'

# Response
{
  "request_id": "bg-req-456",
  "status": "PENDING_APPROVAL",
  "approvals_needed": 2,
  "approvals_received": 0,
  "expires_at": "2024-01-15T14:00:00Z"
}
```

### 2. Approve Request

```bash
# First approver
curl -X POST https://api.ishastra.dev/api/v1/break-glass/bg-req-456/approve \
  -H "Authorization: Bearer $APPROVER1_KEY" \
  -H "Content-Type: application/json" \
  -d '{"mfa_token": "123456"}'

# Second approver
curl -X POST https://api.ishastra.dev/api/v1/break-glass/bg-req-456/approve \
  -H "Authorization: Bearer $APPROVER2_KEY" \
  -H "Content-Type: application/json" \
  -d '{"mfa_token": "654321"}'
```

### 3. Use Extended Scope

```python
# Worker automatically gets extended scope
from ishastra.core.scope_breakglass import BreakGlassManager

bg = BreakGlassManager()

# Check if break-glass active for scope
extended_scope = await bg.get_extended_scope("scope-prod-123")

if extended_scope:
    # Use extended scope for this task
    with ScopeContext(extended_scope):
        dest = await gate.validate_outbound("https://169.254.169.254/...")
        # This would normally be DENIED but now ALLOWED
```

---

## Implementation

### BreakGlassManager

**File**: `src/ishastra/core/scope_breakglass.py` — `BreakGlassManager`

```python
class BreakGlassManager:
    def __init__(
        self,
        db: Database,
        signer: Ed25519PrivateKey,
        key_id: str,
        jwks_manager: JWKSManager,
        notifier: NotificationService,
    ):
        self.db = db
        self.signer = signer
        self.key_id = key_id
        self.jwks_manager = jwks_manager
        self.notifier = notifier

    async def create_request(
        self,
        scope_id: str,
        requester: str,
        target: str,
        reason: str,
        duration: timedelta,
    ) -> BreakGlassRequest:
        # Validate scope has break-glass enabled
        scope = await self.db.get_scope(scope_id)
        if not scope.break_glass or not scope.break_glass.enabled:
            raise BreakGlassDisabledError()

        # Validate duration
        max_duration = parse_duration(scope.break_glass.max_duration)
        if duration > max_duration:
            raise DurationExceededError(max_duration)

        # Create request
        request = BreakGlassRequest(
            id=generate_id("bg-req"),
            scope_id=scope_id,
            requester=requester,
            target=target,
            reason=reason,
            duration=duration,
            status=BreakGlassStatus.PENDING,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + duration,
        )

        await self.db.save_request(request)

        # Notify approvers
        await self.notifier.notify_approvers(
            scope.break_glass.approvers,
            request
        )

        return request

    async def approve(
        self,
        request_id: str,
        approver: str,
        mfa_token: str,
    ) -> BreakGlassRequest:
        request = await self.db.get_request(request_id)

        # Validate request state
        if request.status != BreakGlassStatus.PENDING:
            raise InvalidStateError(request.status)

        # Validate approver
        scope = await self.db.get_scope(request.scope_id)
        if approver not in scope.break_glass.approvers:
            raise UnauthorizedApproverError()

        # Verify MFA
        if scope.break_glass.require_mfa:
            if not await self._verify_mfa(approver, mfa_token):
                raise MFAVerificationError()

        # Record approval
        request.approvals.append(BreakGlassApproval(
            approver=approver,
            approved_at=datetime.utcnow(),
        ))

        # Check if fully approved
        if len(request.approvals) >= 2:
            await self._grant_access(request)

        await self.db.save_request(request)
        return request

    async def _grant_access(self, request: BreakGlassRequest):
        scope = await self.db.get_scope(request.scope_id)

        # Create extended scope with additional network
        extended = ScopeDocument(
            version=scope.version,
            metadata=scope.metadata,
            authorized_networks=scope.authorized_networks + [self._target_to_cidr(request.target)],
            include_hosts=scope.include_hosts,
            exclude_hosts=scope.exclude_hosts,
            allowed_ports=scope.allowed_ports,
            break_glass=scope.break_glass,
        )

        # Sign with break-glass key
        grant_receipt = self._sign_grant(extended, request)

        # Store extended scope
        extended_id = f"{scope.id}-bg-{request.id}"
        await self.db.save_scope(extended_id, extended, grant_receipt)

        # Update request
        request.status = BreakGlassStatus.ACTIVE
        request.extended_scope_id = extended_id
        request.grant_receipt = grant_receipt

        # Notify requester
        await self.notifier.notify_requester(request.requester, request)

    def _target_to_cidr(self, target: str) -> str:
        """Convert target URL to CIDR for scope extension"""
        parsed = parse_url(target)
        ip = resolve_host_sync(parsed.host)[0]  # First IP
        return f"{ip}/32"  # Single IP
```

### Extended Scope Usage

```python
# In worker, when running assessment
async def run_assessment(assessment: Assessment):
    # Check for active break-glass
    bg = BreakGlassManager(...)
    extended_scope = await bg.get_active_extended_scope(assessment.scope_id)

    if extended_scope:
        scope = extended_scope
        is_break_glass = True
    else:
        scope = assessment.scope
        is_break_glass = False

    with ScopeContext(scope):
        for target in assessment.targets:
            dest = await gate.validate_outbound(target, scope)

            # Mark finding as break-glass if applicable
            if is_break_glass and target == extended_scope.target:
                finding.metadata["break_glass"] = True
                finding.metadata["break_glass_request"] = extended_scope.request_id
```

---

## Audit & Compliance

### Ishastra Proof Integration

Every break-glass action creates signed receipts:

```
Grant Receipt (Extended Scope signed with break-glass key)
    │
    ├── Gate Receipt (Layer 1: ALLOW - break_glass=true)
    ├── Gate Receipt (Layer 2: ALLOW - break_glass=true)
    ├── Gate Receipt (Layer 3: Pinned - break_glass=true)
    │
    ▼
Proof Receipt (Contains break-glass metadata)
```

### Receipt Fields

```python
@dataclass
class GateReceipt:
    # ... standard fields ...
    metadata: dict = field(default_factory=dict)

    # Break-glass additions
    metadata["break_glass"] = True
    metadata["break_glass_request_id"] = "bg-req-456"
    metadata["break_glass_approvers"] = ["security-lead@...", "cto@..."]
    metadata["break_glass_reason"] = "Incident response..."
```

### Compliance Reports

```bash
# Generate break-glass audit report
ishastra break-glass report --start 2024-01-01 --end 2024-01-31

# Output:
# BREAK-GLASS AUDIT REPORT
# Period: 2024-01-01 to 2024-01-31
# Total Activations: 3
# Total Duration: 6h 30m
# 
# Activation 1:
#   Request ID: bg-req-456
#   Scope: scope-prod-123
#   Target: 169.254.169.254
#   Reason: Incident response...
#   Requester: analyst@example.com
#   Approvers: security-lead@..., cto@...
#   Duration: 2h
#   Status: EXPIRED
#   Findings: 2 (both marked break_glass=true)
```

---

## Metrics

### Prometheus Metrics

```prometheus
# Break-glass activations
break_glass_activations_total{scope_id, status}

# Active break-glass sessions
break_glass_active_sessions

# Approval latency
break_glass_approval_duration_seconds

# Expired vs revoked
break_glass_expiry_total{type="expired|revoked"}
```

### Grafana Alerts

```yaml
# Break-glass activated
- alert: BreakGlassActivated
  expr: increase(break_glass_activations_total[5m]) > 0
  labels:
    severity: warning
  annotations:
    summary: "Break-glass activated for {{ $labels.scope_id }}"

# Break-glass active too long
- alert: BreakGlassLongDuration
  expr: time() - break_glass_session_start_timestamp > 14400
  labels:
    severity: critical
  annotations:
    summary: "Break-glass session exceeds 4 hours"

# Approval taking too long
- alert: BreakGlassApprovalPending
  expr: time() - break_glass_request_created_timestamp > 900
  labels:
    severity: warning
  annotations:
    summary: "Break-glass request pending approval > 15min"
```

---

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Compromised approver account | MFA required, dual approval |
| Malicious requester | Reason required, audited, time-bounded |
| Scope escalation | Single IP only (/32), not network |
| Persistent access | Auto-expiry, manual revoke |
| Audit tampering | Signed receipts, Merkle tree |

### Best Practices

1. **Limit approvers**: 3-5 people, diverse roles
2. **Require MFA**: Always enable `require_mfa: true`
3. **Short durations**: Default 2h, max 4h
4. **Specific targets**: Single IP (/32), not CIDR blocks
5. **Document reasons**: Require detailed incident reference
6. **Review regularly**: Monthly audit of all activations
7. **Test quarterly**: Simulate break-glass scenario

---

## Revocation

### Automatic Expiry

```python
# Background task checks every minute
async def _expiry_check(self):
    while True:
        active = await self.db.get_active_break_glass()
        for session in active:
            if session.expires_at < datetime.utcnow():
                await self.revoke(session.id, reason="expired")
        await asyncio.sleep(60)
```

### Manual Revocation

```bash
# Any approver can revoke
curl -X POST https://api.ishastra.dev/api/v1/break-glass/bg-req-456/revoke \
  -H "Authorization: Bearer $APPROVER_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Incident resolved"}'
```

### Revocation Propagation

```python
async def revoke(self, request_id: str, reason: str):
    request = await self.db.get_request(request_id)
    request.status = BreakGlassStatus.REVOKED
    request.revoked_at = datetime.utcnow()
    request.revocation_reason = reason
    await self.db.save_request(request)

    # Invalidate extended scope
    if request.extended_scope_id:
        await self.db.delete_scope(request.extended_scope_id)

    # Notify all workers (via Redis pub/sub)
    await self.redis.publish("break-glass:revoked", json.dumps({
        "scope_id": request.scope_id,
        "extended_scope_id": request.extended_scope_id,
    }))
```

---

## Testing

### Unit Tests

```bash
pytest tests/unit/test_scope_breakglass.py -v
```

### Key Test Cases

| Test | Purpose |
|------|---------|
| `test_create_request` | Request creation with validation |
| `test_approve_dual` | Two approvals required |
| `test_approve_mfa_required` | MFA enforced |
| `test_grant_extended_scope` | Extended scope created correctly |
| `test_revoke_propagates` | Revocation invalidates scope |
| `test_expiry_auto` | Automatic expiry works |
| `test_audit_receipts` | Break-glass marked in receipts |

### Integration Test

```bash
# Full flow test
pytest tests/integration/test_break_glass_flow.py -v
```

---

## Troubleshooting

| Issue | Cause | Fix |
|-------|-------|-----|
| `BreakGlassDisabledError` | Not enabled in scope | Add `break_glass.enabled: true` |
| `DurationExceededError` | Requested > max_duration | Reduce duration or increase max |
| `UnauthorizedApproverError` | Email not in approvers list | Add to scope or use correct account |
| `MFAVerificationError` | Invalid MFA token | Check TOTP, time sync |
| Approval not working | Only 1 approver | Need 2 approvals |
| Scope not extended | Grant failed | Check signer, JWKS |

---

## Related

- [Configuration](../scope-gate/configuration.md#break-glass)
- [Concepts](../scope-gate/concepts.md)
- [Architecture: Proof Chain](../architecture/proof-chain.md)
- [API: Break-Glass](../api/scope-management.md#break-glass)