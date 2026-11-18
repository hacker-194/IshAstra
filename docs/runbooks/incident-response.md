# Incident Response Runbook

## Overview
This runbook covers incident response procedures for Strix platform incidents.

---

## Severity Levels

| Level | Definition | Response Time | Escalation |
|-------|------------|---------------|------------|
| **SEV-1** | Platform down, data loss, auth bypass | 15 min | Page on-call + manager |
| **SEV-2** | Degraded functionality, scan failures | 1 hour | Page on-call |
| **SEV-3** | Minor issues, non-critical bugs | 4 hours | Ticket + next business day |
| **SEV-4** | Cosmetic, documentation | Next sprint | Backlog |

---

## Common Incidents

### 1. Audit Chain Verification Failed (SEV-1)

**Symptoms**:
- Startup failure: `Audit chain verification failed at startup`
- `/api/audit/verify` returns `{"valid": false, ...}`
- Logs show `Audit chain tampered`

**Immediate Actions**:
```bash
# 1. Stop the service immediately
systemctl stop strix

# 2. Preserve database for forensics
cp /data/strix.db /data/strix.db.forensic.$(date +%s)

# 3. Check audit chain manually
sqlite3 /data/strix.db "SELECT * FROM audit_chain ORDER BY seq DESC LIMIT 10;"

# 4. Verify HMAC key hasn't changed
echo $STRIX_AUDIT_HMAC_KEY
# Compare with deployment config / secrets manager
```

**Investigation**:
1. Check if `STRIX_AUDIT_HMAC_KEY` was rotated without re-hashing chain
2. Check for unauthorized database writes
3. Review access logs for suspicious activity
4. Verify backup integrity

**Recovery**:
- If key rotated: re-hash chain with new key (requires admin)
- If tampered: restore from last known-good backup
- If unknown: full forensic investigation required

**Post-Incident**:
- Rotate `STRIX_AUDIT_HMAC_KEY`
- Review database access controls
- Update runbook with lessons learned

---

### 2. Scope Gate Bypass / Unauthorized Scan Attempt (SEV-1)

**Symptoms**:
- Logs show `Target https://evil.com is not within authorized scope`
- Multiple 403 responses from `/api/assess`
- Alert from monitoring on repeated scope violations

**Immediate Actions**:
```bash
# 1. Identify source API key
grep "scope violation" /var/log/strix.log | tail -20

# 2. Revoke compromised key
curl -X POST http://localhost:8000/api/keys/revoke/<tenant_id> \
  -H "Authorization: Bearer $ADMIN_KEY"

# 3. Check for successful unauthorized scans
sqlite3 /data/strix.db "SELECT * FROM jobs WHERE actor='<tenant_id>' AND state='completed';"
```

**Investigation**:
1. Determine if key was leaked or brute-forced
2. Check if any scans completed before detection
3. Review all findings from suspicious jobs
4. Check webhook deliveries for leaked data

**Recovery**:
- Rotate all keys for affected tenant
- Invalidate any findings from unauthorized scans
- Notify affected parties if data exposed

---

### 3. Worker Process Dead / Jobs Stuck (SEV-2)

**Symptoms**:
- Jobs stuck in `running` state > timeout
- `/api/monitor/status` shows `running: true` but no job progress
- Queue depth growing

**Immediate Actions**:
```bash
# 1. Check worker status
curl -H "Authorization: Bearer $ADMIN_KEY" \
  http://localhost:8000/api/monitor/status

# 2. Check worker logs
journalctl -u strix -f | grep -i worker

# 3. Force cancel stuck jobs
curl -X POST http://localhost:8000/api/assess/<job_id>/cancel \
  -H "Authorization: Bearer $ADMIN_KEY"

# 4. Restart worker
systemctl restart strix
```

**Investigation**:
1. Check for OOM kills: `dmesg | grep -i kill`
2. Check disk space: `df -h`
3. Check database locks: `sqlite3 /data/strix.db "PRAGMA busy_timeout;"`
4. Check Redis connectivity (if used)

**Recovery**:
- Restart Strix service
- Re-queue cancelled jobs if needed
- Increase `STRIX_QUEUE_MAX` if queue saturation

---

### 4. Redis Unavailable (SEV-2)

**Symptoms**:
- Rate limiting fails open/closed
- Scheduler fails to start
- Logs: `Redis required but unreachable`

**Immediate Actions**:
```bash
# 1. Check Redis status
redis-cli ping

# 2. Check Redis logs
journalctl -u redis -f

# 3. If STRIX_REDIS_REQUIRED=false, Strix falls back to in-memory
#    Verify: grep "RateLimitMiddleware" /var/log/strix.log

# 4. Restart Redis
systemctl restart redis
```

**Recovery**:
- Verify Redis persistence (AOF/RDB)
- Check memory: `redis-cli INFO memory`
- If data loss: rate limiter state reset (acceptable)

---

### 5. Database Corruption / Locked (SEV-1)

**Symptoms**:
- `sqlite3.OperationalError: database is locked`
- `sqlite3.DatabaseError: database disk image is malformed`
- All write operations fail

**Immediate Actions**:
```bash
# 1. Stop service
systemctl stop strix

# 2. Check database integrity
sqlite3 /data/strix.db "PRAGMA integrity_check;"

# 3. If locked, check for stale locks
ls -la /data/strix.db*
# Remove -shm/-wal if no other process using

# 4. Restore from backup if corrupted
cp /backups/strix.db.latest /data/strix.db
```

**Recovery**:
- Restore from latest backup
- Verify audit chain after restore
- Re-queue any lost jobs

---

### 6. TLS Certificate Expired (SEV-2)

**Symptoms**:
- Clients report certificate errors
- Reverse proxy logs show cert validation failures
- `/api/health` works but browser shows warning

**Immediate Actions**:
```bash
# 1. Check certificate expiry
openssl x509 -in /etc/ssl/certs/strix.pem -text -noout | grep "Not After"

# 2. Renew certificate (Certbot example)
certbot renew --nginx

# 3. Reload reverse proxy
nginx -s reload
```

**Prevention**:
- Monitor cert expiry: `certbot certificates`
- Set up expiry alerts (30/14/7 days)

---

### 7. Webhook Delivery Failures (SEV-3)

**Symptoms**:
- Webhook retries exhausted in logs
- Alerting not firing for critical findings
- `/api/monitor/status` shows webhook errors

**Immediate Actions**:
```bash
# 1. Check webhook endpoint health
curl -v https://your-webhook-endpoint.com/health

# 2. Verify STRIX_WEBHOOK_SECRET matches
# 3. Check firewall / security groups
# 4. Test manually
curl -X POST https://your-webhook-endpoint.com/strix-webhook \
  -H "Content-Type: application/json" \
  -H "X-Strix-Signature: sha256=$(echo -n 'test' | openssl dgst -sha256 -hmac "$STRIX_WEBHOOK_SECRET" | cut -d' ' -f2)" \
  -d '{"event": "test"}'
```

**Recovery**:
- Fix endpoint / network connectivity
- Re-send failed alerts from audit log
- Update webhook URL if changed

---

## Communication Templates

### SEV-1 Internal Alert
```
[SEV-1] Strix Platform Incident
Time: <timestamp>
Issue: <brief description>
Impact: <customer impact>
Actions Taken: <immediate actions>
On-Call: <name>
War Room: <link>
```

### Customer Notification (if data exposed)
```
Subject: Security Incident Notification - Strix Assessment Platform

We detected an unauthorized access attempt on <date>. 
Your assessment data for target <target> may have been accessed.
We have revoked the compromised credentials and are investigating.
No other tenant data was affected.
Contact: security@example.com
```

---

## Runbook Maintenance

- Review quarterly
- Update after each SEV-1/SEV-2
- Test procedures annually
- Version control in `/docs/runbooks/`