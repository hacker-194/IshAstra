# Certificate Expiry Runbook

## Alert Triggers

| Alert | Severity | Threshold | Duration |
|-------|----------|-----------|----------|
| `KubeCertificateExpiring` | warning | Expires in < 7 days | 1h |
| `KubeCertificateExpired` | critical | Already expired | 1m |
| `IshastraTLSCertExpiring` (custom) | warning | Expires in < 30 days | 1h |

---

## Symptoms & Impact

**Symptoms:**
- Browser/security tool shows certificate warnings
- `curl` fails with `SSL certificate problem: certificate has expired`
- Ingress controller logs show TLS handshake failures
- cert-manager `Certificate` resource shows `Ready: False`
- Monitoring alerts for certificate expiry

**Impact:**
- **SEV-2** (expired): All HTTPS traffic fails, API inaccessible
- **SEV-3** (expiring soon): Risk of outage if not renewed

---

## Diagnosis Commands

### 1. Check Certificate Status (cert-manager)
```bash
# List all certificates
kubectl get certificates -A

# Check specific certificate details
kubectl describe certificate ishastra-tls -n ishastra
kubectl describe certificate ishastra-tls-staging -n ishastra

# Check certificate requests
kubectl get certificaterequests -A

# Check issuer status
kubectl get clusterissuers
kubectl describe clusterissuer letsencrypt-prod
kubectl describe clusterissuer letsencrypt-staging
```

### 2. Check Certificate Expiry Directly
```bash
# Check secret content
kubectl get secret ishastra-tls -n ishastra -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -text -noout | grep -A2 "Validity"

# Check expiry date
kubectl get secret ishastra-tls -n ishastra -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -enddate -noout

# Check all TLS secrets
for secret in $(kubectl get secrets -n ishastra -o name | grep tls); do
  echo "=== $secret ==="
  kubectl get $secret -n ishastra -o jsonpath='{.data.tls\.crt}' | base64 -d | openssl x509 -enddate -noout -subject -issuer
done
```

### 3. Check Ingress & TLS Configuration
```bash
# Check ingress TLS config
kubectl get ingress -n ishastra -o yaml | grep -A5 "tls:"

# Check ingress controller logs
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx --tail=100 | grep -iE "cert|tls|ssl"

# Test TLS connection
openssl s_client -connect ishastra.example.com:443 -servername ishastra.example.com < /dev/null 2>/dev/null | openssl x509 -enddate -noout
```

### 4. Check cert-manager Logs
```bash
# cert-manager controller logs
kubectl logs -n cert-manager -l app=cert-manager --tail=100 | grep -iE "ishastra|error|fail"

# cert-manager webhook logs
kubectl logs -n cert-manager -l app=webhook --tail=50

# cert-manager cainjector logs
kubectl logs -n cert-manager -l app=cainjector --tail=50
```

### 5. External Validation
```bash
# Check with SSL Labs (external)
# https://www.ssllabs.com/ssltest/analyze.html?d=ishastra.example.com

# Check certificate transparency logs
# https://crt.sh/?q=ishastra.example.com
```

---

## Resolution Procedures

### Immediate Mitigation (Certificate Expired - SEV-2)

#### Option 1: Force cert-manager Renewal
```bash
# Delete certificate request to trigger renewal
kubectl delete certificaterequest -n ishastra -l cert-manager.io/certificate-name=ishastra-tls

# Or annotate certificate to force renewal
kubectl annotate certificate ishastra-tls -n ishastra cert-manager.io/force-renew=$(date +%s) --overwrite

# Check renewal triggered
kubectl get certificaterequests -n ishastra -w
```

#### Option 2: Manual Certificate Replacement (Emergency)
```bash
# 1. Generate new certificate (Let's Encrypt via certbot)
# On a machine with certbot and DNS access:
certbot certonly --dns-cloudflare -d ishastra.example.com -d api.ishastra.example.com

# 2. Create new TLS secret
kubectl create secret tls ishastra-tls-new \
  --cert=/etc/letsencrypt/live/ishastra.example.com/fullchain.pem \
  --key=/etc/letsencrypt/live/ishastra.example.com/privkey.pem \
  -n ishastra --dry-run=client -o yaml | kubectl apply -f -

# 3. Update ingress to use new secret
kubectl patch ingress ishastra -n ishastra -p '{"spec":{"tls":[{"secretName":"ishastra-tls-new","hosts":["ishastra.example.com"]}]}}'

# 4. Verify
openssl s_client -connect ishastra.example.com:443 -servername ishastra.example.com < /dev/null 2>/dev/null | openssl x509 -enddate -noout

# 5. Clean up old secret after verification
kubectl delete secret ishastra-tls -n ishastra
kubectl patch secret ishastra-tls-new -n ishastra -p '{"metadata":{"name":"ishastra-tls"}}'
```

#### Option 3: Switch to Staging Issuer (Temporary)
```bash
# If production issuer failing, use staging (not trusted by browsers but works for API)
kubectl patch certificate ishastra-tls -n ishastra -p '{"spec":{"issuerRef":{"name":"letsencrypt-staging","kind":"ClusterIssuer"}}}'

# Force renewal
kubectl annotate certificate ishastra-tls -n ishastra cert-manager.io/force-renew=$(date +%s) --overwrite
```

### Root Cause Resolution

#### Cause 1: DNS Challenge Failure
```bash
# Check DNS records exist
dig TXT _acme-challenge.ishastra.example.com
dig TXT _acme-challenge.api.ishastra.example.com

# Check DNS provider credentials
kubectl get secret cloudflare-api-token -n cert-manager -o yaml

# Verify cert-manager has DNS permissions
kubectl logs -n cert-manager -l app=cert-manager --tail=50 | grep -i dns
```

#### Cause 2: Rate Limited by Let's Encrypt
```bash
# Check cert-manager events for rate limit errors
kubectl get events -n ishastra --field-selector involvedObject.name=ishastra-tls

# Wait for rate limit to reset (1 hour for identical certs)
# Or use staging issuer temporarily
```

#### Cause 3: ClusterIssuer Misconfiguration
```bash
# Check ClusterIssuer status
kubectl get clusterissuer letsencrypt-prod -o yaml

# Verify ACME server URL
kubectl get clusterissuer letsencrypt-prod -o jsonpath='{.spec.acme.server}'

# Verify email is valid
kubectl get clusterissuer letsencrypt-prod -o jsonpath='{.spec.acme.email}'

# Recreate if corrupted
kubectl delete clusterissuer letsencrypt-prod
# Re-apply from git
kubectl apply -f deploy/argocd/secrets/external-secrets/clusterissuer.yaml
```

#### Cause 4: Private Key Compromise / Rotation Needed
```bash
# Force private key rotation
kubectl patch certificate ishastra-tls -n ishastra -p '{"spec":{"privateKey":{"rotationPolicy":"Always"}}}'

# Trigger renewal with new key
kubectl annotate certificate ishastra-tls -n ishastra cert-manager.io/force-renew=$(date +%s) --overwrite
```

### Recovery Verification
```bash
# 1. Verify certificate valid
openssl s_client -connect ishastra.example.com:443 -servername ishastra.example.com < /dev/null 2>/dev/null | openssl x509 -enddate -noout

# 2. Verify full chain
openssl s_client -connect ishastra.example.com:443 -servername ishastra.example.com -showcerts < /dev/null 2>/dev/null

# 3. Test API access
curl -v https://ishastra.example.com/api/health

# 4. Check cert-manager shows Ready
kubectl get certificate ishastra-tls -n ishastra -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}'

# 5. Clear alert
# Alert should auto-resolve when certificate Ready=True
```

---

## Escalation & SLA

| Severity | Response Time | Escalation Path |
|----------|---------------|-----------------|
| **Expired (SEV-2)** | 15 minutes | On-call → Infrastructure → Platform Lead |
| **Expiring < 7 days (SEV-3)** | 4 hours | On-call → Infrastructure |
| **Expiring < 30 days** | Next business day | Infrastructure team |

**SLA Targets:**
- Certificate renewal: automated, > 30 days before expiry
- Emergency manual replacement: < 30 minutes
- DNS challenge resolution: < 1 hour

**Contacts:**
- Platform On-Call: `platform-oncall@example.com`
- Infrastructure: `infrastructure@example.com`
- DNS Admin: `dns-admin@example.com`

---

## Post-Incident Actions

1. **Root cause analysis** - why auto-renewal failed
2. **cert-manager upgrade** - if version-related bug
3. **DNS provider reliability review** - consider multiple providers
4. **Monitoring enhancement** - add 60/30/14/7 day expiry alerts
5. **Runbook update** - document new failure modes
6. **Disaster recovery test** - simulate cert expiry in staging

---

## Grafana Dashboard Links

- **Kubernetes Certificates**: `https://grafana.example.com/d/k8s-certificates/certificates`
- **cert-manager**: `https://grafana.example.com/d/cert-manager/cert-manager`

**Key Panels:**
- Certificate Expiry Timeline (table)
- Certificate Ready Status (stat)
- cert-manager Renewal Rate (time series)
- DNS Challenge Success Rate (gauge)
- TLS Handshake Errors (time series)