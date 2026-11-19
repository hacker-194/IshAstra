# Runbook: TLS Certificate Expiring Soon

# Runbook: TLS Certificate Expiring Soon

**Alert**: `StrixCertExpiringSoon`
**Severity**: Warning
**Team**: Platform

## Symptoms

- `certmanager_certificate_expiration_timestamp_seconds - time() < 86400 * 30`
- Certificate expires in < 30 days
- Browser/API clients may show warnings

## Investigation Steps

### 1. Check Certificate Status

```bash
# List all certificates
kubectl get certificates -n strix-system

# Check specific certificate
kubectl describe certificate strix-tls -n strix-system

# Check cert-manager logs
kubectl logs -n cert-manager deploy/cert-manager --tail=100 | grep -i "strix\|renew"
```

### 2. Check Issuer/ClusterIssuer

```bash
kubectl get clusterissuers
kubectl describe clusterissuer letsencrypt-prod
```

### 3. Check ACME Challenges

```bash
kubectl get challenges -n strix-system
kubectl describe challenge -n strix-system
```

## Common Causes & Fixes

| Cause | Diagnosis | Fix |
|-------|-----------|-----|
| Auto-renewal failed | cert-manager logs show errors | Check issuer config, DNS challenge |
| DNS challenge failing | Challenge stuck in pending | Verify Cloudflare DNS credentials, rate limits |
| Issuer misconfigured | No valid issuer for certificate | Fix ClusterIssuer, ensure ACME server reachable |
| Certificate not managed | cert-manager doesn't own cert | Add `cert-manager.io/issue-tls: "true"` annotation |
| Private key rotation | Key rotated but cert not renewed | Trigger manual renewal |

## Immediate Mitigation

```bash
# Force renewal
kubectl annotate certificate strix-tls -n strix-system cert-manager.io/force-renew=$(date +%s) --overwrite

# Or delete and let cert-manager recreate
kubectl delete certificate strix-tls -n strix-system

# Check renewal status
kubectl get certificate strix-tls -n strix-system -w
```

## Manual Certificate Renewal (Emergency)

```bash
# Generate new cert with cert-manager CLI
cmctl renew strix-tls -n strix-system

# Or create temporary self-signed (last resort)
openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
  -keyout /tmp/tls.key -out /tmp/tls.crt \
  -subj "/CN=api.strix.dev"
kubectl create secret tls strix-tls-temp \
  --cert=/tmp/tls.crt --key=/tmp/tls.key \
  -n strix-system --dry-run=client -o yaml | kubectl apply -f -
```

## Permanent Fix

```yaml
# Ensure cert-manager has proper permissions
# ClusterIssuer config
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: security@strix.dev
    privateKeySecretRef:
      name: letsencrypt-prod-key
    solvers:
    - dns01:
        cloudflare:
          email: dns@strix.dev
          apiTokenSecretRef:
            name: cloudflare-api-token
            key: api-token
      selector:
        dnsZones:
        - "strix.dev"
```

```yaml
# Certificate with proper renewal
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: strix-tls
  namespace: strix-system
  annotations:
    cert-manager.io/issue-tls: "true"
spec:
  secretName: strix-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  commonName: api.strix.dev
  dnsNames:
  - api.strix.dev
  - grafana.strix.dev
  renewBefore: 720h  # 30 days
  privateKey:
    algorithm: ECDSA
    size: 256
```

## Escalation

1. **24 hours before expiry**: Platform on-call
2. **7 days before expiry**: Platform lead
3. **1 day before expiry**: Engineering director

## Post-Incident

- [ ] Verify auto-renewal working
- [ ] Add earlier alert (60 days, 14 days)
- [ ] Document root cause
- [ ] Test renewal in staging

## Related

- [Kubernetes Deployment](../deployment/kubernetes.md)
- [Helm Deployment](../deployment/helm.md)
- [Monitoring](../deployment/monitoring.md)