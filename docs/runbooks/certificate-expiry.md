# Runbook: TLS Certificate Expiring Soon

# Runbook: TLS Certificate Expiring Soon

**Alert**: `IshAstraCertExpiringSoon`
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
kubectl get certificates -n ishastra-system

# Check specific certificate
kubectl describe certificate ishastra-tls -n ishastra-system

# Check cert-manager logs
kubectl logs -n cert-manager deploy/cert-manager --tail=100 | grep -i "ishastra\|renew"
```

### 2. Check Issuer/ClusterIssuer

```bash
kubectl get clusterissuers
kubectl describe clusterissuer letsencrypt-prod
```

### 3. Check ACME Challenges

```bash
kubectl get challenges -n ishastra-system
kubectl describe challenge -n ishastra-system
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
kubectl annotate certificate ishastra-tls -n ishastra-system cert-manager.io/force-renew=$(date +%s) --overwrite

# Or delete and let cert-manager recreate
kubectl delete certificate ishastra-tls -n ishastra-system

# Check renewal status
kubectl get certificate ishastra-tls -n ishastra-system -w
```

## Manual Certificate Renewal (Emergency)

```bash
# Generate new cert with cert-manager CLI
cmctl renew ishastra-tls -n ishastra-system

# Or create temporary self-signed (last resort)
openssl req -x509 -nodes -days 30 -newkey rsa:2048 \
  -keyout /tmp/tls.key -out /tmp/tls.crt \
  -subj "/CN=api.example.com"
kubectl create secret tls ishastra-tls-temp \
  --cert=/tmp/tls.crt --key=/tmp/tls.key \
  -n ishastra-system --dry-run=client -o yaml | kubectl apply -f -
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
    email: security@example.com
    privateKeySecretRef:
      name: letsencrypt-prod-key
    solvers:
    - dns01:
        cloudflare:
          email: dns@example.com
          apiTokenSecretRef:
            name: cloudflare-api-token
            key: api-token
      selector:
        dnsZones:
        - "example.com"
```

```yaml
# Certificate with proper renewal
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ishastra-tls
  namespace: ishastra-system
  annotations:
    cert-manager.io/issue-tls: "true"
spec:
  secretName: ishastra-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  commonName: api.example.com
  dnsNames:
  - api.example.com
  - grafana.example.com
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