# Secret and Signing-Key Rotation

## What is automated

Only scope-signing JWKS rotation has an optional CronJob. There is no generic
application, database, Redis, or audit-key rotation job. Do not treat a
Kubernetes Secret refresh as proof that running processes have adopted a new
value; environment variables are read when pods start.

Use the configured secret manager as the source of truth. Never print secret
values, place them in command arguments, or inspect a pod's environment.
Replace the example namespace and release names below with the deployment's
actual values.

## Application secrets

The application secret must contain `STRIX_API_KEY`,
`STRIX_AUDIT_HMAC_KEY`, and `STRIX_ENCRYPTION_KEY`. The encryption key must be
base64-encoded 32-byte key material. Keep a recoverable, access-controlled
backup of the encryption key separate from the database backups.

1. Approve the rotation and identify every client or service using the key.
2. Generate and store the new value in the secret manager without exposing it
   in terminal output or process arguments.
3. Update the Kubernetes Secret through the secret manager or External Secrets
   Operator and verify its sync status without reading its values.
4. Restart the Strix Deployments so they reload environment variables:

   ```bash
   NAMESPACE=your-namespace
   RELEASE=your-release
   for component in api scheduler worker; do
     deployment="deployment/${RELEASE}-${component}"
     kubectl rollout restart "$deployment" -n "$NAMESPACE"
     kubectl rollout status "$deployment" -n "$NAMESPACE" --timeout=10m
   done
   ```

5. Verify `/api/health`, `/api/ready`, the authenticated audit-chain check, and
   a harmless authorized request before revoking any old credential.
6. Record the change and notify affected key holders through the approved
   incident or change process.

Rotate the bootstrap API key only with a coordinated client update; replacing
it immediately invalidates clients still using the old value.

### Keys that cannot be replaced directly

- **`STRIX_ENCRYPTION_KEY`:** replacing it makes existing encrypted fields
  unreadable. The project does not provide an online re-encryption/rewrap
  migration. Do not rotate this key by simply updating the Kubernetes Secret.
  A migration with old/new key support, a verified backup, and a tested restore
  is required first.
- **`STRIX_AUDIT_HMAC_KEY`:** replacing it without re-hashing the audit chain
  makes verification fail. Do not change it as part of routine rotation. Use an
  explicitly approved maintenance procedure with a verified backup and
  post-migration chain verification.
- **Database and Redis credentials:** use a backend-supported overlap (for
  example, a second database role) where available. Update the managed secret,
  restart Strix, verify connections and job processing, then revoke the old
  credential. A single-password change may require coordinated downtime.
- **`STRIX_WEBHOOK_SECRET`:** coordinate the change with every webhook receiver;
  signatures made with the old value will no longer validate.

## Scope-signing JWKS rotation

The optional Helm CronJob appends a key and preserves existing public keys. It
requires an operator-provisioned ReadWriteMany PVC containing the `public/` and
`private/` directories and a seeded `public/scope-jwks.json`. The API mounts
only the public directory read-only.

After enabling the CronJob, verify it ran and that the verifier sees the new
public key:

```bash
NAMESPACE=your-namespace
RELEASE=your-release
JOB=completed-scope-key-rotation-job
kubectl get cronjob,jobs -n "$NAMESPACE" | grep scope-key-rotation
kubectl logs -n "$NAMESPACE" "job/$JOB"
kubectl exec -n "$NAMESPACE" "deploy/${RELEASE}-api" -- \
  cat /etc/strix/scope-signing/scope-jwks.json
```

Keep old public keys until all scopes signed by them have been re-signed or
expired. Never prune keys just to make the JWKS smaller. If verification fails,
stop pruning and restore the last valid public JWKS from the protected backup.

For manual rotation, run `strix scope-key-rotate` from an authorized operator
environment against the same managed files:

```bash
KEY_ID=unique-key-id
PRIVATE_KEY=/secure/path/to/private-key.pem
JWKS=/secure/path/to/public-scope-jwks.json
strix scope-key-rotate \
  --kid "$KEY_ID" \
  --key "$PRIVATE_KEY" \
  --jwks "$JWKS"
```

Do not pass private-key material as a literal command argument or store it in
the application container.

## Emergency response

For suspected compromise, follow the organization's incident-response process:
contain access, preserve evidence, identify affected clients/data, rotate only
the affected credentials using the procedures above, verify service and audit
integrity, and notify stakeholders through approved channels. Do not use
unreviewed bulk scripts or delete old keys/secrets before confirming recovery.

The deployment owner must supply current on-call contacts, monitoring links,
retention requirements, and recovery objectives; this repository intentionally
does not ship example contacts as operational destinations.
