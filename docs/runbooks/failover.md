# Multi-Region Failover Runbook

## Topology

Argo CD manages three independent regional applications from `deploy/argocd/applicationset-regions.yaml`:

| Region | Argo CD application / cluster name | Namespace | Kustomize overlay |
|---|---|---|---|
| `us-east` | `ishastra-us-east` | `ishastra-us-east` | `deploy/kustomize/overlays/us-east` |
| `eu-west` | `ishastra-eu-west` | `ishastra-eu-west` | `deploy/kustomize/overlays/eu-west` |
| `ap-south` | `ishastra-ap-south` | `ishastra-ap-south` | `deploy/kustomize/overlays/ap-south` |

Each overlay deploys one `ishastra-api` replica, the `ishastra-api` ClusterIP service, a
20 GiB `ishastra-data-pvc`, and a region-scoped ingress NetworkPolicy. Ingress to
port 8000 is allowed only from pods labeled `app.kubernetes.io/name=ingress-nginx`
in the `ingress-nginx` namespace. The policy does not restrict egress.

The database PVC, scope ConfigMap (`ishastra-config`, key `scope.json`), and
application Secret (`ishastra-secrets`) are local to each region. They are not
replicated by these manifests. Maintain verified backups and restore the
selected backup in the target region before routing traffic. Verify that the
configured image repository is accessible in all three clusters. The base image
uses the chart's `ghcr.io/hacker-194/ishastra:3.5.0` placeholder; set it to the
organization's published image before syncing.

## Prerequisites

- Argo CD is installed, and the clusters are registered with Argo CD under the
  exact names `us-east`, `eu-west`, and `ap-south`.
- The operator's kubeconfig has contexts with those same names (or the
  `kubectl --context` arguments below are adjusted to the local context names).
- Each cluster has a functioning ingress-nginx controller in the
  `ingress-nginx` namespace with the label used by the NetworkPolicy.
- A `ishastra-config` ConfigMap containing `scope.json` and a `ishastra-secrets`
  Secret exist in each regional namespace before the API rollout. Populate
  secrets through the approved secrets manager; do not copy credentials in
  this runbook.
- The default StorageClass can provision the 20 GiB `ReadWriteOnce` claim, and
  the target region has a verified database backup available.
- The DNS/load-balancer change process and regional health URLs are known to
  the incident commander.

## Fail over to a healthy region

### 1. Select and verify the target

Choose a healthy region from the three listed above. Confirm the target
application and its dependencies are ready before changing traffic:

```bash
TARGET=eu-west # use us-east, eu-west, or ap-south
NAMESPACE="ishastra-${TARGET}"
APP="ishastra-${TARGET}"

argocd app get "$APP"
kubectl --context "$TARGET" get namespace "$NAMESPACE"
kubectl --context "$TARGET" get pvc -n "$NAMESPACE" ishastra-data-pvc
kubectl --context "$TARGET" get configmap/ishastra-config secret/ishastra-secrets \
  -n "$NAMESPACE"
kubectl --context "$TARGET" get networkpolicy -n "$NAMESPACE"
kubectl --context "$TARGET" rollout status deployment/ishastra-api \
  -n "$NAMESPACE" --timeout=300s
kubectl --context "$TARGET" get endpoints ishastra-api -n "$NAMESPACE"
```

Confirm the PVC is `Bound`, the API has ready endpoints, and the region's
NetworkPolicy selects the API pods. If the target has stale or empty data,
restore and verify the approved backup using the normal database recovery
procedure before continuing. Ensure the failed region cannot still accept
writes; fence it or revoke its traffic before promoting the target to avoid
split-brain.

### 2. Reconcile the target overlay

The ApplicationSet continuously syncs the three overlays. If the target app is
out of sync, reconcile only that region and wait for its deployment:

```bash
argocd app sync "$APP"
argocd app wait "$APP" --sync --health --timeout 300
kubectl --context "$TARGET" rollout status deployment/ishastra-api \
  -n "$NAMESPACE" --timeout=300s
```

Do not scale the deployment manually: its desired replica count is one in the
base manifest and Argo CD self-healing will restore that value.

### 3. Cut over and verify traffic

Update the production DNS record or global load balancer to send traffic to the
target region's ingress endpoint, using the provider's approved change process.
Then verify the public and in-cluster endpoints:

```bash
curl -fsS "https://<target-region-host>/api/health"
curl -fsS "https://<target-region-host>/api/ready"
dig ishastra.example.com
```

Check API error rate, latency, audit-chain status, and database health in the
regional dashboards. Notify stakeholders and record the selected backup,
region, cutover time, and observed data loss/RPO.

## Failback

1. Restore and validate the recovered region, including its PVC, ConfigMap,
   Secret, ingress, and NetworkPolicy. Do not send traffic to it while its
   data is stale.
2. Reconcile its Argo CD application and wait for `ishastra-api` rollout and
   readiness using the commands above.
3. Ensure only the intended region is writable, then move DNS/load-balancer
   traffic back using the approved change process.
4. Verify health, readiness, audit-chain status, and regional monitoring.
   Keep the former active region available until the incident commander
   confirms failback completion.

## Rollback / escalation

If the target fails readiness or cannot serve traffic, keep the DNS cutover
unchanged until another healthy region is verified. Fence the failed target
before promoting another region, restore its data from a verified backup, and
repeat the target checks. Escalate to Platform On-Call and the Platform Lead;
involve the database, network, and cloud-provider teams as needed.
