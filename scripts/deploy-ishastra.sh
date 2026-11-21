#!/usr/bin/env bash




set -euo pipefail

NAMESPACE="${1:-ishastra-system}"
RELEASE="${2:-ishastra}"
REGISTRY="${REGISTRY:-ghcr.io/your-org}"
TAG="${TAG:-v3.5.0}"

echo "Deploying Ishastra ${RELEASE} to namespace ${NAMESPACE}"
echo "Images: ${REGISTRY}/ishastra-*:${TAG}"


command -v helm >/dev/null 2>&1 || { echo "helm not found"; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found"; exit 1; }


kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -


if ! kubectl get crd certificaterequests.cert-manager.io >/dev/null 2>&1; then
    echo "WARNING: cert-manager not found. Webhook certs will need manual setup."
    echo "Install: kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml"
fi


if ! kubectl get crd servicemonitors.monitoring.coreos.com >/dev/null 2>&1; then
    echo "WARNING: Prometheus Operator not found. ServiceMonitor will not be created."
fi


WEBHOOK_CA_BUNDLE=""
if kubectl get secret -n cert-manager cert-manager-webhook-ca >/dev/null 2>&1; then
    WEBHOOK_CA_BUNDLE=$(kubectl get secret -n cert-manager cert-manager-webhook-ca -o jsonpath='{.data.ca\.crt}')
elif kubectl get secret -n "${NAMESPACE}" "${RELEASE}-webhook-certs" >/dev/null 2>&1; then
    WEBHOOK_CA_BUNDLE=$(kubectl get secret -n "${NAMESPACE}" "${RELEASE}-webhook-certs" -o jsonpath='{.data.ca\.crt}')
fi


helm upgrade --install "${RELEASE}" deploy/helm/ishastra \
  --namespace "${NAMESPACE}" \
  --create-namespace \
  --set operator.enabled=true \
  --set operator.image.repository="${REGISTRY}/ishastra-operator" \
  --set operator.image.tag="${TAG}" \
  --set api.image.repository="${REGISTRY}/ishastra-api" \
  --set api.image.tag="${TAG}" \
  --set worker.image.repository="${REGISTRY}/ishastra-worker" \
  --set worker.image.tag="${TAG}" \
  --set scheduler.image.repository="${REGISTRY}/ishastra-scheduler" \
  --set scheduler.image.tag="${TAG}" \
  --set postgresql.enabled=true \
  --set redis.enabled=true \
  --set operator.webhook.enabled=true \
  ${WEBHOOK_CA_BUNDLE:+--set operator.webhook.caBundle="${WEBHOOK_CA_BUNDLE}"} \
  --set global.image.pullSecrets[0]=ghcr-secret \
  --wait --timeout=5m

echo ""
echo "Deployment complete!"
echo ""
echo "Verify:"
echo "  kubectl get pods -n ${NAMESPACE}"
echo "  kubectl logs -n ${NAMESPACE} -l app.kubernetes.io/component=operator"
echo "  kubectl get crd | grep ishastra.io"
echo ""
echo "Run health check:"
echo "  kubectl exec -n ${NAMESPACE} deploy/${RELEASE}-operator -- ishastra dr health"
echo ""
echo "Create your first tenant (edit tenant.yaml first):"
echo "  kubectl apply -f tenant.yaml"