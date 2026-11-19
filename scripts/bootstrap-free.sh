#!/usr/bin/env bash
# bootstrap-free.sh — One-shot bootstrap for Strix on $0/month free tier
#
# Prerequisites:
#   - Oracle Cloud account (Always Free tier eligible)
#   - Domain name (for Cloudflare DNS)
#   - GitHub account (for GHCR + Actions)
#   - Local machine: kubectl, helm, k0sctl, cloudflared, kubeseal
#
# Run: chmod +x bootstrap-free.sh && ./bootstrap-free.sh

set -euo pipefail

# ========== CONFIGURATION ==========
CLUSTER_NAME="strix-cluster"
NAMESPACE="strix"
DOMAIN="yourdomain.com"
GHCR_ORG="your-org"
ORACLE_KEY_PATH="~/.ssh/oracle_key"
CP1_IP=""
CP2_IP=""
# ===================================

echo "🚀 Strix Free Tier Bootstrap"
echo "=============================="

for tool in kubectl helm k0sctl cloudflared kubeseal; do
  if ! command -v $tool &> /dev/null; then
    echo "❌ Missing: $tool — install first"
    exit 1
  fi
done
echo "✅ All tools present"

if [[ -z "$CP1_IP" || -z "$CP2_IP" ]]; then
  echo ""
  echo "📋 MANUAL STEP: Create 2x Oracle Cloud Always Free VMs"
  echo "   1. Go to cloud.oracle.com → Compute → Instances"
  echo "   2. Create 2x VM.Standard.A1.Flex (4 OCPU, 24GB RAM)"
  echo "   3. Ubuntu 22.04, SSH key, open ports: 22, 6443, 80, 443"
  echo "   4. Name: strix-cp1, strix-cp2"
  echo "   5. Note public IPs, then edit this script with CP1_IP and CP2_IP"
  echo ""
  read -p "Enter CP1 public IP: " CP1_IP
  read -p "Enter CP2 public IP: " CP2_IP
  sed -i "s/CP1_IP=\"\"/CP1_IP=\"$CP1_IP\"/" "$0"
  sed -i "s/CP2_IP=\"\"/CP2_IP=\"$CP2_IP\"/" "$0"
  echo "✅ IPs saved. Re-run script."
  exit 0
fi

echo ""
echo "📝 Generating k0sctl config..."
cat > deploy/k0sctl.yaml <<EOF
apiVersion: k0sctl.k0sproject.io/v1beta1
metadata:
  name: $CLUSTER_NAME
spec:
  hosts:
  - role: controller+worker
    ssh:
      address: $CP1_IP
      user: ubuntu
      keyPath: $ORACLE_KEY_PATH
      port: 22
    installFlags:
      - --enable-worker
      - --enable-controller
  - role: controller+worker
    ssh:
      address: $CP2_IP
      user: ubuntu
      keyPath: $ORACLE_KEY_PATH
      port: 22
    installFlags:
      - --enable-worker
      - --enable-controller
  k0s:
    version: 1.29.4+k0s.0
    config:
      api:
        address: 0.0.0.0
        port: 6443
      network:
        calico:
          kubeProxy:
            mode: ipvs
      storage:
        type: local-path
      telemetry:
        enabled: false
      featureGates:
        InPlacePodVerticalScaling: true
EOF

echo ""
echo "☸️  Bootstrapping k0s cluster (3-5 min)..."
k0sctl apply --config deploy/k0sctl.yaml

echo ""
echo "📥 Fetching kubeconfig..."
k0sctl kubeconfig --config deploy/k0sctl.yaml > kubeconfig-strix
export KUBECONFIG=$PWD/kubeconfig-strix
echo "✅ Kubeconfig saved to kubeconfig-strix"

echo ""
echo "🔐 Installing SealedSecrets + cert-manager..."
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.27.0/controller.yaml
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.0/cert-manager.yaml

echo "⏳ Waiting for cert-manager..."
kubectl wait --for=condition=ready pod -l app=cert-manager -n cert-manager --timeout=120s

echo ""
echo "🔑 Generating production secrets..."
python3 scripts/generate-secrets.py --output-dir ./prod-secrets --k8s-manifest --env-file --namespace $NAMESPACE

echo "🔏 Sealing secrets with kubeseal..."
kubeseal --format=yaml < ./prod-secrets/secrets.yaml > sealedsecrets.yaml
kubectl apply -f sealedsecrets.yaml
echo "✅ SealedSecrets applied"

echo ""
echo "🐘 MANUAL: Create Neon PostgreSQL database"
echo "   1. Go to console.neon.tech → Create Project"
echo "   2. Copy connection string"
read -p "Paste Neon connection string: " NEON_DSN

echo "🔄 Updating sealed secrets with Neon..."
python3 scripts/generate-secrets.py \
  --output-dir ./prod-secrets \
  --k8s-manifest \
  --env-file \
  --namespace $NAMESPACE \
  --postgres-host "$(echo $NEON_DSN | sed -n 's/.*@\([^:]*\):.*/\1/p')" \
  --postgres-port "$(echo $NEON_DSN | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')" \
  --postgres-user "$(echo $NEON_DSN | sed -n 's/.*\/\/\([^:]*\):.*/\1/p')" \
  --postgres-db "$(echo $NEON_DSN | sed -n 's/.*\/\([^?]*\).*/\1/p')"

echo "⚠️  Edit ./prod-secrets/secrets.yaml and set postgresql-password from Neon connection string"
read -p "Press Enter after editing..."

kubeseal --format=yaml < ./prod-secrets/secrets.yaml > sealedsecrets.yaml
kubectl apply -f sealedsecrets.yaml

echo ""
echo "🔴 MANUAL: Create Upstash Redis database"
echo "   1. Go to console.upstash.com → Create Database"
echo "   2. Copy Redis URL (rediss://...)"
read -p "Paste Upstash Redis URL: " UPSTASH_URL

echo "🔄 Updating sealed secrets with Upstash..."
python3 scripts/generate-secrets.py \
  --output-dir ./prod-secrets \
  --k8s-manifest \
  --env-file \
  --namespace $NAMESPACE \
  --redis-host "$(echo $UPSTASH_URL | sed -n 's/.*@\([^:]*\):.*/\1/p')" \
  --redis-port "$(echo $UPSTASH_URL | sed -n 's/.*:\([0-9]*\)$/\1/p')"

echo "⚠️  Edit ./prod-secrets/secrets.yaml and set redis-password from Upstash URL"
read -p "Press Enter after editing..."

kubeseal --format=yaml < ./prod-secrets/secrets.yaml > sealedsecrets.yaml
kubectl apply -f sealedsecrets.yaml

echo ""
echo "☁️  MANUAL: Set up Cloudflare Tunnel"
echo "   1. cloudflared tunnel login"
echo "   2. cloudflared tunnel create strix"
echo "   3. cloudflared tunnel route dns strix api.$DOMAIN"
echo "   4. kubectl create secret generic cloudflare-tunnel-credentials \\"
echo "        --from-file=credentials.json=/path/to/<TUNNEL_UUID>.json \\"
echo "        -n $NAMESPACE"
read -p "Enter Tunnel UUID: " TUNNEL_UUID
read -p "Press Enter after creating secret..."

sed -i "s/<TUNNEL_UUID>/$TUNNEL_UUID/g" deploy/cloudflare-tunnel-ingress.yaml
sed -i "s/yourdomain.com/$DOMAIN/g" deploy/cloudflare-tunnel-ingress.yaml
kubectl apply -f deploy/cloudflare-tunnel-ingress.yaml

echo ""
echo "📄 Creating scope document..."
cat > /tmp/scope.json <<EOF
{
  "program": "Strix Production",
  "authorized_by": "Security Team",
  "authorization_ref": "AUTH-001",
  "include": ["$DOMAIN", "*.$DOMAIN"],
  "exclude": ["admin.$DOMAIN"],
  "authorized_networks": ["10.0.0.0/8", "172.16.0.0/12"],
  "allowed_ports": [80, 443, 8080],
  "allow_broad_networks": false
}
EOF

echo ""
echo "🚀 Deploying Strix..."
GREEN_SHA=$(git rev-parse --short HEAD)
helm upgrade --install strix ./deploy/helm/strix -n $NAMESPACE --create-namespace \
  -f ./deploy/helm/strix/values-free.yaml \
  --set secrets.createSecrets=false \
  --set global.image.repository=ghcr.io/$GHCR_ORG/strix \
  --set global.image.tag=sha-$GREEN_SHA \
  --set-file configMap.scopeJson=/tmp/scope.json \
  --wait --timeout 10m

echo ""
echo "✅ Verifying deployment..."
kubectl rollout status deployment/strix-strix-api -n $NAMESPACE --timeout=5m
kubectl run smoke-test --rm -i --restart=Never \
  --image=curlimages/curl:8.7.1 \
  -- curl -sf https://api.$DOMAIN/api/health

echo ""
echo "🎉 Bootstrap complete!"
echo "   API: https://api.$DOMAIN"
echo "   Grafana: https://grafana.$DOMAIN (add DNS route)"
echo "   Kubeconfig: $PWD/kubeconfig-strix"
echo ""
echo "Next steps:"
echo "  1. Push to GitHub → Actions will build & publish to GHCR"
echo "  2. Tag release: git tag v3.5.0 && git push origin v3.5.0"
echo "  3. CI will deploy to staging automatically"