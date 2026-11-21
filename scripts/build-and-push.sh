#!/usr/bin/env bash

set -euo pipefail

REGISTRY="${1:-ghcr.io/your-org}"
TAG="${2:-v3.5.0}"
PLATFORM="${3:-linux/amd64,linux/arm64}"

echo "Building Ishastra image for ${REGISTRY} with tag ${TAG} (platform: ${PLATFORM})"

docker buildx create --name ishastra-builder --use 2>/dev/null || docker buildx use ishastra-builder

docker buildx build \
  --platform "${PLATFORM}" \
  -t "${REGISTRY}/ishastra:${TAG}" \
  -f Dockerfile \
  --push .

docker buildx build \
  --platform "${PLATFORM}" \
  -t "${REGISTRY}/ishastra-operator:${TAG}" \
  -t "${REGISTRY}/ishastra-api:${TAG}" \
  -t "${REGISTRY}/ishastra-worker:${TAG}" \
  -t "${REGISTRY}/ishastra-scheduler:${TAG}" \
  -f Dockerfile \
  --push .

echo "All images pushed to ${REGISTRY} with tag ${TAG}"
echo ""
echo "Next: Deploy with ./scripts/deploy-ishastra.sh or helm directly"