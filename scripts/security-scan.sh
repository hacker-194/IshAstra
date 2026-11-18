#!/usr/bin/env bash
# Trivy Security Scanner for Strix Docker Images
# Usage: ./scripts/security-scan.sh [image_name] [severity]
# Example: ./scripts/security-scan.sh strix:latest HIGH,CRITICAL

set -euo pipefail

IMAGE_NAME="${1:-strix:latest}"
SEVERITY="${2:-HIGH,CRITICAL}"
OUTPUT_DIR="${3:-./security-reports}"
TRIVY_VERSION="0.56.2"

mkdir -p "${OUTPUT_DIR}"

echo "=== Trivy Security Scan for ${IMAGE_NAME} ==="
echo "Severity filter: ${SEVERITY}"
echo "Output directory: ${OUTPUT_DIR}"
echo ""

# Scan for vulnerabilities
echo "--- Vulnerability Scan ---"
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${OUTPUT_DIR}:/reports" \
  aquasec/trivy:${TRIVY_VERSION} image \
  --severity "${SEVERITY}" \
  --format table \
  --output /reports/trivy-vuln-${IMAGE_NAME//\//-}.txt \
  "${IMAGE_NAME}"

# Also output JSON for CI integration
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${OUTPUT_DIR}:/reports" \
  aquasec/trivy:${TRIVY_VERSION} image \
  --severity "${SEVERITY}" \
  --format json \
  --output /reports/trivy-vuln-${IMAGE_NAME//\//-}.json \
  "${IMAGE_NAME}"

# Scan for misconfigurations (Dockerfile, docker-compose)
echo "--- Misconfiguration Scan ---"
docker run --rm \
  -v "$(pwd):/workspace" \
  -v "${OUTPUT_DIR}:/reports" \
  aquasec/trivy:${TRIVY_VERSION} config \
  --severity "${SEVERITY}" \
  --format table \
  --output /reports/trivy-config-${IMAGE_NAME//\//-}.txt \
  /workspace

# Scan for secrets
echo "--- Secret Scan ---"
docker run --rm \
  -v "$(pwd):/workspace" \
  -v "${OUTPUT_DIR}:/reports" \
  aquasec/trivy:${TRIVY_VERSION} fs \
  --scanners secret \
  --severity "${SEVERITY}" \
  --format table \
  --output /reports/trivy-secrets-${IMAGE_NAME//\//-}.txt \
  /workspace

# Summary
echo ""
echo "=== Scan Complete ==="
echo "Reports saved to: ${OUTPUT_DIR}"
ls -la "${OUTPUT_DIR}"/trivy-*-${IMAGE_NAME//\//-}.*

# Exit with error if HIGH/CRITICAL vulnerabilities found
if [[ -f "${OUTPUT_DIR}/trivy-vuln-${IMAGE_NAME//\//-}.json" ]]; then
  CRITICAL_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL")] | length' "${OUTPUT_DIR}/trivy-vuln-${IMAGE_NAME//\//-}.json" 2>/dev/null || echo 0)
  HIGH_COUNT=$(jq '[.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH")] | length' "${OUTPUT_DIR}/trivy-vuln-${IMAGE_NAME//\//-}.json" 2>/dev/null || echo 0)

  echo ""
  echo "CRITICAL: ${CRITICAL_COUNT}"
  echo "HIGH: ${HIGH_COUNT}"

  if [[ ${CRITICAL_COUNT} -gt 0 ]] || [[ ${HIGH_COUNT} -gt 0 ]]; then
    echo "❌ FAIL: Critical or High vulnerabilities detected"
    exit 1
  fi
fi

echo "✅ PASS: No critical/high vulnerabilities found"
exit 0