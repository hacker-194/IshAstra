#!/usr/bin/env bash
# SBOM Generator for Strix Docker Images
# Generates Software Bill of Materials in SPDX and CycloneDX formats
# Usage: ./scripts/generate-sbom.sh [image_name] [output_dir]

set -euo pipefail

IMAGE_NAME="${1:-strix:latest}"
OUTPUT_DIR="${2:-./sbom-reports}"
SYFT_VERSION="v1.10.0"

mkdir -p "${OUTPUT_DIR}"

TIMESTAMP=$(date -u +"%Y%m%d-%H%M%S")
BASE_NAME="sbom-${IMAGE_NAME//\//-}-${TIMESTAMP}"

echo "=== SBOM Generation for ${IMAGE_NAME} ==="
echo "Output directory: ${OUTPUT_DIR}"
echo ""

# Generate SPDX JSON format
echo "--- Generating SPDX JSON ---"
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${OUTPUT_DIR}:/reports" \
  anchore/syft:${SYFT_VERSION} \
  "${IMAGE_NAME}" \
  -o spdx-json=/reports/${BASE_NAME}.spdx.json

# Generate CycloneDX JSON format
echo "--- Generating CycloneDX JSON ---"
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${OUTPUT_DIR}:/reports" \
  anchore/syft:${SYFT_VERSION} \
  "${IMAGE_NAME}" \
  -o cyclonedx-json=/reports/${BASE_NAME}.cyclonedx.json

# Generate human-readable table
echo "--- Generating Human-Readable Table ---"
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${OUTPUT_DIR}:/reports" \
  anchore/syft:${SYFT_VERSION} \
  "${IMAGE_NAME}" \
  -o table=/reports/${BASE_NAME}.table.txt

# Generate SPDX tag-value format (for some compliance tools)
echo "--- Generating SPDX Tag-Value ---"
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "${OUTPUT_DIR}:/reports" \
  anchore/syft:${SYFT_VERSION} \
  "${IMAGE_NAME}" \
  -o spdx-tag-value=/reports/${BASE_NAME}.spdx.tv

# Also generate SBOM from source (for comparison)
echo "--- Generating Source SBOM (for comparison) ---"
docker run --rm \
  -v "$(pwd):/workspace" \
  -v "${OUTPUT_DIR}:/reports" \
  anchore/syft:${SYFT_VERSION} \
  dir:/workspace \
  -o spdx-json=/reports/${BASE_NAME}-source.sbom.json

echo ""
echo "=== SBOM Generation Complete ==="
echo "Reports saved to: ${OUTPUT_DIR}"
ls -la "${OUTPUT_DIR}"/${BASE_NAME}*

# Verify SPDX JSON is valid
if [[ -f "${OUTPUT_DIR}/${BASE_NAME}.spdx.json" ]]; then
  echo ""
  echo "--- SPDX Summary ---"
  jq -r '.packages | length' "${OUTPUT_DIR}/${BASE_NAME}.spdx.json" | xargs -I {} echo "Packages found: {}"
  jq -r '.packages[] | select(.name == "strix") | .versionInfo' "${OUTPUT_DIR}/${BASE_NAME}.spdx.json" 2>/dev/null | xargs -I {} echo "Strix version: {}"
fi

# Verify CycloneDX JSON is valid
if [[ -f "${OUTPUT_DIR}/${BASE_NAME}.cyclonedx.json" ]]; then
  echo ""
  echo "--- CycloneDX Summary ---"
  jq -r '.components | length' "${OUTPUT_DIR}/${BASE_NAME}.cyclonedx.json" | xargs -I {} echo "Components found: {}"
fi

echo ""
echo "✅ SBOM generation complete"
echo "   SPDX JSON:      ${OUTPUT_DIR}/${BASE_NAME}.spdx.json"
echo "   CycloneDX JSON: ${OUTPUT_DIR}/${BASE_NAME}.cyclonedx.json"
echo "   Table:          ${OUTPUT_DIR}/${BASE_NAME}.table.txt"
echo "   SPDX Tag-Value: ${OUTPUT_DIR}/${BASE_NAME}.spdx.tv"
echo "   Source SBOM:    ${OUTPUT_DIR}/${BASE_NAME}-source.sbom.json"