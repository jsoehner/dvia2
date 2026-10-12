#!/usr/bin/env bash
# ==============================================================================
# attach_oci_bom.sh - Attach SBOM and CBOM to Container Image as OCI 1.1 Artifacts
# ==============================================================================
# Publishes SBOM and CBOM documents to an OCI 1.1 registry alongside the image
# using ORAS (OCI Registry As Storage) or Regclient without packing them inside
# the container rootfs.
#
# Dependencies:
#   - oras CLI (https://oras.land) or regctl
#
# Usage:
#   attach_oci_bom.sh [OPTIONS] <IMAGE_REF>
#
# Example:
#   attach_oci_bom.sh -c oss/cbom.json -s oss/sbom.cyclonedx.json ghcr.io/my-org/my-app:1.0.0
# ==============================================================================

set -euo pipefail

IMAGE_REF=""
CBOM_FILE="oss/cbom.json"
SBOM_FILE="oss/sbom.cyclonedx.json"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <IMAGE_REF>

Arguments:
  <IMAGE_REF>             Target image reference (e.g., ghcr.io/org/repo:v1.0.0)

Options:
  -c, --cbom FILE         Path to CycloneDX CBOM JSON (default: oss/cbom.json)
  -s, --sbom FILE         Path to CycloneDX/SPDX SBOM JSON (default: oss/sbom.cyclonedx.json)
  -h, --help              Show this help message and exit

Examples:
  $(basename "$0") ghcr.io/acme/api:1.0.0
  $(basename "$0") -c build/cbom.json -s build/sbom.json myregistry.azurecr.io/app:latest
EOF
    exit "${1:-1}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--cbom)
            CBOM_FILE="$2"
            shift 2
            ;;
        -s|--sbom)
            SBOM_FILE="$2"
            shift 2
            ;;
        -h|--help)
            usage 0
            ;;
        *)
            if [[ -z "$IMAGE_REF" ]]; then
                IMAGE_REF="$1"
                shift
            else
                echo "Error: Unexpected argument '$1'" >&2
                usage 1
            fi
            ;;
    esac
done

if [[ -z "$IMAGE_REF" ]]; then
    echo "Error: IMAGE_REF is required." >&2
    usage 1
fi

if ! command -v oras &>/dev/null; then
    echo "Error: 'oras' CLI is required to attach OCI artifacts." >&2
    echo "Install ORAS: https://oras.land/docs/installation" >&2
    exit 1
fi

# Attach CBOM if present
if [[ -f "$CBOM_FILE" && -s "$CBOM_FILE" ]]; then
    echo "==> Attaching CBOM to ${IMAGE_REF} via ORAS..."
    oras attach \
        --artifact-type "application/vnd.cyclonedx+json" \
        --annotation "org.opencontainers.image.title=cbom.cyclonedx.json" \
        --annotation "io.cyclonedx.bomFormat=CycloneDX" \
        --annotation "io.cyclonedx.type=cbom" \
        "$IMAGE_REF" \
        "${CBOM_FILE}:application/vnd.cyclonedx+json"
    echo "✅ CBOM attached successfully."
fi

# Attach SBOM if present
if [[ -f "$SBOM_FILE" && -s "$SBOM_FILE" ]]; then
    echo "==> Attaching SBOM to ${IMAGE_REF} via ORAS..."
    oras attach \
        --artifact-type "application/vnd.cyclonedx+json" \
        --annotation "org.opencontainers.image.title=sbom.cyclonedx.json" \
        --annotation "io.cyclonedx.bomFormat=CycloneDX" \
        --annotation "io.cyclonedx.type=sbom" \
        "$IMAGE_REF" \
        "${SBOM_FILE}:application/vnd.cyclonedx+json"
    echo "✅ SBOM attached successfully."
fi
