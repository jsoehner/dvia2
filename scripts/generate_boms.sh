#!/usr/bin/env bash
# ==============================================================================
# generate_boms.sh - Automated SBOM & CBOM Generator
# ==============================================================================
# Generates Software Bill of Materials (SBOM) and Cryptographic Bill of
# Materials (CBOM) for container images or source directories.
#
# Dependencies:
#   - syft (for SPDX/CycloneDX SBOM) or cdxgen / npx @cyclonedx/cdxgen
#   - cdxgen (or npx @cyclonedx/cdxgen) for CBOM with --include-crypto
#   - docker (if target is a container image)
# ==============================================================================

set -euo pipefail

# Default settings
TARGET_TYPE="docker"      # "docker" or "dir"
TARGET=""
OUTPUT_DIR="oss"
SBOM_FORMAT="spdx-json"   # "spdx-json" or "cyclonedx-json"
VERBOSE=false

usage() {
    local exit_code="${1:-1}"
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <TARGET>

Arguments:
  <TARGET>              Container image name (e.g., my-app:latest) or directory path (e.g., .)

Options:
  -t, --type TYPE       Target type: 'docker' (default) or 'dir'
  -o, --output-dir DIR  Directory to store generated BOMs (default: oss)
  -f, --format FORMAT   SBOM format: 'spdx-json' (default), 'cyclonedx-json'
  -v, --verbose         Enable verbose log output
  -h, --help            Show this help message and exit

Examples:
  $(basename "$0") my-demo-app:local
  $(basename "$0") -t dir -o build/boms .
  $(basename "$0") -t docker -o artifacts my-registry.io/app:v1.0.0
EOF
    exit "$exit_code"
}

# Parse options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--type)
            TARGET_TYPE="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -f|--format)
            SBOM_FORMAT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage 0
            ;;
        -*)
            echo "Error: Unknown option $1" >&2
            usage 1
            ;;
        *)
            if [[ -z "$TARGET" ]]; then
                TARGET="$1"
                shift
            else
                echo "Error: Multiple targets provided: '$TARGET' and '$1'" >&2
                usage
            fi
            ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "Error: Target is required." >&2
    usage
fi

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

# Resolve cdxgen runner (cdxgen in PATH, or npx -y @cyclonedx/cdxgen)
CDXGEN_CMD=()
if command -v cdxgen &>/dev/null; then
    CDXGEN_CMD=(cdxgen)
elif command -v npx &>/dev/null; then
    CDXGEN_CMD=(npx -y @cyclonedx/cdxgen)
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

SBOM_OUTPUT="${OUTPUT_DIR}/sbom.${SBOM_FORMAT%%-*}.json"
CBOM_OUTPUT="${OUTPUT_DIR}/cbom.json"

log "Target: $TARGET (type: $TARGET_TYPE)"
log "Output directory: $OUTPUT_DIR"

# ------------------------------------------------------------------------------
# 1. Generate SBOM (using syft if installed, else fallback to cdxgen)
# ------------------------------------------------------------------------------
log "Step 1: Generating Software Bill of Materials (SBOM)..."

if command -v syft &>/dev/null; then
    log "Using syft for SBOM generation..."
    if [[ "$TARGET_TYPE" == "docker" ]]; then
        syft "$TARGET" -o "$SBOM_FORMAT" > "$SBOM_OUTPUT"
    else
        syft "dir:$TARGET" -o "$SBOM_FORMAT" > "$SBOM_OUTPUT"
    fi
elif [[ ${#CDXGEN_CMD[@]} -gt 0 ]]; then
    log "Syft not found; using cdxgen (${CDXGEN_CMD[*]}) for SBOM generation..."
    if [[ "$TARGET_TYPE" == "docker" ]]; then
        "${CDXGEN_CMD[@]}" -t docker -o "$SBOM_OUTPUT" "$TARGET"
    else
        "${CDXGEN_CMD[@]}" -o "$SBOM_OUTPUT" "$TARGET"
    fi
else
    echo "Error: Neither 'syft' nor 'cdxgen'/'npx' was found in PATH." >&2
    echo "Please install syft (curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh) or cdxgen (npm install -g @cyclonedx/cdxgen)." >&2
    exit 1
fi

log "SBOM generated successfully: $SBOM_OUTPUT"

# ------------------------------------------------------------------------------
# 2. Generate CBOM (using cdxgen with --include-crypto)
# ------------------------------------------------------------------------------
log "Step 2: Generating Cryptographic Bill of Materials (CBOM)..."

if [[ ${#CDXGEN_CMD[@]} -eq 0 ]]; then
    echo "Error: 'cdxgen' or 'npx' is required to generate CBOM with cryptographic inventory." >&2
    echo "Install via: npm install -g @cyclonedx/cdxgen" >&2
    exit 1
fi

log "Running cdxgen with cryptographic discovery (${CDXGEN_CMD[*]})..."
if [[ "$TARGET_TYPE" == "docker" ]]; then
    "${CDXGEN_CMD[@]}" -t docker --include-crypto -o "$CBOM_OUTPUT" "$TARGET"
else
    "${CDXGEN_CMD[@]}" --include-crypto -o "$CBOM_OUTPUT" "$TARGET"
fi

log "CBOM generated successfully: $CBOM_OUTPUT"
log "BOM generation process complete."
