#!/usr/bin/env bash
# ==============================================================================
# test_boms.sh - Automated Validation & Test Harness for Generated BOMs
# ==============================================================================
# Verifies that generated SBOM and CBOM artifacts exist, conform to JSON
# standards, contain expected schema properties, and pass cryptographic checks.
#
# Usage:
#   bash test_boms.sh [BOM_DIR]
#
# Default BOM_DIR: oss
# ==============================================================================

set -euo pipefail

BOM_DIR="${1:-oss}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZER="${SCRIPT_DIR}/analyze_cbom.py"

echo "=================================================================="
echo " BOM Verification & Test Harness: ${BOM_DIR}"
echo "=================================================================="

FAILED=0

# 1. Verify Directory Exists
if [[ ! -d "$BOM_DIR" ]]; then
    echo "❌ Error: BOM directory '${BOM_DIR}' not found." >&2
    exit 1
fi

# 2. Check for SBOM
echo -n "[1/4] Checking SBOM artifact ... "
SBOM_FILE=$(find "$BOM_DIR" -maxdepth 1 -name "sbom*.json" | head -n 1)
if [[ -n "$SBOM_FILE" && -s "$SBOM_FILE" ]]; then
    # Validate JSON syntax
    if python3 -m json.tool "$SBOM_FILE" >/dev/null 2>&1; then
        echo "✅ FOUND & VALID (${SBOM_FILE})"
    else
        echo "❌ INVALID JSON (${SBOM_FILE})"
        FAILED=1
    fi
else
    echo "❌ MISSING or EMPTY (expected sbom.spdx.json or sbom.cyclonedx.json)"
    FAILED=1
fi

# 3. Check for CBOM
echo -n "[2/4] Checking CBOM artifact ... "
CBOM_FILE="${BOM_DIR}/cbom.json"
if [[ -f "$CBOM_FILE" && -s "$CBOM_FILE" ]]; then
    if python3 -m json.tool "$CBOM_FILE" >/dev/null 2>&1; then
        echo "✅ FOUND & VALID (${CBOM_FILE})"
    else
        echo "❌ INVALID JSON (${CBOM_FILE})"
        FAILED=1
    fi
else
    echo "❌ MISSING or EMPTY (${CBOM_FILE})"
    FAILED=1
fi

# 4. Validate CBOM Schema & Cryptographic Assets
echo -n "[3/4] Validating CBOM CycloneDX schema and crypto assets ... "
if [[ -f "$CBOM_FILE" && -s "$CBOM_FILE" ]]; then
    SCHEMA_CHECK=$(python3 -c '
import json, sys
try:
    with open("'"$CBOM_FILE"'") as f:
        data = json.load(f)
    if data.get("bomFormat") != "CycloneDX":
        print("Invalid bomFormat: expected CycloneDX, got", data.get("bomFormat"))
        sys.exit(1)
    comps = data.get("components", [])
    crypto_count = sum(1 for c in comps if c.get("cryptoProperties") or c.get("type") in ("cryptographic-asset", "crypto"))
    print(f"Total components: {len(comps)}, Crypto assets: {crypto_count}")
    if len(comps) == 0:
        print("Warning: zero components found in CBOM")
    sys.exit(0)
except Exception as e:
    print("Schema error:", e)
    sys.exit(1)
')
    if [[ $? -eq 0 ]]; then
        echo "✅ VALID (${SCHEMA_CHECK})"
    else
        echo "❌ FAILED (${SCHEMA_CHECK})"
        FAILED=1
    fi
else
    echo "⏭️ SKIPPED (no CBOM)"
fi

# 5. Run Cryptographic Inventory & PQC Audit
echo "[4/4] Running Cryptographic Audit & PQC Assessment ..."
if [[ -f "$CBOM_FILE" && -s "$CBOM_FILE" && -f "$ANALYZER" ]]; then
    python3 "$ANALYZER" "$CBOM_FILE"
    echo "✅ AUDIT COMPLETE"
elif [[ ! -f "$ANALYZER" ]]; then
    echo "⚠️ analyze_cbom.py not found at ${ANALYZER}, skipping detailed analysis."
fi

echo "=================================================================="
if [[ $FAILED -eq 0 ]]; then
    echo "🎉 ALL BOM VERIFICATION CHECKS PASSED!"
    echo "=================================================================="
    exit 0
else
    echo "❌ BOM VERIFICATION FAILED!"
    echo "=================================================================="
    exit 1
fi
