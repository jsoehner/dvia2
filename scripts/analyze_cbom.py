#!/usr/bin/env python3
"""
analyze_cbom.py - Analyze CycloneDX Cryptographic Bill of Materials (CBOM)

Reads a CycloneDX CBOM JSON file produced by cdxgen (--include-crypto),
inventories cryptographic assets (algorithms, certificates, keys, protocols),
and flags quantum-vulnerable vs post-quantum safe primitives.
"""

import sys
import json
import argparse
from pathlib import Path
from collections import Counter

import re

QUANTUM_VULNERABLE_PATTERNS = [
    r"\bRSA\b", r"\bECDSA\b", r"\bECDH\b", r"\bDIFFIE[-_ ]?HELLMAN\b",
    r"\bED25519\b", r"\bED448\b", r"\bX25519\b", r"\bX448\b",
    r"\bSECP\d+R1\b", r"(?<![A-Z0-9_-])(?:DSA|DH)(?![A-Z0-9_-])"
]

POST_QUANTUM_PATTERNS = [
    r"\bML[-_]KEM\b", r"\bKYBER\b", r"\bML[-_]DSA\b", r"\bDILITHIUM\b",
    r"\bSLH[-_]DSA\b", r"\bSPHINCS\+?\b", r"\bFALCON\b", r"\bLMS\b", r"\bXMSS\b"
]

SYMMETRIC_CLASSICAL = {
    "AES", "CHACHA20", "3DES", "DES", "BLOWFISH", "RC4", "SHA-256", "SHA-384", "SHA-512", "SHA-3"
}


def analyze_cbom(cbom_path: Path):
    with open(cbom_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    bom_format = data.get("bomFormat", "Unknown")
    spec_version = data.get("specVersion", "Unknown")
    components = data.get("components", [])

    crypto_assets = []
    algorithm_counter = Counter()
    asset_types_counter = Counter()
    vulnerable_assets = []
    pqc_assets = []

    for comp in components:
        comp_type = comp.get("type", "")
        crypto_props = comp.get("cryptoProperties", {})

        asset_type = crypto_props.get("assetType", comp_type or "unknown")
        name = str(comp.get("name") or "Unnamed")
        version = str(comp.get("version") or "N/A")

        asset_info = {
            "name": name,
            "version": version,
            "type": comp_type,
            "asset_type": asset_type,
        }

        # Evidence / occurrences (file locations and code snippets)
        evidence = comp.get("evidence", {})
        occurrences = evidence.get("occurrences", [])
        asset_info["occurrences"] = occurrences

        # Algorithm properties
        algo_details = crypto_props.get("algorithmProperties", {})
        algo_name = str(algo_details.get("name") or comp.get("name") or "")
        comp_name = str(comp.get("name") or "")
        algo_upper = f"{algo_name} {comp_name}".upper()

        asset_info["algorithm"] = algo_name
        asset_info["primitive"] = str(algo_details.get("primitive") or "unknown")
        asset_info["key_length"] = str(algo_details.get("parameterSetIdentifier") or algo_details.get("keyLength") or "N/A")

        # Certificate / Protocol properties
        cert_details = crypto_props.get("certificateProperties", {})
        proto_details = crypto_props.get("protocolProperties", {})

        if cert_details:
            asset_info["certificate_subject"] = cert_details.get("subjectName")
            asset_info["certificate_expiry"] = cert_details.get("validTo")

        if proto_details:
            asset_info["protocol_type"] = proto_details.get("type")
            asset_info["protocol_version"] = proto_details.get("version")

        # Classify PQC status (check PQC first so ML-DSA/SLH-DSA are not flagged as classical DSA)
        is_pqc = any(re.search(pat, algo_upper) for pat in POST_QUANTUM_PATTERNS)
        is_qv = any(re.search(pat, algo_upper) for pat in QUANTUM_VULNERABLE_PATTERNS)

        if is_pqc:
            asset_info["pqc_status"] = "POST-QUANTUM READY"
            pqc_assets.append(asset_info)
        elif is_qv:
            asset_info["pqc_status"] = "QUANTUM-VULNERABLE"
            vulnerable_assets.append(asset_info)
        else:
            asset_info["pqc_status"] = "CLASSICAL/SYMMETRIC"

        if crypto_props or comp_type in ("cryptographic-asset", "crypto"):
            crypto_assets.append(asset_info)
            asset_types_counter[asset_type] += 1
            if algo_name:
                algorithm_counter[algo_name] += 1

    asym_total = len(pqc_assets) + len(vulnerable_assets)
    migration_pct = round((len(pqc_assets) / asym_total * 100), 1) if asym_total > 0 else 100.0
    symmetric_assets = [a for a in crypto_assets if a["pqc_status"] == "CLASSICAL/SYMMETRIC"]

    return {
        "bomFormat": bom_format,
        "specVersion": spec_version,
        "total_components": len(components),
        "total_crypto_assets": len(crypto_assets),
        "quantum_vulnerable_count": len(vulnerable_assets),
        "pqc_ready_count": len(pqc_assets),
        "symmetric_count": len(symmetric_assets),
        "pqc_migration_percentage": migration_pct,
        "asset_types": dict(asset_types_counter),
        "algorithm_distribution": dict(algorithm_counter),
        "vulnerable_assets": vulnerable_assets,
        "pqc_assets": pqc_assets,
        "symmetric_assets": symmetric_assets,
        "crypto_assets": crypto_assets
    }


def generate_markdown_summary(summary: dict) -> str:
    md = []
    md.append("## 🛡️ Cryptographic Bill of Materials (CBOM) & PQC Migration Assessment\n")
    md.append(f"**Format**: {summary['bomFormat']} (v{summary['specVersion']}) | **Total Components**: {summary['total_components']} | **Crypto Assets**: {summary['total_crypto_assets']}\n")
    
    # Status badges / overview
    pqc_pct = summary["pqc_migration_percentage"]
    asym_total = summary["pqc_ready_count"] + summary["quantum_vulnerable_count"]
    
    md.append("### 📊 Post-Quantum Migration Scorecard\n")
    md.append("| Metric | Count | Migration Status |")
    md.append("|---|---|---|")
    md.append(f"| **Post-Quantum Ready (PQC)** | **{summary['pqc_ready_count']}** | 🟢 Quantum-Resistant (NIST FIPS 203/204/205) |")
    md.append(f"| **Quantum-Vulnerable (Backlog)** | **{summary['quantum_vulnerable_count']}** | 🔴 At Risk of 'Harvest Now, Decrypt Later' |")
    md.append(f"| **Classical Symmetric / Hashing** | **{summary['symmetric_count']}** | 🟡 Classical Security (Requires AES-256 / SHA-256+) |")
    md.append(f"| **Asymmetric PQC Migration Progress** | **{pqc_pct}%** | ({summary['pqc_ready_count']} of {asym_total} asymmetric primitives migrated) |\n")

    def format_locations(occurrences: list) -> str:
        if not occurrences:
            return "Dependencies / External"
        locs = [f"`{occ.get('location', '')}`" for occ in occurrences if occ.get("location")]
        return "<br>".join(locs) if locs else "Dependencies / External"

    # PQC Assets Table
    md.append("### ✅ Post-Quantum Cryptography Migrated Assets\n")
    if summary["pqc_assets"]:
        md.append("| Component Name | Primitive | Key/Parameter Set | PQC Standard | Location(s) |")
        md.append("|---|---|---|---|---|")
        for asset in summary["pqc_assets"]:
            std = "NIST FIPS 203 (ML-KEM)" if "KEM" in asset["algorithm"].upper() or "KYBER" in asset["algorithm"].upper() else \
                  "NIST FIPS 204 (ML-DSA)" if "DSA" in asset["algorithm"].upper() or "DILITHIUM" in asset["algorithm"].upper() else \
                  "NIST FIPS 205 (SLH-DSA)" if "SLH" in asset["algorithm"].upper() or "SPHINCS" in asset["algorithm"].upper() else \
                  "Stateful Hash (RFC 8554/8391)" if "LMS" in asset["algorithm"].upper() or "XMSS" in asset["algorithm"].upper() else "PQC Algorithm"
            locs_str = format_locations(asset.get("occurrences", []))
            md.append(f"| `{asset['name']}` | {asset['primitive']} | {asset['key_length']} | {std} | {locs_str} |")
        md.append("")
    else:
        md.append("> ⚠️ **No Post-Quantum Ready assets detected.** Immediate migration planning recommended for asymmetric key exchanges and digital signatures.\n")

    # Quantum-Vulnerable Assets & Remediation Plan (Consolidated & Deduplicated)
    md.append("### ⚠️ Quantum-Vulnerable Assets & Remediation Plan\n")
    if summary["vulnerable_assets"]:
        md.append("| Component / Algorithm | Type / Primitive | Key Length / Curve | Recommended Target | Source Location(s) & Code Context |")
        md.append("|---|---|---|---|---|")
        for asset in summary["vulnerable_assets"]:
            algo_u = asset["algorithm"].upper()
            recom = "ML-KEM-768 / Kyber (FIPS 203)" if any(k in algo_u for k in ["RSA", "DH", "ECDH", "X25519"]) and "SIGN" not in asset["primitive"] else \
                    "ML-DSA-65 / Dilithium (FIPS 204)" if any(k in algo_u for k in ["ECDSA", "ED25519", "DSA"]) or "SIGN" in asset["primitive"] else \
                    "ML-KEM (KEM) or ML-DSA (Signatures)"
            
            occs = asset.get("occurrences", [])
            if occs:
                loc_details = []
                for occ in occs:
                    loc = occ.get("location", "")
                    snip = occ.get("snippet", "").strip().replace("|", "\\|")
                    if snip:
                        loc_details.append(f"`{loc}`<br><sub><code>{snip}</code></sub>")
                    else:
                        loc_details.append(f"`{loc}`")
                locs_str = "<br><br>".join(loc_details)
            else:
                locs_str = "Dependencies / External"

            md.append(f"| **`{asset['name']}`**<br><sub>{asset['algorithm']}</sub> | {asset['asset_type']} / {asset['primitive']} | {asset['key_length']} | **{recom}** | {locs_str} |")
        md.append("")
    else:
        md.append("> ✅ **Zero quantum-vulnerable asymmetric assets found.** All public-key cryptography conforms to post-quantum standards.\n")

    # Symmetric Assets Summary
    md.append("### 🔒 Classical Symmetric & Digest Assets\n")
    if summary["symmetric_assets"]:
        md.append("| Component Name | Primitive | Key Length | Quantum Resistance Assessment | Location(s) |")
        md.append("|---|---|---|---|---|")
        for asset in summary["symmetric_assets"]:
            algo_u = asset["algorithm"].upper()
            sec_note = "Quantum-Resistant (Grover's proof)" if "256" in str(asset["key_length"]) or "384" in algo_u or "512" in algo_u else \
                       "Legacy bit-length (Recommend 256-bit upgrade)" if "128" in str(asset["key_length"]) or "128" in algo_u else \
                       "Review key length for Grover resistance"
            locs_str = format_locations(asset.get("occurrences", []))
            md.append(f"| `{asset['name']}` | {asset['primitive']} | {asset['key_length']} | {sec_note} | {locs_str} |")
        md.append("")

    return "\n".join(md)


def print_report(summary: dict):
    print("=" * 70)
    print(" CBOM Cryptographic Inventory & PQC Readiness Assessment")
    print("=" * 70)
    print(f"Format: {summary['bomFormat']} (v{summary['specVersion']})")
    print(f"Total Components Scanned: {summary['total_components']}")
    print(f"Identified Cryptographic Assets: {summary['total_crypto_assets']}")
    print(f"Quantum-Vulnerable Assets: {summary['quantum_vulnerable_count']}")
    print(f"Post-Quantum Ready Assets: {summary['pqc_ready_count']}")
    print(f"PQC Migration Progress: {summary['pqc_migration_percentage']}%")
    print("-" * 70)

    if summary.get("asset_types"):
        print("\nAsset Types:")
        for atype, count in summary["asset_types"].items():
            print(f"  - {atype}: {count}")

    if summary.get("algorithm_distribution"):
        print("\nAlgorithm Breakdown:")
        for algo, count in summary["algorithm_distribution"].items():
            print(f"  - {algo}: {count}")

    if summary.get("pqc_assets"):
        print("\n✅ Post-Quantum Ready Assets Detected (Migrated):")
        for asset in summary["pqc_assets"]:
            print(f"  • [{asset['pqc_status']}] {asset['name']} (Primitive: {asset['primitive']}, Key/Param: {asset['key_length']})")

    if summary.get("vulnerable_assets"):
        print("\n⚠️ Quantum-Vulnerable Cryptographic Findings (Backlog for Migration):")
        for asset in summary["vulnerable_assets"][:10]:
            print(f"  • [{asset['pqc_status']}] {asset['name']} (Primitive: {asset['primitive']}, Key/Param: {asset['key_length']})")
        if len(summary["vulnerable_assets"]) > 10:
            print(f"  ... and {len(summary['vulnerable_assets']) - 10} more.")

    print("=" * 70)


def main():
    import os
    parser = argparse.ArgumentParser(description="Analyze CycloneDX CBOM files.")
    parser.add_argument("cbom_file", type=Path, help="Path to CycloneDX CBOM JSON file")
    parser.add_argument("--json", type=Path, nargs="?", const="STDOUT", help="Output summary as raw JSON to stdout or specified file")
    parser.add_argument("--markdown", type=Path, help="Output markdown assessment report to specified file")
    parser.add_argument("--step-summary", action="store_true", help="Append markdown assessment to $GITHUB_STEP_SUMMARY if available")
    args = parser.parse_args()

    if not args.cbom_file.exists():
        print(f"Error: CBOM file not found: {args.cbom_file}", file=sys.stderr)
        sys.exit(1)

    summary = analyze_cbom(args.cbom_file)
    md_content = generate_markdown_summary(summary)

    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(md_content)
        print(f"Saved Markdown report to: {args.markdown}")

    if args.step_summary or "GITHUB_STEP_SUMMARY" in os.environ:
        step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if step_summary_path:
            with open(step_summary_path, "a", encoding="utf-8") as f:
                f.write(md_content + "\n")

    if args.json:
        json_str = json.dumps(summary, indent=2)
        if args.json == "STDOUT":
            print(json_str)
        else:
            args.json.parent.mkdir(parents=True, exist_ok=True)
            with open(args.json, "w", encoding="utf-8") as f:
                f.write(json_str)
            print(f"Saved JSON report to: {args.json}")
    elif not args.markdown:
        print_report(summary)


if __name__ == "__main__":
    main()
