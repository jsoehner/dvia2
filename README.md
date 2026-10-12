# DVIA-v2

[![Git](https://app.soluble.cloud/api/v1/public/badges/19830954-aee2-4728-9a73-d1cadc97c4f1.svg?orgId=320408544746)](https://app.soluble.cloud/repos/details/github.com/jsoehner/dvia2?orgId=320408544746)  
DVIA-v2 written in Swift along with additional vulnerabilities

Damn Vulnerable iOS App (DVIA) is an iOS application that is damn vulnerable. Its main goal is to provide a platform to mobile security enthusiasts/professionals or students to test their iOS penetration testing skills in a legal environment. This project is developed and maintained by @prateekg147. The vulnerabilities and solutions covered in this app are tested up to iOS 11. The current version is writen in Swift and has the following vulnerabilities.

1. Local Data Storage
2. Jailbreak Detection
3. Excessive Permissions
4. Runtime Manipulation
5. Anti Anti Hooking/Debugging
6. Binary Protection
7. Touch/Face ID Bypass
8. Phishing
9. Side Channel Data Leakage
10. IPC Issues
11. Broken Cryptography
12. Webview Issues
13. Network Layer Security
14. Application Patching
15. Sensitive Information in Memory

## Installing DVIA on any iOS device 

The best way to install DVIA is using <a href="www.cydiaimpactor.com/
">Cydia Impactor</a>

### Steps
1. Create an Apple ID https://appleid.apple.com/account
2. Download <em>Impactor</em>, make sure the device you want to install the app on is connected to your computer. Now drag and drop the <em>IPA</em> file to <em>Impactor</em>.
3. Enter your Apple ID credentials. App will install on the device
4. Go to your device, <em>Settings -> General -> Device Management</em>. Select the Apple ID you used to install the app. Click on <em>Verify App</em> under DVIAv2.

## Compiling DVIA using Xcode

### Steps

1. Clone the DVIA repo , git clone https://github.com/prateek147/DVIA-v2
2. cd to the project root directory where the <em>Podfile</em> is present (/DVIA-v2/DVIA-v2). Then run <em>pod install</em>
3. Open the <em>DVIA-v2.xcworkspace</em> file with Xcode. You can now directly run the app on a simulator.
4. For running on the device, go under Project settings in Xcode on the top left, head over to the <em>General</em> tab and under <em>Signing</em>, enter credentials for your Apple ID.
5. Now you can build and run the project on the device. You will have to trust the app again by going under Settings -> General -> Device Management. 



## 🛡️ Security & Cryptographic Posture
This project tracks Software & Cryptographic Bill of Materials (SBOM & CBOM) and Post-Quantum Cryptography (PQC) readiness. See the latest [Cryptographic Audit & PQC Migration Report](docs/security/CRYPTOGRAPHIC_AUDIT.md).

## Automated SBOM & CBOM Supply Chain Pipeline

This repository integrates an automated Software Bill of Materials (SBOM) and Cryptographic Bill of Materials (CBOM) supply chain pipeline to satisfy modern security and compliance requirements (Executive Order 14028, NIST SP 800-218 SSDF, and NIST IR 8547 PQC Migration Guidance).

### CI Pipeline Stages

The GitHub Actions workflow [`.github/workflows/sbom-cbom.yml`](.github/workflows/sbom-cbom.yml) executes on pushes to `master` and `main`, release tags (`v*`), and all pull requests:

1. **Dual-Engine SBOM Generation**: Uses `anchore/sbom-action` to produce standard CycloneDX (`oss/sbom.cyclonedx.json`) and SPDX (`oss/sbom.spdx.json`) inventory files.
2. **Cryptographic Bill of Materials (CBOM)**: Uses `cbomkit/cbomkit-action` to discover cryptographic algorithms, certificates, keys, and cryptographic assets (`oss/cbom.json`).
3. **Dual-Engine AST Semantic Crypto Scan**: Executes `scripts/scan_crypto_ast.py` to parse source code abstract syntax trees (ASTs), mapping cryptographic call-sites and cipher initializations to the CBOM inventory.
4. **Automated Verification Harness**: Runs `scripts/test_boms.sh` to validate JSON schemas, verify required CycloneDX attributes, and enforce non-empty inventory thresholds as a build gate.
5. **Post-Quantum Cryptography (PQC) Assessment**: Runs `scripts/analyze_cbom.py` to classify cryptographic assets by quantum-readiness and output markdown summary dashboards to `$GITHUB_STEP_SUMMARY`.
6. **Continuous Governance Publishing**: Automatically syncs the latest cryptographic posture to [`docs/security/CRYPTOGRAPHIC_AUDIT.md`](docs/security/CRYPTOGRAPHIC_AUDIT.md) and publishes all BOM assets to workflow artifacts.

---

## Local Scripts & Verification

All pipeline stages can be executed locally in development environments using scripts in `scripts/`:

### 1. Generating BOMs (`scripts/generate_boms.sh`)

Generate SBOMs and CBOMs for either source directories or Docker container images:

```bash
# Scan current repository directory (outputs to oss/)
bash scripts/generate_boms.sh -t dir .

# Scan a local Docker image
bash scripts/generate_boms.sh -t docker dvia2:local

# Specify custom output directory and format
bash scripts/generate_boms.sh -t dir -o build/boms -f cyclonedx-json .
```

### 2. Testing & Validating BOMs (`scripts/test_boms.sh`)

Run automated JSON validation, schema verification, and inventory count checks:

```bash
bash scripts/test_boms.sh oss
```

### 3. Scanning Source AST for Crypto Callsites (`scripts/scan_crypto_ast.py`)

Scan Swift, Objective-C, and repository source code ASTs for cryptographic primitive invocations and reconcile with an existing CBOM:

```bash
python3 scripts/scan_crypto_ast.py . \
  --cbom oss/cbom.json \
  --output-json oss/crypto-callsites.json
```

### 4. PQC Readiness Analysis (`scripts/analyze_cbom.py`)

Analyze a generated CBOM against software dependencies and generate markdown or JSON risk summaries:

```bash
python3 scripts/analyze_cbom.py oss/cbom.json \
  --sbom oss/sbom.spdx.json \
  --json oss/crypto-analysis.json \
  --markdown docs/security/CRYPTOGRAPHIC_AUDIT.md
```

### 5. OCI Artifact Attachment (`scripts/attach_oci_bom.sh` & `scripts/fetch_oci_cbom.py`)

Publish and retrieve CBOMs attached to OCI container registries:

```bash
# Attach CBOM to container image in registry
bash scripts/attach_oci_bom.sh oss/cbom.json my-registry.io/app:v1.0.0

# Fetch CBOM from container image
python3 scripts/fetch_oci_cbom.py my-registry.io/app:v1.0.0 --output-dir oss
```

---

## Architectural Decision Records (ADRs)

Key architectural decisions governing this repository's security, supply chain, and cryptography strategy are documented under [`docs/adr/`](docs/adr/):

- [**ADR-0001: Automated SBOM and CBOM Supply Chain Governance Pipeline**](docs/adr/0001-automated-sbom-cbom-supply-chain-governance.md) - Context, alternatives considered, decision rationale, and downstream consequences for adopting automated dual-engine SBOM/CBOM scanning, AST call-site analysis, and CI gate verification.
