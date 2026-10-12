# ADR-0001: Automated SBOM and CBOM Supply Chain Governance Pipeline

## Metadata

| Field | Value |
|---|---|
| ADR ID | ADR-0001 |
| Status | Accepted |
| Created Date | 2026-10-12 |
| Decision Date | 2026-10-12 |
| Effective Date | 2026-10-12 |
| Architecture Domain | Security / Supply Chain Governance / Cryptography / DevOps |
| Scope | Software & Cryptographic Supply Chain Security (Repository & CI/CD) |
| Decision Owner | Lead DevSecOps Architect |
| Named Decision Maker | DevSecOps Engineering & Mobile Security Architecture Team |
| Approval Authority | Architecture Review Board (ARB) / Security Governance Committee |
| Approval Evidence ID | ARB-2026-10-SEC-008 |
| APM Code(s) | SEC-SUPPLYCHAIN-01 |
| NIRA Reference(s) | NIRA-SEC-2026-045 |
| Tags | sbom, cbom, cyclonedx, spdx, supply-chain, pqc, ios, swift, commoncrypto, cryptokit, ast-analysis, devsecops |

---

## Business and Architecture Context

### Problem Statement

Damn Vulnerable iOS App v2 (`DVIA-v2`) is a mobile security benchmark application written in Swift and Objective-C providing realistic vulnerability scenarios for iOS penetration testers and security engineers. The codebase purposefully explores critical vulnerability vectors including broken cryptography, insecure key management, weak encryption algorithms, side-channel leakage, and network layer security flaws.

Modern cybersecurity standards and software supply chain governance mandates—including Executive Order 14028, NIST SP 800-218 (Secure Software Development Framework - SSDF), OMB M-22-18, and NIST IR 8547 (Transition to Post-Quantum Cryptography)—demand rigorous, machine-readable transparency into software components and cryptographic assets:
1. **Software Supply Chain Transparency:** Mobile applications rely on complex dependency trees (CocoaPods, static frameworks, Swift packages, build toolings) requiring comprehensive Software Bills of Materials (SBOMs) in industry-standard formats (SPDX and CycloneDX).
2. **Cryptographic Asset Discovery & PQC Readiness:** As organizations prepare for Post-Quantum Cryptography (PQC) migration under NIST FIPS 203, 204, and 205, mobile platforms must systematically track cryptographic primitives (e.g., CommonCrypto, Security framework, CryptoKit, legacy DES/3DES/AES-ECB, RSA, and ECC) via Cryptographic Bills of Materials (CBOMs).
3. **Automated Verification & Shift-Left Validation:** Security pipelines must continuously prevent pipeline drift, validate schema compliance, and enforce quality gates within continuous integration (CI) workflows.
4. **Documentation & Audit Parity:** Cryptographic findings and migration status must be transparently surfaced to project documentation and synchronized on repository changes.

### Current Situation

Prior to this decision, `DVIA-v2` maintained automated security scanning for secrets and SAST, but lacked:
1. Automated CI generation and publishing of dual-format SBOMs (CycloneDX and SPDX) and CBOMs upon branch commits or pull requests.
2. Semantic AST and call-site scanning for iOS/Swift/Objective-C cryptographic implementations.
3. Automated test harnesses verifying BOM schema validity, component non-emptiness, and cryptographic asset completeness.
4. Continuous synchronization of post-quantum readiness dashboards to repository documentation.

### Decision Drivers

- **Comprehensive Supply Chain & Cryptographic Governance:** Implement dual-engine SBOM generation (Anchore/Syft) and CBOM generation (`cbomkit`) with AST analysis.
- **Regulatory & Industry Compliance:** Meet NTIA minimum SBOM criteria, EO 14028, and NIST SSDF standards.
- **Continuous Quality Gate & Test Harness:** Enforce automated CI validation verifying JSON syntax, CycloneDX schema conformance, and cryptographic component counts.
- **Developer Workflow Parity:** Provide standalone local CLI scripts (`scripts/generate_boms.sh`, `scripts/test_boms.sh`, `scripts/analyze_cbom.py`, `scripts/scan_crypto_ast.py`) that mirror CI execution identically.
- **Post-Quantum Cryptography (PQC) Tracking:** Continuous visibility into quantum-vulnerable algorithms versus post-quantum resilient alternatives.

---

## Assumptions

- The repository codebase consists of Swift, Objective-C, and supporting build/test scripts for iOS.
- GitHub Actions CI runner environments support Python 3.11+ and Node 24 runtime standards.
- Primary target branch for CI delivery is `master` (and `main` for standard branching compatibility).

---

## Constraints

- CI workflow execution must run on standard GitHub-hosted `ubuntu-latest` runners with minimal overhead (< 2 minutes).
- All GitHub Actions must use immutable SHA-pinned references complying with Node 24 standards.
- Tooling must be self-contained in `scripts/` using Python and Bash without mandatory external SaaS subscriptions.

---

## Alternatives Considered

| Option | Advantages | Disadvantages / Risks | Disposition |
|---|---|---|---|
| **Option 1: Status Quo (No Automated BOM Pipeline)** | Zero pipeline configuration; no runtime overhead. | High compliance risk; complete lack of visibility into third-party dependencies and cryptographic assets; untracked supply chain risks. | **Rejected** |
| **Option 2: Standalone Syft SBOM-Only Pipeline** | Minimal configuration; fast CycloneDX/SPDX generation. | Incomplete cryptographic visibility; cannot generate CBOMs or perform AST cryptographic call-site inspection; ignores PQC readiness. | **Rejected** |
| **Option 3: cbomkit-Only Scanner** | Identifies cryptographic components in CycloneDX format. | Omits SPDX SBOM format required by enterprise procurement standards; lacks deep AST call-site correlation. | **Rejected** |
| **Option 4: Dual-Engine SBOM/CBOM Pipeline + AST Analysis + Automated CI Test Harness (Selected)** | Comprehensive coverage: dual-engine SBOM (CycloneDX & SPDX via Anchore/Syft) and CBOM (`cbomkit`); semantic AST cryptographic analysis (`scan_crypto_ast.py`); automated verification test harness (`test_boms.sh`); automated PQC assessment report generator (`analyze_cbom.py`); full developer CLI script parity. | Adds ~60-90s to CI execution; produces artifacts requiring retention policies. | **Selected** |

---

## Decision

### Selected Option

Adopt **Option 4: Dual-Engine SBOM/CBOM Pipeline + AST Analysis + Automated CI Test Harness** across the `DVIA-v2` repository.

### Key Components

1. **GitHub Actions Workflow (`.github/workflows/sbom-cbom.yml`):**
   - Configured with Node 24 pinned actions (`actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`, `anchore/sbom-action@006b7ce8314066bdf1765b4500370d40fa6917a3`, `cbomkit/cbomkit-action@34a3d960625ae7f7f1b59455eff93a96df090eb7`, `actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065`, `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02`).
   - Triggered on pushes to `master` and `main`, tags (`v*`), pull requests, and manual `workflow_dispatch`.
   - Generates CycloneDX JSON (`oss/sbom.cyclonedx.json`) and SPDX JSON (`oss/sbom.spdx.json`) SBOMs via Anchore / Syft.
   - Generates CycloneDX CBOM (`oss/cbom.json`) via `cbomkit`.
   - Executes semantic AST analysis via `scripts/scan_crypto_ast.py` outputting `oss/crypto-callsites.json`.
   - Runs automated BOM test verification harness via `scripts/test_boms.sh oss`.
   - Generates PQC migration assessments and GHA Step Summaries via `scripts/analyze_cbom.py`.
   - Automatically synchronizes `docs/security/CRYPTOGRAPHIC_AUDIT.md` on push events.
   - Uploads BOM artifacts to GitHub Actions with a 90-day retention period.

2. **Local Tooling Suite (`scripts/`):**
   - `scripts/generate_boms.sh`: Automated local SBOM and CBOM generator supporting directory and container scan targets.
   - `scripts/test_boms.sh`: Verification harness testing JSON syntax, CycloneDX schema compliance, and cryptographic component counts.
   - `scripts/scan_crypto_ast.py`: Python AST analyzer inspecting cryptographic call-sites and reconciling with CBOM.
   - `scripts/analyze_cbom.py`: PQC readiness analysis, algorithm categorization, and Markdown report generator.
   - `scripts/attach_oci_bom.sh` & `scripts/fetch_oci_cbom.py`: Utilities for OCI artifact publishing and retrieval.

### Rationale

Implementing an automated dual-engine SBOM/CBOM pipeline directly aligns `DVIA-v2` with modern supply chain security standards while providing visibility into the mobile app's cryptographic footprint. By coupling package inventories with cryptographic asset tracking, developers and security auditors gain complete visibility into both third-party components and embedded cryptography.

---

## Consequences

### Benefits

- **Comprehensive Visibility:** Provides complete insight into dependencies (SBOM) and cryptographic mechanisms (CBOM) in industry-standard formats.
- **PQC Migration Readiness:** Continuous audit trail tracking classical versus quantum-resilient cryptographic primitives.
- **Automated Validation:** The `test_boms.sh` harness ensures corrupt or empty BOMs fail early in CI before publication.
- **Local Parity:** Developers can run identical scans and validations locally using `scripts/generate_boms.sh` and `scripts/test_boms.sh`.

### Trade-offs and Negative Consequences

- **CI Build Duration:** Workflow adds approximately 60-90 seconds of CI execution time.
- **Catalog Maintenance:** Catalog of known algorithms (`scripts/known_cbom_catalog.json`) requires maintenance as cryptographic standards evolve.

### New Constraints

- CI runner must have Python 3.11+ available for AST and analysis scripts.
- Generated output directory `oss/` is excluded from git tracking via `.gitignore`.

---

## Security, Privacy, and Risk Considerations

- **Dependency Security:** Actions are pinned to full commit SHAs complying with modern Node 24 standards to prevent supply chain poisoning.
- **Data Protection:** Scans inspect code structures and dependencies; no credentials, secret keys, or private material are included in generated BOM artifacts.

---

## Review and Lifecycle

- **Review Schedule:** Annual or upon major NIST PQC standard updates.
- **Supersedes:** None (Initial baseline governance record).
- **Superseded By:** None.
