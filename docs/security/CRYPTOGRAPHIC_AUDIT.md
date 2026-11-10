## 🛡️ Cryptographic Bill of Materials (CBOM) & PQC Migration Assessment

**Format**: CycloneDX (v1.6) | **First-Party Code Crypto Assets**: 0 | **Total Tracked Crypto Assets**: 0

### 📊 Post-Quantum Migration Scorecard

| Metric | Count | Migration Status |
|---|---|---|
| **Post-Quantum Ready (PQC)** | **0** | 🟢 Quantum-Resistant (NIST FIPS 203/204/205) |
| **Quantum-Vulnerable (Backlog)** | **0** | 🔴 At Risk of 'Harvest Now, Decrypt Later' |
| **Classical Symmetric / Digest** | **0** | 🟡 Classical Security (Requires AES-256 / SHA-256+) |
| **Asymmetric PQC Migration Progress** | **N/A (0 detected)** | (No asymmetric primitives detected in current scope) |

### 🎯 Cryptographic Supply Chain Coverage & Confidence

| Evaluation Layer | Coverage / Status | Audit Confidence Assessment |
|---|---|---|
| **First-Party Code (`src/`, `scripts/`)** | **100% Audited** (0 Custom Primitives) | 🟢 **HIGH** (Direct AST & SAST verified) |
| **Third-Party Supply Chain** | **52.4%** (11 of 21 dependencies cataloged) | 🟡 MEDIUM (Known profiles assimilated) |
| **Overall Audit Confidence Score** | **54.5%** | 🟡 MEDIUM (10 unassimilated supply chain dependencies) |

| **System OS Inventory** | **Pending Update** | 🟡 **Warning** (Local OS crypto components not yet inventoried) |

### ✅ Post-Quantum Ready Assets

> ⚠️ **No Post-Quantum Ready assets detected.** Immediate migration planning recommended for asymmetric key exchanges and digital signatures.

### ⚠️ Quantum-Vulnerable Assets & Remediation Plan

> ℹ️ **No quantum-vulnerable asymmetric assets found.** Asymmetric cryptographic primitives were not detected in current scope.

### 🔒 Classical Symmetric & Digest Assets

> ℹ️ **No classical symmetric assets detected.**

### ⚠️ Unassimilated Third-Party Binaries & Cryptographic Blind Spots

> ℹ️ *The following third-party dependencies do not have verified upstream CBOM attestations in the catalog. They lower the audit confidence score until explicit CBOMs or attestations are published.* 

| Dependency Name | Version | Package URL (purl) | Status |
|---|---|---|---|
| `Bolts/Tasks` | 1.9.0 | `pkg:cocoapods/Bolts%2FTasks@1.9.0` | 🟡 Unassimilated (No upstream CBOM) |
| `Flurry-iOS-SDK/FlurrySDK` | 8.3.4 | `pkg:cocoapods/Flurry-iOS-SDK%2FFlurrySDK@8.3.4` | 🟡 Unassimilated (No upstream CBOM) |
| `GoogleAnalytics` | 3.17.0 | `pkg:cocoapods/GoogleAnalytics@3.17.0` | 🟡 Unassimilated (No upstream CBOM) |
| `Parse` | 1.16.0 | `pkg:cocoapods/Parse@1.16.0` | 🟡 Unassimilated (No upstream CBOM) |
| `Parse/Core` | 1.16.0 | `pkg:cocoapods/Parse%2FCore@1.16.0` | 🟡 Unassimilated (No upstream CBOM) |
| `Realm` | 3.1.1 | `pkg:cocoapods/Realm@3.1.1` | 🟡 Unassimilated (No upstream CBOM) |
| `Realm/Headers` | 3.1.1 | `pkg:cocoapods/Realm%2FHeaders@3.1.1` | 🟡 Unassimilated (No upstream CBOM) |
| `RealmSwift` | 3.1.1 | `pkg:cocoapods/RealmSwift@3.1.1` | 🟡 Unassimilated (No upstream CBOM) |
| `couchbase-lite-ios` | 1.4.1 | `pkg:cocoapods/couchbase-lite-ios@1.4.1` | 🟡 Unassimilated (No upstream CBOM) |
| `couchbase-lite-ios/SQLite` | 1.4.1 | `pkg:cocoapods/couchbase-lite-ios%2FSQLite@1.4.1` | 🟡 Unassimilated (No upstream CBOM) |
