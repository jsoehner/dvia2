## 🛡️ Cryptographic Bill of Materials (CBOM) & PQC Migration Assessment

**Format**: CycloneDX (v1.6) | **Total Components**: 1 | **Crypto Assets**: 1

### 📊 Post-Quantum Migration Scorecard

| Metric | Count | Migration Status |
|---|---|---|
| **Post-Quantum Ready (PQC)** | **0** | 🟢 Quantum-Resistant (NIST FIPS 203/204/205) |
| **Quantum-Vulnerable (Backlog)** | **0** | 🔴 At Risk of 'Harvest Now, Decrypt Later' |
| **Classical Symmetric / Hashing** | **1** | 🟡 Classical Security (Requires AES-256 / SHA-256+) |
| **Asymmetric PQC Migration Progress** | **100.0%** | (0 of 0 asymmetric primitives migrated) |

### ✅ Post-Quantum Cryptography Migrated Assets

> ⚠️ **No Post-Quantum Ready assets detected.** Immediate migration planning recommended for asymmetric key exchanges and digital signatures.

### ⚠️ Quantum-Vulnerable Assets & Remediation Plan

> ✅ **Zero quantum-vulnerable asymmetric assets found.** All public-key cryptography conforms to post-quantum standards.

### 🔒 Classical Symmetric & Digest Assets

| Component Name | Primitive | Key Length | Quantum Resistance Assessment | Location(s) |
|---|---|---|---|---|
| `AES-256-GCM` | block-cipher | 256 | Quantum-Resistant (Grover's proof) | `DVIA-v2/Pods/couchbase-lite-ios/CouchbaseLite.framework/Headers/CBLDatabase.h:94`<br>`DVIA-v2/Pods/couchbase-lite-ios/CouchbaseLite.framework/Headers/CBLManager.h:39`<br>`DVIA-v2/Pods/couchbase-lite-ios/CouchbaseLite.framework/Headers/CBLManager.h:42` |
