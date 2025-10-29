# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Comprehensive RFC/NIST Test Vectors** - 13 new test cases covering 28 test vectors from 8 standards
  - NIST CAVP vectors for AES-128/256-GCM (3 test cases)
  - RFC 7539 vectors for ChaCha20-Poly1305 (2 test cases)
  - RFC 4634 vectors for SHA-256/512 (7 test vectors)
  - RFC 4231 vectors for HMAC-SHA256/512 (10 test vectors)
  - RFC 6070 vectors for PBKDF2 (4 test cases, adapted for security minimums)
  - RFC 5869 vectors for HKDF (2 test cases)
  - Total test count increased to 177 tests (from 164)

- **Constant-Time Operations Audit** - Complete review and documentation
  - Added `subtle` crate v2.6 for constant-time comparisons
  - Updated `constant_time_eq()` to use industry-standard `subtle::ConstantTimeEq`
  - Created comprehensive `CONSTANT_TIME_AUDIT.md` documentation
  - Verified all MAC and AEAD operations use constant-time tag verification
  - Added security notes to MAC verification functions
  - Documented guidelines for when to use constant-time comparisons

- **Serde Serialization Support** (behind `serde-support` feature flag)
  - Full serialization/deserialization for `Ciphertext` (encrypted data)
  - Serialization for Ed25519 public keys and signatures
  - Support for JSON, TOML, bincode, and all serde formats
  - Comprehensive example demonstrating usage patterns
  - Binary serialization ~55% more compact than JSON
  - Perfect for storing encrypted data and cryptographic keys

- **Dependency Updates** - Updated 21 packages to latest stable versions
  - RustCrypto: aes-gcm 0.10.3, chacha20poly1305 0.10.1, pbkdf2 0.12.2, argon2 0.5.3
  - Asymmetric: ed25519-dalek 2.2.0 (from 2.1), x25519-dalek 2.0.1
  - Security: zeroize 1.8.2, subtle 2.6.1 (new), pkcs8 0.10.2 (new)
  - Encoding: base64 0.22.1
  - Dev deps: proptest 1.9.0 (from 1.5.0), hex-literal 1.1.0, serde_json 1.0.141, serde_bytes 0.11.19
  - All tests passing (193 with all features: 103 unit + 6 integration + 7 interop + 13 RFC vectors + 64 doc tests)
  - Avoided breaking changes: getrandom stays on 0.2.x, rand_core on 0.6.x for RustCrypto compatibility

- **PKCS#8 Key Import/Export** (RFC 5208, RFC 5958, RFC 8410)
  - Full PKCS#8 DER/PEM support for Ed25519 and X25519 private keys
  - SPKI (SubjectPublicKeyInfo) DER/PEM support for public keys
  - Standards-compliant implementation using `pkcs8` crate v0.10.2
  - OpenSSL-compatible key formats
  - Algorithm OIDs: Ed25519 (1.3.101.112), X25519 (1.3.101.110)
  - 8 new methods: `to_pkcs8_der/pem`, `from_pkcs8_der/pem` for keypairs
  - 8 new methods: `to_public_key_der/pem`, `from_public_key_der/pem` for public keys
  - Comprehensive example in `examples/pkcs8_example.rs`
  - All doc tests passing with roundtrip verification

### Planned
- Streaming encryption API
- SHA-3 and BLAKE2 support
- Property-based testing with proptest

## [0.2.0] - 2025-10-29

### Added
- **RSA Support** (behind `rsa-support` feature flag)
  - RSA-OAEP encryption with SHA-256
  - RSA-PSS signatures with SHA-256
  - 2048-bit and 4096-bit key generation
  - PEM/DER import/export (PKCS#8)
  - Complete test suite with RFC test vectors
  - Benchmarks for RSA operations
  - Example code demonstrating usage

### Security
- ⚠️ **IMPORTANT**: RSA implementation has known vulnerability (RUSTSEC-2023-0071 - Marvin timing attack)
- Added prominent security warnings in documentation
- Recommend Ed25519 for signatures and X25519+AEAD for encryption unless RSA is required for compatibility

### Changed
- Excluded development files from published crate (`.github/`, `fuzz/`, `TODOs.md`, etc.)
- Updated documentation to include RSA examples and security warnings

## [0.1.0] - 2025-10-28

### Added
- **Authenticated Encryption (AEAD)**
  - AES-128-GCM and AES-256-GCM
  - ChaCha20-Poly1305
  - Unified `CrabAead` trait
  - Automatic nonce generation
  - Serialization (bytes, base64)

- **Key Derivation Functions (KDFs)**
  - PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA512
  - Argon2id with configurable parameters
  - HKDF-SHA256 (extract-and-expand)
  - Recommended iteration counts and memory parameters

- **Asymmetric Cryptography**
  - Ed25519 digital signatures
  - X25519 Diffie-Hellman key exchange
  - Key serialization (base64, hex)

- **Message Authentication**
  - HMAC-SHA256
  - HMAC-SHA512
  - Constant-time verification

- **Hashing**
  - SHA-256 and SHA-512
  - Hex output helpers

- **Utilities**
  - Secure random number generation (via `getrandom`)
  - Secret zeroization (`SecretVec`, `SecretArray`)
  - Base64 and hex encoding/decoding
  - Constant-time equality comparison

- **Documentation**
  - Comprehensive API docs with examples
  - Migration guide from CryptoJS
  - Security policy and contributing guidelines
  - Code of conduct

- **Testing**
  - Unit tests with RFC test vectors
  - Integration tests
  - Benchmark suite (Criterion)
  - Fuzz testing harness

- **CI/CD**
  - GitHub Actions workflows (test, lint, audit, fuzz, benchmarks)
  - Multi-platform testing (Linux, Windows, macOS)
  - Security audit integration

### Security
- All secret material automatically zeroized on drop
- Safe-by-default APIs (authenticated encryption, random nonces)
- No unsafe code in core library
- Built on audited primitives (RustCrypto, dalek-cryptography)

### Notes
- ⚠️ **This library has NOT been audited.** See SECURITY.md before using in production.
- Minimum Rust version: 1.70

[Unreleased]: https://github.com/AriajSarkar/crabgraph/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AriajSarkar/crabgraph/releases/tag/v0.1.0
