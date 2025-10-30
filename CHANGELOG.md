# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Property-Based Testing** - Comprehensive property tests using proptest
  - 37 property tests covering all major cryptographic operations
  - AEAD: Encrypt/decrypt round-trips, AAD integrity, nonce uniqueness, ciphertext length (10 tests)
  - KDF: PBKDF2/HKDF determinism, different inputs produce different outputs (6 tests)
  - Key Wrapping: Kw128/192/256 round-trips, determinism, wrong KEK detection (5 tests)
  - Encoding: Base64/hex round-trips, character validation, length properties (5 tests)
  - Hash: SHA-256/512 determinism, output lengths, avalanche effect (5 tests)
  - MAC: HMAC-SHA256/512 determinism, verification round-trips (4 tests)
  - Edge cases: Single-byte operations, large data handling (2 tests)
  - Optimized configuration: 10-20 cases per test (vs default 256) for CI performance
  - Total runtime: ~1.7 seconds
  - Slow tests (Argon2) documented but commented out

- **Expanded Fuzzing Coverage** - Comprehensive fuzz targets for all modules
  - Expanded from 2 to 9 fuzz targets (added 7 new)
  - New targets: `key_wrap_fuzz`, `encoding_fuzz`, `hash_fuzz`, `mac_fuzz`, `stream_fuzz`, `ed25519_fuzz`, `x25519_fuzz`
  - Coverage: AEAD, KDF, key wrapping, encoding, hashing, MACs, streaming, Ed25519, X25519
  - Tests invariants: round-trips, determinism, tamper resistance, no panics
  - All targets compile successfully with nightly Rust
  - Windows limitation documented: DLL issues require WSL2/Linux for actual fuzzing
  - Created comprehensive `fuzz/README.md` with usage examples and troubleshooting
  - Ready for CI integration and OSS-Fuzz

### Changed
- Total test count: 313 tests (160 unit + 13 RFC vectors + 6 integration + 7 interop + 37 proptest + 90 doc tests)
- Improved test coverage to ~95% of critical cryptographic paths

### Documentation
- Added troubleshooting section to `fuzz/README.md` for Windows fuzzing issues
- Updated `TODOs.md` marking property testing and fuzzing expansion as complete
- Documented WSL2 workaround for Windows users running fuzz tests

### Added (Previous - Streaming AEAD)
- **Streaming AEAD Encryption** - High-performance streaming encryption for large files
  - `Aes256GcmStreamEncryptor` and `Aes256GcmStreamDecryptor` for AES-256-GCM
  - `ChaCha20Poly1305StreamEncryptor` and `ChaCha20Poly1305StreamDecryptor`
  - Uses RustCrypto's `aead::stream` module (STREAM construction from RFC)
  - Implements EncryptorBE32/DecryptorBE32 with proper nonce derivation
  - Auto-generates 7-byte nonces (12-byte AEAD nonce - 5 bytes for counter/flag)
  - Methods: `new()`, `nonce()`, `encrypt_next()`, `encrypt_last()`, `from_nonce()`, `decrypt_next()`, `decrypt_last()`
  - Proper ownership semantics (encrypt_last/decrypt_last consume self)
  - Each chunk independently authenticated with nonce-reuse resistance
  - Maximum 2^32 chunks per stream
  - Default chunk size: 64 KB, max chunk size: 1 MB
  - 5 comprehensive tests covering roundtrip, large data, authentication failures, and edge cases
  - Total test count increased to 108 tests (from 103)

- **Comprehensive RFC/NIST Test Vectors** - 13 new test cases covering 28 test vectors from 8 standards
  - NIST CAVP vectors for AES-128/256-GCM (3 test cases)
  - RFC 7539 vectors for ChaCha20-Poly1305 (2 test cases)
  - RFC 4634 vectors for SHA-256/512 (7 test vectors)
  - RFC 4231 vectors for HMAC-SHA256/512 (10 test vectors)
  - RFC 6070 vectors for PBKDF2 (4 test cases, adapted for security minimums)
  - RFC 5869 vectors for HKDF (2 test cases)

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
