# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- RSA encryption and signatures (optional feature)
- PKCS#8 key import/export
- Streaming encryption API
- SHA-3 and BLAKE2 support

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
