# CrabGraph TODOs and Roadmap

This document tracks planned features, improvements, and ongoing work for CrabGraph.

## High Priority (v0.2.0)

### Core Functionality
- [x] Add RSA encryption and signatures (behind `rsa` feature flag)
  - Implementation: Use `rsa` crate with OAEP/PSS ✓
  - Complexity: Medium (2-3 days) ✓
  - Security: Requires careful parameter selection ✓
  - Status: **COMPLETED v0.2.0** - Includes full test suite, benchmarks, examples

- [x] Add more RFC test vectors for all algorithms
  - NIST vectors for AES-GCM ✓
  - RFC 7539 vectors for ChaCha20-Poly1305 ✓
  - RFC 4231 vectors for HMAC-SHA256/512 ✓
  - RFC 4634 vectors for SHA-256/512 ✓
  - RFC 6070 vectors for PBKDF2 ✓
  - RFC 5869 vectors for HKDF ✓
  - Complexity: Low (1 day) ✓
  - Status: **COMPLETED v0.2.0** - 13 comprehensive RFC test cases in `tests/rfc_vectors.rs`

- [x] Implement constant-time comparison everywhere
  - Review all comparison operations ✓
  - Use `subtle` crate ✓
  - Added comprehensive documentation ✓
  - Complexity: Low (1 day) ✓
  - Status: **COMPLETED v0.2.0** - `subtle` crate integrated, all critical paths audited in `docs/CONSTANT_TIME_AUDIT.md`

### API Improvements
- [x] Add `serde` support for keys and ciphertexts
  - Enable serialization with `serde-support` feature ✓
  - Add examples for JSON/TOML/binary serialization ✓
  - Works with Ciphertext, Ed25519 keys, signatures ✓
  - Complexity: Low (1 day) ✓
  - Status: **COMPLETED v0.2.0** - Full implementation with comprehensive example in `examples/serde_example.rs`

- [x] Add PKCS#8 import/export for keys
  - Ed25519, X25519 key formats ✓
  - PEM encoding helpers ✓
  - DER binary encoding ✓
  - SPKI (SubjectPublicKeyInfo) for public keys ✓
  - Complexity: Medium (2 days) ✓
  - Status: **COMPLETED v0.2.0** - Full implementation using `pkcs8` crate with proper RFC compliance, comprehensive example in `examples/pkcs8_example.rs`

- [x] Add streaming encryption API
  - For large files that don't fit in memory ✓
  - Use `aead::stream` from RustCrypto ✓
  - Implements STREAM construction (RFC: Online Authenticated-Encryption) ✓
  - AES-256-GCM and ChaCha20-Poly1305 support ✓
  - 7-byte nonce derivation with nonce-reuse resistance ✓
  - Complexity: Medium (2-3 days) ✓
  - Status: **COMPLETED v0.2.0** - Full implementation with 5 comprehensive tests, example in `examples/stream_example.rs`

## Medium Priority (v0.3.0)

### Extended Algorithms
- [x] Add SHA-3 support (behind `extended-hashes` feature)
  - Implementation: Already in dependencies, just expose ✓
  - SHA3-256 and SHA3-512 with NIST test vectors ✓
  - Complexity: Low (0.5 day) ✓
  - Status: **COMPLETED** - Full implementation with 6 tests and comprehensive example

- [x] Add BLAKE2 support (behind `extended-hashes` feature)
  - For high-performance hashing ✓
  - BLAKE2s-256 (32-bit optimized) and BLAKE2b-512 (64-bit optimized) ✓
  - Official test vectors included ✓
  - Complexity: Low (0.5 day) ✓
  - Status: **COMPLETED** - 2-3x faster than SHA-2, comprehensive example in `examples/extended_hashes_example.rs`

- [x] Add BLAKE3 support
  - Fastest hash function ✓
  - Parallelizable ✓
  - 5-10x faster than SHA-256 ✓
  - Official test vectors (empty, "hello world", large data) ✓
  - 3 public functions: blake3_hash, blake3_hex, blake3_hasher ✓
  - 7 comprehensive tests including incremental hashing and parallelization ✓
  - Complexity: Low (1 day) ✓
  - Actual: ~45 minutes ✓
  - Status: **COMPLETED** - Fastest option, excellent for high-throughput, content-addressable storage

### Key Management
- [x] Add key rotation helpers
  - API for versioning keys ✓
  - Re-encryption utilities ✓
  - KeyRotationManager for managing multiple key versions ✓
  - Support for AES-GCM and ChaCha20-Poly1305 ✓
  - Automatic old key cleanup with configurable max versions ✓
  - 17 comprehensive tests ✓
  - Full example demonstrating real-world usage ✓
  - Complexity: Medium (3 days) ✓
  - Actual: ~2 hours ✓
  - Status: **COMPLETED** - Production-ready key rotation with zero-downtime support

- [x] Add key wrapping (AES-KW)
  - RFC 3394 key wrap ✓
  - For encrypting key material with KEKs (Key Encryption Keys) ✓
  - Kw128, Kw256, Kw192 support (all AES key sizes) ✓
  - Deterministic encryption by design (wraps keys, not general data) ✓
  - Built-in integrity protection with IV checking ✓
  - RFC 3394 official test vectors from sections 4.1 and 4.6 ✓
  - 15 comprehensive tests covering all scenarios ✓
  - Full example with 6 demos (basic, HSM workflow, error handling, etc.) ✓
  - Complexity: Medium (2 days) ✓
  - Actual: ~1 hour ✓
  - Status: **COMPLETED** - Production-ready RFC 3394 compliance for HSM/key distribution

### Testing
- [ ] Add property-based tests with `proptest`
  - Encrypt/decrypt round-trips
  - Key derivation consistency
  - Complexity: Low (1 day)

- [ ] Expand fuzzing coverage
  - More fuzz targets
  - Longer fuzzing runs in CI
  - Complexity: Low (1 day)

## Low Priority / Future

### Performance
- [ ] SIMD optimizations (where available)
  - Hardware AES-NI detection
  - AVX2 for ChaCha20
  - Complexity: High (5+ days)
  - Impact: 2-4x faster encryption

- [ ] Zero-copy API improvements
  - In-place encryption/decryption
  - Use `bytes` crate integration
  - Complexity: Medium (3 days)

### Platform Support
- [ ] WASM-specific optimizations
  - Test in browsers (Node.js, Chrome, Firefox)
  - Ensure `getrandom` works properly
  - Complexity: Medium (2 days)

- [ ] Add Windows CNG backend (optional)
  - Use Windows crypto APIs
  - Behind `windows-crypto` feature
  - Complexity: High (7+ days)

- [ ] Add macOS/iOS Keychain integration
  - For key storage on Apple platforms
  - Complexity: High (7+ days)

### Advanced Features
- [ ] Post-quantum cryptography
  - CRYSTALS-Kyber for key encapsulation
  - CRYSTALS-Dilithium for signatures
  - Complexity: High (10+ days)
  - Note: Wait for NIST standardization

- [ ] Threshold cryptography
  - Shamir secret sharing
  - Distributed key generation
  - Complexity: Very High (14+ days)

- [ ] Hardware Security Module (HSM) integration
  - PKCS#11 interface
  - For enterprise deployments
  - Complexity: Very High (14+ days)

### Documentation
- [ ] Add video tutorials
  - Basic usage
  - Migration from other libraries
  - Complexity: Medium (3 days)

- [ ] Create comparison guide
  - vs. ring
  - vs. sodiumoxide
  - vs. OpenSSL
  - Complexity: Low (1 day)

- [ ] Write security best practices guide
  - When to use which algorithm
  - Key management strategies
  - Threat modeling
  - Complexity: Medium (3 days)

## Security & Compliance

### Audits
- [ ] **Third-party security audit** (CRITICAL)
  - Engage professional cryptographers
  - Full code review and penetration testing
  - Cost: $10,000-$50,000
  - Timeline: 4-8 weeks
  - Status: NOT YET FUNDED

- [ ] FIPS 140-3 compliance (if needed for enterprise)
  - Requires certified implementations
  - Complexity: Very High (months)
  - Cost: Very High ($50,000+)

### Hardening
- [ ] Side-channel resistance review
  - Timing analysis
  - Cache timing attacks
  - Power analysis (for embedded)
  - Complexity: High (7+ days)
  - Requires: Expertise in side-channel attacks

- [ ] Formal verification (aspirational)
  - Prove correctness of critical functions
  - Use tools like Kani or Prusti
  - Complexity: Very High (months)

## CI/CD Improvements

- [ ] Add ARM64 to CI matrix
  - Test on Raspberry Pi / ARM servers
  - Complexity: Low (0.5 day)

- [ ] Add cross-compilation tests
  - Various target triples
  - WASM, embedded targets
  - Complexity: Medium (2 days)

- [ ] Automated performance regression detection
  - Track benchmark results over time
  - Alert on significant slowdowns
  - Complexity: Low (1 day)

## Community & Ecosystem

- [ ] Create Discord/Slack community
  - For discussions and support
  - Complexity: Low (0.5 day)

- [ ] Write blog posts
  - Announcement post
  - Technical deep-dives
  - Migration guides
  - Complexity: Medium (2 days each)

- [ ] Present at conferences
  - RustConf, RustNL, etc.
  - Complexity: Medium (prep time)

## Known Issues

- None reported yet (v0.1.0)

## Contribution Estimates

### Effort Levels
- **Low**: 0.5-1 day (good first issues)
- **Medium**: 2-3 days (intermediate)
- **High**: 5-10 days (experienced contributors)
- **Very High**: 2+ weeks (core team / specialists)

### Skills Needed
- **Core Crypto**: Understanding of cryptographic primitives
- **Rust Advanced**: Lifetimes, unsafe, FFI
- **Security**: Threat modeling, side-channel analysis
- **Systems**: Platform-specific APIs, performance optimization

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority is given to:
1. Security fixes (CRITICAL)
2. RFC test vectors (HIGH)
3. Documentation (HIGH)
4. API ergonomics (MEDIUM)
5. Performance (MEDIUM)
6. New features (LOW to MEDIUM)

---

**Last Updated**: October 29, 2025
**Version**: 0.2.0
