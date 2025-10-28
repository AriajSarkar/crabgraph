# Security Policy

## ⚠️ Audit Status

**CrabGraph has NOT undergone a formal third-party security audit.** While this library is built on top of audited cryptographic primitives (RustCrypto, dalek-cryptography, Argon2), the composition and high-level API have not been independently reviewed.

**DO NOT use this library in production environments without conducting your own security review or commissioning a professional cryptographic audit.**

## Supported Versions

Currently, only the latest version receives security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security issues seriously. If you discover a security vulnerability in CrabGraph, please follow responsible disclosure practices:

### DO:
- **Email**: Send vulnerability details to `ariajsarkar@gmail.com` with subject line `[SECURITY] CrabGraph Vulnerability`
- **Encrypt**: Use PGP if possible (key available on request)
- **Include**: 
  - Description of the vulnerability
  - Steps to reproduce
  - Potential impact assessment
  - Suggested fix (if available)
- **Allow time**: Give us at least 90 days to respond and patch before public disclosure

### DON'T:
- Publicly disclose the vulnerability before a fix is available
- Exploit the vulnerability maliciously
- Demand payment or compensation

## What to Report

Please report:
- **Cryptographic vulnerabilities**: Improper use of primitives, weak parameters, timing attacks
- **Memory safety issues**: Buffer overflows, use-after-free, data races
- **Side-channel leaks**: Timing leaks, cache timing, power analysis vectors
- **API misuse vectors**: Footguns that could lead developers to insecure implementations
- **Dependency vulnerabilities**: Issues in upstream crates we depend on

## Response Timeline

1. **Acknowledgment**: Within 48 hours
2. **Initial Assessment**: Within 7 days
3. **Fix Development**: Depends on severity (critical: days, high: weeks)
4. **Public Disclosure**: Coordinated after patch is released

## Security Best Practices

When using CrabGraph:

### ✅ DO:
- Use the latest version
- Follow documented examples and best practices
- Use `cargo audit` in your CI/CD pipeline
- Understand the cryptographic primitives you're using
- Test your implementation thoroughly
- Consider a security review for production systems
- Use AEAD modes (AES-GCM, ChaCha20-Poly1305) for encryption
- Generate keys and nonces using the provided secure random functions
- Use Argon2 for password hashing with recommended parameters

### ❌ DON'T:
- Reuse nonces with the same key for AEAD ciphers
- Use weak passwords or low iteration counts for KDFs
- Store keys in plaintext or version control
- Ignore compiler warnings or clippy lints
- Assume this library is audited or "production-ready" without verification
- Implement custom cryptographic schemes on top of primitives without expert review

## Known Limitations

1. **No Hardware Security Module (HSM) integration**: Keys are stored in process memory
2. **Side-channel resistance**: Not all operations are constant-time; some may leak timing information
3. **No key rotation helpers**: Applications must implement their own key management
4. **Limited post-quantum support**: No post-quantum cryptographic algorithms included yet

## Known Vulnerabilities

### RSA Marvin Attack (RUSTSEC-2023-0071)
- **Affected**: Optional `rsa` feature (when enabled)
- **Severity**: Medium (CVSS 5.9)
- **Issue**: Potential key recovery through timing side-channels (Marvin Attack)
- **Status**: No fix available upstream as of October 2025
- **Mitigation**: 
  - RSA support is **optional** and not enabled by default
  - Consider using Ed25519 for signatures and X25519 for key exchange instead
  - If RSA is required, be aware of the timing attack risk in padding oracle scenarios
- **Reference**: https://rustsec.org/advisories/RUSTSEC-2023-0071

**Recommendation**: Do not enable the `rsa-support` feature unless absolutely necessary. Use the default Ed25519/X25519 algorithms which are not affected.

## Dependencies

CrabGraph relies on these cryptographic libraries:

- `aes-gcm` (RustCrypto) - AES-GCM AEAD
- `chacha20poly1305` (RustCrypto) - ChaCha20-Poly1305 AEAD
- `ed25519-dalek` - Ed25519 signatures
- `x25519-dalek` - X25519 key exchange
- `argon2` - Argon2 password hashing
- `pbkdf2` (RustCrypto) - PBKDF2 key derivation
- `sha2`, `hmac` (RustCrypto) - Hashing and MAC

We monitor these dependencies for security advisories. Run `cargo audit` regularly to check for known vulnerabilities.

## Cryptographic Algorithms

### Strong (Recommended)
- AES-256-GCM
- ChaCha20-Poly1305
- Ed25519
- X25519
- HMAC-SHA-256/512
- Argon2id
- HKDF-SHA-256

### Acceptable (Context-Dependent)
- PBKDF2-HMAC-SHA-256 (with high iteration count ≥600,000)

### Deprecated/Not Implemented
- ECB mode (not exposed)
- Unauthenticated encryption modes
- MD5, SHA-1 (not included)

## Vulnerability History

No vulnerabilities have been reported yet (as of v0.1.0).

Future CVEs and security advisories will be listed here.

## Security Audits

No formal audits have been conducted. We welcome offers from security firms or independent researchers to perform audits.

## Contact

- **Email**: ariajsarkar@gmail.com
- **Subject**: `[SECURITY] CrabGraph Vulnerability`

## Acknowledgments

We appreciate responsible disclosure and will acknowledge security researchers (with permission) who report valid vulnerabilities.

---

**Last Updated**: October 28, 2025
