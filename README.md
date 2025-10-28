# 🦀 CrabGraph

[![Crates.io](https://img.shields.io/crates/v/crabgraph.svg)](https://crates.io/crates/crabgraph)
[![Documentation](https://docs.rs/crabgraph/badge.svg)](https://docs.rs/crabgraph)
[![GitHub Pages Docs](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://ariajsarkar.github.io/crabgraph/crabgraph/)
[![Build Status](https://github.com/AriajSarkar/crabgraph/workflows/CI/badge.svg)](https://github.com/AriajSarkar/crabgraph/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

A **safe**, **ergonomic**, and **high-performance** cryptographic library for Rust, built on top of audited primitives from the RustCrypto ecosystem and other trusted sources.

## ⚠️ Security Notice

**This library is NOT yet audited by third-party cryptographic experts. While it uses audited primitives (RustCrypto, dalek-cryptography), mistakes in composition can still lead to vulnerabilities. DO NOT use in production without a professional security audit.**

**Note**: The optional `rsa-support` feature has a known vulnerability (RUSTSEC-2023-0071 - Marvin timing attack). Use Ed25519/X25519 instead.

For security issues, please see [SECURITY.md](SECURITY.md).

## ✨ Features

- 🔒 **Authenticated Encryption (AEAD)**: AES-GCM, ChaCha20-Poly1305
- 🔑 **Key Derivation**: PBKDF2, Argon2, HKDF
- ✍️ **Digital Signatures**: Ed25519, (optional: RSA-PSS)
- 🤝 **Key Exchange**: X25519 (Elliptic Curve Diffie-Hellman)
- 🔐 **Message Authentication**: HMAC (SHA-256, SHA-512)
- #️⃣ **Hashing**: SHA-256, SHA-512, (optional: SHA-3, BLAKE2)
- 🔒 **Optional RSA Support**: RSA-OAEP encryption & RSA-PSS signatures (⚠️ opt-in only, not recommended)
- 🎲 **Secure Random**: Cryptographically secure RNG wrapper
- 🧹 **Memory Safety**: Automatic zeroization of sensitive data
- 🌐 **Interoperability**: Helpers for CryptoJS compatibility
- 🚀 **Performance**: Zero-copy operations, hardware acceleration support
- 📦 **No-std Support**: Core functionality available in embedded contexts

## 🚀 Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
crabgraph = "0.1"
```

### Authenticated Encryption (AES-GCM)

```rust
use crabgraph::{aead::AesGcm256, CrabResult};

fn main() -> CrabResult<()> {
    // Generate a random key
    let key = AesGcm256::generate_key()?;
    
    // Create cipher instance
    let cipher = AesGcm256::new(&key)?;
    
    // Encrypt data with associated data (AAD)
    let plaintext = b"Secret message";
    let aad = b"public header";
    let ciphertext = cipher.encrypt(plaintext, Some(aad))?;
    
    // Decrypt
    let decrypted = cipher.decrypt(&ciphertext, Some(aad))?;
    assert_eq!(decrypted, plaintext);
    
    Ok(())
}
```

### Key Derivation (Argon2)

```rust
use crabgraph::{kdf::argon2_derive, CrabResult};

fn main() -> CrabResult<()> {
    let password = b"correct horse battery staple";
    let salt = b"random_salt_16by"; // 16+ bytes
    
    // Derive a 32-byte key
    let key = argon2_derive(password, salt, 32)?;
    
    println!("Derived key: {}", hex::encode(&key));
    Ok(())
}
```

### Digital Signatures (Ed25519)

```rust
use crabgraph::{asym::Ed25519KeyPair, CrabResult};

fn main() -> CrabResult<()> {
    // Generate keypair
    let keypair = Ed25519KeyPair::generate()?;
    
    // Sign message
    let message = b"Important document";
    let signature = keypair.sign(message);
    
    // Verify signature
    assert!(keypair.verify(message, &signature)?);
    
    Ok(())
}
```

### HMAC Authentication

```rust
use crabgraph::{mac::hmac_sha256, CrabResult};

fn main() -> CrabResult<()> {
    let key = b"secret_key_at_least_32_bytes_long!!!";
    let message = b"Message to authenticate";
    
    // Generate HMAC
    let tag = hmac_sha256(key, message)?;
    
    // Verify HMAC
    let is_valid = crabgraph::mac::hmac_sha256_verify(key, message, &tag)?;
    assert!(is_valid);
    
    Ok(())
}
```

## 📚 Documentation

- [API Documentation](https://docs.rs/crabgraph)
- [Migration from CryptoJS](docs/MIGRATE_CRYPTOJS.md)
- [Examples](examples/)

## 🏗️ Architecture

CrabGraph is built on these audited cryptographic libraries:

- **RustCrypto**: `aes-gcm`, `chacha20poly1305`, `sha2`, `hmac`, `pbkdf2`, `hkdf`
- **dalek-cryptography**: `ed25519-dalek`, `x25519-dalek`
- **Argon2**: Official Rust bindings to the Argon2 reference implementation

## 🎯 Design Principles

1. **Safe by Default**: AEAD modes, proper nonce handling, automatic secret zeroization
2. **No Footguns**: High-level API hides complexity; low-level access requires opt-in
3. **Audited Primitives**: Never implements crypto from scratch
4. **Performance**: Zero-copy, hardware acceleration, minimal allocations
5. **Ergonomic**: Builder patterns, clear error messages, comprehensive docs
6. **Interoperable**: Helpers for common JS library compatibility

## 🧪 Testing & Quality

```bash
# Run all tests
cargo test --all-features

# Run benchmarks
cargo bench

# Run fuzzing (requires cargo-fuzz)
cargo fuzz run aead_fuzz

# Security audit
cargo audit
```

## 🔧 Feature Flags

- `default`: Enables `std` support
- `std`: Standard library support (enabled by default)
- `alloc`: Allocation support without full std
- `no_std`: Embedded/bare-metal support
- `extended-hashes`: SHA-3 and BLAKE2 support
- `rsa-support`: RSA encryption/signatures (⚠️ **NOT enabled by default** - opt-in only, has known vulnerability RUSTSEC-2023-0071)
- `serde-support`: Serialization for keys and ciphertexts
- `zero-copy`: `bytes` crate integration for high-performance scenarios
- `wasm`: WebAssembly support

### Enabling RSA Support

RSA is **not included by default** due to security concerns. To use RSA:

```toml
[dependencies]
crabgraph = { version = "0.2", features = ["rsa-support"] }
```

⚠️ **Security Warning**: RSA has a known timing attack vulnerability (RUSTSEC-2023-0071). Use Ed25519 for signatures and X25519+AEAD for encryption unless RSA is specifically required for legacy compatibility.

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) and our [Code of Conduct](CODE_OF_CONDUCT.md).

## 📜 License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## 🙏 Acknowledgments

Built on the shoulders of giants:
- [RustCrypto](https://github.com/RustCrypto) team
- [dalek-cryptography](https://github.com/dalek-cryptography) contributors
- Argon2 reference implementation authors

## ⚠️ Disclaimer

This software is provided "as is", without warranty of any kind. See LICENSE files for details.

**IMPORTANT**: Cryptography is hard. This library has not undergone a formal security audit. Use at your own risk, especially in production environments. Always consult with security professionals for critical applications.
