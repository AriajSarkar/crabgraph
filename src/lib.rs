//! CrabGraph: A safe, ergonomic cryptographic library for Rust.
//!
//! # ⚠️ Security Warning
//!
//! **This library has NOT been audited by third-party cryptographic experts.**
//! While it uses audited primitives (RustCrypto, dalek-cryptography), mistakes
//! in composition can still lead to vulnerabilities.
//!
//! **DO NOT use in production without a professional security audit.**
//!
//! # Overview
//!
//! CrabGraph provides high-level, safe-by-default cryptographic operations:
//!
//! - **Authenticated Encryption (AEAD)**: [`aead::AesGcm256`], [`aead::ChaCha20Poly1305`]
//! - **Key Derivation**: [`kdf::argon2_derive`], [`kdf::pbkdf2_derive`], [`kdf::hkdf_extract_expand`]
//! - **Digital Signatures**: [`asym::Ed25519KeyPair`], [`asym::RsaKeyPair`] (with `rsa-support` feature)
//! - **Key Exchange**: [`asym::X25519KeyPair`]
//! - **Message Authentication**: [`mac::hmac_sha256`]
//! - **Hashing**: [`hash::sha256`], [`hash::sha512`]
//! - **Secure Random**: [`rand::secure_bytes`]
//!
//! # ⚠️ RSA Security Warning (rsa-support feature)
//!
//! The RSA implementation has a known vulnerability (RUSTSEC-2023-0071 - Marvin timing attack).
//! **Use Ed25519 for signatures and X25519+AEAD for encryption** unless RSA is specifically
//! required for compatibility with legacy systems.
//!
//! # Quick Start
//!
//! ## Authenticated Encryption
//!
//! ```
//! use crabgraph::{aead::{AesGcm256, CrabAead}, CrabResult};
//!
//! fn encrypt_example() -> CrabResult<()> {
//!     // Generate a key
//!     let key = AesGcm256::generate_key()?;
//!     let cipher = AesGcm256::new(&key)?;
//!
//!     // Encrypt
//!     let plaintext = b"Secret message";
//!     let ciphertext = cipher.encrypt(plaintext, None)?;
//!
//!     // Decrypt
//!     let decrypted = cipher.decrypt(&ciphertext, None)?;
//!     assert_eq!(decrypted, plaintext);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Password Hashing
//!
//! ```
//! use crabgraph::{kdf::argon2_derive, CrabResult};
//!
//! fn hash_password() -> CrabResult<()> {
//!     let password = b"user_password";
//!     let salt = crabgraph::rand::secure_bytes(16)?;
//!     
//!     let hash = argon2_derive(password, &salt, 32)?;
//!     // Store hash and salt in database
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Digital Signatures
//!
//! ```
//! use crabgraph::{asym::Ed25519KeyPair, CrabResult};
//!
//! fn sign_example() -> CrabResult<()> {
//!     let keypair = Ed25519KeyPair::generate()?;
//!     let message = b"Important document";
//!     
//!     let signature = keypair.sign(message);
//!     assert!(keypair.verify(message, &signature)?);
//!
//!     Ok(())
//! }
//! ```
//!
//! # Design Principles
//!
//! 1. **Safe by Default**: AEAD modes, automatic nonce generation, memory zeroing
//! 2. **Audited Primitives**: Built on RustCrypto and dalek-cryptography
//! 3. **Ergonomic API**: Clear function names, comprehensive docs, helpful errors
//! 4. **Performance**: Zero-copy operations, hardware acceleration support
//! 5. **Interoperable**: Helpers for compatibility with CryptoJS and OpenSSL
//!
//! # Feature Flags
//!
//! - `default`: Enables `std` support
//! - `std`: Standard library support
//! - `alloc`: Allocation without full std
//! - `no_std`: Embedded/bare-metal support
//! - `extended-hashes`: SHA-3 and BLAKE2
//! - `rsa-support`: RSA encryption/signatures
//! - `serde-support`: Serialization support
//! - `zero-copy`: High-performance `bytes` integration
//! - `wasm`: WebAssembly support

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod aead;
pub mod asym;
pub mod encoding;
pub mod errors;
pub mod hash;
pub mod kdf;
pub mod key_rotation;
pub mod mac;
pub mod rand;
pub mod secrets;
pub mod utils;

// Re-export commonly used types
pub use aead::{AesGcm256, ChaCha20Poly1305, Ciphertext, CrabAead};
pub use asym::{Ed25519KeyPair, X25519KeyPair};
pub use errors::{CrabError, CrabResult};
pub use hash::{sha256, sha512};

// Re-export extended hash functions (when feature is enabled)
#[cfg(feature = "extended-hashes")]
pub use hash::{blake2b_512, blake2s_256, blake3_hash, blake3_hex, sha3_256, sha3_512};

pub use kdf::{argon2_derive, hkdf_extract_expand, pbkdf2_derive};
pub use mac::{hmac_sha256, hmac_sha256_verify};
pub use secrets::{SecretArray, SecretVec};

/// Library version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Prelude module for convenient imports.
///
/// # Example
///
/// ```
/// use crabgraph::prelude::*;
///
/// let key = AesGcm256::generate_key()?;
/// let cipher = AesGcm256::new(&key)?;
/// # Ok::<(), crabgraph::CrabError>(())
/// ```
pub mod prelude {
    pub use crate::{
        aead::{AesGcm128, AesGcm256, ChaCha20Poly1305, Ciphertext, CrabAead},
        asym::{
            Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature, X25519KeyPair, X25519PublicKey,
            X25519SharedSecret,
        },
        encoding::{base64_decode, base64_encode, hex_decode, hex_encode},
        hash::{sha256, sha256_hex, sha512, sha512_hex},
        kdf::{
            argon2_derive, argon2_derive_with_params, hkdf_extract_expand, hkdf_sha256,
            pbkdf2_derive, pbkdf2_derive_sha256, pbkdf2_derive_sha512, Argon2Params,
        },
        mac::{hmac_sha256, hmac_sha256_verify, hmac_sha512, hmac_sha512_verify},
        rand::{generate_key_256, secure_bytes},
        secrets::{SecretArray, SecretVec},
        CrabError, CrabResult,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        // Just verify the version string exists and has expected format
        assert!(VERSION.starts_with("0."));
    }

    #[test]
    fn test_full_workflow() {
        // Test a complete workflow: key derivation -> encryption -> signing

        // 1. Derive a key from password
        let password = b"my_secret_password";
        let salt = rand::secure_bytes(16).unwrap();
        let key_material = kdf::pbkdf2_derive(password, &salt, 10_000, 32).unwrap();

        // 2. Encrypt data
        let cipher = AesGcm256::new(key_material.as_slice()).unwrap();
        let plaintext = b"Sensitive data";
        let ciphertext = cipher.encrypt(plaintext, None).unwrap();

        // 3. Decrypt
        let decrypted = cipher.decrypt(&ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);

        // 4. Sign the ciphertext
        let keypair = Ed25519KeyPair::generate().unwrap();
        let signature = keypair.sign(&ciphertext.to_bytes());

        // 5. Verify signature
        assert!(keypair.verify(&ciphertext.to_bytes(), &signature).unwrap());
    }

    #[test]
    fn test_key_exchange_with_encryption() {
        // Simulate Alice and Bob doing key exchange and encrypting messages

        // Key exchange
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let alice_shared = alice.diffie_hellman(&bob.public_key()).unwrap();
        let bob_shared = bob.diffie_hellman(&alice.public_key()).unwrap();

        // Derive encryption key
        let alice_key = alice_shared.derive_key(b"chat_app_v1", 32).unwrap();
        let bob_key = bob_shared.derive_key(b"chat_app_v1", 32).unwrap();

        // Alice encrypts
        let alice_cipher = AesGcm256::new(alice_key.as_slice()).unwrap();
        let message = b"Hello Bob!";
        let ciphertext = alice_cipher.encrypt(message, None).unwrap();

        // Bob decrypts
        let bob_cipher = AesGcm256::new(bob_key.as_slice()).unwrap();
        let decrypted = bob_cipher.decrypt(&ciphertext, None).unwrap();

        assert_eq!(decrypted, message);
    }
}
