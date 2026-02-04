//! TLS CryptoProvider implementation for rustls.
//!
//! This module implements `rustls::crypto::CryptoProvider` using crabgraph's
//! existing cryptographic primitives, enabling rustls-based applications
//! (reqwest, hyper-rustls, tokio-rustls, etc.) to use crabgraph for all
//! cryptographic operations.
//!
//! **Requires**: `tls` feature flag
//!
//! # Usage
//!
//! Install the crabgraph provider as the default early in your application:
//!
//! ```ignore
//! use crabgraph::tls;
//!
//! fn main() {
//!     // Install crabgraph as the TLS crypto provider
//!     tls::install_default();
//!     
//!     // Now all rustls-based libraries will use crabgraph
//!     let client = reqwest::Client::new();
//!     // ...
//! }
//! ```
//!
//! Or use it explicitly with a specific config:
//!
//! ```ignore
//! use crabgraph::tls::provider;

// Allow dead_code for internal helpers that are part of the complete implementation
// but may not be used in all configurations or tests
#![allow(dead_code)]
//! use rustls::ClientConfig;
//! use std::sync::Arc;
//!
//! let config = ClientConfig::builder_with_provider(Arc::new(provider()))
//!     .with_safe_default_protocol_versions()
//!     .expect("valid versions")
//!     .with_root_certificates(root_store)
//!     .with_no_client_auth();
//! ```
//!
//! # Supported Cipher Suites
//!
//! ## TLS 1.3
//! - `TLS_AES_256_GCM_SHA384`
//! - `TLS_AES_128_GCM_SHA256`
//! - `TLS_CHACHA20_POLY1305_SHA256`
//!
//! ## TLS 1.2
//! - `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
//! - `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
//! - `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`
//! - `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
//! - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
//! - `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`
//!
//! # Supported Key Exchange Groups
//! - X25519
//! - secp256r1 (P-256)
//! - secp384r1 (P-384)
//!
//! # Security Considerations
//!
//! This implementation wraps audited RustCrypto and dalek-cryptography primitives.
//! While the underlying primitives are audited, this integration layer has not
//! been independently audited. Use in production after appropriate security review.

mod aead;
mod hash;
mod hmac;
mod key_provider;
mod kx;
mod random;
mod signature;
mod ticketer;
mod tls12;
mod tls13;

use rustls::crypto::CryptoProvider;
use std::sync::Arc;

/// Returns the crabgraph CryptoProvider.
///
/// This provider uses crabgraph's cryptographic primitives for all TLS operations.
/// It supports both TLS 1.2 and TLS 1.3 with modern cipher suites.
///
/// # Example
/// ```ignore
/// use crabgraph::tls::provider;
/// use rustls::ClientConfig;
/// use std::sync::Arc;
///
/// let config = ClientConfig::builder_with_provider(Arc::new(provider()))
///     .with_safe_default_protocol_versions()
///     .expect("valid versions")
///     .with_root_certificates(root_store)
///     .with_no_client_auth();
/// ```
///
/// # Cipher Suite Priority
///
/// Cipher suites are ordered by security strength:
/// 1. TLS 1.3 AES-256-GCM (strongest)
/// 2. TLS 1.3 ChaCha20-Poly1305 (excellent for non-AES-NI hardware)
/// 3. TLS 1.3 AES-128-GCM
/// 4. TLS 1.2 ECDHE suites (for legacy compatibility)
pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: signature::SUPPORTED_SIG_ALGS,
        secure_random: &random::CrabgraphRng,
        key_provider: &key_provider::CrabKeyProvider,
    }
}

/// Installs crabgraph as the default TLS CryptoProvider for the process.
///
/// This should be called early in your application (e.g., at the start of `main()`).
/// After installation, all rustls-based libraries (reqwest, hyper-rustls, etc.)
/// will automatically use crabgraph for TLS cryptography.
///
/// # Panics
/// Panics if a default provider has already been installed.
///
/// # Example
/// ```ignore
/// use crabgraph::tls;
///
/// fn main() {
///     tls::install_default();
///     
///     // Now reqwest, octocrab, etc. will use crabgraph
///     let client = reqwest::Client::new();
/// }
/// ```
pub fn install_default() {
    CryptoProvider::install_default(provider())
        .expect("Failed to install crabgraph as the default TLS CryptoProvider");
}

/// Attempts to install crabgraph as the default TLS CryptoProvider.
///
/// Unlike `install_default()`, this returns an error instead of panicking
/// if a provider has already been installed.
///
/// # Returns
/// - `Ok(())` if installation succeeded
/// - `Err(Arc<CryptoProvider>)` if a provider was already installed (returns the crabgraph provider)
pub fn try_install_default() -> Result<(), Arc<CryptoProvider>> {
    CryptoProvider::install_default(provider())
}

/// All supported cipher suites, in preference order.
///
/// TLS 1.3 suites are preferred over TLS 1.2.
pub static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    // TLS 1.3 cipher suites (preferred)
    rustls::SupportedCipherSuite::Tls13(tls13::TLS13_AES_256_GCM_SHA384),
    rustls::SupportedCipherSuite::Tls13(tls13::TLS13_CHACHA20_POLY1305_SHA256),
    rustls::SupportedCipherSuite::Tls13(tls13::TLS13_AES_128_GCM_SHA256),
    // TLS 1.2 cipher suites
    rustls::SupportedCipherSuite::Tls12(tls12::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
    rustls::SupportedCipherSuite::Tls12(tls12::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
    rustls::SupportedCipherSuite::Tls12(tls12::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
    rustls::SupportedCipherSuite::Tls12(tls12::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
    rustls::SupportedCipherSuite::Tls12(tls12::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
    rustls::SupportedCipherSuite::Tls12(tls12::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
];

/// TLS 1.3 cipher suites only, in preference order.
///
/// Use this when you want to restrict connections to TLS 1.3 only.
pub static TLS13_CIPHER_SUITES: &[&rustls::Tls13CipherSuite] = tls13::ALL_TLS13_CIPHER_SUITES;

/// TLS 1.2 cipher suites only, in preference order.
///
/// Use this when you need legacy TLS 1.2 compatibility.
/// TLS 1.3 is recommended for new deployments.
pub static TLS12_CIPHER_SUITES: &[&rustls::Tls12CipherSuite] = tls12::ALL_TLS12_CIPHER_SUITES;

// Re-export key exchange groups for custom configurations
pub use kx::{Secp256r1 as SECP256R1, Secp384r1 as SECP384R1, X25519, ALL_KX_GROUPS};

// Re-export cipher suites for custom configurations
pub use tls12::{
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
};
pub use tls13::{
    TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384,
    TLS13_CHACHA20_POLY1305_SHA256,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let p = provider();
        assert!(
            !p.cipher_suites.is_empty(),
            "Should have cipher suites"
        );
        assert!(!p.kx_groups.is_empty(), "Should have key exchange groups");
    }

    #[test]
    fn test_cipher_suite_count() {
        // 3 TLS 1.3 + 6 TLS 1.2 = 9 total
        assert_eq!(ALL_CIPHER_SUITES.len(), 9);
        assert_eq!(TLS13_CIPHER_SUITES.len(), 3);
        assert_eq!(TLS12_CIPHER_SUITES.len(), 6);
    }

    #[test]
    fn test_kx_groups_count() {
        // X25519, P-256, P-384
        assert_eq!(kx::ALL_KX_GROUPS.len(), 3);
    }

    #[test]
    fn test_provider_has_all_components() {
        let p = provider();

        // Verify all required components are present
        // 3 TLS 1.3 + 6 TLS 1.2 = 9 cipher suites
        assert_eq!(p.cipher_suites.len(), 9, "Should have 9 cipher suites total");
        assert_eq!(p.kx_groups.len(), 3, "Should have 3 key exchange groups");
    }
}
