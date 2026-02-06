//! TLS session ticket encryption for stateless resumption.
//!
//! This module provides secure session ticket encryption using AES-256-GCM,
//! enabling stateless TLS session resumption for improved performance.
//!
//! # Usage with rustls ServerConfig
//!
//! ```ignore
//! use std::sync::Arc;
//! use crabgraph::tls::ticketer::AeadTicketer;
//!
//! let ticketer = AeadTicketer::new().expect("Failed to create ticketer");
//! let config = ServerConfig::builder()
//!     .with_crypto_provider(provider)
//!     .with_no_client_auth()
//!     .with_single_cert(certs, key)?
//!     // Set our custom ticketer
//!     .ticketer(Arc::new(ticketer));
//! ```

use std::fmt::Debug;
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rustls::server::ProducesTickets;

/// AES-256-GCM based ticket encryptor.
///
/// Provides secure encryption of TLS session tickets for stateless resumption.
/// Each ticket is encrypted with a fresh random nonce.
///
/// # Security Properties
///
/// - Uses AES-256-GCM for authenticated encryption
/// - Fresh random nonce (12 bytes) for each encryption
/// - Key material is zeroized after cipher creation
/// - Default ticket lifetime of 6 hours (21600 seconds)
///
/// # Implementation Notes
///
/// This implements `rustls::server::ProducesTickets` for use with rustls
/// server configurations. The ticketer is NOT part of CryptoProvider;
/// instead, set it via `ServerConfig::ticketer()`.
pub struct AeadTicketer {
    /// The AES-256-GCM cipher instance
    cipher: Aes256Gcm,
    /// Ticket lifetime in seconds (default: 6 hours = 21600 seconds)
    lifetime_secs: u32,
}

/// Nonce size for AES-GCM (96 bits = 12 bytes)
const NONCE_SIZE: usize = 12;

/// Authentication tag size for AES-GCM (128 bits = 16 bytes)
const TAG_SIZE: usize = 16;

/// Default ticket lifetime: 6 hours in seconds
const DEFAULT_LIFETIME_SECS: u32 = 6 * 60 * 60;

impl AeadTicketer {
    /// Create a new ticketer with a randomly generated key.
    ///
    /// The key is generated using the crabgraph secure random generator
    /// and is automatically zeroized after cipher initialization.
    ///
    /// # Errors
    ///
    /// Returns an error if random key generation fails.
    pub fn new() -> Result<Self, rustls::Error> {
        Self::with_lifetime(DEFAULT_LIFETIME_SECS)
    }

    /// Create a new ticketer with a custom lifetime.
    ///
    /// # Arguments
    ///
    /// * `lifetime_secs` - Ticket lifetime in seconds
    ///
    /// # Errors
    ///
    /// Returns an error if random key generation fails.
    pub fn with_lifetime(lifetime_secs: u32) -> Result<Self, rustls::Error> {
        let mut key = [0u8; 32];
        crate::rand::fill_secure_bytes(&mut key).map_err(|_| {
            rustls::Error::General("Failed to generate random key for ticketer".into())
        })?;

        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| {
            rustls::Error::General("Failed to create AES-256-GCM cipher for ticketer".into())
        })?;

        // Zeroize the key after creating the cipher
        use zeroize::Zeroize;
        key.zeroize();

        Ok(Self {
            cipher,
            lifetime_secs,
        })
    }

    /// Create an Arc-wrapped ticketer ready for use with ServerConfig.
    ///
    /// Convenience method that wraps the ticketer in an Arc for use with
    /// `ServerConfig::ticketer()`.
    ///
    /// # Errors
    ///
    /// Returns an error if ticketer creation fails.
    pub fn arc() -> Result<Arc<dyn ProducesTickets>, rustls::Error> {
        Ok(Arc::new(Self::new()?))
    }

    /// Create an Arc-wrapped ticketer with custom lifetime.
    ///
    /// # Arguments
    ///
    /// * `lifetime_secs` - Ticket lifetime in seconds
    ///
    /// # Errors
    ///
    /// Returns an error if ticketer creation fails.
    pub fn arc_with_lifetime(
        lifetime_secs: u32,
    ) -> Result<Arc<dyn ProducesTickets>, rustls::Error> {
        Ok(Arc::new(Self::with_lifetime(lifetime_secs)?))
    }
}

impl Debug for AeadTicketer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadTicketer")
            .field("lifetime_secs", &self.lifetime_secs)
            .finish_non_exhaustive()
    }
}

// SAFETY: AeadTicketer contains only Send+Sync types
// - Aes256Gcm contains a fixed-size key array and is Send+Sync
// - u32 is Send+Sync
unsafe impl Send for AeadTicketer {}
unsafe impl Sync for AeadTicketer {}

impl ProducesTickets for AeadTicketer {
    fn enabled(&self) -> bool {
        true
    }

    fn lifetime(&self) -> u32 {
        self.lifetime_secs
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        // Generate a random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        crate::rand::fill_secure_bytes(&mut nonce_bytes).ok()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the plaintext
        let ciphertext = self.cipher.encrypt(nonce, plain).ok()?;

        // Prepend nonce to ciphertext: [nonce (12 bytes) | ciphertext | tag (16 bytes)]
        let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        Some(result)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        // Minimum size: nonce + tag
        if cipher.len() < NONCE_SIZE + TAG_SIZE {
            return None;
        }

        // Split nonce and encrypted data
        let (nonce_bytes, encrypted) = cipher.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        self.cipher.decrypt(nonce, encrypted).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ticketer_roundtrip() {
        let ticketer = AeadTicketer::new().unwrap();
        let plaintext = b"session ticket data for TLS resumption";

        let ciphertext = ticketer.encrypt(plaintext).unwrap();
        let decrypted = ticketer.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ticketer_different_nonces() {
        let ticketer = AeadTicketer::new().unwrap();
        let plaintext = b"same plaintext";

        let ct1 = ticketer.encrypt(plaintext).unwrap();
        let ct2 = ticketer.encrypt(plaintext).unwrap();

        // Same plaintext should produce different ciphertexts (different nonces)
        assert_ne!(ct1, ct2);

        // Both should decrypt correctly
        assert_eq!(ticketer.decrypt(&ct1).unwrap(), plaintext);
        assert_eq!(ticketer.decrypt(&ct2).unwrap(), plaintext);
    }

    #[test]
    fn test_ticketer_tampered_data() {
        let ticketer = AeadTicketer::new().unwrap();
        let plaintext = b"sensitive session data";

        let mut ciphertext = ticketer.encrypt(plaintext).unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = ciphertext.get_mut(NONCE_SIZE + 5) {
            *byte ^= 0xFF;
        }

        // Decryption should fail
        assert!(ticketer.decrypt(&ciphertext).is_none());
    }

    #[test]
    fn test_ticketer_too_short() {
        let ticketer = AeadTicketer::new().unwrap();

        // Data too short to contain nonce + tag
        let short_data = vec![0u8; NONCE_SIZE + TAG_SIZE - 1];
        assert!(ticketer.decrypt(&short_data).is_none());
    }

    #[test]
    fn test_ticketer_default_lifetime() {
        let ticketer = AeadTicketer::new().unwrap();
        // Default is 6 hours = 21600 seconds
        assert_eq!(ticketer.lifetime(), DEFAULT_LIFETIME_SECS);
        assert_eq!(ticketer.lifetime(), 21600);
    }

    #[test]
    fn test_ticketer_custom_lifetime() {
        let ticketer = AeadTicketer::with_lifetime(3600).unwrap();
        assert_eq!(ticketer.lifetime(), 3600);
    }

    #[test]
    fn test_ticketer_enabled() {
        let ticketer = AeadTicketer::new().unwrap();
        assert!(ticketer.enabled());
    }

    #[test]
    fn test_ticketer_arc() {
        let ticketer = AeadTicketer::arc().unwrap();

        let plaintext = b"test data";
        let ciphertext = ticketer.encrypt(plaintext).unwrap();
        let decrypted = ticketer.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ticketer_arc_with_lifetime() {
        let ticketer = AeadTicketer::arc_with_lifetime(7200).unwrap();
        assert_eq!(ticketer.lifetime(), 7200);
    }

    #[test]
    fn test_ticketer_empty_plaintext() {
        let ticketer = AeadTicketer::new().unwrap();
        let plaintext = b"";

        let ciphertext = ticketer.encrypt(plaintext).unwrap();
        let decrypted = ticketer.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ticketer_large_plaintext() {
        let ticketer = AeadTicketer::new().unwrap();
        let plaintext = vec![0xAB; 10000]; // 10KB of data

        let ciphertext = ticketer.encrypt(&plaintext).unwrap();
        let decrypted = ticketer.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ticketer_debug() {
        let ticketer = AeadTicketer::new().unwrap();
        let debug_str = format!("{:?}", ticketer);
        assert!(debug_str.contains("AeadTicketer"));
        assert!(debug_str.contains("lifetime_secs"));
    }
}
