//! Generic AEAD trait for authenticated encryption operations.

use crate::errors::CrabResult;
use crate::aead::Ciphertext;

/// Trait for Authenticated Encryption with Associated Data (AEAD) operations.
///
/// This trait provides a uniform interface for all AEAD ciphers in CrabGraph.
/// Implementations guarantee:
/// - Confidentiality (ciphertext hides plaintext)
/// - Authenticity (detects tampering)
/// - Associated data authentication (binds public metadata to ciphertext)
pub trait CrabAead {
    /// Encrypts plaintext with optional associated data.
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `associated_data` - Optional public data to authenticate (not encrypted)
    ///
    /// # Returns
    /// `Ciphertext` containing nonce, encrypted data, and authentication tag
    ///
    /// # Security
    /// - Generates a random nonce automatically
    /// - Never reuses nonces with the same key
    /// - Produces a 16-byte authentication tag
    fn encrypt(&self, plaintext: &[u8], associated_data: Option<&[u8]>) -> CrabResult<Ciphertext>;

    /// Decrypts ciphertext with optional associated data.
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted data with nonce and tag
    /// * `associated_data` - Optional public data (must match encryption)
    ///
    /// # Returns
    /// Decrypted plaintext
    ///
    /// # Errors
    /// Returns `CrabError::AuthenticationFailed` if:
    /// - The authentication tag is invalid
    /// - The ciphertext was tampered with
    /// - The associated data doesn't match
    fn decrypt(&self, ciphertext: &Ciphertext, associated_data: Option<&[u8]>) -> CrabResult<Vec<u8>>;

    /// Encrypts plaintext with an explicit nonce (advanced use only).
    ///
    /// # Safety
    /// **WARNING**: Nonce reuse with the same key is catastrophic for security.
    /// Only use this if you have a robust nonce management strategy.
    /// Prefer `encrypt()` which generates random nonces.
    ///
    /// # Arguments
    /// * `plaintext` - Data to encrypt
    /// * `nonce` - Unique nonce (must never repeat for this key)
    /// * `associated_data` - Optional public data to authenticate
    fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
        associated_data: Option<&[u8]>,
    ) -> CrabResult<Ciphertext>;
}
