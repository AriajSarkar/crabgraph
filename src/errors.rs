//! Error types for CrabGraph cryptographic operations.
//!
//! This module defines a unified error type [`CrabError`] that covers all possible
//! failure modes in the library. Errors never leak sensitive information.

use thiserror::Error;

/// Result type alias using [`CrabError`] as the error type.
pub type CrabResult<T> = Result<T, CrabError>;

/// Unified error type for all CrabGraph operations.
///
/// This enum covers encryption, key derivation, signing, and other cryptographic
/// operations. Error messages are designed to be safe for logging and never
/// expose sensitive data like keys or plaintexts.
#[derive(Error, Debug)]
pub enum CrabError {
    /// Invalid input parameter (e.g., wrong key size, empty data)
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Cryptographic operation failed (e.g., decryption, verification)
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    /// Key generation or derivation failed
    #[error("Key operation failed: {0}")]
    KeyError(String),

    /// Authentication tag verification failed
    #[error("Authentication failed: invalid tag or corrupted data")]
    AuthenticationFailed,

    /// Signature verification failed
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Invalid nonce or IV
    #[error("Invalid nonce/IV: {0}")]
    InvalidNonce(String),

    /// Invalid ciphertext format or encoding
    #[error("Invalid ciphertext format: {0}")]
    InvalidCiphertext(String),

    /// Encoding/decoding error (base64, hex, etc.)
    #[error("Encoding error: {0}")]
    EncodingError(String),

    /// Random number generation failed
    #[error("Random number generation failed: {0}")]
    RandomError(String),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Feature not enabled (requires feature flag)
    #[error("Feature not enabled: {0}")]
    FeatureNotEnabled(String),

    /// Internal error (should not happen in normal operation)
    #[error("Internal error: {0}")]
    Internal(String),
}

impl CrabError {
    /// Creates an `InvalidInput` error with a formatted message.
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }

    /// Creates a `CryptoError` with a formatted message.
    pub fn crypto_error(msg: impl Into<String>) -> Self {
        Self::CryptoError(msg.into())
    }

    /// Creates a `KeyError` with a formatted message.
    pub fn key_error(msg: impl Into<String>) -> Self {
        Self::KeyError(msg.into())
    }

    /// Creates an `EncodingError` with a formatted message.
    pub fn encoding_error(msg: impl Into<String>) -> Self {
        Self::EncodingError(msg.into())
    }

    /// Creates a `RandomError` with a formatted message.
    pub fn random_error(msg: impl Into<String>) -> Self {
        Self::RandomError(msg.into())
    }
}

// Conversions from external error types
// Note: aes_gcm::Error and chacha20poly1305::Error are the same type from the aead crate
impl From<aes_gcm::Error> for CrabError {
    fn from(_e: aes_gcm::Error) -> Self {
        CrabError::AuthenticationFailed
    }
}

impl From<argon2::Error> for CrabError {
    fn from(e: argon2::Error) -> Self {
        CrabError::KeyError(format!("Argon2 error: {}", e))
    }
}

impl From<pbkdf2::password_hash::Error> for CrabError {
    fn from(e: pbkdf2::password_hash::Error) -> Self {
        CrabError::KeyError(format!("PBKDF2 error: {}", e))
    }
}

impl From<ed25519_dalek::SignatureError> for CrabError {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        CrabError::SignatureVerificationFailed
    }
}

impl From<getrandom::Error> for CrabError {
    fn from(e: getrandom::Error) -> Self {
        CrabError::RandomError(format!("getrandom error: {}", e))
    }
}

impl From<base64::DecodeError> for CrabError {
    fn from(e: base64::DecodeError) -> Self {
        CrabError::EncodingError(format!("Base64 decode error: {}", e))
    }
}

impl From<hex::FromHexError> for CrabError {
    fn from(e: hex::FromHexError) -> Self {
        CrabError::EncodingError(format!("Hex decode error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CrabError::invalid_input("Key too short");
        assert_eq!(err.to_string(), "Invalid input: Key too short");

        let auth_err = CrabError::AuthenticationFailed;
        assert_eq!(
            auth_err.to_string(),
            "Authentication failed: invalid tag or corrupted data"
        );
    }

    #[test]
    fn test_error_construction() {
        let err = CrabError::crypto_error("test error");
        assert!(matches!(err, CrabError::CryptoError(_)));
    }
}
