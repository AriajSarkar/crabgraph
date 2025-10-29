//! Message Authentication Code (MAC) utilities.
//!
//! This module provides HMAC-based message authentication.

use crate::errors::{CrabError, CrabResult};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// HMAC-SHA256 tag output (32 bytes).
pub type HmacTag256 = [u8; 32];

/// HMAC-SHA512 tag output (64 bytes).
pub type HmacTag512 = [u8; 64];

/// Computes HMAC-SHA256 of the message with the given key.
///
/// # Arguments
/// * `key` - Secret key (recommended ≥32 bytes)
/// * `message` - Data to authenticate
///
/// # Returns
/// 32-byte authentication tag
///
/// # Example
/// ```
/// use crabgraph::mac::hmac_sha256;
///
/// let key = b"secret_key_at_least_32_bytes_long!!!";
/// let message = b"Important message";
/// let tag = hmac_sha256(key, message).unwrap();
/// assert_eq!(tag.len(), 32);
/// ```
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> CrabResult<HmacTag256> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| CrabError::crypto_error(format!("HMAC key error: {}", e)))?;
    mac.update(message);
    let result = mac.finalize();
    Ok(result.into_bytes().into())
}

/// Verifies an HMAC-SHA256 tag in constant time.
///
/// **Security Note**: This function uses constant-time comparison via the `hmac` crate's
/// `verify_slice()` method, which prevents timing attacks that could leak information
/// about the expected tag value.
///
/// # Arguments
/// * `key` - Secret key (same as used for generation)
/// * `message` - Data to authenticate
/// * `tag` - Expected authentication tag
///
/// # Returns
/// `Ok(true)` if valid, `Ok(false)` if invalid
///
/// # Example
/// ```
/// use crabgraph::mac::{hmac_sha256, hmac_sha256_verify};
///
/// let key = b"secret_key_at_least_32_bytes_long!!!";
/// let message = b"Important message";
/// let tag = hmac_sha256(key, message).unwrap();
///
/// assert!(hmac_sha256_verify(key, message, &tag).unwrap());
/// assert!(!hmac_sha256_verify(key, b"Wrong message", &tag).unwrap());
/// ```
pub fn hmac_sha256_verify(key: &[u8], message: &[u8], tag: &[u8]) -> CrabResult<bool> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| CrabError::crypto_error(format!("HMAC key error: {}", e)))?;
    mac.update(message);
    // verify_slice uses constant-time comparison from the `subtle` crate
    Ok(mac.verify_slice(tag).is_ok())
}

/// Computes HMAC-SHA512 of the message with the given key.
///
/// # Arguments
/// * `key` - Secret key (recommended ≥64 bytes)
/// * `message` - Data to authenticate
///
/// # Returns
/// 64-byte authentication tag
///
/// # Example
/// ```
/// use crabgraph::mac::hmac_sha512;
///
/// let key = b"secret_key_at_least_64_bytes_long_for_sha512_hmac_operations!!!!!";
/// let message = b"Important message";
/// let tag = hmac_sha512(key, message).unwrap();
/// assert_eq!(tag.len(), 64);
/// ```
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> CrabResult<HmacTag512> {
    let mut mac = HmacSha512::new_from_slice(key)
        .map_err(|e| CrabError::crypto_error(format!("HMAC key error: {}", e)))?;
    mac.update(message);
    let result = mac.finalize();
    Ok(result.into_bytes().into())
}

/// Verifies an HMAC-SHA512 tag in constant time.
///
/// **Security Note**: This function uses constant-time comparison via the `hmac` crate's
/// `verify_slice()` method, which prevents timing attacks that could leak information
/// about the expected tag value.
///
/// # Arguments
/// * `key` - Secret key (same as used for generation)
/// * `message` - Data to authenticate
/// * `tag` - Expected authentication tag
///
/// # Returns
/// `Ok(true)` if valid, `Ok(false)` if invalid
///
/// # Example
/// ```
/// use crabgraph::mac::{hmac_sha512, hmac_sha512_verify};
///
/// let key = b"secret_key_at_least_64_bytes_long_for_sha512_hmac_operations!!!!!";
/// let message = b"Important message";
/// let tag = hmac_sha512(key, message).unwrap();
///
/// assert!(hmac_sha512_verify(key, message, &tag).unwrap());
/// ```
pub fn hmac_sha512_verify(key: &[u8], message: &[u8], tag: &[u8]) -> CrabResult<bool> {
    let mut mac = HmacSha512::new_from_slice(key)
        .map_err(|e| CrabError::crypto_error(format!("HMAC key error: {}", e)))?;
    mac.update(message);
    // verify_slice uses constant-time comparison from the `subtle` crate
    Ok(mac.verify_slice(tag).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_hmac_sha256_basic() {
        let key = b"secret_key";
        let message = b"message";
        let tag = hmac_sha256(key, message).unwrap();
        assert_eq!(tag.len(), 32);

        // Verify with correct tag
        assert!(hmac_sha256_verify(key, message, &tag).unwrap());

        // Verify with wrong message
        assert!(!hmac_sha256_verify(key, b"wrong", &tag).unwrap());
    }

    #[test]
    fn test_hmac_sha256_rfc_vector() {
        // RFC 4231 Test Case 2
        let key = b"Jefe";
        let message = b"what do ya want for nothing?";
        let expected = hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

        let tag = hmac_sha256(key, message).unwrap();
        assert_eq!(tag, expected);
    }

    #[test]
    fn test_hmac_sha512_basic() {
        let key = b"secret_key_for_sha512";
        let message = b"message";
        let tag = hmac_sha512(key, message).unwrap();
        assert_eq!(tag.len(), 64);

        // Verify with correct tag
        assert!(hmac_sha512_verify(key, message, &tag).unwrap());

        // Verify with wrong key
        assert!(!hmac_sha512_verify(b"wrong_key", message, &tag).unwrap());
    }

    #[test]
    fn test_hmac_deterministic() {
        let key = b"consistent_key";
        let message = b"consistent_message";

        let tag1 = hmac_sha256(key, message).unwrap();
        let tag2 = hmac_sha256(key, message).unwrap();

        assert_eq!(tag1, tag2);
    }
}
