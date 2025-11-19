//! Secure random number generation utilities.
//!
//! This module provides a safe wrapper around the operating system's
//! cryptographically secure random number generator.

use crate::errors::{CrabError, CrabResult};

/// Generates cryptographically secure random bytes.
///
/// Uses the operating system's CSPRNG (via `getrandom`) to produce
/// high-quality random data suitable for cryptographic operations.
///
/// # Arguments
/// * `len` - Number of random bytes to generate
///
/// # Returns
/// A `Vec<u8>` containing `len` random bytes
///
/// # Errors
/// Returns `CrabError::RandomError` if the OS RNG fails
///
/// # Example
/// ```
/// use crabgraph::rand::secure_bytes;
///
/// let random_key = secure_bytes(32).unwrap();
/// assert_eq!(random_key.len(), 32);
/// ```
pub fn secure_bytes(len: usize) -> CrabResult<Vec<u8>> {
    let mut buf = vec![0u8; len];
    getrandom::fill(&mut buf)
        .map_err(|e| CrabError::random_error(format!("Failed to generate random bytes: {}", e)))?;
    Ok(buf)
}

/// Fills a provided buffer with cryptographically secure random bytes.
///
/// This is a zero-allocation variant of [`secure_bytes`] that fills an
/// existing buffer rather than allocating a new one.
///
/// # Arguments
/// * `buf` - Mutable slice to fill with random data
///
/// # Errors
/// Returns `CrabError::RandomError` if the OS RNG fails
///
/// # Example
/// ```
/// use crabgraph::rand::fill_secure_bytes;
///
/// let mut key = [0u8; 32];
/// fill_secure_bytes(&mut key).unwrap();
/// assert_ne!(key, [0u8; 32]); // Should be random
/// ```
pub fn fill_secure_bytes(buf: &mut [u8]) -> CrabResult<()> {
    getrandom::fill(buf).map_err(|e| {
        CrabError::random_error(format!("Failed to fill buffer with random bytes: {}", e))
    })?;
    Ok(())
}

/// Generates a random 32-byte key suitable for symmetric encryption.
///
/// This is a convenience function equivalent to `secure_bytes(32)`.
///
/// # Example
/// ```
/// use crabgraph::rand::generate_key_256;
///
/// let key = generate_key_256().unwrap();
/// assert_eq!(key.len(), 32);
/// ```
pub fn generate_key_256() -> CrabResult<Vec<u8>> {
    secure_bytes(32)
}

/// Generates a random 16-byte key suitable for 128-bit operations.
///
/// This is a convenience function equivalent to `secure_bytes(16)`.
///
/// # Example
/// ```
/// use crabgraph::rand::generate_key_128;
///
/// let key = generate_key_128().unwrap();
/// assert_eq!(key.len(), 16);
/// ```
pub fn generate_key_128() -> CrabResult<Vec<u8>> {
    secure_bytes(16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_bytes() {
        let bytes = secure_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);

        // Generate twice and ensure they're different (with overwhelming probability)
        let bytes2 = secure_bytes(32).unwrap();
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_fill_secure_bytes() {
        let mut buf = [0u8; 64];
        fill_secure_bytes(&mut buf).unwrap();
        assert_ne!(buf, [0u8; 64]);
    }

    #[test]
    fn test_generate_key_256() {
        let key = generate_key_256().unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_generate_key_128() {
        let key = generate_key_128().unwrap();
        assert_eq!(key.len(), 16);
    }

    #[test]
    fn test_randomness_quality() {
        // Generate 1000 bytes and ensure they're not all zeros or all the same
        let bytes = secure_bytes(1000).unwrap();
        let first = bytes[0];
        let all_same = bytes.iter().all(|&b| b == first);
        assert!(!all_same, "Random bytes should not all be identical");
    }
}
