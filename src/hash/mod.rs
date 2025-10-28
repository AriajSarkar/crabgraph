//! Hashing utilities using SHA-2 family.
//!
//! This module provides convenient wrappers around SHA-256 and SHA-512.

use sha2::{Digest, Sha256, Sha512};

/// SHA-256 digest output (32 bytes).
pub type Sha256Digest = [u8; 32];

/// SHA-512 digest output (64 bytes).
pub type Sha512Digest = [u8; 64];

/// Computes SHA-256 hash of the input data.
///
/// # Example
/// ```
/// use crabgraph::hash::sha256;
///
/// let digest = sha256(b"hello world");
/// assert_eq!(digest.len(), 32);
/// ```
pub fn sha256(data: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes SHA-512 hash of the input data.
///
/// # Example
/// ```
/// use crabgraph::hash::sha512;
///
/// let digest = sha512(b"hello world");
/// assert_eq!(digest.len(), 64);
/// ```
pub fn sha512(data: &[u8]) -> Sha512Digest {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes SHA-256 hash with hex-encoded output.
///
/// This is a convenience function for getting a hex string directly.
///
/// # Example
/// ```
/// use crabgraph::hash::sha256_hex;
///
/// let hex_digest = sha256_hex(b"hello");
/// assert_eq!(hex_digest.len(), 64); // 32 bytes * 2 hex chars
/// ```
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// Computes SHA-512 hash with hex-encoded output.
///
/// # Example
/// ```
/// use crabgraph::hash::sha512_hex;
///
/// let hex_digest = sha512_hex(b"hello");
/// assert_eq!(hex_digest.len(), 128); // 64 bytes * 2 hex chars
/// ```
pub fn sha512_hex(data: &[u8]) -> String {
    hex::encode(sha512(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_sha256_empty() {
        // SHA-256 of empty string
        let expected = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let digest = sha256(b"");
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha256_abc() {
        // SHA-256 of "abc"
        let expected = hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let digest = sha256(b"abc");
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha512_empty() {
        // SHA-512 of empty string
        let expected = hex!(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        let digest = sha512(b"");
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha256_hex() {
        let hex_digest = sha256_hex(b"abc");
        assert_eq!(
            hex_digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_sha512_hex() {
        let hex_digest = sha512_hex(b"");
        assert_eq!(hex_digest.len(), 128);
    }
}
