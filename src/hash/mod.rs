//! Hashing utilities using SHA-2, SHA-3, BLAKE2, and BLAKE3 families.
//!
//! This module provides convenient wrappers around:
//! - SHA-256 and SHA-512 (always available)
//! - SHA3-256 and SHA3-512 (with `extended-hashes` feature)
//! - BLAKE2b-512 and BLAKE2s-256 (with `extended-hashes` feature)
//! - BLAKE3 (with `extended-hashes` feature)

use sha2::{Digest, Sha256, Sha512};

#[cfg(feature = "extended-hashes")]
use sha3::{Sha3_256, Sha3_512};

#[cfg(feature = "extended-hashes")]
use blake2::{Blake2b512, Blake2s256};

#[cfg(feature = "extended-hashes")]
use blake3::Hasher as Blake3Hasher;

/// SHA-256 digest output (32 bytes).
pub type Sha256Digest = [u8; 32];

/// SHA-512 digest output (64 bytes).
pub type Sha512Digest = [u8; 64];

/// SHA3-256 digest output (32 bytes).
#[cfg(feature = "extended-hashes")]
pub type Sha3_256Digest = [u8; 32];

/// SHA3-512 digest output (64 bytes).
#[cfg(feature = "extended-hashes")]
pub type Sha3_512Digest = [u8; 64];

/// BLAKE2s-256 digest output (32 bytes).
#[cfg(feature = "extended-hashes")]
pub type Blake2s256Digest = [u8; 32];

/// BLAKE2b-512 digest output (64 bytes).
#[cfg(feature = "extended-hashes")]
pub type Blake2b512Digest = [u8; 64];

/// BLAKE3 digest output (32 bytes, default size).
///
/// BLAKE3 can produce variable-length output, but we use the standard 32-byte size.
#[cfg(feature = "extended-hashes")]
pub type Blake3Digest = [u8; 32];

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

// ============================================================================
// SHA-3 Family (Keccak) - Available with `extended-hashes` feature
// ============================================================================

/// Computes SHA3-256 hash of the input data.
///
/// SHA-3 uses the Keccak sponge construction and is part of the SHA-3 family
/// standardized by NIST in 2015. It provides 256-bit security.
///
/// **Requires**: `extended-hashes` feature flag
///
/// # Example
/// ```ignore
/// use crabgraph::hash::sha3_256;
///
/// let digest = sha3_256(b"hello world");
/// assert_eq!(digest.len(), 32);
/// ```
#[cfg(feature = "extended-hashes")]
pub fn sha3_256(data: &[u8]) -> Sha3_256Digest {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes SHA3-512 hash of the input data.
///
/// SHA-3 uses the Keccak sponge construction and provides 512-bit security.
/// It's resistant to length extension attacks unlike SHA-2.
///
/// **Requires**: `extended-hashes` feature flag
///
/// # Example
/// ```ignore
/// use crabgraph::hash::sha3_512;
///
/// let digest = sha3_512(b"hello world");
/// assert_eq!(digest.len(), 64);
/// ```
#[cfg(feature = "extended-hashes")]
pub fn sha3_512(data: &[u8]) -> Sha3_512Digest {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes SHA3-256 hash with hex-encoded output.
///
/// **Requires**: `extended-hashes` feature flag
///
/// # Example
/// ```ignore
/// use crabgraph::hash::sha3_256_hex;
///
/// let hex_digest = sha3_256_hex(b"hello");
/// assert_eq!(hex_digest.len(), 64);
/// ```
#[cfg(feature = "extended-hashes")]
pub fn sha3_256_hex(data: &[u8]) -> String {
    hex::encode(sha3_256(data))
}

/// Computes SHA3-512 hash with hex-encoded output.
///
/// **Requires**: `extended-hashes` feature flag
///
/// # Example
/// ```ignore
/// use crabgraph::hash::sha3_512_hex;
///
/// let hex_digest = sha3_512_hex(b"hello");
/// assert_eq!(hex_digest.len(), 128);
/// ```
#[cfg(feature = "extended-hashes")]
pub fn sha3_512_hex(data: &[u8]) -> String {
    hex::encode(sha3_512(data))
}

// ============================================================================
// BLAKE2 Family - High-performance hashing
// ============================================================================

/// Computes BLAKE2s-256 hash of the input data.
///
/// BLAKE2s is optimized for 8- to 32-bit platforms and provides excellent
/// performance. It's faster than MD5 while being cryptographically secure.
/// BLAKE2s-256 produces 32-byte (256-bit) digests.
///
/// **Requires**: `extended-hashes` feature flag
///
/// # Performance
/// BLAKE2s is typically 2-3x faster than SHA-256 on small messages.
///
/// # Example
/// ```ignore
/// use crabgraph::hash::blake2s_256;
///
/// let digest = blake2s_256(b"hello world");
/// assert_eq!(digest.len(), 32);
/// ```
#[cfg(feature = "extended-hashes")]
pub fn blake2s_256(data: &[u8]) -> Blake2s256Digest {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes BLAKE2b-512 hash of the input data.
///
/// BLAKE2b is optimized for 64-bit platforms and provides the best performance
/// on modern CPUs. It's faster than SHA-512 while being cryptographically secure.
/// BLAKE2b-512 produces 64-byte (512-bit) digests.
///
/// **Requires**: `extended-hashes` feature flag
///
/// # Performance
/// BLAKE2b is typically 2-3x faster than SHA-512 and is one of the fastest
/// cryptographic hash functions available.
///
/// # Example
/// ```ignore
/// use crabgraph::hash::blake2b_512;
///
/// let digest = blake2b_512(b"hello world");
/// assert_eq!(digest.len(), 64);
/// ```
#[cfg(feature = "extended-hashes")]
pub fn blake2b_512(data: &[u8]) -> Blake2b512Digest {
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Computes BLAKE2s-256 hash with hex-encoded output.
///
/// **Requires**: `extended-hashes` feature flag
///
/// # Example
/// ```ignore
/// use crabgraph::hash::blake2s_256_hex;
///
/// let hex_digest = blake2s_256_hex(b"hello");
/// assert_eq!(hex_digest.len(), 64);
/// ```
#[cfg(feature = "extended-hashes")]
pub fn blake2s_256_hex(data: &[u8]) -> String {
    hex::encode(blake2s_256(data))
}

/// Computes BLAKE2b-512 hash with hex-encoded output.
///
/// **Requires**: `extended-hashes` feature flag
///
/// # Example
/// ```ignore
/// use crabgraph::hash::blake2b_512_hex;
///
/// let hex_digest = blake2b_512_hex(b"hello");
/// assert_eq!(hex_digest.len(), 128);
/// ```
#[cfg(feature = "extended-hashes")]
pub fn blake2b_512_hex(data: &[u8]) -> String {
    hex::encode(blake2b_512(data))
}

// ============================================================================
// BLAKE3 - Fastest hash function with parallel computation
// ============================================================================

/// Computes BLAKE3 hash of the input data.
///
/// BLAKE3 is the fastest cryptographic hash function available and supports
/// parallel computation on multi-core systems. It's based on Bao (verified streaming)
/// and is significantly faster than BLAKE2.
///
/// **Requires**: `extended-hashes` feature flag
///
/// # Performance
/// BLAKE3 is typically 5-10x faster than SHA-256 and can utilize multiple CPU cores
/// for very large inputs (>16KB). It's the fastest option in this library.
///
/// # Security
/// BLAKE3 provides 256-bit security (output is 32 bytes by default, but can be
/// extended to any length). It's designed to be secure against all known attacks.
///
/// # Use Cases
/// - High-throughput applications (logging, file integrity, checksums)
/// - Large file hashing (benefits from parallelization)
/// - Content-addressable storage systems
/// - Modern replacements for SHA-256 where speed is critical
///
/// # Example
/// ```ignore
/// use crabgraph::hash::blake3_hash;
///
/// let digest = blake3_hash(b"hello world");
/// assert_eq!(digest.len(), 32);
/// ```
#[cfg(feature = "extended-hashes")]
pub fn blake3_hash(data: &[u8]) -> Blake3Digest {
    let mut hasher = Blake3Hasher::new();
    hasher.update(data);
    let hash = hasher.finalize();
    *hash.as_bytes()
}

/// Computes BLAKE3 hash with hex-encoded output.
///
/// **Requires**: `extended-hashes` feature flag
///
/// # Example
/// ```ignore
/// use crabgraph::hash::blake3_hex;
///
/// let hex_digest = blake3_hex(b"hello");
/// assert_eq!(hex_digest.len(), 64); // 32 bytes * 2 hex chars
/// ```
#[cfg(feature = "extended-hashes")]
pub fn blake3_hex(data: &[u8]) -> String {
    hex::encode(blake3_hash(data))
}

/// Creates a BLAKE3 hasher for incremental hashing.
///
/// This is useful when you want to hash data incrementally (streaming)
/// rather than all at once. BLAKE3 can take advantage of multi-threading
/// for large inputs.
///
/// **Requires**: `extended-hashes` feature flag
///
/// # Example
/// ```ignore
/// use crabgraph::hash::blake3_hasher;
///
/// let mut hasher = blake3_hasher();
/// hasher.update(b"hello ");
/// hasher.update(b"world");
/// let digest = hasher.finalize();
/// assert_eq!(digest.as_bytes().len(), 32);
/// ```
#[cfg(feature = "extended-hashes")]
pub fn blake3_hasher() -> Blake3Hasher {
    Blake3Hasher::new()
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
        assert_eq!(hex_digest, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn test_sha512_hex() {
        let hex_digest = sha512_hex(b"");
        assert_eq!(hex_digest.len(), 128);
    }

    // ========================================================================
    // SHA-3 Tests (extended-hashes feature)
    // ========================================================================

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_sha3_256_empty() {
        // SHA3-256 of empty string (NIST test vector)
        let expected = hex!("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        let digest = sha3_256(b"");
        assert_eq!(digest, expected);
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_sha3_256_abc() {
        // SHA3-256 of "abc" (NIST test vector)
        let expected = hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
        let digest = sha3_256(b"abc");
        assert_eq!(digest, expected);
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_sha3_512_empty() {
        // SHA3-512 of empty string (NIST test vector)
        let expected = hex!(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6"
            "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
        let digest = sha3_512(b"");
        assert_eq!(digest, expected);
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_sha3_512_abc() {
        // SHA3-512 of "abc" (NIST test vector)
        let expected = hex!(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
            "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        );
        let digest = sha3_512(b"abc");
        assert_eq!(digest, expected);
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_sha3_256_hex() {
        let hex_digest = sha3_256_hex(b"test");
        assert_eq!(hex_digest.len(), 64); // 32 bytes * 2
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_sha3_512_hex() {
        let hex_digest = sha3_512_hex(b"test");
        assert_eq!(hex_digest.len(), 128); // 64 bytes * 2
    }

    // ========================================================================
    // BLAKE2 Tests (extended-hashes feature)
    // ========================================================================

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_blake2s_256_empty() {
        // BLAKE2s-256 of empty string (official test vector)
        let expected = hex!("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
        let digest = blake2s_256(b"");
        assert_eq!(digest, expected);
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_blake2s_256_abc() {
        // BLAKE2s-256 of "abc" (official test vector)
        let expected = hex!("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
        let digest = blake2s_256(b"abc");
        assert_eq!(digest, expected);
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_blake2b_512_empty() {
        // BLAKE2b-512 of empty string (official test vector)
        let expected = hex!(
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
            "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
        let digest = blake2b_512(b"");
        assert_eq!(digest, expected);
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_blake2b_512_abc() {
        // BLAKE2b-512 of "abc" (official test vector)
        let expected = hex!(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
            "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
        let digest = blake2b_512(b"abc");
        assert_eq!(digest, expected);
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_blake2s_256_hex() {
        let hex_digest = blake2s_256_hex(b"test");
        assert_eq!(hex_digest.len(), 64); // 32 bytes * 2
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_blake2b_512_hex() {
        let hex_digest = blake2b_512_hex(b"test");
        assert_eq!(hex_digest.len(), 128); // 64 bytes * 2
    }

    // ========================================================================
    // BLAKE3 Tests (extended-hashes feature)
    // ========================================================================

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_blake3_empty() {
        // BLAKE3 of empty string (official test vector)
        let expected = hex!("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
        let digest = blake3_hash(b"");
        assert_eq!(digest, expected);
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_blake3_hello_world() {
        // BLAKE3 of "hello world" (official test vector)
        let expected = hex!("d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24");
        let digest = blake3_hash(b"hello world");
        assert_eq!(digest, expected);
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_blake3_abc() {
        // BLAKE3 of "abc"
        let digest = blake3_hash(b"abc");
        assert_eq!(digest.len(), 32);
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_blake3_hex() {
        let hex_digest = blake3_hex(b"test");
        assert_eq!(hex_digest.len(), 64); // 32 bytes * 2
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_blake3_incremental() {
        // Test incremental hashing
        let mut hasher = blake3_hasher();
        hasher.update(b"hello ");
        hasher.update(b"world");
        let digest1 = hasher.finalize();

        // Compare with one-shot hashing
        let digest2 = blake3_hash(b"hello world");

        assert_eq!(digest1.as_bytes(), &digest2);
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_blake3_large_data() {
        // Test with larger data (BLAKE3 shines with larger inputs)
        let data = vec![0u8; 1024 * 1024]; // 1 MB of zeros
        let digest = blake3_hash(&data);
        assert_eq!(digest.len(), 32);

        // Verify it's deterministic
        let digest2 = blake3_hash(&data);
        assert_eq!(digest, digest2);
    }

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_blake3_different_from_others() {
        let data = b"test data";

        let blake3_out = blake3_hash(data);
        let blake2b_out = blake2b_512(data);
        let sha256_out = sha256(data);

        // BLAKE3 should produce different output than others
        assert_ne!(&blake3_out[..], &blake2b_out[..32]);
        assert_ne!(&blake3_out[..], &sha256_out[..]);
    }

    // ========================================================================
    // Performance comparison tests (informational)
    // ========================================================================

    #[test]
    #[cfg(feature = "extended-hashes")]
    fn test_all_hash_functions_produce_different_outputs() {
        let data = b"The quick brown fox jumps over the lazy dog";

        // All hash functions should produce different outputs
        let sha256_out = sha256(data);
        let sha512_out = sha512(data);
        let sha3_256_out = sha3_256(data);
        let sha3_512_out = sha3_512(data);
        let blake2s_out = blake2s_256(data);
        let blake2b_out = blake2b_512(data);
        let blake3_out = blake3_hash(data);

        // Verify different outputs (just checking a few pairs)
        assert_ne!(&sha256_out[..], &sha3_256_out[..]);
        assert_ne!(&sha256_out[..], &blake2s_out[..]);
        assert_ne!(&sha256_out[..], &blake3_out[..]);
        assert_ne!(&sha512_out[..], &sha3_512_out[..]);
        assert_ne!(&sha512_out[..], &blake2b_out[..]);
        assert_ne!(&blake2s_out[..], &blake3_out[..]);
        assert_ne!(&blake2b_out[..32], &blake3_out[..]);
    }
}
