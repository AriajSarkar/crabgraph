//! HKDF (HMAC-based Extract-and-Expand Key Derivation Function).
//!
//! HKDF is used to derive cryptographic keys from existing key material.
//! Unlike password-based KDFs, HKDF assumes the input is already
//! cryptographically strong (e.g., output from Diffie-Hellman).

use crate::errors::{CrabError, CrabResult};
use crate::secrets::SecretVec;
use hkdf::Hkdf;
use sha2::Sha256;

/// Derives key material using HKDF-SHA256.
///
/// HKDF operates in two phases:
/// 1. **Extract**: Creates a pseudorandom key from input key material and salt
/// 2. **Expand**: Expands the pseudorandom key to desired length with optional context
///
/// # Arguments
/// * `salt` - Optional salt value (use empty slice if none)
/// * `input_key_material` - Source key material (e.g., DH shared secret)
/// * `info` - Optional context/application-specific info (use empty slice if none)
/// * `output_len` - Desired output key length in bytes
///
/// # Returns
/// A `SecretVec` containing the derived key material
///
/// # Example
/// ```
/// use crabgraph::kdf::hkdf_extract_expand;
///
/// let ikm = b"input_key_material_from_dh_or_ecdh";
/// let salt = b"optional_salt";
/// let info = b"application_context";
/// let key = hkdf_extract_expand(salt, ikm, info, 32).unwrap();
///
/// assert_eq!(key.len(), 32);
/// ```
pub fn hkdf_extract_expand(
    salt: &[u8],
    input_key_material: &[u8],
    info: &[u8],
    output_len: usize,
) -> CrabResult<SecretVec> {
    if output_len == 0 || output_len > 255 * 32 {
        return Err(CrabError::invalid_input(
            "HKDF output length must be between 1 and 8160 bytes for SHA-256",
        ));
    }

    let hkdf = Hkdf::<Sha256>::new(Some(salt), input_key_material);

    let mut output = vec![0u8; output_len];
    hkdf.expand(info, &mut output)
        .map_err(|e| CrabError::key_error(format!("HKDF expand failed: {}", e)))?;

    Ok(SecretVec::new(output))
}

/// Convenience function for HKDF-SHA256 with default parameters.
///
/// Uses empty salt and info. Suitable for simple key derivation scenarios.
///
/// # Example
/// ```
/// use crabgraph::kdf::hkdf_sha256;
///
/// let ikm = b"source_key_material";
/// let key = hkdf_sha256(ikm, 32).unwrap();
/// assert_eq!(key.len(), 32);
/// ```
pub fn hkdf_sha256(input_key_material: &[u8], output_len: usize) -> CrabResult<SecretVec> {
    hkdf_extract_expand(&[], input_key_material, &[], output_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_hkdf_basic() {
        let ikm = b"input_key_material";
        let salt = b"salt";
        let info = b"info";
        
        let key = hkdf_extract_expand(salt, ikm, info, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let ikm = b"input_key_material";
        let salt = b"salt";
        let info = b"info";
        
        let key1 = hkdf_extract_expand(salt, ikm, info, 32).unwrap();
        let key2 = hkdf_extract_expand(salt, ikm, info, 32).unwrap();
        
        assert_eq!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_hkdf_different_ikm() {
        let salt = b"salt";
        let info = b"info";
        
        let key1 = hkdf_extract_expand(salt, b"ikm1", info, 32).unwrap();
        let key2 = hkdf_extract_expand(salt, b"ikm2", info, 32).unwrap();
        
        assert_ne!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_hkdf_different_info() {
        let ikm = b"input_key_material";
        let salt = b"salt";
        
        let key1 = hkdf_extract_expand(salt, ikm, b"info1", 32).unwrap();
        let key2 = hkdf_extract_expand(salt, ikm, b"info2", 32).unwrap();
        
        assert_ne!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_hkdf_no_salt() {
        let ikm = b"input_key_material";
        let info = b"info";
        
        let key = hkdf_extract_expand(&[], ikm, info, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_no_info() {
        let ikm = b"input_key_material";
        let salt = b"salt";
        
        let key = hkdf_extract_expand(salt, ikm, &[], 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_sha256_convenience() {
        let ikm = b"input_key_material";
        let key = hkdf_sha256(ikm, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_variable_length() {
        let ikm = b"input_key_material";
        
        let key16 = hkdf_sha256(ikm, 16).unwrap();
        let key32 = hkdf_sha256(ikm, 32).unwrap();
        let key64 = hkdf_sha256(ikm, 64).unwrap();
        
        assert_eq!(key16.len(), 16);
        assert_eq!(key32.len(), 32);
        assert_eq!(key64.len(), 64);
    }

    #[test]
    fn test_hkdf_rfc_vector() {
        // RFC 5869 Test Case 1
        let ikm = hex!("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex!("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");
        
        let key = hkdf_extract_expand(&salt, &ikm, &info, 32).unwrap();
        assert_eq!(key.as_slice(), &expected[..]);
    }

    #[test]
    fn test_hkdf_max_output_length() {
        let ikm = b"input_key_material";
        
        // SHA-256 allows up to 255 * 32 = 8160 bytes
        let key = hkdf_sha256(ikm, 255 * 32).unwrap();
        assert_eq!(key.len(), 255 * 32);
    }

    #[test]
    fn test_hkdf_invalid_output_length() {
        let ikm = b"input_key_material";
        
        // Too long
        let result = hkdf_sha256(ikm, 255 * 32 + 1);
        assert!(result.is_err());
        
        // Zero
        let result = hkdf_sha256(ikm, 0);
        assert!(result.is_err());
    }
}
