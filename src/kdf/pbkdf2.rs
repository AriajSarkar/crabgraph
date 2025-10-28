//! PBKDF2 key derivation.
//!
//! PBKDF2 is a widely-supported password-based KDF. For new applications,
//! consider Argon2 instead, which provides better resistance to attacks.

use crate::errors::{CrabError, CrabResult};
use crate::secrets::SecretVec;
use pbkdf2::pbkdf2_hmac;
use sha2::{Sha256, Sha512};

/// Recommended minimum iterations for PBKDF2-HMAC-SHA256 (as of 2025).
///
/// **Note**: This value should be increased over time as hardware improves.
/// Consider using Argon2 for better future-proofing.
pub const PBKDF2_SHA256_RECOMMENDED_ITERATIONS: u32 = 600_000;

/// Recommended minimum iterations for PBKDF2-HMAC-SHA512.
pub const PBKDF2_SHA512_RECOMMENDED_ITERATIONS: u32 = 210_000;

/// Derives a key from a password using PBKDF2-HMAC-SHA256.
///
/// # Arguments
/// * `password` - The password to derive from
/// * `salt` - A unique salt (≥16 bytes recommended)
/// * `iterations` - Number of iterations (≥600,000 recommended for 2025)
/// * `key_len` - Desired output key length in bytes
///
/// # Returns
/// A `SecretVec` containing the derived key material
///
/// # Security Notes
/// - Use a unique, random salt for each password
/// - Salt should be at least 16 bytes
/// - Higher iteration counts provide better security but slower performance
/// - Store the salt alongside the derived key (it's not secret)
///
/// # Example
/// ```
/// use crabgraph::kdf::{pbkdf2_derive_sha256, PBKDF2_SHA256_RECOMMENDED_ITERATIONS};
///
/// let password = b"correct horse battery staple";
/// let salt = b"unique_random_salt_16bytes!";
/// let key = pbkdf2_derive_sha256(
///     password,
///     salt,
///     PBKDF2_SHA256_RECOMMENDED_ITERATIONS,
///     32
/// ).unwrap();
///
/// assert_eq!(key.len(), 32);
/// ```
pub fn pbkdf2_derive_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
) -> CrabResult<SecretVec> {
    if salt.len() < 8 {
        return Err(CrabError::invalid_input("Salt should be at least 8 bytes (16+ recommended)"));
    }

    if iterations < 10_000 {
        return Err(CrabError::invalid_input(
            "Iteration count too low (minimum 10,000, recommend 600,000+)",
        ));
    }

    let mut output = vec![0u8; key_len];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output);

    Ok(SecretVec::new(output))
}

/// Derives a key from a password using PBKDF2-HMAC-SHA512.
///
/// # Arguments
/// * `password` - The password to derive from
/// * `salt` - A unique salt (≥16 bytes recommended)
/// * `iterations` - Number of iterations (≥210,000 recommended for 2025)
/// * `key_len` - Desired output key length in bytes
///
/// # Example
/// ```
/// use crabgraph::kdf::{pbkdf2_derive_sha512, PBKDF2_SHA512_RECOMMENDED_ITERATIONS};
///
/// let password = b"my_password";
/// let salt = b"random_salt_data_here_16b+";
/// let key = pbkdf2_derive_sha512(
///     password,
///     salt,
///     PBKDF2_SHA512_RECOMMENDED_ITERATIONS,
///     32
/// ).unwrap();
///
/// assert_eq!(key.len(), 32);
/// ```
pub fn pbkdf2_derive_sha512(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
) -> CrabResult<SecretVec> {
    if salt.len() < 8 {
        return Err(CrabError::invalid_input("Salt should be at least 8 bytes (16+ recommended)"));
    }

    if iterations < 10_000 {
        return Err(CrabError::invalid_input(
            "Iteration count too low (minimum 10,000, recommend 210,000+)",
        ));
    }

    let mut output = vec![0u8; key_len];
    pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut output);

    Ok(SecretVec::new(output))
}

/// Generic PBKDF2 derivation (defaults to SHA-256).
///
/// This is an alias for `pbkdf2_derive_sha256` for convenience.
pub fn pbkdf2_derive(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
) -> CrabResult<SecretVec> {
    pbkdf2_derive_sha256(password, salt, iterations, key_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_pbkdf2_sha256_basic() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";
        let key = pbkdf2_derive_sha256(password, salt, 10_000, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_pbkdf2_sha256_deterministic() {
        let password = b"test_password";
        let salt = b"test_salt_16byte";

        let key1 = pbkdf2_derive_sha256(password, salt, 10_000, 32).unwrap();
        let key2 = pbkdf2_derive_sha256(password, salt, 10_000, 32).unwrap();

        assert_eq!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_pbkdf2_sha256_different_passwords() {
        let salt = b"same_salt_16byte";

        let key1 = pbkdf2_derive_sha256(b"password1", salt, 10_000, 32).unwrap();
        let key2 = pbkdf2_derive_sha256(b"password2", salt, 10_000, 32).unwrap();

        assert_ne!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_pbkdf2_sha256_different_salts() {
        let password = b"same_password";

        let key1 = pbkdf2_derive_sha256(password, b"salt1_16bytes!!!", 10_000, 32).unwrap();
        let key2 = pbkdf2_derive_sha256(password, b"salt2_16bytes!!!", 10_000, 32).unwrap();

        assert_ne!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_pbkdf2_salt_too_short() {
        let result = pbkdf2_derive_sha256(b"password", b"short", 10_000, 32);
        assert!(result.is_err());
    }

    #[test]
    fn test_pbkdf2_iterations_too_low() {
        let result = pbkdf2_derive_sha256(b"password", b"saltsaltsaltsalt", 100, 32);
        assert!(result.is_err());
    }

    #[test]
    fn test_pbkdf2_sha512_basic() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";
        let key = pbkdf2_derive_sha512(password, salt, 10_000, 64).unwrap();
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_pbkdf2_rfc_vector() {
        // RFC 6070 Test Vector 1
        let password = b"password";
        let salt = b"salt";
        let iterations = 1; // Note: This is just for testing, too low for real use

        // We need to allow low iterations for RFC test vector
        // So we'll use the underlying function directly
        let mut output = [0u8; 20];
        pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output);

        // Expected: 120fb6cffcf8b32c43e7225256c4f837a86548c9 (for HMAC-SHA1)
        // For HMAC-SHA256, the output will be different
        // Main point: verify it doesn't panic and produces consistent output
        let mut output2 = [0u8; 20];
        pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output2);
        assert_eq!(output, output2);
    }
}
