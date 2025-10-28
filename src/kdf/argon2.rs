//! Argon2 key derivation.
//!
//! Argon2 is the recommended password hashing algorithm, winner of the
//! Password Hashing Competition (2015). It provides strong resistance
//! to GPU and ASIC attacks through memory-hard operations.

use crate::errors::{CrabError, CrabResult};
use crate::secrets::SecretVec;
use argon2::{
    Algorithm, Argon2, Params, Version,
};

/// Argon2 parameters configuration.
///
/// These parameters control the time and memory cost of the algorithm.
/// Higher values provide better security but slower performance.
#[derive(Debug, Clone)]
pub struct Argon2Params {
    /// Memory size in KiB (recommended: 64 MiB = 65536 KiB for interactive use)
    pub memory_cost: u32,
    /// Number of iterations (recommended: 3-4 for interactive use)
    pub time_cost: u32,
    /// Degree of parallelism (recommended: match CPU cores, e.g., 4)
    pub parallelism: u32,
}

impl Default for Argon2Params {
    /// Returns recommended parameters for interactive use (2025).
    ///
    /// These values balance security and user experience for authentication:
    /// - 64 MiB memory
    /// - 3 iterations
    /// - 4 parallel threads
    fn default() -> Self {
        Self {
            memory_cost: 65536,  // 64 MiB
            time_cost: 3,
            parallelism: 4,
        }
    }
}

impl Argon2Params {
    /// Creates parameters optimized for interactive authentication.
    ///
    /// Fast enough for login flows (~100-200ms on modern hardware).
    pub fn interactive() -> Self {
        Self::default()
    }

    /// Creates parameters optimized for high-security scenarios.
    ///
    /// Slower but provides maximum protection (~1-2 seconds).
    pub fn high_security() -> Self {
        Self {
            memory_cost: 262144,  // 256 MiB
            time_cost: 5,
            parallelism: 4,
        }
    }

    /// Creates parameters optimized for low-memory environments.
    ///
    /// Suitable for embedded systems or constrained environments.
    pub fn low_memory() -> Self {
        Self {
            memory_cost: 32768,  // 32 MiB
            time_cost: 4,
            parallelism: 2,
        }
    }
}

/// Derives a key from a password using Argon2id with default parameters.
///
/// # Arguments
/// * `password` - The password to derive from
/// * `salt` - A unique salt (≥16 bytes required)
/// * `key_len` - Desired output key length in bytes
///
/// # Returns
/// A `SecretVec` containing the derived key material
///
/// # Security Notes
/// - Uses Argon2id variant (hybrid of Argon2i and Argon2d)
/// - Default parameters: 64 MiB memory, 3 iterations, 4 parallelism
/// - Salt must be at least 16 bytes and unique per password
/// - Store the salt and parameters alongside the hash
///
/// # Example
/// ```
/// use crabgraph::kdf::argon2_derive;
///
/// let password = b"correct horse battery staple";
/// let salt = b"unique_random_salt_16bytes!!";
/// let key = argon2_derive(password, salt, 32).unwrap();
///
/// assert_eq!(key.len(), 32);
/// ```
pub fn argon2_derive(password: &[u8], salt: &[u8], key_len: usize) -> CrabResult<SecretVec> {
    argon2_derive_with_params(password, salt, key_len, &Argon2Params::default())
}

/// Derives a key from a password using Argon2id with custom parameters.
///
/// # Arguments
/// * `password` - The password to derive from
/// * `salt` - A unique salt (≥16 bytes required)
/// * `key_len` - Desired output key length in bytes
/// * `params` - Argon2 parameters (memory cost, time cost, parallelism)
///
/// # Example
/// ```
/// use crabgraph::kdf::{argon2_derive_with_params, Argon2Params};
///
/// let password = b"my_password";
/// let salt = b"random_salt_16+b";
/// let params = Argon2Params::high_security();
/// let key = argon2_derive_with_params(password, salt, 32, &params).unwrap();
///
/// assert_eq!(key.len(), 32);
/// ```
pub fn argon2_derive_with_params(
    password: &[u8],
    salt: &[u8],
    key_len: usize,
    params: &Argon2Params,
) -> CrabResult<SecretVec> {
    if salt.len() < 16 {
        return Err(CrabError::invalid_input(
            "Argon2 requires salt of at least 16 bytes",
        ));
    }

    if key_len == 0 || key_len > 4294967295 {
        return Err(CrabError::invalid_input(
            "Invalid key length",
        ));
    }

    // Build Argon2 parameters
    let argon2_params = Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallelism,
        Some(key_len),
    )?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    // Derive key
    let mut output = vec![0u8; key_len];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| CrabError::key_error(format!("Argon2 derivation failed: {}", e)))?;

    Ok(SecretVec::new(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_basic() {
        let password = b"password123";
        let salt = b"saltsaltsaltsalt";
        let key = argon2_derive(password, salt, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_argon2_deterministic() {
        let password = b"test_password";
        let salt = b"test_salt_16byte";
        
        let key1 = argon2_derive(password, salt, 32).unwrap();
        let key2 = argon2_derive(password, salt, 32).unwrap();
        
        assert_eq!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_argon2_different_passwords() {
        let salt = b"same_salt_16byte";
        
        let key1 = argon2_derive(b"password1", salt, 32).unwrap();
        let key2 = argon2_derive(b"password2", salt, 32).unwrap();
        
        assert_ne!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_argon2_different_salts() {
        let password = b"same_password";
        
        let key1 = argon2_derive(password, b"salt1_16bytes!!!", 32).unwrap();
        let key2 = argon2_derive(password, b"salt2_16bytes!!!", 32).unwrap();
        
        assert_ne!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_argon2_salt_too_short() {
        let result = argon2_derive(b"password", b"short", 32);
        assert!(result.is_err());
    }

    #[test]
    fn test_argon2_custom_params() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";
        let params = Argon2Params::low_memory();
        
        let key = argon2_derive_with_params(password, salt, 32, &params).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_argon2_high_security() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";
        let params = Argon2Params::high_security();
        
        let key = argon2_derive_with_params(password, salt, 32, &params).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_argon2_variable_output_length() {
        let password = b"password";
        let salt = b"saltsaltsaltsalt";
        
        let key16 = argon2_derive(password, salt, 16).unwrap();
        let key32 = argon2_derive(password, salt, 32).unwrap();
        let key64 = argon2_derive(password, salt, 64).unwrap();
        
        assert_eq!(key16.len(), 16);
        assert_eq!(key32.len(), 32);
        assert_eq!(key64.len(), 64);
    }
}
