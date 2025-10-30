//! AES Key Wrap (AES-KW) implementation per RFC 3394.
//!
//! AES Key Wrap is a specialized encryption mode designed specifically for
//! encrypting cryptographic key material with a Key Encryption Key (KEK).
//!
//! # Use Cases
//!
//! - **Key Storage**: Encrypting keys before storing them in databases
//! - **Key Distribution**: Securely transmitting keys between parties
//! - **HSM Integration**: Import/export keys to Hardware Security Modules
//! - **Key Backup**: Protecting backup copies of cryptographic keys
//!
//! # Security Properties
//!
//! - **RFC 3394 Compliant**: Industry standard for key wrapping
//! - **Integrity Protection**: Built-in integrity check via IV
//! - **Deterministic**: Same KEK + key = same wrapped output (no nonce)
//! - **AES-Based**: Uses AES block cipher (128, 192, or 256-bit KEKs)
//!
//! # Important Constraints
//!
//! - **Input Size**: Key to wrap must be at least 16 bytes (128 bits)
//! - **Alignment**: Input must be a multiple of 8 bytes (64 bits)
//! - **Key Material Only**: Designed for keys, not general-purpose data
//! - **No Confidentiality for Length**: Wrapped key reveals approximate length
//!
//! # ⚠️ Security Warnings
//!
//! 1. **Deterministic Encryption**: AES-KW produces the same output for the same
//!    input every time. This is intentional but means it doesn't provide semantic
//!    security. Use AES-GCM for general data encryption.
//!
//! 2. **KEK Protection**: The Key Encryption Key (KEK) must be kept secure.
//!    Compromise of the KEK compromises all keys wrapped with it.
//!
//! 3. **Not for Large Data**: AES-KW is designed for small key material (16-256 bytes).
//!    For larger data, use AES-GCM or ChaCha20-Poly1305.
//!
//! 4. **Padding Required**: If your key is not a multiple of 8 bytes, use
//!    AES-KWP (Key Wrap with Padding) - not yet implemented.
//!
//! # Examples
//!
//! ## Basic Key Wrapping
//!
//! ```
//! use crabgraph::{kw::{Kw128, Kw256}, CrabResult};
//!
//! fn example() -> CrabResult<()> {
//!     // Generate a KEK (Key Encryption Key)
//!     let kek = Kw256::generate_kek()?;
//!     let wrapper = Kw256::new(&kek)?;
//!     
//!     // Key to protect (e.g., an AES-256 key)
//!     let session_key = [0x42u8; 32];
//!     
//!     // Wrap the key
//!     let wrapped = wrapper.wrap_key(&session_key)?;
//!     println!("Wrapped key: {} bytes", wrapped.len());
//!     
//!     // Unwrap to recover the original key
//!     let unwrapped = wrapper.unwrap_key(&wrapped)?;
//!     assert_eq!(unwrapped, session_key);
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## With Hex Encoding for Storage
//!
//! ```
//! use crabgraph::{kw::Kw256, encoding::hex_encode, CrabResult};
//!
//! fn storage_example() -> CrabResult<()> {
//!     let kek = Kw256::generate_kek()?;
//!     let wrapper = Kw256::new(&kek)?;
//!     
//!     let key_to_store = [0x01u8; 32];
//!     let wrapped = wrapper.wrap_key(&key_to_store)?;
//!     
//!     // Store as hex string in database
//!     let hex_wrapped = hex_encode(&wrapped);
//!     println!("Store in DB: {}", hex_wrapped);
//!     
//!     Ok(())
//! }
//! ```

use crate::errors::{CrabError, CrabResult};
use aes_kw::{KekAes128, KekAes192, KekAes256};

/// AES-128 Key Wrap cipher.
///
/// Uses a 128-bit (16-byte) Key Encryption Key (KEK) to wrap other keys.
///
/// # Security Note
///
/// AES-128 provides 128-bit security level. For most applications, AES-256
/// is recommended for future-proofing and compliance requirements.
///
/// # Example
///
/// ```
/// use crabgraph::{kw::Kw128, CrabResult};
///
/// fn example() -> CrabResult<()> {
///     let kek = [0x01u8; 16]; // In practice, use generate_kek()
///     let wrapper = Kw128::new(&kek)?;
///     
///     let key = [0x42u8; 24]; // 192-bit key to wrap
///     let wrapped = wrapper.wrap_key(&key)?;
///     let unwrapped = wrapper.unwrap_key(&wrapped)?;
///     
///     assert_eq!(unwrapped, key);
///     Ok(())
/// }
/// ```
pub struct Kw128 {
    kek: KekAes128,
}

impl Kw128 {
    /// KEK size in bytes (16 bytes = 128 bits)
    pub const KEK_SIZE: usize = 16;

    /// Minimum key size that can be wrapped (16 bytes)
    pub const MIN_KEY_SIZE: usize = 16;

    /// Create a new AES-128 Key Wrap cipher from a KEK.
    ///
    /// # Arguments
    ///
    /// * `kek` - Key Encryption Key (must be exactly 16 bytes)
    ///
    /// # Errors
    ///
    /// Returns `CrabError::InvalidInput` if KEK is not 16 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{kw::Kw128, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let kek = Kw128::generate_kek()?;
    ///     let wrapper = Kw128::new(&kek)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn new(kek: &[u8]) -> CrabResult<Self> {
        if kek.len() != Self::KEK_SIZE {
            return Err(CrabError::invalid_input(format!(
                "AES-128-KW requires 16-byte KEK, got {}",
                kek.len()
            )));
        }

        let kek_array: [u8; 16] = kek
            .try_into()
            .map_err(|_| CrabError::invalid_input("Failed to convert KEK to array"))?;

        Ok(Self {
            kek: KekAes128::from(kek_array),
        })
    }

    /// Generate a random 16-byte KEK.
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::kw::Kw128;
    ///
    /// let kek = Kw128::generate_kek().unwrap();
    /// assert_eq!(kek.len(), 16);
    /// ```
    pub fn generate_kek() -> CrabResult<Vec<u8>> {
        crate::rand::secure_bytes(Self::KEK_SIZE)
    }

    /// Wrap (encrypt) a cryptographic key.
    ///
    /// # Arguments
    ///
    /// * `key` - Key material to wrap (must be ≥16 bytes and multiple of 8)
    ///
    /// # Returns
    ///
    /// Wrapped key (8 bytes longer than input due to integrity check value)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key is less than 16 bytes
    /// - Key length is not a multiple of 8 bytes
    /// - Wrapping operation fails
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{kw::Kw128, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let kek = Kw128::generate_kek()?;
    ///     let wrapper = Kw128::new(&kek)?;
    ///     
    ///     let session_key = [0x42u8; 32]; // AES-256 key
    ///     let wrapped = wrapper.wrap_key(&session_key)?;
    ///     
    ///     println!("Original: {} bytes", session_key.len());
    ///     println!("Wrapped: {} bytes", wrapped.len());
    ///     
    ///     Ok(())
    /// }
    /// ```
    pub fn wrap_key(&self, key: &[u8]) -> CrabResult<Vec<u8>> {
        // Validate input constraints
        if key.len() < Self::MIN_KEY_SIZE {
            return Err(CrabError::invalid_input(format!(
                "Key must be at least {} bytes, got {}",
                Self::MIN_KEY_SIZE,
                key.len()
            )));
        }

        if key.len() % 8 != 0 {
            return Err(CrabError::invalid_input(format!(
                "Key length must be multiple of 8 bytes, got {}. Consider using AES-KWP for arbitrary lengths.",
                key.len()
            )));
        }

        // Perform the wrap
        let mut output = vec![0u8; key.len() + 8];
        self.kek
            .wrap(key, &mut output)
            .map_err(|e| CrabError::crypto_error(format!("Key wrap failed: {:?}", e)))?;

        Ok(output)
    }

    /// Unwrap (decrypt) a wrapped key.
    ///
    /// # Arguments
    ///
    /// * `wrapped_key` - Previously wrapped key material
    ///
    /// # Returns
    ///
    /// Original unwrapped key
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Wrapped key is too small (< 24 bytes)
    /// - Wrapped key length is invalid
    /// - Integrity check fails (wrong KEK or tampered data)
    ///
    /// # Security Note
    ///
    /// Unwrapping performs integrity verification. Failure indicates either
    /// wrong KEK or data tampering.
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{kw::Kw128, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let kek = Kw128::generate_kek()?;
    ///     let wrapper = Kw128::new(&kek)?;
    ///     
    ///     let original_key = [0x42u8; 16];
    ///     let wrapped = wrapper.wrap_key(&original_key)?;
    ///     let unwrapped = wrapper.unwrap_key(&wrapped)?;
    ///     
    ///     assert_eq!(unwrapped, original_key);
    ///     Ok(())
    /// }
    /// ```
    pub fn unwrap_key(&self, wrapped_key: &[u8]) -> CrabResult<Vec<u8>> {
        if wrapped_key.len() < 24 {
            return Err(CrabError::invalid_input(format!(
                "Wrapped key must be at least 24 bytes, got {}",
                wrapped_key.len()
            )));
        }

        if wrapped_key.len() % 8 != 0 {
            return Err(CrabError::invalid_input(format!(
                "Wrapped key length must be multiple of 8 bytes, got {}",
                wrapped_key.len()
            )));
        }

        // Output is 8 bytes shorter (removes integrity check value)
        let mut output = vec![0u8; wrapped_key.len() - 8];
        self.kek.unwrap(wrapped_key, &mut output).map_err(|e| {
            CrabError::crypto_error(format!(
                "Key unwrap failed: {:?}. Wrong KEK or tampered data.",
                e
            ))
        })?;

        Ok(output)
    }
}

/// AES-256 Key Wrap cipher.
///
/// Uses a 256-bit (32-byte) Key Encryption Key (KEK) to wrap other keys.
/// **Recommended** for most applications due to higher security margin.
///
/// # Example
///
/// ```
/// use crabgraph::{kw::Kw256, CrabResult};
///
/// fn example() -> CrabResult<()> {
///     let kek = Kw256::generate_kek()?;
///     let wrapper = Kw256::new(&kek)?;
///     
///     // Wrap a 256-bit session key
///     let session_key = [0x42u8; 32];
///     let wrapped = wrapper.wrap_key(&session_key)?;
///     
///     // Store wrapped key securely...
///     
///     // Later, unwrap to use
///     let unwrapped = wrapper.unwrap_key(&wrapped)?;
///     assert_eq!(unwrapped, session_key);
///     
///     Ok(())
/// }
/// ```
pub struct Kw256 {
    kek: KekAes256,
}

impl Kw256 {
    /// KEK size in bytes (32 bytes = 256 bits)
    pub const KEK_SIZE: usize = 32;

    /// Minimum key size that can be wrapped (16 bytes)
    pub const MIN_KEY_SIZE: usize = 16;

    /// Create a new AES-256 Key Wrap cipher from a KEK.
    ///
    /// # Arguments
    ///
    /// * `kek` - Key Encryption Key (must be exactly 32 bytes)
    ///
    /// # Errors
    ///
    /// Returns `CrabError::InvalidInput` if KEK is not 32 bytes.
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{kw::Kw256, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let kek = Kw256::generate_kek()?;
    ///     let wrapper = Kw256::new(&kek)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn new(kek: &[u8]) -> CrabResult<Self> {
        if kek.len() != Self::KEK_SIZE {
            return Err(CrabError::invalid_input(format!(
                "AES-256-KW requires 32-byte KEK, got {}",
                kek.len()
            )));
        }

        let kek_array: [u8; 32] = kek
            .try_into()
            .map_err(|_| CrabError::invalid_input("Failed to convert KEK to array"))?;

        Ok(Self {
            kek: KekAes256::from(kek_array),
        })
    }

    /// Generate a random 32-byte KEK.
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::kw::Kw256;
    ///
    /// let kek = Kw256::generate_kek().unwrap();
    /// assert_eq!(kek.len(), 32);
    /// ```
    pub fn generate_kek() -> CrabResult<Vec<u8>> {
        crate::rand::secure_bytes(Self::KEK_SIZE)
    }

    /// Wrap (encrypt) a cryptographic key.
    ///
    /// # Arguments
    ///
    /// * `key` - Key material to wrap (must be ≥16 bytes and multiple of 8)
    ///
    /// # Returns
    ///
    /// Wrapped key (8 bytes longer than input due to integrity check value)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key is less than 16 bytes
    /// - Key length is not a multiple of 8 bytes
    /// - Wrapping operation fails
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{kw::Kw256, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let kek = Kw256::generate_kek()?;
    ///     let wrapper = Kw256::new(&kek)?;
    ///     
    ///     // Wrap an Ed25519 private key (32 bytes)
    ///     let ed25519_key = [0x99u8; 32];
    ///     let wrapped = wrapper.wrap_key(&ed25519_key)?;
    ///     
    ///     assert_eq!(wrapped.len(), 40); // 32 + 8
    ///     Ok(())
    /// }
    /// ```
    pub fn wrap_key(&self, key: &[u8]) -> CrabResult<Vec<u8>> {
        if key.len() < Self::MIN_KEY_SIZE {
            return Err(CrabError::invalid_input(format!(
                "Key must be at least {} bytes, got {}",
                Self::MIN_KEY_SIZE,
                key.len()
            )));
        }

        if key.len() % 8 != 0 {
            return Err(CrabError::invalid_input(format!(
                "Key length must be multiple of 8 bytes, got {}. Consider using AES-KWP for arbitrary lengths.",
                key.len()
            )));
        }

        let mut output = vec![0u8; key.len() + 8];
        self.kek
            .wrap(key, &mut output)
            .map_err(|e| CrabError::crypto_error(format!("Key wrap failed: {:?}", e)))?;

        Ok(output)
    }

    /// Unwrap (decrypt) a wrapped key.
    ///
    /// # Arguments
    ///
    /// * `wrapped_key` - Previously wrapped key material
    ///
    /// # Returns
    ///
    /// Original unwrapped key
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Wrapped key is too small (< 24 bytes)
    /// - Wrapped key length is invalid
    /// - Integrity check fails (wrong KEK or tampered data)
    ///
    /// # Security Note
    ///
    /// Unwrapping performs integrity verification. Failure indicates either
    /// wrong KEK or data tampering.
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{kw::Kw256, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let kek = Kw256::generate_kek()?;
    ///     let wrapper = Kw256::new(&kek)?;
    ///     
    ///     let key = [0xAAu8; 24]; // 192-bit key
    ///     let wrapped = wrapper.wrap_key(&key)?;
    ///     let unwrapped = wrapper.unwrap_key(&wrapped)?;
    ///     
    ///     assert_eq!(unwrapped, key);
    ///     Ok(())
    /// }
    /// ```
    pub fn unwrap_key(&self, wrapped_key: &[u8]) -> CrabResult<Vec<u8>> {
        if wrapped_key.len() < 24 {
            return Err(CrabError::invalid_input(format!(
                "Wrapped key must be at least 24 bytes, got {}",
                wrapped_key.len()
            )));
        }

        if wrapped_key.len() % 8 != 0 {
            return Err(CrabError::invalid_input(format!(
                "Wrapped key length must be multiple of 8 bytes, got {}",
                wrapped_key.len()
            )));
        }

        let mut output = vec![0u8; wrapped_key.len() - 8];
        self.kek.unwrap(wrapped_key, &mut output).map_err(|e| {
            CrabError::crypto_error(format!(
                "Key unwrap failed: {:?}. Wrong KEK or tampered data.",
                e
            ))
        })?;

        Ok(output)
    }
}

/// AES-192 Key Wrap cipher.
///
/// Uses a 192-bit (24-byte) Key Encryption Key (KEK) to wrap other keys.
/// Less common than AES-128 or AES-256.
///
/// # Example
///
/// ```
/// use crabgraph::{kw::Kw192, CrabResult};
///
/// fn example() -> CrabResult<()> {
///     let kek = Kw192::generate_kek()?;
///     let wrapper = Kw192::new(&kek)?;
///     
///     let key = [0x77u8; 24];
///     let wrapped = wrapper.wrap_key(&key)?;
///     let unwrapped = wrapper.unwrap_key(&wrapped)?;
///     
///     assert_eq!(unwrapped, key);
///     Ok(())
/// }
/// ```
pub struct Kw192 {
    kek: KekAes192,
}

impl Kw192 {
    /// KEK size in bytes (24 bytes = 192 bits)
    pub const KEK_SIZE: usize = 24;

    /// Minimum key size that can be wrapped (16 bytes)
    pub const MIN_KEY_SIZE: usize = 16;

    /// Create a new AES-192 Key Wrap cipher from a KEK.
    pub fn new(kek: &[u8]) -> CrabResult<Self> {
        if kek.len() != Self::KEK_SIZE {
            return Err(CrabError::invalid_input(format!(
                "AES-192-KW requires 24-byte KEK, got {}",
                kek.len()
            )));
        }

        let kek_array: [u8; 24] = kek
            .try_into()
            .map_err(|_| CrabError::invalid_input("Failed to convert KEK to array"))?;

        Ok(Self {
            kek: KekAes192::from(kek_array),
        })
    }

    /// Generate a random 24-byte KEK.
    pub fn generate_kek() -> CrabResult<Vec<u8>> {
        crate::rand::secure_bytes(Self::KEK_SIZE)
    }

    /// Wrap (encrypt) a cryptographic key.
    pub fn wrap_key(&self, key: &[u8]) -> CrabResult<Vec<u8>> {
        if key.len() < Self::MIN_KEY_SIZE {
            return Err(CrabError::invalid_input(format!(
                "Key must be at least {} bytes, got {}",
                Self::MIN_KEY_SIZE,
                key.len()
            )));
        }

        if key.len() % 8 != 0 {
            return Err(CrabError::invalid_input(format!(
                "Key length must be multiple of 8 bytes, got {}",
                key.len()
            )));
        }

        let mut output = vec![0u8; key.len() + 8];
        self.kek
            .wrap(key, &mut output)
            .map_err(|e| CrabError::crypto_error(format!("Key wrap failed: {:?}", e)))?;

        Ok(output)
    }

    /// Unwrap (decrypt) a wrapped key.
    pub fn unwrap_key(&self, wrapped_key: &[u8]) -> CrabResult<Vec<u8>> {
        if wrapped_key.len() < 24 {
            return Err(CrabError::invalid_input(format!(
                "Wrapped key must be at least 24 bytes, got {}",
                wrapped_key.len()
            )));
        }

        if wrapped_key.len() % 8 != 0 {
            return Err(CrabError::invalid_input(format!(
                "Wrapped key length must be multiple of 8 bytes, got {}",
                wrapped_key.len()
            )));
        }

        let mut output = vec![0u8; wrapped_key.len() - 8];
        self.kek
            .unwrap(wrapped_key, &mut output)
            .map_err(|e| CrabError::crypto_error(format!("Key unwrap failed: {:?}", e)))?;

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 3394 Test Vectors for AES-128-KW
    #[test]
    fn test_kw128_rfc_vector() {
        // Test vector from RFC 3394 Section 4.1
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
        let key_data = hex::decode("00112233445566778899AABBCCDDEEFF").unwrap();
        let expected = hex::decode("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5").unwrap();

        let wrapper = Kw128::new(&kek).unwrap();
        let wrapped = wrapper.wrap_key(&key_data).unwrap();

        assert_eq!(wrapped, expected);

        let unwrapped = wrapper.unwrap_key(&wrapped).unwrap();
        assert_eq!(unwrapped, key_data);
    }

    // RFC 3394 Test Vectors for AES-256-KW
    #[test]
    fn test_kw256_rfc_vector() {
        // Test vector from RFC 3394 Section 4.6
        let kek = hex::decode("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
            .unwrap();
        let key_data =
            hex::decode("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
                .unwrap();
        let expected = hex::decode(
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        )
        .unwrap();

        let wrapper = Kw256::new(&kek).unwrap();
        let wrapped = wrapper.wrap_key(&key_data).unwrap();

        assert_eq!(wrapped, expected);

        let unwrapped = wrapper.unwrap_key(&wrapped).unwrap();
        assert_eq!(unwrapped, key_data);
    }

    #[test]
    fn test_kw128_generate_kek() {
        let kek = Kw128::generate_kek().unwrap();
        assert_eq!(kek.len(), 16);
    }

    #[test]
    fn test_kw256_generate_kek() {
        let kek = Kw256::generate_kek().unwrap();
        assert_eq!(kek.len(), 32);
    }

    #[test]
    fn test_kw128_roundtrip() {
        let kek = Kw128::generate_kek().unwrap();
        let wrapper = Kw128::new(&kek).unwrap();

        let key = [0x42u8; 32]; // 256-bit key
        let wrapped = wrapper.wrap_key(&key).unwrap();
        let unwrapped = wrapper.unwrap_key(&wrapped).unwrap();

        assert_eq!(unwrapped, key);
        assert_eq!(wrapped.len(), key.len() + 8);
    }

    #[test]
    fn test_kw256_roundtrip() {
        let kek = Kw256::generate_kek().unwrap();
        let wrapper = Kw256::new(&kek).unwrap();

        let key = [0xAAu8; 24]; // 192-bit key
        let wrapped = wrapper.wrap_key(&key).unwrap();
        let unwrapped = wrapper.unwrap_key(&wrapped).unwrap();

        assert_eq!(unwrapped, key);
        assert_eq!(wrapped.len(), key.len() + 8);
    }

    #[test]
    fn test_kw192_roundtrip() {
        let kek = Kw192::generate_kek().unwrap();
        let wrapper = Kw192::new(&kek).unwrap();

        let key = [0x77u8; 16]; // 128-bit key
        let wrapped = wrapper.wrap_key(&key).unwrap();
        let unwrapped = wrapper.unwrap_key(&wrapped).unwrap();

        assert_eq!(unwrapped, key);
    }

    #[test]
    fn test_kw256_wrong_kek_fails() {
        let kek1 = Kw256::generate_kek().unwrap();
        let kek2 = Kw256::generate_kek().unwrap();

        let wrapper1 = Kw256::new(&kek1).unwrap();
        let wrapper2 = Kw256::new(&kek2).unwrap();

        let key = [0x55u8; 32];
        let wrapped = wrapper1.wrap_key(&key).unwrap();

        // Unwrapping with wrong KEK should fail
        let result = wrapper2.unwrap_key(&wrapped);
        assert!(result.is_err());
    }

    #[test]
    fn test_kw256_invalid_key_size() {
        let kek = Kw256::generate_kek().unwrap();
        let wrapper = Kw256::new(&kek).unwrap();

        // Too small (< 16 bytes)
        let result = wrapper.wrap_key(&[0u8; 8]);
        assert!(result.is_err());

        // Not multiple of 8
        let result = wrapper.wrap_key(&[0u8; 17]);
        assert!(result.is_err());
    }

    #[test]
    fn test_kw128_invalid_kek_size() {
        let result = Kw128::new(&[0u8; 15]);
        assert!(result.is_err());

        let result = Kw128::new(&[0u8; 17]);
        assert!(result.is_err());
    }

    #[test]
    fn test_kw256_invalid_kek_size() {
        let result = Kw256::new(&[0u8; 31]);
        assert!(result.is_err());

        let result = Kw256::new(&[0u8; 33]);
        assert!(result.is_err());
    }

    #[test]
    fn test_kw256_tampered_data_fails() {
        let kek = Kw256::generate_kek().unwrap();
        let wrapper = Kw256::new(&kek).unwrap();

        let key = [0x42u8; 32];
        let mut wrapped = wrapper.wrap_key(&key).unwrap();

        // Tamper with the wrapped data
        wrapped[10] ^= 0xFF;

        // Unwrapping should fail due to integrity check
        let result = wrapper.unwrap_key(&wrapped);
        assert!(result.is_err());
    }

    #[test]
    fn test_kw256_different_sizes() {
        let kek = Kw256::generate_kek().unwrap();
        let wrapper = Kw256::new(&kek).unwrap();

        // Test various key sizes (multiples of 8, >= 16)
        for size in [16, 24, 32, 40, 48, 56, 64] {
            let key = vec![0x99u8; size];
            let wrapped = wrapper.wrap_key(&key).unwrap();
            let unwrapped = wrapper.unwrap_key(&wrapped).unwrap();

            assert_eq!(unwrapped, key);
            assert_eq!(wrapped.len(), size + 8);
        }
    }

    #[test]
    fn test_kw128_deterministic() {
        let kek = Kw128::generate_kek().unwrap();
        let wrapper = Kw128::new(&kek).unwrap();

        let key = [0x33u8; 16];

        // Wrap the same key twice
        let wrapped1 = wrapper.wrap_key(&key).unwrap();
        let wrapped2 = wrapper.wrap_key(&key).unwrap();

        // Should produce identical output (deterministic)
        assert_eq!(wrapped1, wrapped2);
    }

    #[test]
    fn test_kw256_multiple_keys() {
        let kek = Kw256::generate_kek().unwrap();
        let wrapper = Kw256::new(&kek).unwrap();

        let key1 = [0x11u8; 32];
        let key2 = [0x22u8; 32];
        let key3 = [0x33u8; 32];

        let wrapped1 = wrapper.wrap_key(&key1).unwrap();
        let wrapped2 = wrapper.wrap_key(&key2).unwrap();
        let wrapped3 = wrapper.wrap_key(&key3).unwrap();

        // All should unwrap correctly
        assert_eq!(wrapper.unwrap_key(&wrapped1).unwrap(), key1);
        assert_eq!(wrapper.unwrap_key(&wrapped2).unwrap(), key2);
        assert_eq!(wrapper.unwrap_key(&wrapped3).unwrap(), key3);

        // Wrapped keys should be different
        assert_ne!(wrapped1, wrapped2);
        assert_ne!(wrapped2, wrapped3);
    }
}
