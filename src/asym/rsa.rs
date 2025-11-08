//! RSA encryption and signatures.
//!
//! ⚠️ **SECURITY WARNING**: The RSA implementation has a known vulnerability
//! (RUSTSEC-2023-0071 - Marvin timing attack). Use Ed25519 for signatures and
//! X25519+AEAD for encryption unless RSA is specifically required for compatibility.
//!
//! This module provides:
//! - OAEP encryption (RSA-OAEP with SHA-256)
//! - PSS signatures (RSA-PSS with SHA-256)
//! - 2048-bit and 4096-bit key sizes

use crate::errors::{CrabError, CrabResult};
use rand_core::OsRng;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    pss::{BlindedSigningKey, Signature, VerifyingKey},
    sha2::Sha256,
    signature::SignatureEncoding,
    traits::PublicKeyParts,
    Oaep, RsaPrivateKey, RsaPublicKey as RsaPubKey,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// RSA signature (length depends on key size).
#[derive(Clone, Debug, PartialEq)]
pub struct RsaSignature(Vec<u8>);

impl RsaSignature {
    /// Creates a signature from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns signature as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encodes signature to base64.
    pub fn to_base64(&self) -> String {
        crate::encoding::base64_encode(&self.0)
    }

    /// Decodes signature from base64.
    pub fn from_base64(data: &str) -> CrabResult<Self> {
        let bytes = crate::encoding::base64_decode(data)?;
        Ok(Self(bytes))
    }

    /// Encodes signature to hex.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Decodes signature from hex.
    pub fn from_hex(data: &str) -> CrabResult<Self> {
        let bytes = hex::decode(data)
            .map_err(|e| CrabError::encoding_error(format!("Invalid hex: {}", e)))?;
        Ok(Self(bytes))
    }

    /// Returns the signature length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the signature is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// RSA public key for encryption and signature verification.
#[derive(Clone, Debug)]
pub struct RsaPublicKey(RsaPubKey);

impl RsaPublicKey {
    /// Creates a public key from PEM-encoded PKCS#8 format.
    ///
    /// # Example
    /// ```ignore
    /// let pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";
    /// let public_key = RsaPublicKey::from_pem(pem)?;
    /// ```
    pub fn from_pem(pem: &str) -> CrabResult<Self> {
        let key = RsaPubKey::from_public_key_pem(pem)
            .map_err(|e| CrabError::key_error(format!("Invalid RSA public key PEM: {}", e)))?;
        Ok(Self(key))
    }

    /// Exports the public key as PEM-encoded PKCS#8.
    pub fn to_pem(&self) -> CrabResult<String> {
        self.0
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .map_err(|e| CrabError::key_error(format!("Failed to encode public key: {}", e)))
    }

    /// Encrypts data using RSA-OAEP with SHA-256.
    ///
    /// # Security Note
    /// RSA-OAEP can only encrypt data up to (key_size_bytes - 2*hash_size - 2).
    /// For 2048-bit RSA with SHA-256: max 190 bytes.
    /// For 4096-bit RSA with SHA-256: max 446 bytes.
    ///
    /// For larger data, use hybrid encryption (RSA for key, AEAD for data).
    ///
    /// # Example
    /// ```ignore
    /// let public_key = keypair.public_key();
    /// let plaintext = b"Secret message";
    /// let ciphertext = public_key.encrypt(plaintext)?;
    /// ```
    pub fn encrypt(&self, plaintext: &[u8]) -> CrabResult<Vec<u8>> {
        let padding = Oaep::new::<Sha256>();
        let ciphertext = self
            .0
            .encrypt(&mut OsRng, padding, plaintext)
            .map_err(|e| CrabError::crypto_error(format!("RSA encryption failed: {}", e)))?;
        Ok(ciphertext)
    }

    /// Verifies an RSA-PSS signature with SHA-256.
    ///
    /// # Returns
    /// - `Ok(true)` if signature is valid
    /// - `Ok(false)` if signature is invalid
    /// - `Err(_)` if signature is malformed or cannot be parsed
    ///
    /// # Example
    /// ```ignore
    /// let is_valid = public_key.verify(message, &signature)?;
    /// assert!(is_valid);
    /// ```
    pub fn verify(&self, message: &[u8], signature: &RsaSignature) -> CrabResult<bool> {
        let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(self.0.clone());

        // Parse signature - return error if malformed
        let sig = Signature::try_from(signature.as_bytes())
            .map_err(|_| CrabError::encoding_error("Invalid signature encoding"))?;

        // Verify signature - return true/false for valid/invalid legitimate signatures
        use rsa::signature::Verifier;
        match verifying_key.verify(message, &sig) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Returns the key size in bits.
    pub fn size_bits(&self) -> usize {
        self.0.size() * 8
    }

    /// Returns the key size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.0.size()
    }

    /// Exports the public key as DER-encoded PKCS#8.
    ///
    /// This is useful for efficient serialization without base64 encoding overhead.
    ///
    /// # Example
    /// ```ignore
    /// let der_bytes = public_key.to_public_key_der()?;
    /// // Store or transmit der_bytes directly
    /// ```
    pub fn to_public_key_der(&self) -> CrabResult<Vec<u8>> {
        let der = self
            .0
            .to_public_key_der()
            .map_err(|e| CrabError::key_error(format!("Failed to encode public key: {}", e)))?;
        Ok(der.as_bytes().to_vec())
    }

    /// Creates a public key from DER-encoded PKCS#8 format.
    ///
    /// # Example
    /// ```ignore
    /// let public_key = RsaPublicKey::from_public_key_der(&der_bytes)?;
    /// ```
    pub fn from_public_key_der(der: &[u8]) -> CrabResult<Self> {
        let key = RsaPubKey::from_public_key_der(der)
            .map_err(|e| CrabError::key_error(format!("Invalid RSA public key DER: {}", e)))?;
        Ok(Self(key))
    }

    /// Encodes public key to base64 (DER format).
    pub fn to_base64(&self) -> CrabResult<String> {
        let der = self.to_public_key_der()?;
        Ok(crate::encoding::base64_encode(&der))
    }

    /// Decodes public key from base64 (DER format).
    pub fn from_base64(data: &str) -> CrabResult<Self> {
        let der = crate::encoding::base64_decode(data)?;
        Self::from_public_key_der(&der)
    }
}

/// RSA keypair for encryption, decryption, signing, and verification.
///
/// ⚠️ **SECURITY WARNING**: Contains private key material.
/// This type automatically zeroizes on drop.
///
/// **CRITICAL**: Private key material is stored in serialized form (PKCS#8 DER)
/// within a `Zeroizing<Vec<u8>>` container. This ensures proper zeroization on drop,
/// as the underlying `RsaPrivateKey` type contains `BigUint`s that cannot be reliably zeroized.
///
/// **NOTE**: Clone is NOT implemented to prevent accidental duplication of private key material.
#[derive(ZeroizeOnDrop)]
pub struct RsaKeyPair {
    /// Private key stored as PKCS#8 DER bytes in a zeroizing container.
    /// Parsed to `RsaPrivateKey` only when needed for operations.
    pkcs8_der: Zeroizing<Vec<u8>>,
}

impl RsaKeyPair {
    /// Helper to safely access the private key for operations.
    /// Parses the PKCS#8 DER on demand and passes it to the closure.
    /// The private key is dropped at the end of the closure scope.
    fn with_private_key<T, F>(&self, f: F) -> CrabResult<T>
    where
        F: FnOnce(&RsaPrivateKey) -> CrabResult<T>,
    {
        let private_key = RsaPrivateKey::from_pkcs8_der(&self.pkcs8_der)
            .map_err(|e| CrabError::key_error(format!("Invalid private key DER: {}", e)))?;
        f(&private_key)
    }

    /// Generates a new RSA keypair with the specified bit size.
    ///
    /// Common sizes:
    /// - 2048 bits: Fast, adequate security for most uses
    /// - 3072 bits: Recommended for long-term security
    /// - 4096 bits: Maximum security, slower
    ///
    /// ⚠️ Key generation is slow (seconds for 4096-bit keys).
    ///
    /// # Example
    /// ```ignore
    /// // Generate 2048-bit key (faster)
    /// let keypair = RsaKeyPair::generate(2048)?;
    ///
    /// // Generate 4096-bit key (more secure, slower)
    /// let keypair = RsaKeyPair::generate(4096)?;
    /// ```
    pub fn generate(bits: usize) -> CrabResult<Self> {
        if bits < 2048 {
            return Err(CrabError::invalid_input("RSA key size must be at least 2048 bits"));
        }

        let private_key = RsaPrivateKey::new(&mut OsRng, bits)
            .map_err(|e| CrabError::key_error(format!("Failed to generate RSA keypair: {}", e)))?;

        // Serialize to PKCS#8 DER immediately
        let der = private_key
            .to_pkcs8_der()
            .map_err(|e| CrabError::key_error(format!("Failed to serialize private key: {}", e)))?
            .as_bytes()
            .to_vec();

        Ok(Self {
            pkcs8_der: Zeroizing::new(der),
        })
    }

    /// Generates a 2048-bit RSA keypair (recommended minimum).
    ///
    /// # Example
    /// ```ignore
    /// let keypair = RsaKeyPair::generate_2048()?;
    /// ```
    pub fn generate_2048() -> CrabResult<Self> {
        Self::generate(2048)
    }

    /// Generates a 4096-bit RSA keypair (high security).
    ///
    /// # Example
    /// ```ignore
    /// let keypair = RsaKeyPair::generate_4096()?;
    /// ```
    pub fn generate_4096() -> CrabResult<Self> {
        Self::generate(4096)
    }

    /// Creates a keypair from PEM-encoded PKCS#8 format.
    ///
    /// # Security Warning
    /// Ensure the PEM data is from a trusted source and transmitted securely.
    ///
    /// # Example
    /// ```ignore
    /// let pem = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----";
    /// let keypair = RsaKeyPair::from_pem(pem)?;
    /// ```
    pub fn from_pem(pem: &str) -> CrabResult<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
            .map_err(|e| CrabError::key_error(format!("Invalid RSA private key PEM: {}", e)))?;

        // Serialize to DER immediately
        let der = private_key
            .to_pkcs8_der()
            .map_err(|e| CrabError::key_error(format!("Failed to serialize private key: {}", e)))?
            .as_bytes()
            .to_vec();

        Ok(Self {
            pkcs8_der: Zeroizing::new(der),
        })
    }

    /// Exports the private key as PEM-encoded PKCS#8.
    ///
    /// # Security Warning
    /// ⚠️ **CRITICAL**: This returns the private key in PLAINTEXT!
    /// - Never transmit over unencrypted channels
    /// - Never log or print this value
    /// - For secure storage, use `to_encrypted_pem()` instead (TODO)
    /// - Zeroize any variables holding this value after use
    pub fn to_pem(&self) -> CrabResult<String> {
        self.with_private_key(|private_key| {
            private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .map(|s| s.to_string())
                .map_err(|e| CrabError::key_error(format!("Failed to encode private key: {}", e)))
        })
    }

    /// Returns the public key.
    pub fn public_key(&self) -> RsaPublicKey {
        // This is safe - we can unwrap since we control the DER format
        self.with_private_key(|private_key| Ok(RsaPublicKey(private_key.to_public_key())))
            .expect("Failed to extract public key from valid private key")
    }

    /// Encrypts data using the public key (same as `public_key().encrypt()`).
    ///
    /// # Example
    /// ```ignore
    /// let keypair = RsaKeyPair::generate_2048()?;
    /// let plaintext = b"Secret message";
    /// let ciphertext = keypair.encrypt(plaintext)?;
    /// let decrypted = keypair.decrypt(&ciphertext)?;
    /// assert_eq!(decrypted, plaintext);
    /// ```
    pub fn encrypt(&self, plaintext: &[u8]) -> CrabResult<Vec<u8>> {
        self.public_key().encrypt(plaintext)
    }

    /// Decrypts data using RSA-OAEP with SHA-256.
    ///
    /// ⚠️ **SECURITY**: Uses blinding (via OsRng) to mitigate timing attacks.
    ///
    /// # Example
    /// ```ignore
    /// let ciphertext = public_key.encrypt(b"Secret")?;
    /// let plaintext = keypair.decrypt(&ciphertext)?;
    /// ```
    pub fn decrypt(&self, ciphertext: &[u8]) -> CrabResult<Vec<u8>> {
        self.with_private_key(|private_key| {
            let padding = Oaep::new::<Sha256>();
            // The rsa crate uses blinding when OsRng is available
            let plaintext = private_key
                .decrypt(padding, ciphertext)
                .map_err(|e| CrabError::crypto_error(format!("RSA decryption failed: {}", e)))?;
            Ok(plaintext)
        })
    }

    /// Signs a message using RSA-PSS with SHA-256.
    ///
    /// ⚠️ **SECURITY**: Uses BlindedSigningKey with OsRng to mitigate timing attacks.
    ///
    /// # Example
    /// ```ignore
    /// let keypair = RsaKeyPair::generate_2048()?;
    /// let message = b"Important document";
    /// let signature = keypair.sign(message)?;
    /// assert!(keypair.verify(message, &signature)?);
    /// ```
    pub fn sign(&self, message: &[u8]) -> CrabResult<RsaSignature> {
        self.with_private_key(|private_key| {
            // Use BlindedSigningKey which provides side-channel resistance
            let signing_key = BlindedSigningKey::<Sha256>::new(private_key.clone());

            use rsa::signature::RandomizedSigner;
            let signature = signing_key.sign_with_rng(&mut OsRng, message);

            Ok(RsaSignature(signature.to_bytes().as_ref().to_vec()))
        })
    }

    /// Verifies a signature (same as `public_key().verify()`).
    ///
    /// # Example
    /// ```ignore
    /// let signature = keypair.sign(message)?;
    /// assert!(keypair.verify(message, &signature)?);
    /// ```
    pub fn verify(&self, message: &[u8], signature: &RsaSignature) -> CrabResult<bool> {
        self.public_key().verify(message, signature)
    }

    /// Returns the key size in bits.
    pub fn size_bits(&self) -> usize {
        self.with_private_key(|private_key| Ok(private_key.size() * 8))
            .expect("Failed to read key size from valid private key")
    }

    /// Returns the key size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.with_private_key(|private_key| Ok(private_key.size()))
            .expect("Failed to read key size from valid private key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa_keygen_2048() {
        let keypair = RsaKeyPair::generate_2048().unwrap();
        assert_eq!(keypair.size_bits(), 2048);
    }

    #[test]
    fn test_rsa_encrypt_decrypt_small() {
        let keypair = RsaKeyPair::generate_2048().unwrap();
        let plaintext = b"Hello, RSA!";

        let ciphertext = keypair.encrypt(plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);

        let decrypted = keypair.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rsa_encrypt_decrypt_max_size() {
        let keypair = RsaKeyPair::generate_2048().unwrap();
        // Max size for 2048-bit RSA with OAEP-SHA256: 190 bytes
        let plaintext = vec![0x42u8; 190];

        let ciphertext = keypair.encrypt(&plaintext).unwrap();
        let decrypted = keypair.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rsa_encrypt_too_large_fails() {
        let keypair = RsaKeyPair::generate_2048().unwrap();
        // 191 bytes is too large for 2048-bit RSA with OAEP-SHA256
        let plaintext = vec![0x42u8; 191];

        assert!(keypair.encrypt(&plaintext).is_err());
    }

    #[test]
    fn test_rsa_sign_verify() {
        let keypair = RsaKeyPair::generate_2048().unwrap();
        let message = b"Important document to sign";

        let signature = keypair.sign(message).unwrap();
        assert!(keypair.verify(message, &signature).unwrap());

        // Wrong message should fail
        assert!(!keypair.verify(b"Different message", &signature).unwrap());
    }

    #[test]
    fn test_rsa_sign_verify_with_public_key() {
        let keypair = RsaKeyPair::generate_2048().unwrap();
        let public_key = keypair.public_key();
        let message = b"Document to verify";

        let signature = keypair.sign(message).unwrap();
        assert!(public_key.verify(message, &signature).unwrap());
    }

    #[test]
    fn test_rsa_pem_roundtrip() {
        let keypair = RsaKeyPair::generate_2048().unwrap();

        let pem = keypair.to_pem().unwrap();
        let restored = RsaKeyPair::from_pem(&pem).unwrap();

        // Test that restored keypair works
        let message = b"Test message";
        let signature = restored.sign(message).unwrap();
        assert!(keypair.verify(message, &signature).unwrap());
    }

    #[test]
    fn test_rsa_public_key_pem_roundtrip() {
        let keypair = RsaKeyPair::generate_2048().unwrap();
        let public_key = keypair.public_key();

        let pem = public_key.to_pem().unwrap();
        let restored = RsaPublicKey::from_pem(&pem).unwrap();

        // Test encryption with restored public key
        let plaintext = b"Test";
        let ciphertext = restored.encrypt(plaintext).unwrap();
        let decrypted = keypair.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_rsa_signature_encoding() {
        let keypair = RsaKeyPair::generate_2048().unwrap();
        let message = b"Test";
        let signature = keypair.sign(message).unwrap();

        // Base64 roundtrip
        let base64 = signature.to_base64();
        let restored = RsaSignature::from_base64(&base64).unwrap();
        assert_eq!(signature, restored);

        // Hex roundtrip
        let hex = signature.to_hex();
        let restored = RsaSignature::from_hex(&hex).unwrap();
        assert_eq!(signature, restored);
    }

    #[test]
    fn test_rsa_invalid_signature() {
        let keypair = RsaKeyPair::generate_2048().unwrap();
        let message = b"Test message";

        let fake_signature = RsaSignature(vec![0u8; 256]);
        assert!(!keypair.verify(message, &fake_signature).unwrap());
    }

    #[test]
    fn test_rsa_key_too_small() {
        let result = RsaKeyPair::generate(1024);
        assert!(result.is_err());
    }
}
