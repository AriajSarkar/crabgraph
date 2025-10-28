//! X25519 Diffie-Hellman key exchange.
//!
//! X25519 is a fast, secure key exchange protocol built on Curve25519.
//! It's used to establish shared secrets for encryption.

use crate::errors::{CrabError, CrabResult};
use crate::secrets::SecretVec;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

const X25519_KEY_SIZE: usize = 32;

/// X25519 shared secret (32 bytes).
///
/// This is the output of the key exchange and should be used with a KDF
/// before using as an encryption key.
#[derive(Clone)]
pub struct X25519SharedSecret(SecretVec);

impl X25519SharedSecret {
    /// Creates a shared secret from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> CrabResult<Self> {
        if bytes.len() != X25519_KEY_SIZE {
            return Err(CrabError::invalid_input(format!(
                "X25519 shared secret must be {} bytes, got {}",
                X25519_KEY_SIZE,
                bytes.len()
            )));
        }
        Ok(Self(SecretVec::new(bytes)))
    }

    /// Returns shared secret as bytes.
    ///
    /// # Security Warning
    /// Do not use this directly as an encryption key! Use a KDF (HKDF) first.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Derives an encryption key from the shared secret using HKDF.
    ///
    /// This is the recommended way to convert a shared secret into a key.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// let alice = X25519KeyPair::generate().unwrap();
    /// let bob = X25519KeyPair::generate().unwrap();
    ///
    /// let shared = alice.diffie_hellman(&bob.public_key()).unwrap();
    /// let key = shared.derive_key(b"my_app_v1", 32).unwrap();
    /// assert_eq!(key.len(), 32);
    /// ```
    pub fn derive_key(&self, info: &[u8], key_len: usize) -> CrabResult<SecretVec> {
        crate::kdf::hkdf_extract_expand(&[], self.as_bytes(), info, key_len)
    }
}

impl std::fmt::Debug for X25519SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519SharedSecret([REDACTED])")
    }
}

/// X25519 public key (32 bytes).
#[derive(Clone, Debug, PartialEq)]
pub struct X25519PublicKey(PublicKey);

impl X25519PublicKey {
    /// Creates a public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> CrabResult<Self> {
        if bytes.len() != X25519_KEY_SIZE {
            return Err(CrabError::invalid_input(format!(
                "X25519 public key must be {} bytes, got {}",
                X25519_KEY_SIZE,
                bytes.len()
            )));
        }

        let mut key_bytes = [0u8; X25519_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(PublicKey::from(key_bytes)))
    }

    /// Returns public key as bytes.
    pub fn as_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        self.0.as_bytes()
    }

    /// Encodes public key to base64.
    pub fn to_base64(&self) -> String {
        crate::encoding::base64_encode(self.0.as_bytes())
    }

    /// Decodes public key from base64.
    pub fn from_base64(data: &str) -> CrabResult<Self> {
        let bytes = crate::encoding::base64_decode(data)?;
        Self::from_bytes(&bytes)
    }

    /// Encodes public key to hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }

    /// Decodes public key from hex.
    pub fn from_hex(data: &str) -> CrabResult<Self> {
        let bytes = hex::decode(data)?;
        Self::from_bytes(&bytes)
    }
}

/// X25519 keypair for Diffie-Hellman key exchange.
pub struct X25519KeyPair {
    secret: StaticSecret,
}

impl X25519KeyPair {
    /// Generates a new random X25519 keypair.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// ```
    pub fn generate() -> CrabResult<Self> {
        let secret = StaticSecret::random_from_rng(OsRng);
        Ok(Self { secret })
    }

    /// Creates a keypair from a 32-byte secret key.
    ///
    /// # Security Warning
    /// The secret key must be kept confidential and zeroized after use.
    pub fn from_secret_bytes(secret: &[u8]) -> CrabResult<Self> {
        if secret.len() != X25519_KEY_SIZE {
            return Err(CrabError::invalid_input(format!(
                "X25519 secret key must be {} bytes, got {}",
                X25519_KEY_SIZE,
                secret.len()
            )));
        }

        let mut key_bytes = [0u8; X25519_KEY_SIZE];
        key_bytes.copy_from_slice(secret);
        let secret = StaticSecret::from(key_bytes);

        Ok(Self { secret })
    }

    /// Returns the secret key bytes.
    ///
    /// # Security Warning
    /// Handle with care! Zeroize after use.
    pub fn secret_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        self.secret.as_bytes()
    }

    /// Returns the public key.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(PublicKey::from(&self.secret))
    }

    /// Performs Diffie-Hellman key exchange with another party's public key.
    ///
    /// # Returns
    /// A shared secret that both parties can compute.
    ///
    /// # Security Notes
    /// - The shared secret should be passed through a KDF before use
    /// - Use `X25519SharedSecret::derive_key()` for this
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// // Alice and Bob generate keypairs
    /// let alice = X25519KeyPair::generate().unwrap();
    /// let bob = X25519KeyPair::generate().unwrap();
    ///
    /// // Exchange public keys and compute shared secret
    /// let alice_shared = alice.diffie_hellman(&bob.public_key()).unwrap();
    /// let bob_shared = bob.diffie_hellman(&alice.public_key()).unwrap();
    ///
    /// // Both should have the same shared secret
    /// assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    /// ```
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> CrabResult<X25519SharedSecret> {
        let shared = self.secret.diffie_hellman(&their_public.0);
        Ok(X25519SharedSecret(SecretVec::new(shared.as_bytes().to_vec())))
    }
}

impl std::fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_generate() {
        let keypair = X25519KeyPair::generate().unwrap();
        let _public_key = keypair.public_key();
        assert_eq!(keypair.secret_bytes().len(), 32);
    }

    #[test]
    fn test_x25519_dh_exchange() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let alice_shared = alice.diffie_hellman(&bob.public_key()).unwrap();
        let bob_shared = bob.diffie_hellman(&alice.public_key()).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_x25519_different_parties() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();
        let charlie = X25519KeyPair::generate().unwrap();

        let alice_bob = alice.diffie_hellman(&bob.public_key()).unwrap();
        let alice_charlie = alice.diffie_hellman(&charlie.public_key()).unwrap();

        // Different shared secrets with different parties
        assert_ne!(alice_bob.as_bytes(), alice_charlie.as_bytes());
    }

    #[test]
    fn test_x25519_from_secret_bytes() {
        let keypair1 = X25519KeyPair::generate().unwrap();
        let secret = keypair1.secret_bytes();

        let keypair2 = X25519KeyPair::from_secret_bytes(secret).unwrap();

        // Same secret should produce same public key
        assert_eq!(
            keypair1.public_key().as_bytes(),
            keypair2.public_key().as_bytes()
        );
    }

    #[test]
    fn test_x25519_public_key_serialization() {
        let keypair = X25519KeyPair::generate().unwrap();
        let public_key = keypair.public_key();

        // Base64
        let b64 = public_key.to_base64();
        let recovered = X25519PublicKey::from_base64(&b64).unwrap();
        assert_eq!(public_key.as_bytes(), recovered.as_bytes());

        // Hex
        let hex = public_key.to_hex();
        let recovered = X25519PublicKey::from_hex(&hex).unwrap();
        assert_eq!(public_key.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn test_x25519_derive_key() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let shared = alice.diffie_hellman(&bob.public_key()).unwrap();
        let key = shared.derive_key(b"test_app", 32).unwrap();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_x25519_derive_key_deterministic() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let shared = alice.diffie_hellman(&bob.public_key()).unwrap();
        let key1 = shared.derive_key(b"test_app", 32).unwrap();
        let key2 = shared.derive_key(b"test_app", 32).unwrap();

        assert_eq!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_x25519_derive_key_different_info() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let shared = alice.diffie_hellman(&bob.public_key()).unwrap();
        let key1 = shared.derive_key(b"app1", 32).unwrap();
        let key2 = shared.derive_key(b"app2", 32).unwrap();

        assert_ne!(key1.as_slice(), key2.as_slice());
    }
}
