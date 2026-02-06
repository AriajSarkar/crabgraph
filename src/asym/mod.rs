//! Asymmetric cryptography (public-key cryptography).
//!
//! This module provides digital signatures and key exchange.

pub mod ed25519;
pub mod x25519;

#[cfg(feature = "rsa-support")]
pub mod rsa;

#[cfg(feature = "tls")]
pub mod p256;

#[cfg(feature = "tls")]
pub mod p384;

pub use ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};
pub use x25519::{X25519KeyPair, X25519PublicKey, X25519SharedSecret};

#[cfg(feature = "rsa-support")]
pub use rsa::{RsaKeyPair, RsaPublicKey, RsaSignature};

#[cfg(feature = "tls")]
pub use p256::{
    P256KeyPair, P256PublicKey, P256SharedSecret, P256Signature, P256SigningKey, P256VerifyingKey,
};

#[cfg(feature = "tls")]
pub use p384::{
    P384KeyPair, P384PublicKey, P384SharedSecret, P384Signature, P384SigningKey, P384VerifyingKey,
};
