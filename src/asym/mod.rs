//! Asymmetric cryptography (public-key cryptography).
//!
//! This module provides digital signatures and key exchange.

pub mod ed25519;
pub mod x25519;

#[cfg(feature = "rsa-support")]
pub mod rsa;

pub use ed25519::{Ed25519KeyPair, Ed25519PublicKey, Ed25519Signature};
pub use x25519::{X25519KeyPair, X25519PublicKey, X25519SharedSecret};

#[cfg(feature = "rsa-support")]
pub use rsa::{RsaKeyPair, RsaPublicKey, RsaSignature};
