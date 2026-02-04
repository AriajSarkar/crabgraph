//! Key exchange implementations for TLS.
//!
//! This module provides key exchange groups for TLS 1.2 and TLS 1.3:
//! - X25519 (Curve25519 ECDH)
//! - SECP256R1 (P-256 ECDH)
//! - SECP384R1 (P-384 ECDH)

use rustls::crypto::{ActiveKeyExchange, CompletedKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::NamedGroup;

/// All supported key exchange groups, in order of preference.
pub static ALL_KX_GROUPS: &[&dyn SupportedKxGroup] = &[&X25519, &Secp256r1, &Secp384r1];

// ============================================================================
// X25519 Key Exchange
// ============================================================================

/// X25519 key exchange group (Curve25519).
///
/// This is the most efficient ECDH group and is preferred for TLS 1.3.
#[derive(Debug)]
pub struct X25519;

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let rng = rand_core::OsRng;
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(rng);
        let public = x25519_dalek::PublicKey::from(&secret);

        Ok(Box::new(X25519KeyExchange {
            secret,
            pub_key: public.as_bytes().to_vec(),
        }))
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<CompletedKeyExchange, rustls::Error> {
        let active = self.start()?;
        let pub_key = active.pub_key().to_vec();
        let secret = active.complete(peer_pub_key)?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key,
            secret,
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

struct X25519KeyExchange {
    secret: x25519_dalek::EphemeralSecret,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for X25519KeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer_key: [u8; 32] = peer_pub_key.try_into().map_err(|_| {
            rustls::Error::General("X25519 peer key must be 32 bytes".into())
        })?;

        let peer_public = x25519_dalek::PublicKey::from(peer_key);
        let shared = self.secret.diffie_hellman(&peer_public);

        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

// ============================================================================
// SECP256R1 (P-256) Key Exchange
// ============================================================================

/// NIST P-256 key exchange group (secp256r1).
#[derive(Debug)]
pub struct Secp256r1;

impl SupportedKxGroup for Secp256r1 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;

        let mut rng = rand_core::OsRng;
        let secret = p256::ecdh::EphemeralSecret::random(&mut rng);
        let public = secret.public_key();

        // Encode public key in uncompressed SEC1 format (65 bytes: 0x04 || x || y)
        let pub_bytes = public.to_encoded_point(false);

        Ok(Box::new(P256KeyExchange {
            secret,
            pub_key: pub_bytes.as_bytes().to_vec(),
        }))
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<CompletedKeyExchange, rustls::Error> {
        let active = self.start()?;
        let pub_key = active.pub_key().to_vec();
        let secret = active.complete(peer_pub_key)?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key,
            secret,
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

struct P256KeyExchange {
    secret: p256::ecdh::EphemeralSecret,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for P256KeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        use p256::elliptic_curve::sec1::FromEncodedPoint;

        let encoded =
            p256::EncodedPoint::from_bytes(peer_pub_key).map_err(|_| {
                rustls::Error::General("invalid P-256 public key encoding".into())
            })?;

        let peer_public = p256::PublicKey::from_encoded_point(&encoded);
        let peer_public = Option::from(peer_public).ok_or_else(|| {
            rustls::Error::General("invalid P-256 public key".into())
        })?;

        let shared = self.secret.diffie_hellman(&peer_public);
        let raw_bytes = shared.raw_secret_bytes();

        Ok(SharedSecret::from(raw_bytes.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

// ============================================================================
// SECP384R1 (P-384) Key Exchange
// ============================================================================

/// NIST P-384 key exchange group (secp384r1).
#[derive(Debug)]
pub struct Secp384r1;

impl SupportedKxGroup for Secp384r1 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        use p384::elliptic_curve::sec1::ToEncodedPoint;

        let mut rng = rand_core::OsRng;
        let secret = p384::ecdh::EphemeralSecret::random(&mut rng);
        let public = secret.public_key();

        // Encode public key in uncompressed SEC1 format (97 bytes: 0x04 || x || y)
        let pub_bytes = public.to_encoded_point(false);

        Ok(Box::new(P384KeyExchange {
            secret,
            pub_key: pub_bytes.as_bytes().to_vec(),
        }))
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<CompletedKeyExchange, rustls::Error> {
        let active = self.start()?;
        let pub_key = active.pub_key().to_vec();
        let secret = active.complete(peer_pub_key)?;

        Ok(CompletedKeyExchange {
            group: self.name(),
            pub_key,
            secret,
        })
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }
}

struct P384KeyExchange {
    secret: p384::ecdh::EphemeralSecret,
    pub_key: Vec<u8>,
}

impl ActiveKeyExchange for P384KeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        use p384::elliptic_curve::sec1::FromEncodedPoint;

        let encoded =
            p384::EncodedPoint::from_bytes(peer_pub_key).map_err(|_| {
                rustls::Error::General("invalid P-384 public key encoding".into())
            })?;

        let peer_public = p384::PublicKey::from_encoded_point(&encoded);
        let peer_public = Option::from(peer_public).ok_or_else(|| {
            rustls::Error::General("invalid P-384 public key".into())
        })?;

        let shared = self.secret.diffie_hellman(&peer_public);
        let raw_bytes = shared.raw_secret_bytes();

        Ok(SharedSecret::from(raw_bytes.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp384r1
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_key_exchange() {
        // Simulate a key exchange between two parties
        let alice = X25519.start().expect("Alice should start");
        let bob = X25519.start().expect("Bob should start");

        let alice_pub = alice.pub_key().to_vec();
        let bob_pub = bob.pub_key().to_vec();

        // Exchange
        let alice_secret = alice.complete(&bob_pub).expect("Alice should complete");
        let bob_secret = bob.complete(&alice_pub).expect("Bob should complete");

        // Shared secrets must match
        assert_eq!(alice_secret.secret_bytes(), bob_secret.secret_bytes());
    }

    #[test]
    fn test_x25519_start_and_complete() {
        let alice = X25519.start().expect("Alice should start");
        let alice_pub = alice.pub_key().to_vec();

        let bob_completed = X25519.start_and_complete(&alice_pub).expect("Bob should complete");

        let alice_secret = alice.complete(&bob_completed.pub_key).expect("Alice should complete");

        assert_eq!(
            alice_secret.secret_bytes(),
            bob_completed.secret.secret_bytes()
        );
        assert_eq!(bob_completed.group, NamedGroup::X25519);
    }

    #[test]
    fn test_p256_key_exchange() {
        let alice = Secp256r1.start().expect("Alice should start");
        let bob = Secp256r1.start().expect("Bob should start");

        let alice_pub = alice.pub_key().to_vec();
        let bob_pub = bob.pub_key().to_vec();

        // P-256 public keys should be 65 bytes (uncompressed)
        assert_eq!(alice_pub.len(), 65);
        assert_eq!(bob_pub.len(), 65);
        assert_eq!(alice_pub[0], 0x04); // Uncompressed point indicator
        assert_eq!(bob_pub[0], 0x04);

        let alice_secret = alice.complete(&bob_pub).expect("Alice should complete");
        let bob_secret = bob.complete(&alice_pub).expect("Bob should complete");

        assert_eq!(alice_secret.secret_bytes(), bob_secret.secret_bytes());
    }

    #[test]
    fn test_p384_key_exchange() {
        let alice = Secp384r1.start().expect("Alice should start");
        let bob = Secp384r1.start().expect("Bob should start");

        let alice_pub = alice.pub_key().to_vec();
        let bob_pub = bob.pub_key().to_vec();

        // P-384 public keys should be 97 bytes (uncompressed)
        assert_eq!(alice_pub.len(), 97);
        assert_eq!(bob_pub.len(), 97);
        assert_eq!(alice_pub[0], 0x04);
        assert_eq!(bob_pub[0], 0x04);

        let alice_secret = alice.complete(&bob_pub).expect("Alice should complete");
        let bob_secret = bob.complete(&alice_pub).expect("Bob should complete");

        assert_eq!(alice_secret.secret_bytes(), bob_secret.secret_bytes());
    }

    #[test]
    fn test_invalid_x25519_key_length() {
        let alice = X25519.start().expect("Should start");
        let invalid_key = vec![0u8; 31]; // Should be 32 bytes
        let result = alice.complete(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_p256_key() {
        let alice = Secp256r1.start().expect("Should start");
        let invalid_key = vec![0u8; 10];
        let result = alice.complete(&invalid_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_group_names() {
        assert_eq!(X25519.name(), NamedGroup::X25519);
        assert_eq!(Secp256r1.name(), NamedGroup::secp256r1);
        assert_eq!(Secp384r1.name(), NamedGroup::secp384r1);
    }

    #[test]
    fn test_no_ffdhe() {
        // These are all ECDH groups, not finite field DH
        assert!(X25519.ffdhe_group().is_none());
        assert!(Secp256r1.ffdhe_group().is_none());
        assert!(Secp384r1.ffdhe_group().is_none());
    }
}
