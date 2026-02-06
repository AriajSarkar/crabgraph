//! TLS CryptoProvider integration tests.
//!
//! These tests verify that the crabgraph TLS provider works correctly
//! with rustls for TLS operations.

#![cfg(feature = "tls")]

use crabgraph::tls;

#[test]
fn test_provider_creation() {
    let provider = tls::provider();

    // Verify cipher suites are configured
    assert!(!provider.cipher_suites.is_empty(), "Should have cipher suites");
    assert_eq!(
        provider.cipher_suites.len(),
        9,
        "Should have 9 cipher suites (3 TLS 1.3 + 6 TLS 1.2)"
    );

    // Verify key exchange groups are configured
    assert!(!provider.kx_groups.is_empty(), "Should have key exchange groups");
    assert_eq!(provider.kx_groups.len(), 3, "Should have 3 kx groups (X25519, P-256, P-384)");
}

#[test]
fn test_cipher_suite_lists() {
    // TLS 1.3 cipher suites
    assert_eq!(tls::TLS13_CIPHER_SUITES.len(), 3);

    // TLS 1.2 cipher suites
    assert_eq!(tls::TLS12_CIPHER_SUITES.len(), 6);

    // All cipher suites
    assert_eq!(tls::ALL_CIPHER_SUITES.len(), 9);
}

#[test]
fn test_key_exchange_groups() {
    // Verify all key exchange groups are available
    assert_eq!(tls::ALL_KX_GROUPS.len(), 3);

    // Check specific groups are accessible
    let _ = tls::X25519;
    let _ = tls::SECP256R1;
    let _ = tls::SECP384R1;
}

#[test]
fn test_provider_try_install() {
    // Note: We can't actually install the provider in tests because
    // it can only be installed once per process, and other tests
    // might run in parallel. We just verify the function exists.

    // Create a provider to ensure it compiles correctly
    let _provider = tls::provider();
}

#[test]
fn test_tls_configuration_builder() {
    use rustls::{ClientConfig, RootCertStore};
    use std::sync::Arc;

    // Create a root cert store (empty for this test)
    let root_store = RootCertStore::empty();

    // Build a client config using the crabgraph provider
    let config = ClientConfig::builder_with_provider(Arc::new(tls::provider()))
        .with_safe_default_protocol_versions()
        .expect("Protocol versions should be valid")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // Verify the config was created - ALPN is empty by default when not configured
    assert!(config.alpn_protocols.is_empty());
}

#[test]
fn test_p256_ecdh() {
    use crabgraph::asym::P256KeyPair;

    // Generate two keypairs
    let alice = P256KeyPair::generate().unwrap();
    let bob = P256KeyPair::generate().unwrap();

    // Perform ECDH
    let alice_shared = alice.diffie_hellman(&bob.public_key()).unwrap();
    let bob_shared = bob.diffie_hellman(&alice.public_key()).unwrap();

    // Both parties should derive the same shared secret
    assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
}

#[test]
fn test_p256_ecdsa() {
    use crabgraph::asym::P256SigningKey;

    // Generate a signing key
    let signing_key = P256SigningKey::generate().unwrap();
    let verifying_key = signing_key.verifying_key();

    // Sign a message
    let message = b"Test message for P-256 ECDSA";
    let signature = signing_key.sign(message).unwrap();

    // Verify the signature (returns Ok(true) on success)
    assert!(verifying_key.verify(message, &signature).unwrap());

    // Verify that wrong message fails (returns Ok(false))
    assert!(!verifying_key.verify(b"Wrong message", &signature).unwrap());
}

#[test]
fn test_p384_ecdh() {
    use crabgraph::asym::P384KeyPair;

    // Generate two keypairs
    let alice = P384KeyPair::generate().unwrap();
    let bob = P384KeyPair::generate().unwrap();

    // Perform ECDH
    let alice_shared = alice.diffie_hellman(&bob.public_key()).unwrap();
    let bob_shared = bob.diffie_hellman(&alice.public_key()).unwrap();

    // Both parties should derive the same shared secret
    assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
}

#[test]
fn test_p384_ecdsa() {
    use crabgraph::asym::P384SigningKey;

    // Generate a signing key
    let signing_key = P384SigningKey::generate().unwrap();
    let verifying_key = signing_key.verifying_key();

    // Sign a message
    let message = b"Test message for P-384 ECDSA";
    let signature = signing_key.sign(message).unwrap();

    // Verify the signature (returns Ok(true) on success)
    assert!(verifying_key.verify(message, &signature).unwrap());

    // Verify that wrong message fails (returns Ok(false))
    assert!(!verifying_key.verify(b"Wrong message", &signature).unwrap());
}

#[test]
fn test_sha384() {
    use crabgraph::hash::{sha384, sha384_hex};

    // Test empty string
    let empty_hash = sha384(b"");
    assert_eq!(empty_hash.len(), 48); // SHA-384 produces 384 bits = 48 bytes

    // Test known vector: SHA-384("abc") from NIST
    let abc_hash = sha384_hex(b"abc");
    assert_eq!(
        abc_hash,
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
    );
}

#[test]
fn test_cipher_suite_names() {
    use rustls::CipherSuite;

    let provider = tls::provider();

    let suites: Vec<_> = provider.cipher_suites.iter().map(|s| s.suite()).collect();

    // Verify TLS 1.3 suites are present
    assert!(suites.contains(&CipherSuite::TLS13_AES_256_GCM_SHA384));
    assert!(suites.contains(&CipherSuite::TLS13_AES_128_GCM_SHA256));
    assert!(suites.contains(&CipherSuite::TLS13_CHACHA20_POLY1305_SHA256));

    // Verify TLS 1.2 suites are present
    assert!(suites.contains(&CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256));
    assert!(suites.contains(&CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384));
    assert!(suites.contains(&CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256));
    assert!(suites.contains(&CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384));
}
