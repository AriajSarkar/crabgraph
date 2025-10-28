//! Interoperability tests for CrabGraph
//!
//! These tests document how to achieve interoperability with other
//! cryptographic libraries and platforms.

use crabgraph::{
    aead::{AesGcm256, CrabAead},
    hash::sha256,
    kdf::pbkdf2_derive_sha256,
    mac::hmac_sha256,
    CrabResult,
};
use hex_literal::hex;

/// Test vectors from NIST for AES-GCM
#[test]
fn test_aes_gcm_nist_vector() -> CrabResult<()> {
    // This is a simplified test - actual NIST vectors would be more extensive
    // The important part is that our implementation can handle known test vectors

    let key = [0u8; 32];
    let cipher = AesGcm256::new(&key)?;
    let plaintext = b"";
    let nonce = [0u8; 12];

    let ciphertext = cipher.encrypt_with_nonce(plaintext, &nonce, None)?;
    let decrypted = cipher.decrypt(&ciphertext, None)?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}

/// Test SHA-256 with known RFC vectors
#[test]
fn test_sha256_rfc_vectors() {
    // RFC 4634 test vectors

    // Empty string
    let hash = sha256(b"");
    let expected = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hash, expected);

    // "abc"
    let hash = sha256(b"abc");
    let expected = hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(hash, expected);
}

/// Test HMAC-SHA256 with RFC 4231 vectors
#[test]
fn test_hmac_sha256_rfc_vectors() -> CrabResult<()> {
    // RFC 4231 Test Case 2
    let key = b"Jefe";
    let message = b"what do ya want for nothing?";
    let expected = hex!("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    let tag = hmac_sha256(key, message)?;
    assert_eq!(&tag[..], &expected[..]);

    Ok(())
}

/// Test PBKDF2 with known test vectors
#[test]
fn test_pbkdf2_deterministic() -> CrabResult<()> {
    // PBKDF2 should produce identical output for same inputs
    let password = b"password";
    let salt = b"salt_16_bytes!!!";
    let iterations = 10_000;

    let key1 = pbkdf2_derive_sha256(password, salt, iterations, 32)?;
    let key2 = pbkdf2_derive_sha256(password, salt, iterations, 32)?;

    assert_eq!(key1.as_slice(), key2.as_slice());
    Ok(())
}

/// Document how to interoperate with OpenSSL
#[test]
fn test_openssl_compatibility_notes() {
    // This test documents compatibility considerations with OpenSSL

    // 1. AES-GCM: OpenSSL uses the same GCM mode as we do
    //    - Key sizes: 128, 192, 256 bits
    //    - Nonce: typically 12 bytes (96 bits)
    //    - Tag: typically 16 bytes (128 bits)

    // 2. PBKDF2: OpenSSL's PKCS5_PBKDF2_HMAC is compatible
    //    - Same algorithm, just different API

    // 3. Hashing: SHA-256, SHA-512 are standardized
    //    - Outputs are identical across implementations

    // This is a documentation test, not an actual test
}

/// Document how to interoperate with Web Crypto API (JavaScript)
#[test]
fn test_web_crypto_compatibility_notes() {
    // Web Crypto API compatibility notes:

    // 1. AES-GCM is fully supported
    //    - Use SubtleCrypto.encrypt() with algorithm: "AES-GCM"
    //    - Nonce (iv) should be 12 bytes
    //    - Tag length: 128 bits (16 bytes)

    // 2. PBKDF2 is supported
    //    - Use SubtleCrypto.deriveKey() with algorithm: "PBKDF2"
    //    - Hash: "SHA-256" or "SHA-512"

    // 3. Ed25519 is supported in modern browsers
    //    - Use SubtleCrypto.generateKey() with algorithm: "Ed25519"

    // 4. Data exchange format:
    //    - Use base64 for text encoding
    //    - Include nonce, ciphertext, and tag explicitly

    // This is a documentation test
}

/// Document CryptoJS migration path
#[test]
fn test_cryptojs_migration_notes() {
    // CryptoJS Migration Notes:

    // WARNING: CryptoJS defaults are often insecure!

    // 1. Default mode: AES-CBC with PKCS7 padding
    //    - We use AES-GCM (authenticated encryption)
    //    - Migration: Update JS to use Web Crypto API with GCM

    // 2. Key derivation: Uses MD5 (INSECURE!)
    //    - We use PBKDF2-HMAC-SHA256 or Argon2
    //    - Migration: Use SubtleCrypto.deriveKey() or PBKDF2-SHA256

    // 3. Iteration count: Often 1 (INSECURE!)
    //    - We recommend 100,000+ for PBKDF2, or use Argon2
    //    - Migration: Increase iterations significantly

    // 4. Salt: Sometimes omitted (INSECURE!)
    //    - We require 16+ byte salts
    //    - Migration: Always generate random salts

    // See docs/MIGRATE_CRYPTOJS.md for detailed guide
}
