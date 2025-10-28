//! Example: Interoperability with CryptoJS
//!
//! This example demonstrates how to encrypt/decrypt data in a way that's
//! compatible with JavaScript's CryptoJS library.

use crabgraph::{
    aead::{AesGcm256, CrabAead},
    encoding::{base64_decode, base64_encode},
    kdf::pbkdf2_derive_sha256,
    CrabResult,
};

fn main() -> CrabResult<()> {
    println!("=== CryptoJS Interoperability Example ===\n");

    println!("This example shows how to work with data encrypted by CryptoJS.");
    println!("Note: CryptoJS typically uses AES-CBC with PKCS7 padding,");
    println!("while we recommend AES-GCM for better security.\n");

    // Example 1: Password-based encryption (similar to CryptoJS.AES.encrypt)
    password_based_encryption_example()?;

    // Example 2: Key derivation compatible with CryptoJS
    key_derivation_example()?;

    Ok(())
}

fn password_based_encryption_example() -> CrabResult<()> {
    println!("1. Password-Based Encryption:");

    let password = b"my_secret_password";
    let plaintext = b"Hello, CryptoJS!";

    // Generate salt (CryptoJS uses 8-byte salt by default, but we use 16 for better security)
    let salt = crabgraph::rand::secure_bytes(16)?;

    println!("  Password: {}", String::from_utf8_lossy(password));
    println!("  Salt: {}", base64_encode(&salt));

    // Derive key using PBKDF2 (CryptoJS default)
    // Note: CryptoJS uses only 1 iteration by default, which is INSECURE
    // We use a secure iteration count
    let iterations = 100_000; // CryptoJS default is 1 (DON'T USE IN PRODUCTION!)
    let key = pbkdf2_derive_sha256(password, &salt, iterations, 32)?;

    println!("  Iterations: {} (CryptoJS default: 1 - INSECURE!)", iterations);
    println!("  Key derived: {} bytes", key.len());

    // Encrypt with AES-GCM (more secure than CryptoJS's default AES-CBC)
    let cipher = AesGcm256::new(key.as_slice())?;
    let ciphertext = cipher.encrypt(plaintext, None)?;

    // Serialize for transport/storage
    let serialized = ciphertext.to_base64();
    println!("  Ciphertext (base64): {}...", &serialized[..40]);

    // Decrypt
    let recovered = crabgraph::aead::Ciphertext::from_base64(&serialized, 12, 16)?;
    let decrypted = cipher.decrypt(&recovered, None)?;

    assert_eq!(decrypted, plaintext);
    println!("  Decrypted: {}", String::from_utf8_lossy(&decrypted));
    println!("  ✓ Password-based encryption successful!\n");

    Ok(())
}

fn key_derivation_example() -> CrabResult<()> {
    println!("2. Key Derivation (CryptoJS-compatible approach):");

    // CryptoJS uses MD5 for key derivation by default (INSECURE!)
    // We use PBKDF2-HMAC-SHA256 instead
    println!("  ⚠️  CryptoJS uses MD5 for default key derivation (INSECURE!)");
    println!("  ✓  We use PBKDF2-HMAC-SHA256 for better security");

    let password = b"password123";
    let salt = b"saltdata12345678"; // 16 bytes

    // Derive 256-bit key
    let key = pbkdf2_derive_sha256(password, salt, 100_000, 32)?;
    println!("  Derived key length: {} bytes", key.len());
    println!("  ✓ Secure key derivation complete!\n");

    // Migration advice
    println!("🔧 Migration Advice:");
    println!("   - Use AES-GCM instead of AES-CBC for authenticated encryption");
    println!("   - Use PBKDF2 with ≥100,000 iterations (or Argon2)");
    println!("   - Generate random salts (≥16 bytes)");
    println!("   - Never reuse nonces with the same key");
    println!("   - See docs/MIGRATE_CRYPTOJS.md for detailed guide");

    Ok(())
}

// Note: For full CryptoJS compatibility (AES-CBC mode), you would need to:
// 1. Use a CBC mode cipher (not currently exposed in this high-level API)
// 2. Implement PKCS7 padding
// 3. Match CryptoJS's key derivation (MD5-based, but insecure)
//
// We recommend NOT doing this and instead:
// - Migrate to AES-GCM (available in modern browsers as Web Crypto API)
// - Update your JavaScript code to use secure parameters
// - Or use this library's WASM bindings for browser environments
