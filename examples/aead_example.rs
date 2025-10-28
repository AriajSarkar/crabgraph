//! Example: Authenticated encryption with AES-GCM and ChaCha20-Poly1305

use crabgraph::{
    aead::{AesGcm256, ChaCha20Poly1305, CrabAead},
    CrabResult,
};

fn main() -> CrabResult<()> {
    println!("=== Authenticated Encryption Example ===\n");

    // Example 1: AES-256-GCM
    println!("1. AES-256-GCM Encryption:");
    aes_gcm_example()?;

    println!("\n2. ChaCha20-Poly1305 Encryption:");
    chacha20_example()?;

    println!("\n3. Encryption with Associated Data:");
    aead_with_aad_example()?;

    println!("\n4. Serialization Example:");
    serialization_example()?;

    Ok(())
}

fn aes_gcm_example() -> CrabResult<()> {
    // Generate a random 256-bit key
    let key = AesGcm256::generate_key()?;
    println!("  Generated key: {} bytes", key.len());

    // Create cipher instance
    let cipher = AesGcm256::new(&key)?;

    // Encrypt some data
    let plaintext = b"This is a secret message!";
    println!("  Plaintext: {}", String::from_utf8_lossy(plaintext));

    let ciphertext = cipher.encrypt(plaintext, None)?;
    println!("  Nonce: {} bytes", ciphertext.nonce.len());
    println!("  Ciphertext: {} bytes", ciphertext.ciphertext.len());
    println!("  Tag: {} bytes", ciphertext.tag.len());

    // Decrypt
    let decrypted = cipher.decrypt(&ciphertext, None)?;
    println!("  Decrypted: {}", String::from_utf8_lossy(&decrypted));

    assert_eq!(decrypted, plaintext);
    println!("  ✓ Encryption/decryption successful!");

    Ok(())
}

fn chacha20_example() -> CrabResult<()> {
    let key = ChaCha20Poly1305::generate_key()?;
    let cipher = ChaCha20Poly1305::new(&key)?;

    let plaintext = b"ChaCha20-Poly1305 is fast!";
    println!("  Plaintext: {}", String::from_utf8_lossy(plaintext));

    let ciphertext = cipher.encrypt(plaintext, None)?;
    let decrypted = cipher.decrypt(&ciphertext, None)?;

    assert_eq!(decrypted, plaintext);
    println!("  ✓ ChaCha20-Poly1305 encryption successful!");

    Ok(())
}

fn aead_with_aad_example() -> CrabResult<()> {
    let key = AesGcm256::generate_key()?;
    let cipher = AesGcm256::new(&key)?;

    let plaintext = b"Secret payload";
    let associated_data = b"version=1,user=alice,timestamp=1234567890";

    println!("  Plaintext: {}", String::from_utf8_lossy(plaintext));
    println!("  AAD: {}", String::from_utf8_lossy(associated_data));

    // Encrypt with AAD
    let ciphertext = cipher.encrypt(plaintext, Some(associated_data))?;

    // Decrypt with correct AAD
    let decrypted = cipher.decrypt(&ciphertext, Some(associated_data))?;
    assert_eq!(decrypted, plaintext);
    println!("  ✓ Decryption with correct AAD succeeded");

    // Try to decrypt with wrong AAD (should fail)
    let wrong_aad = b"tampered_aad";
    let result = cipher.decrypt(&ciphertext, Some(wrong_aad));
    assert!(result.is_err());
    println!("  ✓ Decryption with wrong AAD failed (as expected)");

    Ok(())
}

fn serialization_example() -> CrabResult<()> {
    let key = AesGcm256::generate_key()?;
    let cipher = AesGcm256::new(&key)?;

    let plaintext = b"Data to store";
    let ciphertext = cipher.encrypt(plaintext, None)?;

    // Serialize to bytes
    let bytes = ciphertext.to_bytes();
    println!("  Serialized to {} bytes", bytes.len());

    // Serialize to base64 (for text storage)
    let base64 = ciphertext.to_base64();
    println!("  Base64: {}...", &base64[..20]);

    // Deserialize from base64
    let recovered = crabgraph::aead::Ciphertext::from_base64(&base64, 12, 16)?;
    let decrypted = cipher.decrypt(&recovered, None)?;

    assert_eq!(decrypted, plaintext);
    println!("  ✓ Serialization/deserialization successful!");

    Ok(())
}
