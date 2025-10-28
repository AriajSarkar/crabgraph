//! RSA encryption and signature example.
//!
//! This example demonstrates RSA-OAEP encryption and RSA-PSS signatures.
//!
//! ⚠️ **SECURITY WARNING**: RSA has a known vulnerability (RUSTSEC-2023-0071).
//! Use Ed25519 for signatures and X25519+AEAD for encryption unless RSA is
//! specifically required for compatibility.

#[cfg(not(feature = "rsa-support"))]
compile_error!("This example requires the 'rsa-support' feature. Run with: cargo run --example rsa_example --features rsa-support");

use crabgraph::{
    asym::{RsaKeyPair, RsaPublicKey},
    CrabResult,
};

fn main() -> CrabResult<()> {
    println!("=== RSA Encryption and Signature Example ===\n");

    // Generate a 2048-bit RSA keypair (faster, adequate security)
    println!("Generating 2048-bit RSA keypair...");
    let keypair = RsaKeyPair::generate_2048()?;
    println!("✓ Keypair generated ({} bits)\n", keypair.size_bits());

    // === Encryption Example ===
    println!("--- RSA-OAEP Encryption ---");
    let plaintext = b"This is a secret message!";
    println!("Plaintext: {:?}", String::from_utf8_lossy(plaintext));

    // Encrypt with public key
    let ciphertext = keypair.encrypt(plaintext)?;
    println!("Ciphertext ({} bytes): {}", ciphertext.len(), hex::encode(&ciphertext[..32]));

    // Decrypt with private key
    let decrypted = keypair.decrypt(&ciphertext)?;
    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
    assert_eq!(decrypted, plaintext);
    println!("✓ Encryption/Decryption successful\n");

    // === Signature Example ===
    println!("--- RSA-PSS Signatures ---");
    let document = b"Important contract document";
    println!("Document: {:?}", String::from_utf8_lossy(document));

    // Sign the document
    let signature = keypair.sign(document)?;
    println!(
        "Signature ({} bytes): {}",
        signature.len(),
        signature.to_hex()[..64].to_string()
    );

    // Verify with the keypair
    let is_valid = keypair.verify(document, &signature)?;
    println!("Signature valid: {}", is_valid);
    assert!(is_valid);

    // Verify with just the public key
    let public_key = keypair.public_key();
    let is_valid = public_key.verify(document, &signature)?;
    println!("Verified with public key: {}", is_valid);
    assert!(is_valid);

    // Verify fails with wrong message
    let is_valid = keypair.verify(b"Wrong document", &signature)?;
    println!("Wrong message fails: {}", !is_valid);
    assert!(!is_valid);
    println!("✓ Signature verification successful\n");

    // === Key Export/Import Example ===
    println!("--- Key Serialization ---");

    // Export private key to PEM
    let private_pem = keypair.to_pem()?;
    println!("Private key PEM (first 80 chars): {}...", &private_pem[..80]);

    // Export public key to PEM
    let public_pem = public_key.to_pem()?;
    println!("Public key PEM (first 80 chars): {}...", &public_pem[..80]);

    // Import keys back
    let restored_keypair = RsaKeyPair::from_pem(&private_pem)?;
    let restored_public = RsaPublicKey::from_pem(&public_pem)?;
    println!("✓ Keys exported and imported successfully\n");

    // Verify imported keys work
    let test_msg = b"Test";
    let test_sig = restored_keypair.sign(test_msg)?;
    assert!(restored_public.verify(test_msg, &test_sig)?);
    println!("✓ Restored keys work correctly\n");

    // === Max Plaintext Size ===
    println!("--- Maximum Plaintext Size ---");
    let max_size = keypair.size_bytes() - 2 * 32 - 2; // key_size - 2*hash_size - 2
    println!("For {}-bit RSA with OAEP-SHA256:", keypair.size_bits());
    println!("Maximum plaintext size: {} bytes", max_size);

    let large_plaintext = vec![0x42u8; max_size];
    let encrypted = keypair.encrypt(&large_plaintext)?;
    let decrypted = keypair.decrypt(&encrypted)?;
    assert_eq!(decrypted, large_plaintext);
    println!("✓ Successfully encrypted maximum size ({} bytes)\n", max_size);

    // === Hybrid Encryption Recommendation ===
    println!("--- Recommendation for Large Data ---");
    println!("For data larger than {} bytes:", max_size);
    println!("1. Use AES-GCM or ChaCha20-Poly1305 for data encryption");
    println!("2. Use RSA to encrypt only the symmetric key");
    println!("3. Send: RSA(symmetric_key) + AEAD(data, symmetric_key)\n");

    // === 4096-bit Key Example (Optional) ===
    println!("--- 4096-bit RSA (Higher Security) ---");
    println!("Generating 4096-bit keypair (this is slow)...");
    let keypair_4096 = RsaKeyPair::generate_4096()?;
    println!("✓ 4096-bit keypair generated");
    println!("Size: {} bits ({} bytes)", keypair_4096.size_bits(), keypair_4096.size_bytes());
    let max_4096 = keypair_4096.size_bytes() - 2 * 32 - 2;
    println!("Maximum plaintext: {} bytes\n", max_4096);

    println!("=== Example Complete ===");
    println!("\n⚠️  SECURITY REMINDER:");
    println!("   - RSA has known vulnerabilities (RUSTSEC-2023-0071)");
    println!("   - Prefer Ed25519 for signatures");
    println!("   - Prefer X25519 + AEAD for encryption");
    println!("   - Use RSA only for legacy system compatibility");

    Ok(())
}
