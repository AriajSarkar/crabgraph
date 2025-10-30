//! Key Rotation Example
//!
//! Demonstrates how to use CrabGraph's key rotation utilities to:
//! 1. Manage multiple key versions
//! 2. Encrypt data with versioned keys
//! 3. Rotate to new keys without service interruption
//! 4. Re-encrypt old data with new keys
//! 5. Remove old keys after successful migration
//!
//! Run with: cargo run --example key_rotation_example

use crabgraph::{
    aead::{AesGcm256, ChaCha20Poly1305},
    key_rotation::KeyRotationManager,
    CrabResult,
};

fn main() -> CrabResult<()> {
    println!("🔐 CrabGraph Key Rotation Example\n");
    println!("==========================================\n");

    // Demo 1: Basic key rotation
    basic_rotation_demo()?;

    // Demo 2: Re-encryption workflow
    re_encryption_demo()?;

    // Demo 3: Key lifecycle management
    key_lifecycle_demo()?;

    // Demo 4: Multiple cipher support
    multi_cipher_demo()?;

    println!("\n✨ All key rotation examples completed successfully!");

    Ok(())
}

/// Demonstrates basic key rotation operations
fn basic_rotation_demo() -> CrabResult<()> {
    println!("📋 Demo 1: Basic Key Rotation\n");

    // Create a key rotation manager with AES-256-GCM
    let mut manager = KeyRotationManager::<AesGcm256>::new()?;
    println!("  ✓ Created KeyRotationManager");
    println!("  Current version: {}\n", manager.current_version());

    // Encrypt some data with version 1
    let user_data = b"User password: hunter2";
    let (v1, ct1) = manager.encrypt(user_data, None)?;
    println!("  ✓ Encrypted data with version {}", v1);

    // Rotate to version 2
    manager.rotate()?;
    println!("  ✓ Rotated to version {}", manager.current_version());

    // New encryptions use version 2
    let new_data = b"New user data";
    let (v2, ct2) = manager.encrypt(new_data, None)?;
    println!("  ✓ Encrypted new data with version {}\n", v2);

    // Old data can still be decrypted with version 1
    let decrypted_old = manager.decrypt(v1, &ct1, None)?;
    println!("  ✓ Decrypted old data (v1): {:?}", String::from_utf8_lossy(&decrypted_old));

    // New data decrypts with version 2
    let decrypted_new = manager.decrypt(v2, &ct2, None)?;
    println!("  ✓ Decrypted new data (v2): {:?}\n", String::from_utf8_lossy(&decrypted_new));

    println!("  Available versions: {:?}\n", manager.available_versions());

    Ok(())
}

/// Demonstrates re-encryption from old to new keys
fn re_encryption_demo() -> CrabResult<()> {
    println!("🔄 Demo 2: Re-encryption Workflow\n");

    let mut manager = KeyRotationManager::<AesGcm256>::new()?;

    // Simulate existing encrypted data
    let records = [
        b"Record 1: Alice's secret" as &[u8],
        b"Record 2: Bob's secret",
        b"Record 3: Carol's secret",
    ];

    println!("  Encrypting {} records with version 1...", records.len());
    let mut encrypted_records = Vec::new();
    for (i, record) in records.iter().enumerate() {
        let (version, ciphertext) = manager.encrypt(record, None)?;
        encrypted_records.push((version, ciphertext));
        println!("    ✓ Record {} encrypted (version {})", i + 1, version);
    }
    println!();

    // Time to rotate keys!
    println!("  🔑 Rotating to new key (version 2)...");
    manager.rotate()?;
    println!("  ✓ Rotation complete\n");

    // Re-encrypt all old records
    println!("  Re-encrypting {} records to version 2...", records.len());
    let mut re_encrypted_records = Vec::new();
    for (i, (old_version, old_ciphertext)) in encrypted_records.iter().enumerate() {
        let (new_version, new_ciphertext) =
            manager.re_encrypt(*old_version, old_ciphertext, None)?;
        re_encrypted_records.push((new_version, new_ciphertext));
        println!("    ✓ Record {} re-encrypted: v{} → v{}", i + 1, old_version, new_version);
    }
    println!();

    // Verify all records decrypt correctly
    println!("  Verifying re-encrypted records...");
    for (i, (version, ciphertext)) in re_encrypted_records.iter().enumerate() {
        let decrypted = manager.decrypt(*version, ciphertext, None)?;
        assert_eq!(decrypted, records[i]);
        println!("    ✓ Record {} verified", i + 1);
    }
    println!();

    // Now safe to remove old key
    println!("  Removing old key (version 1)...");
    manager.remove_version(1)?;
    println!("  ✓ Old key removed");
    println!("  Available versions: {:?}\n", manager.available_versions());

    Ok(())
}

/// Demonstrates key lifecycle management
fn key_lifecycle_demo() -> CrabResult<()> {
    println!("♻️  Demo 3: Key Lifecycle Management\n");

    // Create manager with max 3 versions
    let mut manager = KeyRotationManager::<ChaCha20Poly1305>::with_max_versions(3)?;
    println!("  Created manager with max 3 versions\n");

    let data = b"Test data";

    // Fill up to max versions
    println!("  Performing rotations...");
    let (v1, ct1) = manager.encrypt(data, None)?;
    println!("    Version {}: {} total versions", v1, manager.version_count());

    manager.rotate()?;
    let (v2, ct2) = manager.encrypt(data, None)?;
    println!("    Version {}: {} total versions", v2, manager.version_count());

    manager.rotate()?;
    let (v3, ct3) = manager.encrypt(data, None)?;
    println!("    Version {}: {} total versions", v3, manager.version_count());

    // Next rotation should remove v1
    manager.rotate()?;
    let (v4, _ct4) = manager.encrypt(data, None)?;
    println!("    Version {}: {} total versions", v4, manager.version_count());
    println!();

    // v1 should be gone
    println!("  Version 1 available? {}", manager.has_version(1));
    println!("  Version 2 available? {}", manager.has_version(2));
    println!("  Version 3 available? {}", manager.has_version(3));
    println!("  Version 4 available? {}", manager.has_version(4));
    println!();

    // Can't decrypt v1 anymore (key was auto-removed)
    println!("  Attempting to decrypt old version 1 data...");
    match manager.decrypt(v1, &ct1, None) {
        Ok(_) => println!("    ✗ Unexpectedly succeeded"),
        Err(_) => println!("    ✓ Correctly failed (key no longer available)"),
    }
    println!();

    // But v2, v3 still work
    println!("  Decrypting version 2: {}", manager.decrypt(v2, &ct2, None).is_ok());
    println!("  Decrypting version 3: {}", manager.decrypt(v3, &ct3, None).is_ok());
    println!();

    Ok(())
}

/// Demonstrates using different cipher algorithms
fn multi_cipher_demo() -> CrabResult<()> {
    println!("🔀 Demo 4: Multiple Cipher Support\n");

    let data = b"Test data for both ciphers";

    // AES-256-GCM manager
    println!("  Using AES-256-GCM:");
    let aes_manager = KeyRotationManager::<AesGcm256>::new()?;
    let (aes_v, aes_ct) = aes_manager.encrypt(data, None)?;
    println!("    ✓ Encrypted with version {}", aes_v);
    let aes_decrypted = aes_manager.decrypt(aes_v, &aes_ct, None)?;
    println!("    ✓ Decrypted: {} bytes", aes_decrypted.len());
    println!();

    // ChaCha20-Poly1305 manager
    println!("  Using ChaCha20-Poly1305:");
    let chacha_manager = KeyRotationManager::<ChaCha20Poly1305>::new()?;
    let (chacha_v, chacha_ct) = chacha_manager.encrypt(data, None)?;
    println!("    ✓ Encrypted with version {}", chacha_v);
    let chacha_decrypted = chacha_manager.decrypt(chacha_v, &chacha_ct, None)?;
    println!("    ✓ Decrypted: {} bytes", chacha_decrypted.len());
    println!();

    // Both produced same plaintext
    assert_eq!(aes_decrypted, chacha_decrypted);
    println!("  ✓ Both ciphers produced identical plaintext\n");

    Ok(())
}
