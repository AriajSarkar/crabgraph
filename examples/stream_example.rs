//! Example: Streaming Encryption for Large Files
//!
//! This example demonstrates how to use CrabGraph's streaming AEAD encryption
//! to encrypt and decrypt large files chunk-by-chunk, avoiding loading the
//! entire file into memory.
//!
//! The streaming encryption uses the STREAM construction (RFC: Online Authenticated-Encryption)
//! which provides nonce-reuse resistance and independent authentication per chunk.

use crabgraph::{
    aead::stream::{
        Aes256GcmStreamDecryptor, Aes256GcmStreamEncryptor, ChaCha20Poly1305StreamDecryptor,
        ChaCha20Poly1305StreamEncryptor,
    },
    rand::secure_bytes,
    CrabResult,
};

/// Example 1: Basic streaming encryption with AES-256-GCM
fn basic_aes_gcm_streaming() -> CrabResult<()> {
    println!("=== Example 1: Basic AES-256-GCM Streaming ===\n");

    // Generate a 32-byte key for AES-256-GCM
    let key = secure_bytes(32)?;
    println!("Generated 32-byte key");

    // Create stream encryptor (auto-generates 7-byte nonce)
    let mut encryptor = Aes256GcmStreamEncryptor::new(&key)?;
    let nonce = encryptor.nonce().to_vec(); // Save nonce for decryption
    println!("Created encryptor with nonce: {} bytes", nonce.len());

    // Encrypt multiple chunks
    let chunks = vec![
        b"First chunk of data...".to_vec(),
        b"Second chunk of data...".to_vec(),
        b"Third chunk of data...".to_vec(),
        b"Final chunk!".to_vec(),
    ];

    println!("\nEncrypting {} chunks:", chunks.len());
    let mut encrypted_chunks = Vec::new();

    // Encrypt all but the last chunk with encrypt_next()
    for (i, chunk) in chunks[..chunks.len() - 1].iter().enumerate() {
        let encrypted = encryptor.encrypt_next(chunk)?;
        println!("  Chunk {}: {} bytes -> {} bytes", i + 1, chunk.len(), encrypted.len());
        encrypted_chunks.push(encrypted);
    }

    // Encrypt the last chunk with encrypt_last() (consumes encryptor)
    let last_chunk = &chunks[chunks.len() - 1];
    let encrypted_last = encryptor.encrypt_last(last_chunk)?;
    println!(
        "  Chunk {} (final): {} bytes -> {} bytes",
        chunks.len(),
        last_chunk.len(),
        encrypted_last.len()
    );
    encrypted_chunks.push(encrypted_last);

    // Decrypt using saved nonce
    println!("\nDecrypting {} chunks:", encrypted_chunks.len());
    let mut decryptor = Aes256GcmStreamDecryptor::from_nonce(&key, &nonce)?;

    let mut decrypted_chunks = Vec::new();

    // Decrypt all but the last chunk with decrypt_next()
    for (i, encrypted) in encrypted_chunks[..encrypted_chunks.len() - 1].iter().enumerate() {
        let decrypted = decryptor.decrypt_next(encrypted)?;
        println!("  Chunk {}: {} bytes -> {} bytes", i + 1, encrypted.len(), decrypted.len());
        decrypted_chunks.push(decrypted);
    }

    // Decrypt the last chunk with decrypt_last() (consumes decryptor)
    let last_encrypted = &encrypted_chunks[encrypted_chunks.len() - 1];
    let decrypted_last = decryptor.decrypt_last(last_encrypted)?;
    println!(
        "  Chunk {} (final): {} bytes -> {} bytes",
        encrypted_chunks.len(),
        last_encrypted.len(),
        decrypted_last.len()
    );
    decrypted_chunks.push(decrypted_last);

    // Verify roundtrip
    assert_eq!(decrypted_chunks, chunks);
    println!("\n✓ Roundtrip successful! All chunks match.");

    Ok(())
}

/// Example 2: Streaming encryption with ChaCha20-Poly1305
fn chacha20poly1305_streaming() -> CrabResult<()> {
    println!("\n=== Example 2: ChaCha20-Poly1305 Streaming ===\n");

    // Generate a 32-byte key for ChaCha20-Poly1305
    let key = secure_bytes(32)?;
    println!("Generated 32-byte key");

    // Create stream encryptor
    let mut encryptor = ChaCha20Poly1305StreamEncryptor::new(&key)?;
    let nonce = encryptor.nonce().to_vec();
    println!("Created ChaCha20-Poly1305 encryptor");

    // Simulate large file by encrypting multiple chunks
    let data = b"This is a simulated large file that we're processing chunk by chunk.";
    let chunk_size = 20; // Small chunk size for demonstration

    println!("\nEncrypting data in {}-byte chunks:", chunk_size);
    let mut encrypted_chunks = Vec::new();
    let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();

    // Encrypt all but the last chunk
    for (i, chunk) in chunks[..chunks.len() - 1].iter().enumerate() {
        let encrypted = encryptor.encrypt_next(chunk)?;
        println!("  Chunk {}: {} bytes", i + 1, chunk.len());
        encrypted_chunks.push(encrypted);
    }

    // Encrypt the last chunk (consumes encryptor)
    let last_chunk = chunks[chunks.len() - 1];
    let encrypted_last = encryptor.encrypt_last(last_chunk)?;
    println!("  Chunk {} (final): {} bytes", chunks.len(), last_chunk.len());
    encrypted_chunks.push(encrypted_last);

    // Decrypt
    println!("\nDecrypting {} chunks:", encrypted_chunks.len());
    let mut decryptor = ChaCha20Poly1305StreamDecryptor::from_nonce(&key, &nonce)?;

    let mut decrypted_data = Vec::new();

    // Decrypt all but the last chunk
    for (i, encrypted) in encrypted_chunks[..encrypted_chunks.len() - 1].iter().enumerate() {
        let decrypted = decryptor.decrypt_next(encrypted)?;
        println!("  Chunk {}: {} bytes", i + 1, encrypted.len());
        decrypted_data.extend_from_slice(&decrypted);
    }

    // Decrypt the last chunk (consumes decryptor)
    let last_encrypted = &encrypted_chunks[encrypted_chunks.len() - 1];
    let decrypted_last = decryptor.decrypt_last(last_encrypted)?;
    println!("  Chunk {} (final): {} bytes", encrypted_chunks.len(), last_encrypted.len());
    decrypted_data.extend_from_slice(&decrypted_last);

    // Verify roundtrip
    assert_eq!(decrypted_data, data);
    println!("\n✓ Roundtrip successful! Original data restored.");

    Ok(())
}

/// Example 3: Simulating file encryption with metadata
fn file_encryption_simulation() -> CrabResult<()> {
    println!("\n=== Example 3: File Encryption Simulation ===\n");

    // Generate key
    let key = secure_bytes(32)?;

    // Create encryptor
    let mut encryptor = Aes256GcmStreamEncryptor::new(&key)?;
    let nonce = encryptor.nonce().to_vec();

    // Simulate file metadata
    let filename = "secret_document.txt";
    let file_data = b"This is the content of the secret document.\n\
                      It contains multiple lines of sensitive information.\n\
                      We're encrypting it chunk by chunk for efficiency.";

    println!("Encrypting file: {}", filename);
    println!("File size: {} bytes", file_data.len());
    println!("Nonce: {} bytes", nonce.len());

    // In a real application, you would:
    // 1. Save the nonce to a header or separate file
    // 2. Stream chunks from disk instead of loading entire file

    const CHUNK_SIZE: usize = 64 * 1024; // 64 KB (default)

    println!("\nProcessing in {}-byte chunks:", CHUNK_SIZE);
    let mut encrypted_chunks = Vec::new();
    let chunks: Vec<&[u8]> = file_data.chunks(CHUNK_SIZE).collect();

    // Encrypt all but the last chunk
    for (i, chunk) in chunks[..chunks.len() - 1].iter().enumerate() {
        let encrypted = encryptor.encrypt_next(chunk)?;
        println!("  Chunk {}: {} bytes", i + 1, chunk.len());
        encrypted_chunks.push(encrypted);
    }

    // Encrypt the last chunk (consumes encryptor)
    let last_chunk = chunks[chunks.len() - 1];
    let encrypted_last = encryptor.encrypt_last(last_chunk)?;
    println!("  Final chunk: {} bytes", last_chunk.len());
    encrypted_chunks.push(encrypted_last);

    let total_encrypted_size: usize = encrypted_chunks.iter().map(|c| c.len()).sum();
    println!("\nTotal encrypted size: {} bytes", total_encrypted_size);
    println!(
        "Overhead: {} bytes ({}%)",
        total_encrypted_size as i32 - file_data.len() as i32,
        ((total_encrypted_size as f64 / file_data.len() as f64 - 1.0) * 100.0) as i32
    );

    // Decrypt
    println!("\nDecrypting file...");
    let mut decryptor = Aes256GcmStreamDecryptor::from_nonce(&key, &nonce)?;

    let mut decrypted_data = Vec::new();

    // Decrypt all but the last chunk
    for encrypted in encrypted_chunks[..encrypted_chunks.len() - 1].iter() {
        let decrypted = decryptor.decrypt_next(encrypted)?;
        decrypted_data.extend_from_slice(&decrypted);
    }

    // Decrypt the last chunk (consumes decryptor)
    let last_encrypted = &encrypted_chunks[encrypted_chunks.len() - 1];
    let decrypted_last = decryptor.decrypt_last(last_encrypted)?;
    decrypted_data.extend_from_slice(&decrypted_last);

    // Verify
    assert_eq!(decrypted_data, file_data);
    println!("✓ File decrypted successfully! Content matches original.");

    Ok(())
}

/// Example 4: Error handling - tampering detection
fn tampering_detection() -> CrabResult<()> {
    println!("\n=== Example 4: Tampering Detection ===\n");

    let key = secure_bytes(32)?;

    // Encrypt data
    let mut encryptor = Aes256GcmStreamEncryptor::new(&key)?;
    let nonce = encryptor.nonce().to_vec();

    let chunk1 = b"Original data chunk 1";
    let chunk2 = b"Original data chunk 2";

    let encrypted1 = encryptor.encrypt_next(chunk1)?;
    let mut encrypted2 = encryptor.encrypt_last(chunk2)?;

    println!("Encrypted 2 chunks");

    // Tamper with the second chunk
    println!("\nTampering with encrypted data...");
    if !encrypted2.is_empty() {
        encrypted2[0] ^= 0xFF; // Flip bits
    }

    // Try to decrypt
    println!("Attempting to decrypt tampered data:");
    let mut decryptor = Aes256GcmStreamDecryptor::from_nonce(&key, &nonce)?;

    // First chunk should decrypt fine
    let decrypted1 = decryptor.decrypt_next(&encrypted1)?;
    assert_eq!(decrypted1, chunk1);
    println!("  Chunk 1: ✓ Decrypted successfully");

    // Second chunk should fail authentication
    match decryptor.decrypt_last(&encrypted2) {
        Ok(_) => {
            println!("  Chunk 2: ✗ ERROR - Tampered data was accepted!");
            panic!("Security failure: tampered data accepted");
        }
        Err(e) => {
            println!("  Chunk 2: ✓ Tampering detected!");
            println!("           Error: {}", e);
        }
    }

    println!("\n✓ Authentication working correctly!");

    Ok(())
}

fn main() -> CrabResult<()> {
    println!("CrabGraph Streaming Encryption Examples\n");
    println!("========================================\n");

    // Run all examples
    basic_aes_gcm_streaming()?;
    chacha20poly1305_streaming()?;
    file_encryption_simulation()?;
    tampering_detection()?;

    println!("\n========================================");
    println!("All examples completed successfully! ✓");

    Ok(())
}
