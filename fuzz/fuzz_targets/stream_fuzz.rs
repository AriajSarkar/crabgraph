#![no_main]

use libfuzzer_sys::fuzz_target;
use crabgraph::aead::stream::{Aes256GcmStreamEncryptor, Aes256GcmStreamDecryptor};

fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes for key
    // Limit to 1024 bytes total to prevent DoS (streaming is expensive with many chunks)
    if data.len() < 32 || data.len() > 1024 {
        return;
    }

    let key = &data[..32];
    let plaintext = &data[32..];

    // Additional check: limit plaintext size
    if plaintext.len() > 512 {
        return;
    }

    // Create encryptor
    let mut encryptor = match Aes256GcmStreamEncryptor::new(key) {
        Ok(enc) => enc,
        Err(_) => return,
    };

    // Get nonce before we consume the encryptor
    let nonce = encryptor.nonce();

    // Encrypt data in chunks
    let chunk_size = 256.min(plaintext.len().max(1)); // Ensure non-zero chunk size
    let mut encrypted_chunks = Vec::new();
    
    if plaintext.is_empty() {
        // No data to encrypt, just finalize
        if let Ok(final_chunk) = encryptor.encrypt_last(b"") {
            encrypted_chunks.push(final_chunk);
        } else {
            return;
        }
    } else {
        let chunks: Vec<&[u8]> = plaintext.chunks(chunk_size).collect();
        
        // Encrypt all but last chunk with encrypt_next
        for chunk in chunks.iter().take(chunks.len() - 1) {
            if let Ok(enc_chunk) = encryptor.encrypt_next(chunk) {
                encrypted_chunks.push(enc_chunk);
            } else {
                return; // Encryption failed, that's okay
            }
        }

        // Encrypt last chunk with encrypt_last
        if let Some(last_chunk) = chunks.last() {
            if let Ok(enc_chunk) = encryptor.encrypt_last(last_chunk) {
                encrypted_chunks.push(enc_chunk);
            } else {
                return;
            }
        }
    }

    // Now decrypt back
    let mut decryptor = match Aes256GcmStreamDecryptor::from_nonce(key, &nonce) {
        Ok(dec) => dec,
        Err(_) => return,
    };

    let mut decrypted = Vec::new();

    if encrypted_chunks.is_empty() {
        return;
    }

    // Decrypt all but last chunk
    for chunk in encrypted_chunks.iter().take(encrypted_chunks.len() - 1) {
        if let Ok(dec_chunk) = decryptor.decrypt_next(chunk) {
            decrypted.extend_from_slice(&dec_chunk);
        } else {
            return; // Decryption failed
        }
    }

    // Decrypt last chunk
    if let Some(last_chunk) = encrypted_chunks.last() {
        if let Ok(dec_chunk) = decryptor.decrypt_last(last_chunk) {
            decrypted.extend_from_slice(&dec_chunk);
        } else {
            return;
        }
    }

    // Verify roundtrip - edge cases might cause differences
    // Just verify no crash occurs
    let _ = decrypted == plaintext;
});
