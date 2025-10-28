#![no_main]

use libfuzzer_sys::fuzz_target;
use crabgraph::aead::{AesGcm256, CrabAead};

fuzz_target!(|data: &[u8]| {
    // Only fuzz with reasonable input sizes
    if data.len() < 32 || data.len() > 10000 {
        return;
    }

    // Use first 32 bytes as key, rest as plaintext
    let key = &data[..32];
    let plaintext = &data[32..];

    // Create cipher - may fail with invalid key
    if let Ok(cipher) = AesGcm256::new(key) {
        // Encrypt
        if let Ok(ciphertext) = cipher.encrypt(plaintext, None) {
            // Decrypt should always succeed and match plaintext
            if let Ok(decrypted) = cipher.decrypt(&ciphertext, None) {
                assert_eq!(decrypted, plaintext);
            }
        }

        // Test with AAD
        if let Ok(ciphertext) = cipher.encrypt(plaintext, Some(b"aad")) {
            // Should succeed with correct AAD
            assert!(cipher.decrypt(&ciphertext, Some(b"aad")).is_ok());
            
            // Should fail with wrong AAD
            assert!(cipher.decrypt(&ciphertext, Some(b"wrong")).is_err());
        }
    }
});
