#![no_main]

use libfuzzer_sys::fuzz_target;
use crabgraph::kdf::{pbkdf2_derive_sha256, hkdf_sha256};

fuzz_target!(|data: &[u8]| {
    // Only fuzz with reasonable input sizes
    if data.len() < 32 {
        return;
    }

    // Split data into password and salt
    let (password, salt) = data.split_at(data.len() / 2);

    if salt.len() >= 8 {
        // Test PBKDF2 - should never panic
        let _ = pbkdf2_derive_sha256(password, salt, 10_000, 32);
        
        // Test HKDF - should never panic
        let _ = hkdf_sha256(password, 32);
    }
});
