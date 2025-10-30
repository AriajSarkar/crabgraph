#![no_main]

use libfuzzer_sys::fuzz_target;
use crabgraph::kw::{Kw128, Kw256};

fuzz_target!(|data: &[u8]| {
    // Need at least 48 bytes (32 KEK + 16 key minimum)
    if data.len() < 48 || data.len() > 1024 {
        return;
    }

    // Use first 32 bytes as KEK, rest as key to wrap
    let kek = &data[..32];
    let key_data = &data[32..];

    // Ensure key is multiple of 8 bytes (AES-KW requirement)
    let key_len = (key_data.len() / 8) * 8;
    if key_len < 16 {
        return;
    }
    let key = &key_data[..key_len];

    // Test Kw256
    if let Ok(wrapper) = Kw256::new(kek) {
        // Wrap should not panic
        if let Ok(wrapped) = wrapper.wrap_key(key) {
            // Unwrap should succeed and match original
            if let Ok(unwrapped) = wrapper.unwrap_key(&wrapped) {
                assert_eq!(unwrapped, key, "Wrap/unwrap roundtrip failed");
            }

            // Tampering should cause unwrap to fail
            let mut tampered = wrapped.clone();
            if !tampered.is_empty() {
                tampered[0] ^= 0xFF;
                assert!(
                    wrapper.unwrap_key(&tampered).is_err(),
                    "Tampered data should fail to unwrap"
                );
            }
        }
    }

    // Test Kw128 with first 16 bytes as KEK
    if data.len() >= 32 {
        let kek128 = &data[..16];
        if let Ok(wrapper) = Kw128::new(kek128) {
            if let Ok(wrapped) = wrapper.wrap_key(key) {
                if let Ok(unwrapped) = wrapper.unwrap_key(&wrapped) {
                    assert_eq!(unwrapped, key);
                }
            }
        }
    }
});
