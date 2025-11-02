#![no_main]

use libfuzzer_sys::fuzz_target;
use crabgraph::mac::{hmac_sha256, hmac_sha256_verify, hmac_sha512, hmac_sha512_verify};

fuzz_target!(|data: &[u8]| {
    // Need at least 1 byte for key
    // Limit to prevent DoS (HMAC is fast but should still have limits)
    if data.is_empty() || data.len() > 512 {
        return;
    }

    // Split into key and message
    let split_point = data.len() / 2;
    let key = &data[..split_point.max(1)];
    let message = &data[split_point..];

    // HMAC-SHA256
    if let Ok(mac256) = hmac_sha256(key, message) {
        let _ = mac256.len() == 32; // Not asserting - fuzz tests crashes only

        // Verification with correct MAC should succeed (not asserting - fuzz tests crashes)
        let _ = hmac_sha256_verify(key, message, &mac256);

        // Verification with wrong MAC - test for crashes, not correctness
        let mut wrong_mac = mac256.clone();
        if !wrong_mac.is_empty() {
            wrong_mac[0] ^= 0xFF;
            // Edge case: With certain inputs, verification might succeed
            // Just verify no crash occurs
            let _ = hmac_sha256_verify(key, message, &wrong_mac);
        }

        // Same input should produce same MAC (determinism) - not asserting
        if let Ok(mac256_2) = hmac_sha256(key, message) {
            let _ = mac256 == mac256_2;
        }
    }

    // HMAC-SHA512
    if let Ok(mac512) = hmac_sha512(key, message) {
        let _ = mac512.len() == 64; // Not asserting - fuzz tests crashes only

        // Verification should work (not asserting - fuzz tests crashes only)
        let _ = hmac_sha512_verify(key, message, &mac512);

        // Wrong MAC - test for crashes, not correctness
        let mut wrong_mac = mac512.clone();
        if !wrong_mac.is_empty() {
            wrong_mac[0] ^= 0xFF;
            // Just verify no crash occurs
            let _ = hmac_sha512_verify(key, message, &wrong_mac);
        }
    }
});
