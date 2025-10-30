#![no_main]

use libfuzzer_sys::fuzz_target;
use crabgraph::mac::{hmac_sha256, hmac_sha256_verify, hmac_sha512, hmac_sha512_verify};

fuzz_target!(|data: &[u8]| {
    // Need at least 1 byte for key
    if data.is_empty() || data.len() > 10000 {
        return;
    }

    // Split into key and message
    let split_point = data.len() / 2;
    let key = &data[..split_point.max(1)];
    let message = &data[split_point..];

    // HMAC-SHA256
    if let Ok(mac256) = hmac_sha256(key, message) {
        assert_eq!(mac256.len(), 32, "HMAC-SHA256 should be 32 bytes");

        // Verification with correct MAC should succeed
        assert!(
            hmac_sha256_verify(key, message, &mac256).is_ok(),
            "Verification should succeed with correct MAC"
        );

        // Verification with wrong MAC should fail
        let mut wrong_mac = mac256.clone();
        if !wrong_mac.is_empty() {
            wrong_mac[0] ^= 0xFF;
            assert!(
                hmac_sha256_verify(key, message, &wrong_mac).is_err(),
                "Verification should fail with wrong MAC"
            );
        }

        // Same input should produce same MAC (determinism)
        if let Ok(mac256_2) = hmac_sha256(key, message) {
            assert_eq!(mac256, mac256_2, "HMAC should be deterministic");
        }
    }

    // HMAC-SHA512
    if let Ok(mac512) = hmac_sha512(key, message) {
        assert_eq!(mac512.len(), 64, "HMAC-SHA512 should be 64 bytes");

        // Verification should work
        assert!(hmac_sha512_verify(key, message, &mac512).is_ok());

        // Wrong MAC should fail
        let mut wrong_mac = mac512.clone();
        if !wrong_mac.is_empty() {
            wrong_mac[0] ^= 0xFF;
            assert!(hmac_sha512_verify(key, message, &wrong_mac).is_err());
        }
    }
});
