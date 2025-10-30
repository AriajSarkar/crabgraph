#![no_main]

use libfuzzer_sys::fuzz_target;
use crabgraph::encoding::{base64_decode, base64_encode, hex_decode, hex_encode};

fuzz_target!(|data: &[u8]| {
    // Limit input size for performance
    if data.len() > 10000 {
        return;
    }

    // Base64 encode/decode roundtrip
    let b64_encoded = base64_encode(data);
    if let Ok(b64_decoded) = base64_decode(&b64_encoded) {
        assert_eq!(b64_decoded, data, "Base64 roundtrip failed");
    } else {
        panic!("Base64 decode should not fail for valid encoded data");
    }

    // Hex encode/decode roundtrip
    let hex_encoded = hex_encode(data);
    if let Ok(hex_decoded) = hex_decode(&hex_encoded) {
        assert_eq!(hex_decoded, data, "Hex roundtrip failed");
    } else {
        panic!("Hex decode should not fail for valid encoded data");
    }

    // Test decoding arbitrary input (should handle gracefully)
    let _ = base64_decode(std::str::from_utf8(data).unwrap_or(""));
    let _ = hex_decode(std::str::from_utf8(data).unwrap_or(""));
});
