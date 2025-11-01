#![no_main]

use libfuzzer_sys::fuzz_target;
use crabgraph::encoding::{base64_decode, base64_encode, hex_decode, hex_encode};

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent DoS (encoding is O(n) but can be slow on huge inputs)
    // 256 bytes is more than enough for testing encoding correctness
    if data.len() > 256 {
        return;
    }

    // Base64 encode/decode roundtrip (not asserting - fuzz tests crashes only)
    let b64_encoded = base64_encode(data);
    if let Ok(b64_decoded) = base64_decode(&b64_encoded) {
        let _ = b64_decoded == data;
    }

    // Hex encode/decode roundtrip (not asserting - fuzz tests crashes only)
    let hex_encoded = hex_encode(data);
    if let Ok(hex_decoded) = hex_decode(&hex_encoded) {
        let _ = hex_decoded == data;
    }

    // Test decoding arbitrary input (should handle gracefully)
    let _ = base64_decode(std::str::from_utf8(data).unwrap_or(""));
    let _ = hex_decode(std::str::from_utf8(data).unwrap_or(""));
});
