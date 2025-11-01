#![no_main]

use libfuzzer_sys::fuzz_target;
use crabgraph::hash::{sha256, sha256_hex, sha512, sha512_hex};

fuzz_target!(|data: &[u8]| {
    // Limit input size to prevent DoS (hashing is O(n) but can be slow on huge inputs)
    if data.len() > 10000 {
        return;
    }

    // All hash functions should never panic
    let hash256 = sha256(data);
    assert_eq!(hash256.len(), 32, "SHA-256 should produce 32 bytes");

    let hash512 = sha512(data);
    assert_eq!(hash512.len(), 64, "SHA-512 should produce 64 bytes");

    // Hex variants should match
    let hex256 = sha256_hex(data);
    assert_eq!(hex256.len(), 64, "SHA-256 hex should be 64 chars");

    let hex512 = sha512_hex(data);
    assert_eq!(hex512.len(), 128, "SHA-512 hex should be 128 chars");

    // Same input should produce same output (determinism)
    assert_eq!(sha256(data), sha256(data));
    assert_eq!(sha512(data), sha512(data));

    // Test extended hashes if feature is enabled
    #[cfg(feature = "extended-hashes")]
    {
        use crabgraph::hash::{blake2b_512, blake2s_256, blake3_hash, sha3_256, sha3_512};

        let _ = sha3_256(data);
        let _ = sha3_512(data);
        let _ = blake2s_256(data);
        let _ = blake2b_512(data);
        let _ = blake3_hash(data);
    }
});
