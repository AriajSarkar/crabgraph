#![no_main]

use libfuzzer_sys::fuzz_target;
use crabgraph::asym::X25519KeyPair;

fuzz_target!(|data: &[u8]| {
    // Only need small amount of data
    if data.len() < 32 || data.len() > 1024 {
        return;
    }

    // Generate two keypairs
    let alice = match X25519KeyPair::generate() {
        Ok(kp) => kp,
        Err(_) => return,
    };

    let bob = match X25519KeyPair::generate() {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Perform Diffie-Hellman key exchange
    let alice_shared = match alice.diffie_hellman(&bob.public_key()) {
        Ok(s) => s,
        Err(_) => return,
    };

    let bob_shared = match bob.diffie_hellman(&alice.public_key()) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Shared secrets should match
    assert_eq!(
        alice_shared.as_bytes(),
        bob_shared.as_bytes(),
        "Shared secrets should match"
    );

    // Derive keys with different info should produce different keys
    let info1 = &data[..data.len() / 2];
    let info2 = &data[data.len() / 2..];

    if !info1.is_empty() && !info2.is_empty() && info1 != info2 {
        if let (Ok(key1), Ok(key2)) = (
            alice_shared.derive_key(info1, 32),
            alice_shared.derive_key(info2, 32),
        ) {
            assert_ne!(
                key1.as_slice(),
                key2.as_slice(),
                "Different info should produce different keys"
            );
        }
    }

    // Same info should produce same key (determinism)
    if let (Ok(key1), Ok(key2)) = (
        alice_shared.derive_key(b"test", 32),
        alice_shared.derive_key(b"test", 32),
    ) {
        assert_eq!(key1.as_slice(), key2.as_slice(), "Key derivation should be deterministic");
    }
});
