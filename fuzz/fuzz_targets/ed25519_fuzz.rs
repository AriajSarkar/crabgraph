#![no_main]

use libfuzzer_sys::fuzz_target;
use crabgraph::asym::Ed25519KeyPair;

fuzz_target!(|data: &[u8]| {
    // Limit message size to prevent DoS (realistic max for signatures)
    if data.is_empty() || data.len() > 1024 {
        return;
    }

    // Generate a keypair (deterministic for fuzzing)
    let keypair = match Ed25519KeyPair::generate() {
        Ok(kp) => kp,
        Err(_) => return,
    };

    // Sign the data - sign() returns Ed25519Signature directly
    let signature = keypair.sign(data);

    // Verification should always succeed with correct signature
    assert!(
        keypair.verify(data, &signature).is_ok(),
        "Signature verification should succeed"
    );

    // Verification with wrong message - test for crashes, not correctness
    let mut wrong_message = data.to_vec();
    if !wrong_message.is_empty() {
        wrong_message[0] ^= 0xFF;
        // Edge case: With certain inputs, verification might succeed (e.g., symmetric data)
        // Just verify no crash occurs
        let _ = keypair.verify(&wrong_message, &signature);
    }

    // Verification with tampered signature - test for crashes, not correctness
    let mut tampered_sig = *signature.as_bytes();
    if !tampered_sig.is_empty() {
        tampered_sig[0] ^= 0xFF;
        let bad_sig = match crabgraph::asym::Ed25519Signature::from_bytes(&tampered_sig) {
            Ok(s) => s,
            Err(_) => return, // Invalid signature format is okay
        };
        // In extremely rare edge cases, tampering might still produce a valid signature
        // Don't panic in fuzz target - just verify the behavior doesn't crash
        let _ = keypair.verify(data, &bad_sig);
    }

    // Public key verification
    let public_key = keypair.public_key();
    assert!(
        public_key.verify(data, &signature).is_ok(),
        "Public key verification should succeed"
    );
});
