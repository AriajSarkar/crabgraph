#![no_main]

use libfuzzer_sys::fuzz_target;
use crabgraph::asym::Ed25519KeyPair;

fuzz_target!(|data: &[u8]| {
    // Limit message size
    if data.len() > 10000 {
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

    // Verification with wrong message should fail
    let mut wrong_message = data.to_vec();
    if !wrong_message.is_empty() {
        wrong_message[0] ^= 0xFF;
        assert!(
            keypair.verify(&wrong_message, &signature).is_err(),
            "Verification should fail with wrong message"
        );
    }

    // Verification with tampered signature should fail
    let mut tampered_sig = *signature.as_bytes();
    if !tampered_sig.is_empty() {
        tampered_sig[0] ^= 0xFF;
        let bad_sig = match crabgraph::asym::Ed25519Signature::from_bytes(&tampered_sig) {
            Ok(s) => s,
            Err(_) => return, // Invalid signature format is okay
        };
        assert!(
            keypair.verify(data, &bad_sig).is_err(),
            "Verification should fail with tampered signature"
        );
    }

    // Public key verification
    let public_key = keypair.public_key();
    assert!(
        public_key.verify(data, &signature).is_ok(),
        "Public key verification should succeed"
    );
});
