//! Example demonstrating serde serialization for cryptographic types.
//!
//! This example shows how to serialize and deserialize:
//! - AEAD ciphertexts (encrypted data)
//! - Ed25519 keypairs and public keys
//! - Ed25519 signatures
//!
//! Run with: cargo run --example serde_example --features serde-support

#[cfg(not(feature = "serde-support"))]
compile_error!("This example requires the 'serde-support' feature. Run with: cargo run --example serde_example --features serde-support");

#[cfg(feature = "serde-support")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use crabgraph::{
        aead::{AesGcm256, CrabAead},
        asym::ed25519::Ed25519KeyPair,
    };

    println!("=== CrabGraph Serde Serialization Example ===\n");

    // ============================================================================
    // Example 1: Serializing Encrypted Data (Ciphertext)
    // ============================================================================
    println!("--- Example 1: AEAD Ciphertext Serialization ---");

    // Encrypt some data
    let plaintext = b"Secret message that needs to be stored";
    let key = AesGcm256::generate_key()?;
    let cipher = AesGcm256::new(&key)?;
    let ciphertext = cipher.encrypt(plaintext, None)?;

    println!("Original plaintext: {:?}", String::from_utf8_lossy(plaintext));

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&ciphertext)?;
    println!("Serialized to JSON:\n{}", json);

    // Deserialize from JSON
    let restored: crabgraph::aead::Ciphertext = serde_json::from_str(&json)?;
    println!("Deserialized from JSON successfully");

    // Verify we can decrypt the restored ciphertext
    let decrypted = cipher.decrypt(&restored, None)?;
    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
    assert_eq!(decrypted, plaintext);
    println!("✓ Roundtrip successful!\n");

    // ============================================================================
    // Example 2: Serializing Ed25519 Public Keys
    // ============================================================================
    println!("--- Example 2: Ed25519 Public Key Serialization ---");

    // Generate a keypair
    let keypair = Ed25519KeyPair::generate()?;
    let public_key = keypair.public_key();

    println!("Public key (hex): {}", public_key.to_hex());

    // Serialize to JSON
    let json = serde_json::to_string(&public_key)?;
    println!("Serialized to JSON: {}", json);

    // Deserialize from JSON
    let restored_pubkey: crabgraph::asym::ed25519::Ed25519PublicKey = serde_json::from_str(&json)?;
    println!("Deserialized from JSON successfully");

    // Verify the keys match
    assert_eq!(public_key.as_bytes(), restored_pubkey.as_bytes());
    println!("✓ Public key roundtrip successful!\n");

    // ============================================================================
    // Example 3: Serializing Ed25519 Signatures
    // ============================================================================
    println!("--- Example 3: Ed25519 Signature Serialization ---");

    let message = b"Important document to sign";
    let signature = keypair.sign(message);

    println!("Message: {:?}", String::from_utf8_lossy(message));
    println!("Signature (hex): {}...", &signature.to_hex()[..32]);

    // Serialize to JSON
    let json = serde_json::to_string(&signature)?;
    println!("Serialized to JSON: {}", json);

    // Deserialize from JSON
    let restored_sig: crabgraph::asym::ed25519::Ed25519Signature = serde_json::from_str(&json)?;
    println!("Deserialized from JSON successfully");

    // Verify the restored signature
    let is_valid = keypair.verify(message, &restored_sig)?;
    println!("Signature verification: {}", is_valid);
    assert!(is_valid);
    println!("✓ Signature roundtrip successful!\n");

    // ============================================================================
    // Example 4: Storing in a Configuration File
    // ============================================================================
    println!("--- Example 4: Configuration File Format ---");

    // Simulate a configuration structure
    #[derive(serde::Serialize, serde::Deserialize)]
    struct ServerConfig {
        server_name: String,
        public_key: crabgraph::asym::ed25519::Ed25519PublicKey,
        encrypted_token: crabgraph::aead::Ciphertext,
    }

    let config = ServerConfig {
        server_name: "api.example.com".to_string(),
        public_key: keypair.public_key(),
        encrypted_token: cipher.encrypt(b"secret_api_token_12345", None)?,
    };

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&config)?;
    println!("Server configuration:\n{}", json);

    // Deserialize back
    let restored_config: ServerConfig = serde_json::from_str(&json)?;
    println!("\n✓ Configuration loaded successfully!");
    println!(
        "Server: {}, Public key: {}...",
        restored_config.server_name,
        &restored_config.public_key.to_hex()[..16]
    );

    // ============================================================================
    // Example 5: Binary Serialization (bincode)
    // ============================================================================
    println!("\n--- Example 5: Binary Serialization (compact) ---");

    // Serialize to compact binary format
    let binary_json = bincode::serialize(&ciphertext)?;
    let binary_pubkey = bincode::serialize(&public_key)?;
    let binary_sig = bincode::serialize(&signature)?;

    println!("Ciphertext JSON size: {} bytes", json.len());
    println!("Ciphertext binary size: {} bytes", binary_json.len());
    println!("Space saved: {}%", 100 - (binary_json.len() * 100 / json.len()));
    println!("\nPublic key binary: {} bytes", binary_pubkey.len());
    println!("Signature binary: {} bytes", binary_sig.len());

    // Deserialize from binary
    let _: crabgraph::aead::Ciphertext = bincode::deserialize(&binary_json)?;
    let _: crabgraph::asym::ed25519::Ed25519PublicKey = bincode::deserialize(&binary_pubkey)?;
    let _: crabgraph::asym::ed25519::Ed25519Signature = bincode::deserialize(&binary_sig)?;
    println!("✓ All binary deserializations successful!\n");

    // ============================================================================
    // Example 6: TOML Configuration
    // ============================================================================
    println!("--- Example 6: TOML Configuration ---");

    #[derive(serde::Serialize, serde::Deserialize)]
    struct AppConfig {
        app_name: String,
        version: String,
        #[serde(with = "serde_bytes")]
        public_key_bytes: Vec<u8>,
    }

    let app_config = AppConfig {
        app_name: "MyApp".to_string(),
        version: "1.0.0".to_string(),
        public_key_bytes: public_key.as_bytes().to_vec(),
    };

    let toml_str = toml::to_string_pretty(&app_config)?;
    println!("TOML configuration:\n{}", toml_str);

    let _: AppConfig = toml::from_str(&toml_str)?;
    println!("✓ TOML roundtrip successful!\n");

    println!("=== All Examples Complete ===");
    println!("\nKey Takeaways:");
    println!("• Ciphertext, public keys, and signatures are serializable");
    println!("• Supports JSON, binary (bincode), TOML, and other serde formats");
    println!("• Binary serialization is more compact than JSON");
    println!("• Perfect for storing encrypted data and cryptographic keys");
    println!("• Always use secure storage for serialized sensitive data!");

    Ok(())
}

#[cfg(not(feature = "serde-support"))]
fn main() {
    eprintln!("This example requires the 'serde-support' feature.");
    eprintln!("Run with: cargo run --example serde_example --features serde-support");
    std::process::exit(1);
}
