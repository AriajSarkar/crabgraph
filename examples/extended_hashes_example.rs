//! Example demonstrating SHA-3 and BLAKE2 hash functions.
//!
//! This example requires the `extended-hashes` feature:
//! ```bash
//! cargo run --example extended_hashes_example --features extended-hashes
//! ```

use crabgraph::hash::{
    blake2b_512, blake2b_512_hex, blake2s_256, blake2s_256_hex, sha256, sha256_hex, sha3_256,
    sha3_256_hex, sha3_512, sha3_512_hex, sha512, sha512_hex,
};

fn main() {
    println!("🦀 CrabGraph Extended Hash Functions Demo\n");
    println!("===========================================\n");

    let data = b"The quick brown fox jumps over the lazy dog";
    println!("Input: {:?}\n", std::str::from_utf8(data).unwrap());

    // SHA-2 Family (always available)
    println!("📊 SHA-2 Family:");
    println!("  SHA-256:   {}", sha256_hex(data));
    println!("  SHA-512:   {}\n", sha512_hex(data));

    // SHA-3 Family (Keccak)
    println!("🌊 SHA-3 Family (Keccak sponge construction):");
    println!("  SHA3-256:  {}", sha3_256_hex(data));
    println!("  SHA3-512:  {}\n", sha3_512_hex(data));

    // BLAKE2 Family (High-performance)
    println!("⚡ BLAKE2 Family (High-performance):");
    println!("  BLAKE2s-256: {}", blake2s_256_hex(data));
    println!("  BLAKE2b-512: {}\n", blake2b_512_hex(data));

    // Binary output comparison
    println!("📏 Digest Sizes:");
    println!("  SHA-256:     {} bytes", sha256(data).len());
    println!("  SHA-512:     {} bytes", sha512(data).len());
    println!("  SHA3-256:    {} bytes", sha3_256(data).len());
    println!("  SHA3-512:    {} bytes", sha3_512(data).len());
    println!("  BLAKE2s-256: {} bytes", blake2s_256(data).len());
    println!("  BLAKE2b-512: {} bytes\n", blake2b_512(data).len());

    // Performance characteristics
    println!("🏎️  Performance Characteristics:");
    println!("  SHA-256:     Good (hardware accelerated on modern CPUs)");
    println!("  SHA-512:     Good (faster than SHA-256 on 64-bit systems)");
    println!("  SHA3-256:    Moderate (newer algorithm, some CPUs have hardware support)");
    println!("  SHA3-512:    Moderate (slower than SHA-512 but resistant to length extension)");
    println!("  BLAKE2s-256: Excellent (2-3x faster than SHA-256, optimized for 32-bit)");
    println!("  BLAKE2b-512: Excellent (2-3x faster than SHA-512, optimized for 64-bit)\n");

    // Security properties
    println!("🔒 Security Properties:");
    println!("  SHA-2:   Well-studied, NIST standard, widely deployed");
    println!("  SHA-3:   NIST standard (2015), resistant to length extension attacks");
    println!("  BLAKE2:  Extremely fast, secure, used in many modern protocols\n");

    // Use cases
    println!("🎯 When to Use:");
    println!("  SHA-256/512:  Compatibility, regulatory compliance, general purpose");
    println!(
        "  SHA3-256/512: When SHA-2 vulnerabilities discovered, resistance to length extension"
    );
    println!("  BLAKE2s:      High-performance on 32-bit systems, IoT devices, embedded");
    println!("  BLAKE2b:      High-performance on 64-bit systems, password hashing alternative\n");

    // Demonstrate hash verification
    println!("✅ Hash Verification Example:");
    let message = b"Important message";
    let expected_blake2b = blake2b_512(message);

    // Simulate verification
    let received_message = b"Important message";
    let received_hash = blake2b_512(received_message);

    if expected_blake2b == received_hash {
        println!("  ✓ Message integrity verified using BLAKE2b-512!");
    } else {
        println!("  ✗ Message has been tampered with!");
    }

    // Demonstrate different algorithms produce different outputs
    println!("\n🔍 Different Algorithms, Different Outputs:");
    let test = b"test";
    println!("  Input: {:?}", std::str::from_utf8(test).unwrap());
    println!("  SHA-256:     {}", sha256_hex(test));
    println!("  SHA3-256:    {}", sha3_256_hex(test));
    println!("  BLAKE2s-256: {}", blake2s_256_hex(test));
    println!("  ↑ All different! Each algorithm has unique properties.\n");

    // Performance tip
    println!("💡 Performance Tip:");
    println!("  For high-throughput applications (logging, file integrity, etc.),");
    println!("  BLAKE2b is recommended - it's ~3x faster than SHA-512 while maintaining");
    println!("  excellent security properties. SHA-3 should be used when you need");
    println!("  resistance to length extension attacks or future-proofing.\n");

    println!("✨ Done! All extended hash functions working correctly.");
}
