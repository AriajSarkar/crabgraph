//! Example: Key derivation functions (PBKDF2, Argon2, HKDF)

use crabgraph::{
    kdf::{
        argon2_derive, argon2_derive_with_params, hkdf_extract_expand, pbkdf2_derive_sha256,
        Argon2Params, PBKDF2_SHA256_RECOMMENDED_ITERATIONS,
    },
    rand::secure_bytes,
    CrabResult,
};

fn main() -> CrabResult<()> {
    println!("=== Key Derivation Example ===\n");

    println!("1. Argon2 Password Hashing:");
    argon2_example()?;

    println!("\n2. PBKDF2 Password Hashing:");
    pbkdf2_example()?;

    println!("\n3. HKDF Key Expansion:");
    hkdf_example()?;

    println!("\n4. Custom Argon2 Parameters:");
    argon2_custom_params()?;

    Ok(())
}

fn argon2_example() -> CrabResult<()> {
    // Simulate user registration
    let password = b"correct_horse_battery_staple";
    let salt = secure_bytes(16)?;

    println!("  Password: {}", String::from_utf8_lossy(password));
    println!("  Salt: {} bytes (hex: {})", salt.len(), hex::encode(&salt));

    // Derive key (hash password)
    let hash = argon2_derive(password, &salt, 32)?;
    println!("  Hash: {} bytes", hash.len());
    println!("  Hash (hex): {}...", hex::encode(&hash.as_slice()[..8]));

    // Verify password
    let input_password = b"correct_horse_battery_staple";
    let verified_hash = argon2_derive(input_password, &salt, 32)?;

    if hash.as_slice() == verified_hash.as_slice() {
        println!("  ✓ Password verified successfully!");
    } else {
        println!("  ✗ Password verification failed!");
    }

    // Try wrong password
    let wrong_password = b"wrong_password";
    let wrong_hash = argon2_derive(wrong_password, &salt, 32)?;

    if hash.as_slice() != wrong_hash.as_slice() {
        println!("  ✓ Wrong password correctly rejected!");
    }

    Ok(())
}

fn pbkdf2_example() -> CrabResult<()> {
    let password = b"user_password_123";
    let salt = secure_bytes(16)?;

    println!("  Using {} iterations", PBKDF2_SHA256_RECOMMENDED_ITERATIONS);

    // Derive 256-bit key
    let key = pbkdf2_derive_sha256(password, &salt, PBKDF2_SHA256_RECOMMENDED_ITERATIONS, 32)?;

    println!("  Derived key: {} bytes", key.len());
    println!("  Key (hex): {}...", hex::encode(&key.as_slice()[..8]));

    // PBKDF2 is deterministic
    let key2 = pbkdf2_derive_sha256(password, &salt, PBKDF2_SHA256_RECOMMENDED_ITERATIONS, 32)?;

    assert_eq!(key.as_slice(), key2.as_slice());
    println!("  ✓ PBKDF2 is deterministic");

    Ok(())
}

fn hkdf_example() -> CrabResult<()> {
    // Simulate Diffie-Hellman key exchange result
    let shared_secret = secure_bytes(32)?;
    println!("  Shared secret: {} bytes", shared_secret.len());

    // Derive multiple keys for different purposes
    let encryption_key = hkdf_extract_expand(b"app_v1_salt", &shared_secret, b"encryption", 32)?;

    let mac_key = hkdf_extract_expand(b"app_v1_salt", &shared_secret, b"authentication", 32)?;

    println!("  Encryption key: {} bytes", encryption_key.len());
    println!("  MAC key: {} bytes", mac_key.len());
    println!("  Keys are different: {}", encryption_key.as_slice() != mac_key.as_slice());
    println!("  ✓ HKDF key expansion successful!");

    Ok(())
}

fn argon2_custom_params() -> CrabResult<()> {
    let password = b"high_security_password";
    let salt = secure_bytes(16)?;

    // Use high-security parameters
    let params = Argon2Params::high_security();
    println!("  Memory cost: {} KiB ({} MiB)", params.memory_cost, params.memory_cost / 1024);
    println!("  Time cost: {}", params.time_cost);
    println!("  Parallelism: {}", params.parallelism);

    let hash = argon2_derive_with_params(password, &salt, 32, &params)?;
    println!("  Hash: {} bytes", hash.len());
    println!("  ✓ High-security Argon2 completed!");

    // Compare with interactive parameters
    let interactive_params = Argon2Params::interactive();
    println!("\n  Interactive parameters:");
    println!(
        "  Memory cost: {} KiB ({} MiB)",
        interactive_params.memory_cost,
        interactive_params.memory_cost / 1024
    );
    println!("  Time cost: {}", interactive_params.time_cost);

    Ok(())
}
