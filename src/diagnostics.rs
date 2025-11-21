//! Diagnostic utilities for checking hardware support and performance optimizations.

/// Checks for available hardware acceleration and returns a list of warnings
/// if optimizations are available but not enabled.
pub fn check_performance() -> Vec<String> {
    #[allow(unused_mut)]
    let mut warnings = Vec::new();

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        // Check AES-NI
        if std::is_x86_feature_detected!("aes") {
            // AES-NI is available.
            // The `aes` crate with `aes` feature should auto-detect this at runtime
            // if compiled with `std` (which we are).
            // However, if the `aes` feature was NOT enabled in Cargo.toml, it might use software fallback.
            // We can't easily check if the *crate* has the feature enabled from here without
            // relying on our own `simd` feature flag as a proxy.

            #[cfg(not(feature = "simd"))]
            {
                warnings.push(
                    "Performance Warning: AES-NI is detected on this CPU but the 'simd' feature is disabled. \
                    Enable the 'simd' feature in Cargo.toml for faster AES-GCM performance.".to_string()
                );
            }
        }

        // Check AVX2 for ChaCha20
        if std::is_x86_feature_detected!("avx2") {
            // AVX2 is available.
            // ChaCha20 crate on stable Rust REQUIRES target-feature=+avx2 to use the AVX2 backend.
            // We check if the target feature is enabled.

            #[cfg(not(target_feature = "avx2"))]
            {
                warnings.push(
                    "Performance Warning: AVX2 is detected on this CPU but not enabled in the binary. \
                    ChaCha20-Poly1305 performance will be significantly slower (~2.5x). \
                    To fix, compile with RUSTFLAGS=\"-C target-feature=+avx2\".".to_string()
                );
            }
        }
    }

    warnings
}

/// Prints performance warnings to stderr.
pub fn print_performance_warnings() {
    let warnings = check_performance();
    for warning in warnings {
        eprintln!("⚠️  [CrabGraph] {}", warning);
    }
}
