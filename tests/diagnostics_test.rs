#[cfg(test)]
mod tests {
    use crabgraph::diagnostics;

    #[test]
    fn test_diagnostics() {
        let warnings = diagnostics::check_performance();
        if warnings.is_empty() {
            println!("No warnings detected. Either SIMD is enabled or CPU doesn't support it.");
        } else {
            println!("Performance warnings detected:");
            for w in warnings {
                println!("- {}", w);
            }
        }
        
        // We expect warnings if we are on x86_64 and haven't enabled AVX2
        #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), not(target_feature = "avx2")))]
        {
            if std::is_x86_feature_detected!("avx2") {
                let warnings = diagnostics::check_performance();
                assert!(warnings.iter().any(|w| w.contains("AVX2")), "Should warn about missing AVX2");
            }
        }
    }
}
