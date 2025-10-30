// Shared utilities for benchmark organization
use std::process::Command;

/// Organizes Criterion benchmark results after benchmarks complete.
/// Moves benchmark folders from target/criterion/ to benches/generated/
/// and extracts the main report index.html
pub fn organize_benchmark_results() {
    #[cfg(target_os = "windows")]
    {
        let result = Command::new("powershell")
            .args([
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                "scripts/organize_benchmarks.ps1",
            ])
            .output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    println!("\n{}", String::from_utf8_lossy(&output.stdout));
                } else {
                    eprintln!(
                        "Warning: Failed to organize benchmarks: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
            Err(e) => {
                eprintln!("Warning: Could not run organize_benchmarks.ps1: {}", e);
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // On Unix systems, try to run with bash if available
        let result = Command::new("bash").args(["scripts/organize_benchmarks.sh"]).output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    println!("\n{}", String::from_utf8_lossy(&output.stdout));
                } else {
                    eprintln!("Note: Benchmark organization not available on this platform");
                }
            }
            Err(_) => {
                eprintln!("Note: Benchmark organization script not available on this platform");
            }
        }
    }
}
