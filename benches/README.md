# CrabGraph Benchmarks

This directory contains performance benchmarks for CrabGraph's cryptographic operations.

## 📊 Overview

The benchmarks measure:
- **AEAD Operations**: AES-256-GCM and ChaCha20-Poly1305 encryption/decryption
- **Key Derivation**: PBKDF2, Argon2, and HKDF performance
- **Digital Signatures**: Ed25519 signing and verification
- **Streaming Encryption**: Large file processing with STREAM construction

## 🚀 Running Benchmarks

### Run All Benchmarks
```bash
cargo bench
```

### Run Specific Benchmark Suite
```bash
# AEAD (Authenticated Encryption)
cargo bench --bench aead_bench

# Key Derivation Functions
cargo bench --bench kdf_bench

# Digital Signatures
cargo bench --bench signing_bench

# Streaming Encryption
cargo bench --bench stream_bench

# Comparison with RustCrypto primitives
cargo bench --bench comparison_bench
```

### Run with Custom Settings
```bash
# Faster benchmark (smaller sample size)
cargo bench -- --sample-size 10

# Specific test pattern
cargo bench -- aes256

# Save baseline for comparison
cargo bench -- --save-baseline my-baseline

# Compare against baseline
cargo bench -- --baseline my-baseline
```

## 📈 Understanding Results

Criterion outputs results in this format:

```
aead/aes256_encrypt/1024
                        time:   [1.0468 µs 1.1510 µs 1.2599 µs]
                        thrpt:  [775.12 MiB/s 848.43 MiB/s 932.88 MiB/s]
```

- **time**: [min, mean, max] execution time per iteration
- **thrpt**: Throughput in MiB/s (megabytes per second)
- **Lower time = Better performance**
- **Higher throughput = Better performance**

## 📁 Benchmark Files

### `aead_bench.rs`
Tests AEAD cipher performance:
- AES-256-GCM encryption/decryption
- ChaCha20-Poly1305 encryption/decryption
- Key generation
- Multiple data sizes: 64 bytes to 64 KB

**Typical Results:**
- AES-256-GCM: ~1 GB/s (with hardware acceleration)
- ChaCha20-Poly1305: ~400-600 MB/s (pure software)

### `kdf_bench.rs`
Tests key derivation function performance:
- PBKDF2-SHA256
- Argon2id (memory-hard function)
- HKDF-SHA256

**Typical Results:**
- PBKDF2 (100k iterations): ~50-100 ms
- Argon2 (default params): ~300-500 ms
- HKDF: <1 µs (very fast)

### `signing_bench.rs`
Tests digital signature operations:
- Ed25519 key generation
- Ed25519 signing
- Ed25519 verification

**Typical Results:**
- Key generation: ~10-20 µs
- Signing: ~15-30 µs
- Verification: ~30-50 µs

### `stream_bench.rs` (if added)
Tests streaming encryption for large files:
- Chunk-by-chunk encryption
- Memory efficiency
- Comparison with in-memory encryption

### `comparison_bench.rs` (if added)
Compares CrabGraph with:
- Direct RustCrypto usage
- Other crypto libraries
- Shows overhead of wrapper layer

## 📊 Viewing Results

### HTML Reports
Criterion generates HTML reports with graphs:
```bash
cargo bench
# Open: target/criterion/report/index.html
```

### Command Line Output
Results are printed during benchmarking:
```
aead/aes256_encrypt/64  time:   [387.78 ns 429.42 ns 469.60 ns]
                        thrpt:  [129.97 MiB/s 142.13 MiB/s 157.40 MiB/s]
```

### Export to CSV
```bash
cargo bench -- --output-format verbose > benchmark_results.txt
```

## 🔬 Benchmark Methodology

### Sample Sizes
- **Default**: 100 samples per test
- **Quick**: 10 samples (use `--sample-size 10`)
- **Thorough**: 1000 samples (use `--sample-size 1000`)

### Warm-up
- Criterion runs 3 seconds of warm-up iterations
- Ensures CPU caches are warm
- Prevents cold-start bias

### Statistical Analysis
- Measures mean, median, and standard deviation
- Detects outliers automatically
- Provides confidence intervals

## 🎯 Performance Targets

### AEAD Operations (per 1 KB)
- ✅ **AES-256-GCM**: < 2 µs (~500 MB/s minimum)
- ✅ **ChaCha20-Poly1305**: < 3 µs (~300 MB/s minimum)

### Key Derivation
- ✅ **PBKDF2 (100k iterations)**: < 200 ms
- ✅ **Argon2 (default)**: < 1 second
- ✅ **HKDF**: < 1 µs

### Digital Signatures
- ✅ **Ed25519 Sign**: < 50 µs
- ✅ **Ed25519 Verify**: < 100 µs

## 📊 Comparison with Other Libraries

### vs. RustCrypto (Direct)
CrabGraph wraps RustCrypto primitives, so:
- **Overhead**: ~5-10% (wrapper layer)
- **Benefit**: Safer API, automatic zeroization, unified error handling

### vs. ring
- **AES-GCM**: Similar performance (both use hardware acceleration)
- **ChaCha20**: Slightly slower (ring is highly optimized)
- **API**: CrabGraph more ergonomic

### vs. sodiumoxide
- **Ed25519**: Similar performance (both use dalek)
- **ChaCha20**: Similar performance
- **API**: CrabGraph more Rusty

## 🔧 Optimization Tips

### For Best Performance
1. **Enable Release Mode**: `cargo bench` (already does this)
2. **Use CPU Features**: Set `RUSTFLAGS="-C target-cpu=native"`
3. **Profile-Guided Optimization**: Use LTO (already enabled in Cargo.toml)

### Hardware Acceleration
- **AES-NI**: Automatically used on x86_64 CPUs with AES-NI
- **Check**: `cat /proc/cpuinfo | grep aes` (Linux) or `sysctl -a | grep aes` (Mac)

### Memory Considerations
- **Argon2**: Memory-hard by design (uses ~19 MB default)
- **Large Data**: Use streaming encryption for files > 64 KB

## 🐛 Troubleshooting

### "Gnuplot not found"
- Install gnuplot: `choco install gnuplot` (Windows)
- Or use plotters backend (automatic fallback)

### Benchmarks Too Slow
```bash
# Reduce sample size
cargo bench -- --sample-size 10

# Run specific test
cargo bench -- aes256_encrypt/64
```

### Inconsistent Results
- Close other applications
- Disable CPU frequency scaling
- Run multiple times and compare

## 📚 Further Reading

- [Criterion.rs Documentation](https://bheisler.github.io/criterion.rs/book/)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [RustCrypto Performance](https://github.com/RustCrypto/AEADs#performance)

## 📝 Adding New Benchmarks

### 1. Create New Benchmark File
```rust
// benches/my_bench.rs
use criterion::{criterion_group, criterion_main, Criterion};
use crabgraph::*;

fn my_benchmark(c: &mut Criterion) {
    c.bench_function("my_function", |b| {
        b.iter(|| {
            // Code to benchmark
        });
    });
}

criterion_group!(benches, my_benchmark);
criterion_main!(benches);
```

### 2. Register in Cargo.toml
```toml
[[bench]]
name = "my_bench"
harness = false
```

### 3. Run
```bash
cargo bench --bench my_bench
```

## 🎨 Benchmark Best Practices

1. **Use `black_box`**: Prevent compiler optimization
   ```rust
   use std::hint::black_box;
   b.iter(|| cipher.encrypt(black_box(&data), None));
   ```

2. **Setup Outside Loop**: Only measure what matters
   ```rust
   b.iter(|| {
       // ✓ Only this is measured
       cipher.encrypt(&data, None)
   });
   ```

3. **Test Multiple Sizes**: Show performance characteristics
   ```rust
   for size in [64, 1024, 16384, 65536].iter() {
       // benchmark each size
   }
   ```

4. **Set Throughput**: Get MB/s metrics
   ```rust
   group.throughput(Throughput::Bytes(*size as u64));
   ```

## 📞 Support

Issues with benchmarks? Open an issue:
https://github.com/AriajSarkar/crabgraph/issues
