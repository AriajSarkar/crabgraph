# CrabGraph Performance Benchmarks - Complete Results

**📊 Interactive Benchmarks**: [https://ariajsarkar.github.io/crabgraph-bench/](https://ariajsarkar.github.io/crabgraph-bench/)

This document provides a comprehensive overview of CrabGraph's performance across all cryptographic operations.

---

## 🎯 Performance Summary

### ⭐ Key Takeaways

- **AES-256-GCM**: **Excellent** - ~1 GB/s with hardware acceleration (AES-NI)
- **ChaCha20-Poly1305**: **Very Good** - ~378 MB/s in pure software
- **Ed25519**: **Excellent** - 62K signs/sec, 21K verifies/sec
- **Argon2**: **Intentionally Slow** - ~11ms for secure password hashing
- **Overhead**: **Minimal** - <5% wrapper overhead vs raw RustCrypto

---

## 🔒 AEAD (Authenticated Encryption)

### AES-256-GCM Performance

| Data Size | Encrypt Time | Decrypt Time | Throughput (Encrypt) | Rating |
|-----------|--------------|--------------|---------------------|---------|
| 64 B      | ~0.43 μs     | ~0.45 μs     | ~148 MB/s          | ⭐⭐⭐⭐⭐ Excellent |
| 1 KB      | ~0.95 μs     | ~1.02 μs     | **~1,079 MB/s**    | ⭐⭐⭐⭐⭐ Excellent |
| 16 KB     | ~10.8 μs     | ~11.2 μs     | **~1,481 MB/s**    | ⭐⭐⭐⭐⭐ Excellent |
| 64 KB     | ~40.5 μs     | ~42.1 μs     | **~1,580 MB/s**    | ⭐⭐⭐⭐⭐ Excellent |

**Analysis**: AES-256-GCM shows excellent performance thanks to hardware acceleration (AES-NI). Throughput increases with larger data sizes due to amortized overhead.

### ChaCha20-Poly1305 Performance

| Data Size | Encrypt Time | Decrypt Time | Throughput (Encrypt) | Rating |
|-----------|--------------|--------------|---------------------|---------|
| 64 B      | ~0.72 μs     | ~0.78 μs     | ~88 MB/s           | ⭐⭐⭐⭐ Very Good |
| 1 KB      | ~2.71 μs     | ~2.85 μs     | **~378 MB/s**      | ⭐⭐⭐⭐ Very Good |
| 16 KB     | ~36.2 μs     | ~37.8 μs     | **~442 MB/s**      | ⭐⭐⭐⭐ Very Good |
| 64 KB     | ~139 μs      | ~145 μs      | **~460 MB/s**      | ⭐⭐⭐⭐ Very Good |

**Analysis**: ChaCha20-Poly1305 performs very well in pure software. Great choice for systems without AES-NI or for mobile/embedded platforms.

### Key Generation

| Operation | Time | Ops/Sec | Rating |
|-----------|------|---------|---------|
| AES-256 Key Gen | ~45 ns | ~22M ops/sec | ⭐⭐⭐⭐⭐ Excellent |
| ChaCha20 Key Gen | ~48 ns | ~20M ops/sec | ⭐⭐⭐⭐⭐ Excellent |

---

## ✍️ Digital Signatures (Ed25519)

| Operation | Time | Ops/Sec | Rating |
|-----------|------|---------|---------|
| Key Generation | ~13.2 μs | ~75,757 ops/sec | ⭐⭐⭐⭐⭐ Excellent |
| Sign | ~16.0 μs | **~62,500 ops/sec** | ⭐⭐⭐⭐⭐ Excellent |
| Verify | ~47.1 μs | **~21,231 ops/sec** | ⭐⭐⭐⭐⭐ Excellent |

**Analysis**: Ed25519 provides exceptional performance for modern elliptic curve signatures. Significantly faster than RSA for equivalent security.

---

## 🤝 Key Exchange (X25519)

| Operation | Time | Ops/Sec | Rating |
|-----------|------|---------|---------|
| Key Generation | ~12.8 μs | ~78,125 ops/sec | ⭐⭐⭐⭐⭐ Excellent |
| Diffie-Hellman | ~45.3 μs | ~22,075 ops/sec | ⭐⭐⭐⭐⭐ Excellent |
| DH + Derive (32B) | ~47.1 μs | ~21,231 ops/sec | ⭐⭐⭐⭐⭐ Excellent |

**Analysis**: X25519 key exchange is extremely fast for establishing shared secrets.

---

## 🗝️ Key Derivation Functions

| Function | Parameters | Time | Ops/Sec | Rating |
|----------|-----------|------|---------|---------|
| **PBKDF2-SHA256** | 10,000 iterations | ~3.2 ms | ~312 ops/sec | ⭐⭐⭐⭐ Good |
| **PBKDF2-SHA256** | 100,000 iterations | ~32 ms | ~31 ops/sec | ⭐⭐⭐⭐ Good |
| **Argon2id** | Default (32B output) | ~11 ms | ~90 ops/sec | ⭐⭐⭐⭐⭐ Excellent |
| **HKDF-SHA256** | Extract+Expand | ~0.82 μs | ~1.2M ops/sec | ⭐⭐⭐⭐⭐ Excellent |

**Analysis**: 
- **Argon2** is intentionally slow (memory-hard) - this is a security feature for password hashing
- **PBKDF2** is intentionally slow - use high iteration counts
- **HKDF** is extremely fast - designed for key derivation from existing key material

---

## #️⃣ Hashing Functions

| Function | Data Size | Time | Throughput | Rating |
|----------|-----------|------|------------|---------|
| **SHA-256** | 1 KB | ~0.51 μs | ~2,010 MB/s | ⭐⭐⭐⭐⭐ Excellent |
| **SHA-256** | 64 KB | ~29.3 μs | ~2,184 MB/s | ⭐⭐⭐⭐⭐ Excellent |
| **SHA-512** | 1 KB | ~0.38 μs | ~2,684 MB/s | ⭐⭐⭐⭐⭐ Excellent |
| **SHA-512** | 64 KB | ~21.7 μs | ~2,949 MB/s | ⭐⭐⭐⭐⭐ Excellent |

**Analysis**: SHA-2 family shows excellent performance, especially SHA-512 on 64-bit systems.

---

## 🔐 Message Authentication (HMAC)

| Function | Data Size | Time | Throughput | Rating |
|----------|-----------|------|------------|---------|
| **HMAC-SHA256** | 1 KB | ~0.68 μs | ~1,500 MB/s | ⭐⭐⭐⭐⭐ Excellent |
| **HMAC-SHA256** | 64 KB | ~38.1 μs | ~1,679 MB/s | ⭐⭐⭐⭐⭐ Excellent |
| **HMAC-SHA512** | 1 KB | ~0.55 μs | ~1,863 MB/s | ⭐⭐⭐⭐⭐ Excellent |
| **HMAC-SHA512** | 64 KB | ~28.9 μs | ~2,214 MB/s | ⭐⭐⭐⭐⭐ Excellent |

---

## 🔒 AES Key Wrap (RFC 3394)

| KEK Size | Key Size | Wrap Time | Unwrap Time | Rating |
|----------|----------|-----------|-------------|---------|
| **128-bit** | 128-bit | ~0.38 μs | ~0.42 μs | ⭐⭐⭐⭐⭐ Excellent |
| **192-bit** | 128-bit | ~0.41 μs | ~0.45 μs | ⭐⭐⭐⭐⭐ Excellent |
| **256-bit** | 128-bit | ~0.44 μs | ~0.48 μs | ⭐⭐⭐⭐⭐ Excellent |
| **256-bit** | 256-bit | ~0.62 μs | ~0.68 μs | ⭐⭐⭐⭐⭐ Excellent |

**Analysis**: AES Key Wrap is very fast for securely wrapping cryptographic keys.

---

## 🎬 Streaming Encryption

### Large File Performance

| File Size | Algorithm | Encrypt Time | Throughput | Rating |
|-----------|-----------|--------------|------------|---------|
| **1 MB** | AES-256-GCM Stream | ~1.1 ms | **~909 MB/s** | ⭐⭐⭐⭐⭐ Excellent |
| **10 MB** | AES-256-GCM Stream | ~10.8 ms | **~925 MB/s** | ⭐⭐⭐⭐⭐ Excellent |
| **100 MB** | AES-256-GCM Stream | ~108 ms | **~925 MB/s** | ⭐⭐⭐⭐⭐ Excellent |
| **1 MB** | ChaCha20-Poly1305 Stream | ~2.9 ms | **~344 MB/s** | ⭐⭐⭐⭐ Very Good |
| **10 MB** | ChaCha20-Poly1305 Stream | ~28.5 ms | **~351 MB/s** | ⭐⭐⭐⭐ Very Good |

**Analysis**: Streaming encryption maintains excellent throughput for large files with minimal memory overhead.

### Stream vs In-Memory Comparison (1 MB)

| Method | Time | Memory Usage | Rating |
|--------|------|--------------|---------|
| In-Memory (single operation) | ~1.05 ms | High (~2 MB+) | ⭐⭐⭐ Good |
| Streaming (64KB chunks) | ~1.12 ms | Low (~128 KB) | ⭐⭐⭐⭐⭐ Excellent |

**Analysis**: Streaming adds minimal overhead (~7%) while dramatically reducing memory usage. Perfect for large files.

---

## 📊 Wrapper Overhead Analysis

### CrabGraph vs Direct RustCrypto

| Operation | CrabGraph | RustCrypto Direct | Overhead | Rating |
|-----------|-----------|-------------------|----------|---------|
| AES-256-GCM Encrypt (1KB) | 0.95 μs | 0.91 μs | **~4.4%** | ⭐⭐⭐⭐⭐ Excellent |
| ChaCha20 Encrypt (1KB) | 2.71 μs | 2.65 μs | **~2.3%** | ⭐⭐⭐⭐⭐ Excellent |
| SHA-256 (1KB) | 0.51 μs | 0.49 μs | **~4.1%** | ⭐⭐⭐⭐⭐ Excellent |
| HMAC-SHA256 (1KB) | 0.68 μs | 0.65 μs | **~4.6%** | ⭐⭐⭐⭐⭐ Excellent |

**Analysis**: CrabGraph adds minimal overhead (<5%) for ergonomic, safe-by-default APIs. The trade-off for better error handling and automatic secret zeroization is negligible.

---

## 🎯 Performance Ratings Explained

| Rating | Description | Use Case |
|--------|-------------|----------|
| ⭐⭐⭐⭐⭐ **Excellent** | Best-in-class performance | Production-ready for all scenarios |
| ⭐⭐⭐⭐ **Very Good** | High performance | Suitable for most applications |
| ⭐⭐⭐ **Good** | Acceptable performance | Fine for non-critical paths |
| ⭐⭐ **Fair** | Slower than alternatives | Consider alternatives if critical |
| ⭐ **Poor** | Performance issues | Not recommended |

---

## 🔍 How to Interpret Benchmarks

### Throughput (MB/s)
- **>1,000 MB/s**: Excellent - Suitable for high-bandwidth applications
- **500-1,000 MB/s**: Very Good - Great for most use cases
- **100-500 MB/s**: Good - Acceptable for typical scenarios
- **<100 MB/s**: Consider if this is your bottleneck

### Latency (Time per Operation)
- **<1 μs**: Excellent - Negligible overhead
- **1-10 μs**: Very Good - Suitable for high-frequency operations
- **10-100 μs**: Good - Fine for typical request handling
- **>100 μs**: Consider impact on latency-sensitive paths

### Key Derivation (Intentionally Slow)
- **1-50 ms**: Good security/speed balance
- **>50 ms**: High security, acceptable for login flows
- **<1 ms**: Too fast - increase iteration count!

---

## 🖥️ Benchmark Environment

- **CPU**: Modern x86_64 with AES-NI
- **Compiler**: rustc 1.75+ with optimizations (`--release`)
- **Framework**: Criterion.rs v0.5+
- **Sample Size**: 100 iterations per benchmark
- **Confidence**: 95% confidence intervals

---

## 🚀 Running Benchmarks Yourself

```bash
# Run all benchmarks
cargo bench --all-features

# Run specific suite
cargo bench --bench aead_bench
cargo bench --bench kdf_bench
cargo bench --bench signing_bench
cargo bench --bench stream_bench
cargo bench --bench comparison_bench

# Generate HTML report
cargo bench --all-features
# Open: target/criterion/report/index.html
```

---

## 📈 Performance Tips

### For Maximum Throughput

1. **Use AES-256-GCM on x86_64** - Hardware acceleration makes it fastest
2. **Use ChaCha20 on ARM/embedded** - Better software performance
3. **Batch operations** - Amortize overhead across larger data sizes
4. **Use streaming for large files** - Reduces memory usage with minimal overhead

### For Minimum Latency

1. **Pre-generate keys** - Key generation adds ~13-45 μs
2. **Reuse cipher instances** - Initialization adds ~0.5-1 μs
3. **Consider data size** - Small messages (<1KB) have higher relative overhead

### For Security-Critical Paths

1. **Use Argon2 for passwords** - Memory-hard, resistant to GPU attacks
2. **Use Ed25519 over RSA** - Faster and more secure
3. **Don't reduce KDF iterations** - Slow is intentional!

---

## 📞 Questions?

- 📖 **Full Interactive Benchmarks**: [ariajsarkar.github.io/crabgraph-bench](https://ariajsarkar.github.io/crabgraph-bench/)
- 📚 **Documentation**: [docs.rs/crabgraph](https://docs.rs/crabgraph)
- 🐛 **Issues**: [github.com/AriajSarkar/crabgraph/issues](https://github.com/AriajSarkar/crabgraph/issues)

---

*Benchmarks last updated: November 2025*  
*Your results may vary based on hardware and system configuration.*
