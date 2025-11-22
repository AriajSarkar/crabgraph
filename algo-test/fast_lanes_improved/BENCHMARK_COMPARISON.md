# FastLanes vs Industry-Standard AEAD: Benchmark Comparison

## System Configuration

- **Platform**: Windows (x86_64)
- **Compiler**: Rust stable
- **Flags**: `RUSTFLAGS="-C target-cpu=native"` (AVX2, AES-NI enabled)
- **Framework**: Criterion.rs v0.7.0

## Implementations

| Implementation | Type | Acceleration | Notes |
|---|---|---|---|
| **FastLanes (Auto)** | ChaCha20-variant | AVX2 intrinsics (pure Rust) | 4 rounds, experimental |
| **Ring AES-GCM** | AES-256-GCM | AES-NI (BoringSSL bindings) | Industry standard |
| **OpenSSL AES-GCM** | AES-256-GCM | AES-NI (OpenSSL bindings) | Industry standard |

## Results

### Small Messages (64 bytes)

| Implementation | Latency (ns) | Throughput (GiB/s) | vs FastLanes |
|---|---|---|---|
| **FastLanes_Auto** | **90.64** | **0.66** | Baseline |
| Ring_AES_GCM | 130.35 | 0.46 | **1.44x slower** |
| OpenSSL_AES_GCM | 776.21 | 0.08 | **8.56x slower** |

### Medium Messages (1 KB)

| Implementation | Latency (ns) | Throughput (GiB/s) | vs FastLanes |
|---|---|---|---|
| **FastLanes_Auto** | **153.94** | **6.20** | Baseline |
| Ring_AES_GCM | 230.73 | 4.13 | **1.50x slower** |
| OpenSSL_AES_GCM | 939.07 | 1.02 | **6.10x slower** |

### Large Messages (1 MB)

| Implementation | Latency (µs) | Throughput (GiB/s) | vs FastLanes |
|---|---|---|---|
| **FastLanes_Auto** | **160.94** | **6.07** | Baseline |
| Ring_AES_GCM | 601.79 | 1.62 | **3.74x slower** |
| OpenSSL_AES_GCM | 400.36 | 2.44 | **2.49x slower** |

## Key Findings

✅ **FastLanes outperforms Ring and OpenSSL** across all message sizes  
✅ **6.20 GiB/s peak throughput** @ 1KB (sustained @ 1MB: 6.07 GiB/s)  
✅ **1.5-8.5x faster** than industry-standard AES-GCM implementations  
✅ **Zero heap allocation** (FastLanes); Ring/OpenSSL allocate Vec per operation  

⚠️ **NOT CRYPTOGRAPHICALLY SECURE** - experimental, reduced rounds, unaudited  
⚠️ **NOT FOR PRODUCTION USE**

## Performance Analysis

**Why is FastLanes faster?**
1. **Pure Rust AVX2**: No FFI overhead, explicit SIMD intrinsics
2. **Reduced rounds**: 4 rounds vs 10 (AES) / 20 (ChaCha20)
3. **Lightweight MAC**: Simpler than Poly1305/GHASH
4. **In-place operation**: No allocations during encryption
5. **8-way parallelism**: AVX2 processes 512 bytes/iteration

**Ring performance notes:**
- AES-GCM typically faster than ChaCha20Poly1305 on x86 (AES-NI)
- Vec allocation adds ~40ns overhead per operation
- Still 1.62-4.13 GiB/s - respectable for production-grade crypto

**OpenSSL performance:**
- Vendored build may not be fully optimized
- encrypt_aead() API forces allocations
- Native OpenSSL install might perform better

## Reproduction

```powershell
$Env:RUSTFLAGS="-C target-cpu=native"
cargo bench --bench fast_lanes_compare
```

Results: `target/criterion/crypto_comparison/`

## Disclaimer

**FastLanes is a research prototype.** Use Ring or RustCrypto for production systems.
