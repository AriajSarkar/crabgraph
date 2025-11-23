# Benchmark Results: Samsung S24 FE (Exynos 2400e)

**Platform:** Android (Termux)
**Architecture:** ARM64 (aarch64)
**CPU:** Exynos 2400e (10 cores)
**Compiler:** Rust stable (Termux)

## Results

### Small Messages (64 bytes)

| Implementation | Latency | Throughput |
|---|---|---|
| FastLanes_Auto | 1.58 µs | 0.04 GiB/s |
| Ring_AES_GCM | 327.53 ns | 0.19 GiB/s |
| OpenSSL_AES_GCM | 2.37 µs | 0.03 GiB/s |

### Medium Messages (1 KB)

| Implementation | Latency | Throughput |
|---|---|---|
| FastLanes_Auto | 571.16 ns | 1.67 GiB/s |
| Ring_AES_GCM | 489.08 ns | 1.95 GiB/s |
| OpenSSL_AES_GCM | 8.24 µs | 0.12 GiB/s |

### Large Messages (1 MB)

| Implementation | Latency | Throughput |
|---|---|---|
| FastLanes_Auto | 525.99 µs | 1.86 GiB/s |
| Ring_AES_GCM | 506.70 µs | 1.93 GiB/s |
| OpenSSL_AES_GCM | 509.01 µs | 1.92 GiB/s |

## Analysis

- **Scalar Fallback**: On ARM, `FastLanes` falls back to the scalar implementation (no NEON intrinsics yet).
- **Small Buffers**: `Ring` (using ARMv8 AES hardware intrinsics) is ~5x faster than `FastLanes` (software).
- **Large Buffers**: Surprisingly, `FastLanes` (Scalar) nearly matches `Ring` and `OpenSSL` (Hardware AES) at ~1.9 GiB/s. This suggests excellent compiler auto-vectorization for the scalar loop on the Exynos 2400e.
- **OpenSSL Overhead**: OpenSSL shows high overhead for small/medium buffers on this platform, likely due to initialization costs via FFI.
