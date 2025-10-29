/// Comparison benchmarks: CrabGraph vs Direct RustCrypto usage
///
/// This benchmark measures the overhead of CrabGraph's wrapper layer
/// compared to using RustCrypto primitives directly.
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::path::Path;

// CrabGraph imports
use crabgraph::aead::{AesGcm256, ChaCha20Poly1305, CrabAead};
use crabgraph::hash::{sha256, sha512};
use crabgraph::mac::{hmac_sha256, hmac_sha512};

// Direct RustCrypto imports
use sha2::{Digest, Sha256, Sha512};
use hmac::{Hmac, Mac};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// Compare CrabGraph wrapper performance for AEAD operations
fn compare_aead_wrapper(c: &mut Criterion) {
    let mut group = c.benchmark_group("crabgraph_aead_comparison");

    for size in [1024, 16384, 65536].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // CrabGraph AES-256-GCM encryption
        group.bench_with_input(
            BenchmarkId::new("aes256_encrypt", size),
            size,
            |b, _| {
                let key = AesGcm256::generate_key().unwrap();
                let cipher = AesGcm256::new(&key).unwrap();
                b.iter(|| cipher.encrypt(black_box(&data), None).unwrap());
            },
        );

        // CrabGraph ChaCha20-Poly1305 encryption
        group.bench_with_input(
            BenchmarkId::new("chacha20_encrypt", size),
            size,
            |b, _| {
                let key = ChaCha20Poly1305::generate_key().unwrap();
                let cipher = ChaCha20Poly1305::new(&key).unwrap();
                b.iter(|| cipher.encrypt(black_box(&data), None).unwrap());
            },
        );
    }

    group.finish();
}

/// Compare SHA-256 hashing: CrabGraph vs RustCrypto
fn compare_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison_sha256");

    for size in [64, 1024, 16384, 65536].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // CrabGraph wrapper
        group.bench_with_input(BenchmarkId::new("crabgraph", size), size, |b, _| {
            b.iter(|| black_box(sha256(black_box(&data))));
        });

        // Direct RustCrypto
        group.bench_with_input(BenchmarkId::new("rustcrypto", size), size, |b, _| {
            b.iter(|| {
                let mut hasher = Sha256::new();
                hasher.update(black_box(&data));
                hasher.finalize()
            });
        });
    }

    group.finish();
}

/// Compare SHA-512 hashing: CrabGraph vs RustCrypto
fn compare_sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison_sha512");

    for size in [64, 1024, 16384, 65536].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // CrabGraph wrapper
        group.bench_with_input(BenchmarkId::new("crabgraph", size), size, |b, _| {
            b.iter(|| black_box(sha512(black_box(&data))));
        });

        // Direct RustCrypto
        group.bench_with_input(BenchmarkId::new("rustcrypto", size), size, |b, _| {
            b.iter(|| {
                let mut hasher = Sha512::new();
                hasher.update(black_box(&data));
                hasher.finalize()
            });
        });
    }

    group.finish();
}

/// Compare HMAC-SHA256: CrabGraph vs RustCrypto
fn compare_hmac_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison_hmac_sha256");

    let key = b"super_secret_key_32_bytes_long!!";

    for size in [64, 1024, 16384, 65536].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // CrabGraph wrapper
        group.bench_with_input(BenchmarkId::new("crabgraph", size), size, |b, _| {
            b.iter(|| hmac_sha256(key, black_box(&data)).unwrap());
        });

        // Direct RustCrypto
        group.bench_with_input(BenchmarkId::new("rustcrypto", size), size, |b, _| {
            b.iter(|| {
                let mut mac = HmacSha256::new_from_slice(key).unwrap();
                mac.update(black_box(&data));
                mac.finalize()
            });
        });
    }

    group.finish();
}

/// Compare HMAC-SHA512: CrabGraph vs RustCrypto
fn compare_hmac_sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison_hmac_sha512");

    let key = b"super_secret_key_32_bytes_long!!";

    for size in [64, 1024, 16384, 65536].iter() {
        let data = vec![0u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // CrabGraph wrapper
        group.bench_with_input(BenchmarkId::new("crabgraph", size), size, |b, _| {
            b.iter(|| hmac_sha512(key, black_box(&data)).unwrap());
        });

        // Direct RustCrypto
        group.bench_with_input(BenchmarkId::new("rustcrypto", size), size, |b, _| {
            b.iter(|| {
                let mut mac = HmacSha512::new_from_slice(key).unwrap();
                mac.update(black_box(&data));
                mac.finalize()
            });
        });
    }

    group.finish();
}

/// Benchmark the overhead of CrabGraph's error handling
fn overhead_analysis(c: &mut Criterion) {
    let mut group = c.benchmark_group("overhead_analysis");

    // Measure key generation overhead
    group.bench_function("aes256_key_gen", |b| {
        b.iter(|| AesGcm256::generate_key().unwrap());
    });

    group.bench_function("chacha20_key_gen", |b| {
        b.iter(|| ChaCha20Poly1305::generate_key().unwrap());
    });

    // Measure cipher initialization overhead
    group.bench_function("aes256_cipher_init", |b| {
        let key = AesGcm256::generate_key().unwrap();
        b.iter(|| AesGcm256::new(black_box(&key)).unwrap());
    });

    group.bench_function("chacha20_cipher_init", |b| {
        let key = ChaCha20Poly1305::generate_key().unwrap();
        b.iter(|| ChaCha20Poly1305::new(black_box(&key)).unwrap());
    });

    group.finish();
}

fn configure_criterion() -> Criterion {
    Criterion::default()
        .output_directory(Path::new("benches/generated"))
}

criterion_group! {
    name = benches;
    config = configure_criterion();
    targets = compare_aead_wrapper, compare_sha256, compare_sha512, compare_hmac_sha256, compare_hmac_sha512, overhead_analysis
}
criterion_main!(benches);
