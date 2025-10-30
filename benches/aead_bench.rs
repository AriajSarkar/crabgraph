use crabgraph::aead::{AesGcm256, ChaCha20Poly1305, CrabAead};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::path::Path;

fn aead_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("aead");

    // Benchmark different message sizes
    for size in [64, 1024, 16384, 65536].iter() {
        let data = vec![0u8; *size];

        // AES-256-GCM encryption
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("aes256_encrypt", size), size, |b, _| {
            let key = AesGcm256::generate_key().unwrap();
            let cipher = AesGcm256::new(&key).unwrap();
            b.iter(|| cipher.encrypt(black_box(&data), None).unwrap());
        });

        // AES-256-GCM decryption
        group.bench_with_input(BenchmarkId::new("aes256_decrypt", size), size, |b, _| {
            let key = AesGcm256::generate_key().unwrap();
            let cipher = AesGcm256::new(&key).unwrap();
            let ciphertext = cipher.encrypt(&data, None).unwrap();
            b.iter(|| cipher.decrypt(black_box(&ciphertext), None).unwrap());
        });

        // ChaCha20-Poly1305 encryption
        group.bench_with_input(BenchmarkId::new("chacha20_encrypt", size), size, |b, _| {
            let key = ChaCha20Poly1305::generate_key().unwrap();
            let cipher = ChaCha20Poly1305::new(&key).unwrap();
            b.iter(|| cipher.encrypt(black_box(&data), None).unwrap());
        });

        // ChaCha20-Poly1305 decryption
        group.bench_with_input(BenchmarkId::new("chacha20_decrypt", size), size, |b, _| {
            let key = ChaCha20Poly1305::generate_key().unwrap();
            let cipher = ChaCha20Poly1305::new(&key).unwrap();
            let ciphertext = cipher.encrypt(&data, None).unwrap();
            b.iter(|| cipher.decrypt(black_box(&ciphertext), None).unwrap());
        });
    }

    group.finish();
}

fn key_generation_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generation");

    group.bench_function("aes256_generate_key", |b| {
        b.iter(|| AesGcm256::generate_key().unwrap());
    });

    group.bench_function("chacha20_generate_key", |b| {
        b.iter(|| ChaCha20Poly1305::generate_key().unwrap());
    });

    group.finish();
}

fn configure_criterion() -> Criterion {
    Criterion::default().output_directory(Path::new("benches/generated"))
}

criterion_group! {
    name = benches;
    config = configure_criterion();
    targets = aead_benchmarks, key_generation_benchmarks
}
criterion_main!(benches);
