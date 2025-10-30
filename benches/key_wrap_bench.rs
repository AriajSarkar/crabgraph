/// AES Key Wrap (AES-KW) benchmarks per RFC 3394
///
/// Measures performance of wrapping and unwrapping cryptographic key material
/// with different KEK (Key Encryption Key) sizes and key payload sizes.
use crabgraph::kw::{Kw128, Kw192, Kw256};
use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::path::Path;

mod bench_utils;

/// Benchmark AES-128 Key Wrap operations
fn bench_kw128(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_wrap_kw128");

    // Test different key sizes (must be multiples of 8 bytes, minimum 16 bytes)
    let key_sizes = [16, 32, 64, 128, 256]; // 128-bit to 2048-bit keys

    let kek = Kw128::generate_kek().unwrap();
    let wrapper = Kw128::new(&kek).unwrap();

    for size in key_sizes.iter() {
        let key_material = vec![0x42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // Benchmark wrap operation
        group.bench_with_input(BenchmarkId::new("wrap", size), size, |b, _| {
            b.iter(|| wrapper.wrap_key(black_box(&key_material)).unwrap());
        });

        // Benchmark unwrap operation
        let wrapped = wrapper.wrap_key(&key_material).unwrap();
        group.bench_with_input(BenchmarkId::new("unwrap", size), size, |b, _| {
            b.iter(|| wrapper.unwrap_key(black_box(&wrapped)).unwrap());
        });
    }

    group.finish();
}

/// Benchmark AES-192 Key Wrap operations
fn bench_kw192(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_wrap_kw192");

    let key_sizes = [16, 32, 64, 128, 256];

    let kek = Kw192::generate_kek().unwrap();
    let wrapper = Kw192::new(&kek).unwrap();

    for size in key_sizes.iter() {
        let key_material = vec![0x42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // Benchmark wrap operation
        group.bench_with_input(BenchmarkId::new("wrap", size), size, |b, _| {
            b.iter(|| wrapper.wrap_key(black_box(&key_material)).unwrap());
        });

        // Benchmark unwrap operation
        let wrapped = wrapper.wrap_key(&key_material).unwrap();
        group.bench_with_input(BenchmarkId::new("unwrap", size), size, |b, _| {
            b.iter(|| wrapper.unwrap_key(black_box(&wrapped)).unwrap());
        });
    }

    group.finish();
}

/// Benchmark AES-256 Key Wrap operations
fn bench_kw256(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_wrap_kw256");

    let key_sizes = [16, 32, 64, 128, 256];

    let kek = Kw256::generate_kek().unwrap();
    let wrapper = Kw256::new(&kek).unwrap();

    for size in key_sizes.iter() {
        let key_material = vec![0x42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));

        // Benchmark wrap operation
        group.bench_with_input(BenchmarkId::new("wrap", size), size, |b, _| {
            b.iter(|| wrapper.wrap_key(black_box(&key_material)).unwrap());
        });

        // Benchmark unwrap operation
        let wrapped = wrapper.wrap_key(&key_material).unwrap();
        group.bench_with_input(BenchmarkId::new("unwrap", size), size, |b, _| {
            b.iter(|| wrapper.unwrap_key(black_box(&wrapped)).unwrap());
        });
    }

    group.finish();
}

/// Benchmark KEK generation for all variants
fn bench_kek_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_wrap_kek_generation");

    group.bench_function("kw128_generate_kek", |b| {
        b.iter(|| Kw128::generate_kek().unwrap());
    });

    group.bench_function("kw192_generate_kek", |b| {
        b.iter(|| Kw192::generate_kek().unwrap());
    });

    group.bench_function("kw256_generate_kek", |b| {
        b.iter(|| Kw256::generate_kek().unwrap());
    });

    group.finish();
}

/// Compare wrap performance across KEK sizes for a standard AES-256 key
fn bench_kek_size_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_wrap_kek_comparison");

    // Standard AES-256 key (32 bytes)
    let aes256_key = vec![0x42u8; 32];
    group.throughput(Throughput::Bytes(32));

    // AES-128 KEK
    let kek128 = Kw128::generate_kek().unwrap();
    let wrapper128 = Kw128::new(&kek128).unwrap();
    group.bench_function("wrap_aes256_key_with_kw128", |b| {
        b.iter(|| wrapper128.wrap_key(black_box(&aes256_key)).unwrap());
    });

    // AES-192 KEK
    let kek192 = Kw192::generate_kek().unwrap();
    let wrapper192 = Kw192::new(&kek192).unwrap();
    group.bench_function("wrap_aes256_key_with_kw192", |b| {
        b.iter(|| wrapper192.wrap_key(black_box(&aes256_key)).unwrap());
    });

    // AES-256 KEK
    let kek256 = Kw256::generate_kek().unwrap();
    let wrapper256 = Kw256::new(&kek256).unwrap();
    group.bench_function("wrap_aes256_key_with_kw256", |b| {
        b.iter(|| wrapper256.wrap_key(black_box(&aes256_key)).unwrap());
    });

    group.finish();
}

fn configure_criterion() -> Criterion {
    Criterion::default()
        .output_directory(Path::new("target/criterion"))
        .with_output_color(true)
}

criterion_group! {
    name = benches;
    config = configure_criterion();
    targets = bench_kw128, bench_kw192, bench_kw256, bench_kek_generation, bench_kek_size_comparison
}

fn main() {
    benches();
    println!("\n📊 Organizing benchmark results...");
    bench_utils::organize_benchmark_results();
}
// criterion_main!(benches);
