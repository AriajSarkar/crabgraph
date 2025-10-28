use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crabgraph::kdf::{
    argon2_derive, argon2_derive_with_params, Argon2Params,
    pbkdf2_derive_sha256, PBKDF2_SHA256_RECOMMENDED_ITERATIONS,
    hkdf_sha256,
};

fn kdf_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf");
    
    let password = b"benchmark_password";
    let salt = b"benchmark_salt16";
    
    // PBKDF2 with recommended iterations
    group.bench_function("pbkdf2_sha256_600k", |b| {
        b.iter(|| {
            pbkdf2_derive_sha256(
                black_box(password),
                black_box(salt),
                PBKDF2_SHA256_RECOMMENDED_ITERATIONS,
                32,
            ).unwrap()
        });
    });

    // PBKDF2 with lower iterations (for comparison)
    group.bench_function("pbkdf2_sha256_10k", |b| {
        b.iter(|| {
            pbkdf2_derive_sha256(
                black_box(password),
                black_box(salt),
                10_000,
                32,
            ).unwrap()
        });
    });

    // Argon2 with interactive parameters
    group.bench_function("argon2_interactive", |b| {
        b.iter(|| {
            argon2_derive(
                black_box(password),
                black_box(salt),
                32,
            ).unwrap()
        });
    });

    // Argon2 with low-memory parameters
    group.bench_function("argon2_low_memory", |b| {
        let params = Argon2Params::low_memory();
        b.iter(|| {
            argon2_derive_with_params(
                black_box(password),
                black_box(salt),
                32,
                &params,
            ).unwrap()
        });
    });

    // HKDF (much faster, but for different use case)
    group.bench_function("hkdf_sha256", |b| {
        let ikm = b"input_key_material_32_bytes_____";
        b.iter(|| {
            hkdf_sha256(black_box(ikm), 32).unwrap()
        });
    });

    group.finish();
}

criterion_group!(benches, kdf_benchmarks);
criterion_main!(benches);
