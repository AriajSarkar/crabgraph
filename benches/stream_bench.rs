use crabgraph::aead::stream::{
    Aes256GcmStreamDecryptor, Aes256GcmStreamEncryptor,
    ChaCha20Poly1305StreamEncryptor,
};
use crabgraph::rand::secure_bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::hint::black_box;
use std::path::Path;

/// Benchmark streaming encryption for different file sizes
fn stream_encryption_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_encryption");

    // Test different "file" sizes: 1 MB, 10 MB, 100 MB
    for size_kb in [1024, 10_240, 102_400].iter() {
        let size = size_kb * 1024; // Convert to bytes
        let data = vec![0u8; size];
        let chunk_size = 64 * 1024; // 64 KB chunks

        group.throughput(Throughput::Bytes(size as u64));

        // AES-256-GCM streaming encryption
        group.bench_with_input(
            BenchmarkId::new("aes256_stream_encrypt", format!("{}MB", size_kb / 1024)),
            &size,
            |b, _| {
                b.iter(|| {
                    let key = secure_bytes(32).unwrap();
                    let mut encryptor = Aes256GcmStreamEncryptor::new(&key).unwrap();
                    let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();

                    let mut encrypted = Vec::new();
                    for chunk in &chunks[..chunks.len() - 1] {
                        encrypted.push(encryptor.encrypt_next(chunk).unwrap());
                    }
                    encrypted.push(encryptor.encrypt_last(chunks[chunks.len() - 1]).unwrap());
                    black_box(encrypted);
                });
            },
        );

        // AES-256-GCM streaming decryption
        group.bench_with_input(
            BenchmarkId::new("aes256_stream_decrypt", format!("{}MB", size_kb / 1024)),
            &size,
            |b, _| {
                // Pre-encrypt data
                let key = secure_bytes(32).unwrap();
                let mut encryptor = Aes256GcmStreamEncryptor::new(&key).unwrap();
                let nonce = encryptor.nonce().to_vec();
                let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();

                let mut encrypted_chunks = Vec::new();
                for chunk in &chunks[..chunks.len() - 1] {
                    encrypted_chunks.push(encryptor.encrypt_next(chunk).unwrap());
                }
                encrypted_chunks.push(encryptor.encrypt_last(chunks[chunks.len() - 1]).unwrap());

                b.iter(|| {
                    let mut decryptor = Aes256GcmStreamDecryptor::from_nonce(&key, &nonce).unwrap();
                    let mut decrypted = Vec::new();

                    for chunk in &encrypted_chunks[..encrypted_chunks.len() - 1] {
                        decrypted.extend_from_slice(&decryptor.decrypt_next(chunk).unwrap());
                    }
                    decrypted.extend_from_slice(
                        &decryptor
                            .decrypt_last(&encrypted_chunks[encrypted_chunks.len() - 1])
                            .unwrap(),
                    );
                    black_box(decrypted);
                });
            },
        );

        // ChaCha20-Poly1305 streaming encryption
        group.bench_with_input(
            BenchmarkId::new(
                "chacha20_stream_encrypt",
                format!("{}MB", size_kb / 1024),
            ),
            &size,
            |b, _| {
                b.iter(|| {
                    let key = secure_bytes(32).unwrap();
                    let mut encryptor = ChaCha20Poly1305StreamEncryptor::new(&key).unwrap();
                    let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();

                    let mut encrypted = Vec::new();
                    for chunk in &chunks[..chunks.len() - 1] {
                        encrypted.push(encryptor.encrypt_next(chunk).unwrap());
                    }
                    encrypted.push(encryptor.encrypt_last(chunks[chunks.len() - 1]).unwrap());
                    black_box(encrypted);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark chunk size impact
fn chunk_size_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_chunk_size");

    let data = vec![0u8; 1024 * 1024]; // 1 MB file

    for chunk_size in [4096, 16384, 65536, 262144].iter() {
        group.throughput(Throughput::Bytes(data.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("aes256_chunk", format!("{}KB", chunk_size / 1024)),
            chunk_size,
            |b, &chunk_size| {
                b.iter(|| {
                    let key = secure_bytes(32).unwrap();
                    let mut encryptor = Aes256GcmStreamEncryptor::new(&key).unwrap();
                    let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();

                    let mut encrypted = Vec::new();
                    for chunk in &chunks[..chunks.len() - 1] {
                        encrypted.push(encryptor.encrypt_next(chunk).unwrap());
                    }
                    encrypted.push(encryptor.encrypt_last(chunks[chunks.len() - 1]).unwrap());
                    black_box(encrypted);
                });
            },
        );
    }

    group.finish();
}

/// Compare streaming vs in-memory encryption
fn stream_vs_memory_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_vs_memory");

    let size = 1024 * 1024; // 1 MB
    let data = vec![0u8; size];

    group.throughput(Throughput::Bytes(size as u64));

    // In-memory encryption (single operation)
    group.bench_function("aes256_inmemory_1mb", |b| {
        use crabgraph::aead::{AesGcm256, CrabAead};

        b.iter(|| {
            let key = AesGcm256::generate_key().unwrap();
            let cipher = AesGcm256::new(&key).unwrap();
            let encrypted = cipher.encrypt(black_box(&data), None).unwrap();
            black_box(encrypted);
        });
    });

    // Streaming encryption (chunked)
    group.bench_function("aes256_stream_1mb", |b| {
        b.iter(|| {
            let key = secure_bytes(32).unwrap();
            let mut encryptor = Aes256GcmStreamEncryptor::new(&key).unwrap();
            let chunk_size = 64 * 1024;
            let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();

            let mut encrypted = Vec::new();
            for chunk in &chunks[..chunks.len() - 1] {
                encrypted.push(encryptor.encrypt_next(chunk).unwrap());
            }
            encrypted.push(encryptor.encrypt_last(chunks[chunks.len() - 1]).unwrap());
            black_box(encrypted);
        });
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
    targets = stream_encryption_benchmarks, chunk_size_benchmarks, stream_vs_memory_benchmarks
}
criterion_main!(benches);
