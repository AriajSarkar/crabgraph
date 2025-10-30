#[cfg(feature = "rsa-support")]
use crabgraph::asym::RsaKeyPair;
use crabgraph::asym::{Ed25519KeyPair, X25519KeyPair};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use std::path::Path;

fn signing_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");

    // Ed25519 key generation
    group.bench_function("ed25519_keygen", |b| {
        b.iter(|| Ed25519KeyPair::generate().unwrap());
    });

    // Ed25519 signing
    let keypair = Ed25519KeyPair::generate().unwrap();
    let message = b"Message to sign for benchmarking purposes";

    group.bench_function("ed25519_sign", |b| {
        b.iter(|| keypair.sign(black_box(message)));
    });

    // Ed25519 verification
    let signature = keypair.sign(message);
    group.bench_function("ed25519_verify", |b| {
        b.iter(|| keypair.verify(black_box(message), black_box(&signature)).unwrap());
    });

    group.finish();
}

fn key_exchange_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_exchange");

    // X25519 key generation
    group.bench_function("x25519_keygen", |b| {
        b.iter(|| X25519KeyPair::generate().unwrap());
    });

    // X25519 Diffie-Hellman
    let alice = X25519KeyPair::generate().unwrap();
    let bob = X25519KeyPair::generate().unwrap();
    let bob_public = bob.public_key();

    group.bench_function("x25519_dh", |b| {
        b.iter(|| alice.diffie_hellman(black_box(&bob_public)).unwrap());
    });

    // X25519 DH + key derivation
    group.bench_function("x25519_dh_derive", |b| {
        b.iter(|| {
            let shared = alice.diffie_hellman(black_box(&bob_public)).unwrap();
            shared.derive_key(b"app_context", 32).unwrap()
        });
    });

    group.finish();
}

#[cfg(feature = "rsa-support")]
fn rsa_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("rsa");
    group.sample_size(10); // RSA is slow, use fewer samples

    // RSA-2048 key generation
    group.bench_function("rsa2048_keygen", |b| {
        b.iter(|| RsaKeyPair::generate_2048().unwrap());
    });

    let keypair = RsaKeyPair::generate_2048().unwrap();
    let message = b"Message to sign for benchmarking purposes";
    let plaintext = b"Short message to encrypt";

    // RSA-2048 signing
    group.bench_function("rsa2048_sign", |b| {
        b.iter(|| keypair.sign(black_box(message)).unwrap());
    });

    // RSA-2048 verification
    let signature = keypair.sign(message).unwrap();
    group.bench_function("rsa2048_verify", |b| {
        b.iter(|| keypair.verify(black_box(message), black_box(&signature)).unwrap());
    });

    // RSA-2048 encryption
    group.bench_function("rsa2048_encrypt", |b| {
        b.iter(|| keypair.encrypt(black_box(plaintext)).unwrap());
    });

    // RSA-2048 decryption
    let ciphertext = keypair.encrypt(plaintext).unwrap();
    group.bench_function("rsa2048_decrypt", |b| {
        b.iter(|| keypair.decrypt(black_box(&ciphertext)).unwrap());
    });

    group.finish();
}

fn configure_criterion() -> Criterion {
    Criterion::default().output_directory(Path::new("benches/generated"))
}

#[cfg(feature = "rsa-support")]
criterion_group! {
    name = benches;
    config = configure_criterion();
    targets = signing_benchmarks, key_exchange_benchmarks, rsa_benchmarks
}

#[cfg(not(feature = "rsa-support"))]
criterion_group! {
    name = benches;
    config = configure_criterion();
    targets = signing_benchmarks, key_exchange_benchmarks
}

criterion_main!(benches);
