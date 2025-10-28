use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crabgraph::asym::{Ed25519KeyPair, X25519KeyPair};

fn signing_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");

    // Ed25519 key generation
    group.bench_function("ed25519_keygen", |b| {
        b.iter(|| {
            Ed25519KeyPair::generate().unwrap()
        });
    });

    // Ed25519 signing
    let keypair = Ed25519KeyPair::generate().unwrap();
    let message = b"Message to sign for benchmarking purposes";
    
    group.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            keypair.sign(black_box(message))
        });
    });

    // Ed25519 verification
    let signature = keypair.sign(message);
    group.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            keypair.verify(black_box(message), black_box(&signature)).unwrap()
        });
    });

    group.finish();
}

fn key_exchange_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_exchange");

    // X25519 key generation
    group.bench_function("x25519_keygen", |b| {
        b.iter(|| {
            X25519KeyPair::generate().unwrap()
        });
    });

    // X25519 Diffie-Hellman
    let alice = X25519KeyPair::generate().unwrap();
    let bob = X25519KeyPair::generate().unwrap();
    let bob_public = bob.public_key();

    group.bench_function("x25519_dh", |b| {
        b.iter(|| {
            alice.diffie_hellman(black_box(&bob_public)).unwrap()
        });
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

criterion_group!(benches, signing_benchmarks, key_exchange_benchmarks);
criterion_main!(benches);
