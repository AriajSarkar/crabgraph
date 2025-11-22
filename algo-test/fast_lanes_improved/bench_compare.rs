use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use openssl::symm::Cipher;
use ring::aead::{self, LessSafeKey, UnboundKey};

#[path = "mod.rs"]
mod fast_lanes_improved;
use fast_lanes_improved::{Backend, FastLanesImproved};

fn bench_compare(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_comparison");

    let key_fl = [0u8; 32];
    let nonce_fl = [0u8; 12];
    let mut cipher_fl = FastLanesImproved::new(key_fl, nonce_fl);
    cipher_fl.set_backend(Backend::Auto);

    let ring_key_bytes = vec![0u8; 32];
    let ring_unbound_key = UnboundKey::new(&aead::AES_256_GCM, &ring_key_bytes).unwrap();
    let ring_key = LessSafeKey::new(ring_unbound_key);

    let openssl_key = [0u8; 32];
    let openssl_iv = [0u8; 12];
    let cipher = Cipher::aes_256_gcm();

    for size in [64, 1024, 1024 * 1024].iter() {
        let mut buffer = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            criterion::BenchmarkId::new("FastLanes_Auto", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    black_box(cipher_fl.encrypt_in_place(&mut buffer));
                });
            },
        );

        group.bench_with_input(
            criterion::BenchmarkId::new("Ring_AES_GCM", size),
            size,
            |b, &len| {
                b.iter(|| {
                    let mut ring_buffer = vec![0u8; len];
                    let nonce = aead::Nonce::try_assume_unique_for_key(&[0u8; 12]).unwrap();
                    let aad = aead::Aad::empty();

                    ring_key.seal_in_place_append_tag(nonce, aad, &mut ring_buffer).unwrap();
                    black_box(&ring_buffer);
                });
            },
        );

        let mut tag = [0u8; 16];
        group.bench_with_input(
            criterion::BenchmarkId::new("OpenSSL_AES_GCM", size),
            size,
            |b, &_len| {
                b.iter(|| {
                    let res = openssl::symm::encrypt_aead(
                        cipher,
                        &openssl_key,
                        Some(&openssl_iv),
                        &[],
                        &buffer,
                        &mut tag,
                    )
                    .unwrap();
                    black_box(res);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_compare);
criterion_main!(benches);
