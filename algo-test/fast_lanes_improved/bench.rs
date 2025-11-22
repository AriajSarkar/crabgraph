use criterion::{criterion_group, criterion_main, Criterion, Throughput};

#[path = "mod.rs"]
mod fast_lanes_improved;
#[path = "../fast_lanes/mod.rs"]
mod fast_lanes_original;

use fast_lanes_improved::{Backend, FastLanesImproved as FastLanesNew};
use fast_lanes_original::FastLanes as FastLanesOld;

fn bench_fast_lanes_improved(c: &mut Criterion) {
    let mut group = c.benchmark_group("fast_lanes_comparison");

    let key = [0u8; 32];
    let nonce = [0u8; 12];

    // Prepare instances
    let cipher_old = FastLanesOld::new(key, nonce);

    let mut cipher_scalar = FastLanesNew::new(key, nonce);
    cipher_scalar.set_backend(Backend::Scalar);

    let mut cipher_avx2 = FastLanesNew::new(key, nonce);
    cipher_avx2.set_backend(Backend::Avx2);

    let mut cipher_auto = FastLanesNew::new(key, nonce);
    cipher_auto.set_backend(Backend::Auto);

    for size in [64, 256, 1024, 16 * 1024, 64 * 1024, 1024 * 1024].iter() {
        let mut buffer = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(criterion::BenchmarkId::new("Original", size), size, |b, &_size| {
            b.iter(|| {
                cipher_old.encrypt_in_place(&mut buffer);
            });
        });

        group.bench_with_input(
            criterion::BenchmarkId::new("Improved_Scalar", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    cipher_scalar.encrypt_in_place(&mut buffer);
                });
            },
        );

        // Only bench AVX2 if supported, but the code handles fallback.
        // However, for clear results, we want to see if it works.
        group.bench_with_input(
            criterion::BenchmarkId::new("Improved_Avx2", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    cipher_avx2.encrypt_in_place(&mut buffer);
                });
            },
        );

        group.bench_with_input(
            criterion::BenchmarkId::new("Improved_Auto", size),
            size,
            |b, &_size| {
                b.iter(|| {
                    cipher_auto.encrypt_in_place(&mut buffer);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_fast_lanes_improved);
criterion_main!(benches);
