use criterion::{criterion_group, criterion_main, Criterion, Throughput};

#[path = "mod.rs"]
mod fast_lanes;

use fast_lanes::FastLanes;

fn bench_fast_lanes(c: &mut Criterion) {
    let mut group = c.benchmark_group("fast_lanes");

    // Key and Nonce
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let cipher = FastLanes::new(key, nonce);

    // Benchmark sizes
    for size in [1024, 16 * 1024, 1024 * 1024].iter() {
        let mut buffer = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(criterion::BenchmarkId::from_parameter(size), size, |b, &_size| {
            b.iter(|| {
                cipher.encrypt_in_place(&mut buffer);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_fast_lanes);
criterion_main!(benches);
