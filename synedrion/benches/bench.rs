use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

use synedrion::{cggmp21::benches, KeyShare, TestParams};

fn bench_happy_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("happy path");

    type Params = TestParams;

    group.bench_function("KeyGen, 3 parties", |b| {
        b.iter(|| benches::keygen::<Params>(&mut OsRng, 3))
    });

    group.bench_function("KeyRefresh, 3 parties", |b| {
        b.iter(|| benches::key_refresh::<Params>(&mut OsRng, 3))
    });

    let key_shares = KeyShare::new_centralized(&mut OsRng, 3, None);

    group.sample_size(10);
    group.bench_function("Presigning, 3 parties", |b| {
        b.iter(|| benches::presigning::<Params>(&mut OsRng, &key_shares))
    });

    group.bench_function("Signing, 3 parties", |b| {
        b.iter(|| benches::signing::<Params>(&mut OsRng, &key_shares))
    });

    group.finish()
}

criterion_group!(benches, bench_happy_paths);

criterion_main!(benches);
