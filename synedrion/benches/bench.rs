use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

use synedrion::{cggmp21::benches, KeyShare, PresigningData, TestParams};

fn bench_happy_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("happy path");

    type Params = TestParams;
    let key_shares = KeyShare::new_centralized(&mut OsRng, 2, None);

    group.bench_function("KeyGen, 2 parties", |b| {
        b.iter(|| benches::key_init::<Params>(&mut OsRng, 2))
    });

    let presigning_datas = PresigningData::new_centralized(&mut OsRng, &key_shares);
    group.bench_function("Signing, 2 parties", |b| {
        b.iter(|| benches::signing::<Params>(&mut OsRng, &key_shares, &presigning_datas))
    });

    group.sample_size(10);
    group.bench_function("Presigning, 2 parties", |b| {
        b.iter(|| benches::presigning::<Params>(&mut OsRng, &key_shares))
    });

    group.bench_function("KeyRefresh, 2 parties", |b| {
        b.iter(|| benches::key_refresh::<Params>(&mut OsRng, 2))
    });

    group.finish()
}

criterion_group!(benches, bench_happy_paths);

criterion_main!(benches);
