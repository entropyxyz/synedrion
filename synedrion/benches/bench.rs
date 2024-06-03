use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;

use synedrion::{
    bench_internals::{
        key_init, key_refresh, presigning, signing, PresigningInputs, SigningInputs,
    },
    TestParams,
};

fn bench_happy_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("happy path");

    type Params = TestParams;

    group.bench_function("KeyGen, 2 parties", |b| {
        b.iter(|| key_init::<Params>(&mut OsRng, 2))
    });

    let presigning_inputs = PresigningInputs::new(&mut OsRng, 2);
    let signing_inputs = SigningInputs::new(&mut OsRng, &presigning_inputs);

    group.bench_function("Signing, 2 parties", |b| {
        b.iter(|| signing::<Params>(&mut OsRng, &presigning_inputs, &signing_inputs))
    });

    group.sample_size(10);
    group.bench_function("Presigning, 2 parties", |b| {
        b.iter(|| presigning::<Params>(&mut OsRng, &presigning_inputs))
    });

    group.bench_function("KeyRefresh, 2 parties", |b| {
        b.iter(|| key_refresh::<Params>(&mut OsRng, 2))
    });

    group.finish()
}

criterion_group!(benches, bench_happy_paths);

criterion_main!(benches);
