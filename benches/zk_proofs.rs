use std::sync::LazyLock;

use criterion::{criterion_group, criterion_main, Criterion};
use rand_core::OsRng;
use synedrion::{k256::ProductionParams112, private_benches::zk_proofs::*};

static KEY0: LazyLock<PreparedKey<ProductionParams112>> = LazyLock::new(|| PreparedKey::new(&mut OsRng));

static KEY1: LazyLock<PreparedKey<ProductionParams112>> = LazyLock::new(|| PreparedKey::new(&mut OsRng));

fn bench_aff_g(c: &mut Criterion) {
    let mut group = c.benchmark_group("AffG proof");
    group.sample_size(20);

    LazyLock::force(&KEY0);
    LazyLock::force(&KEY1);

    group.bench_function("prove", |b| {
        b.iter_custom(|iters| measure_aff_g(&mut OsRng, &KEY0, &KEY1, iters, Measure::Creation))
    });
    group.bench_function("verify", |b| {
        b.iter_custom(|iters| measure_aff_g(&mut OsRng, &KEY0, &KEY1, iters, Measure::Verification))
    });
}

fn bench_aff_g_star(c: &mut Criterion) {
    let mut group = c.benchmark_group("AffG* proof");
    group.sample_size(10);

    LazyLock::force(&KEY0);
    LazyLock::force(&KEY1);

    group.bench_function("prove", |b| {
        b.iter_custom(|iters| measure_aff_g_star(&mut OsRng, &KEY0, &KEY1, iters, Measure::Creation))
    });
    group.bench_function("verify", |b| {
        b.iter_custom(|iters| measure_aff_g_star(&mut OsRng, &KEY0, &KEY1, iters, Measure::Verification))
    });
}

fn bench_dec(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dec proof");
    group.sample_size(10);

    LazyLock::force(&KEY0);

    group.bench_function("prove", |b| {
        b.iter_custom(|iters| measure_dec(&mut OsRng, &KEY0, iters, Measure::Creation))
    });
    group.bench_function("verify", |b| {
        b.iter_custom(|iters| measure_dec(&mut OsRng, &KEY0, iters, Measure::Verification))
    });
}

fn bench_elog(c: &mut Criterion) {
    let mut group = c.benchmark_group("Elog proof");

    group.bench_function("prove", |b| {
        b.iter_custom(|iters| measure_elog(&mut OsRng, iters, Measure::Creation))
    });
    group.bench_function("verify", |b| {
        b.iter_custom(|iters| measure_elog(&mut OsRng, iters, Measure::Verification))
    });
}

fn bench_enc_elg(c: &mut Criterion) {
    let mut group = c.benchmark_group("Enc-Elg proof");

    LazyLock::force(&KEY0);

    group.bench_function("prove", |b| {
        b.iter_custom(|iters| measure_enc_elg(&mut OsRng, &KEY0, iters, Measure::Creation))
    });
    group.bench_function("verify", |b| {
        b.iter_custom(|iters| measure_enc_elg(&mut OsRng, &KEY0, iters, Measure::Verification))
    });
}

fn bench_fac(c: &mut Criterion) {
    let mut group = c.benchmark_group("Fac proof");

    LazyLock::force(&KEY0);

    group.bench_function("prove", |b| {
        b.iter_custom(|iters| measure_fac(&mut OsRng, &KEY0, iters, Measure::Creation))
    });
    group.bench_function("verify", |b| {
        b.iter_custom(|iters| measure_fac(&mut OsRng, &KEY0, iters, Measure::Verification))
    });
}

fn bench_mod(c: &mut Criterion) {
    let mut group = c.benchmark_group("Mod proof");
    group.sample_size(10);

    LazyLock::force(&KEY0);

    group.bench_function("prove", |b| {
        b.iter_custom(|iters| measure_mod(&mut OsRng, &KEY0, iters, Measure::Creation))
    });
    group.bench_function("verify", |b| {
        b.iter_custom(|iters| measure_mod(&mut OsRng, &KEY0, iters, Measure::Verification))
    });
}

fn bench_prm(c: &mut Criterion) {
    let mut group = c.benchmark_group("Prm proof");
    group.sample_size(20);

    LazyLock::force(&KEY0);

    group.bench_function("prove", |b| {
        b.iter_custom(|iters| measure_prm(&mut OsRng, &KEY0, iters, Measure::Creation))
    });
    group.bench_function("verify", |b| {
        b.iter_custom(|iters| measure_prm(&mut OsRng, &KEY0, iters, Measure::Verification))
    });
}

fn bench_sch(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sch proof");

    group.bench_function("prove", |b| {
        b.iter_custom(|iters| measure_sch(&mut OsRng, iters, Measure::Creation))
    });
    group.bench_function("verify", |b| {
        b.iter_custom(|iters| measure_sch(&mut OsRng, iters, Measure::Verification))
    });
}

criterion_group!(
    benches,
    bench_aff_g,
    bench_aff_g_star,
    bench_dec,
    bench_elog,
    bench_enc_elg,
    bench_fac,
    bench_mod,
    bench_prm,
    bench_sch
);

criterion_main!(benches);
