use criterion::{criterion_group, criterion_main, Criterion};
use rand::SeedableRng;
use synedrion::private_benches::paillier;

criterion_group!(benches, bench_encrypt);
criterion_main!(benches);

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("Paillier");

    group.sample_size(10);

    let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
    group.bench_function("encrypt", paillier::encrypt(rng));

    let rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
    group.bench_function("decrypt", paillier::decrypt(rng));
}
