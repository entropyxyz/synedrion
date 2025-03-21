use crate::{
    paillier::{Ciphertext, Randomizer, SecretKeyPaillierWire},
    params::SchemeParams,
    uint::SecretSigned,
};
use criterion::{black_box, BatchSize, Bencher, Criterion};
use rand::SeedableRng;

type Params = crate::k256::ProductionParams112;
type Paillier = <Params as SchemeParams>::Paillier;

pub fn bench_paillier(c: &mut Criterion) {
    let mut group = c.benchmark_group("Paillier");

    group.sample_size(10);

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
    group.bench_function("encrypt", |b: &mut Bencher<'_>| {
        b.iter_batched(
            || {
                let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                let pk = sk.public_key().clone();
                let m = SecretSigned::random_in_exponent_range(&mut rng, Params::LP_BOUND);
                let r = Randomizer::random(&mut rng, &pk);
                (pk, m, r)
            },
            |(pk, m, r)| black_box(Ciphertext::new_with_randomizer(&pk, &m, &r)),
            BatchSize::SmallInput,
        );
    });

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1234567890);
    group.bench_function("decrypt", |b: &mut Bencher<'_>| {
        b.iter_batched(
            || {
                let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                let pk = sk.public_key();
                let m = SecretSigned::random_in_exponent_range(&mut rng, Params::LP_BOUND);
                let r = Randomizer::random(&mut rng, pk);
                let ct = Ciphertext::new_with_randomizer(pk, &m, &r);
                (ct, sk)
            },
            |(ct, sk)| black_box(Ciphertext::decrypt(&ct, &sk)),
            BatchSize::SmallInput,
        );
    });
}
