use criterion::{black_box, BatchSize, Bencher};
use rand_core::CryptoRngCore;

use crate::{
    paillier::{Ciphertext, Randomizer, SecretKeyPaillierWire},
    params::SchemeParams,
    uint::SecretSigned,
};

type Params = crate::k256::ProductionParams112;
type Paillier = <Params as SchemeParams>::Paillier;

pub fn encrypt<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
    move |b: &mut Bencher<'_>| {
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
    }
}

pub fn decrypt<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
    move |b: &mut Bencher<'_>| {
        b.iter_batched(
            || {
                let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                let pk = sk.public_key();
                let m = SecretSigned::random_in_exponent_range(&mut rng, Params::LP_BOUND);
                let r = Randomizer::random(&mut rng, &pk);
                let ct = Ciphertext::new_with_randomizer(&pk, &m, &r);
                (ct, sk)
            },
            |(ct, sk)| black_box(Ciphertext::decrypt(&ct, &sk)),
            BatchSize::SmallInput,
        );
    }
}
