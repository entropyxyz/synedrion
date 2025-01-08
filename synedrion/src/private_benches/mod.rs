use criterion::{black_box, BatchSize, Bencher};
use rand_core::CryptoRngCore;

use crate::cggmp21::{sigma::FacProof, PaillierProduction, ProductionParams};
use crate::paillier::{PublicKeyPaillier, RPParams, SecretKeyPaillierWire};
use crate::SchemeParams;

/// Benchmark Fac-proof construction
pub fn fac_proof_prove<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
    let mut rng2 = rng.clone();
    move |b: &mut Bencher<'_>| {
        b.iter_batched(
            || {
                let sk = SecretKeyPaillierWire::<<ProductionParams as SchemeParams>::Paillier>::random(&mut rng)
                    .into_precomputed();

                let setup = RPParams::random(&mut rng);

                let aux: &[u8] = b"abcde";
                (sk, setup, aux)
            },
            |(sk, setup, aux)| black_box(FacProof::<ProductionParams>::new(&mut rng2, &sk, &setup, &aux)),
            BatchSize::SmallInput,
        );
    }
}

/// Benchmark Fac-proof verification
pub fn fac_proof_verify<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
    type Paillier = <ProductionParams as SchemeParams>::Paillier;
    move |b: &mut Bencher<'_>| {
        b.iter_batched(
            || {
                let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();

                let setup = RPParams::random(&mut rng);

                let aux: &[u8] = b"abcde";
                let proof = FacProof::<ProductionParams>::new(&mut rng, &sk, &setup, &aux);
                (proof, sk.public_key().clone(), setup, aux)
            },
            |(proof, pk0, setup, aux): (
                FacProof<ProductionParams>,
                PublicKeyPaillier<PaillierProduction>,
                RPParams<PaillierProduction>,
                &[u8],
            )| {
                proof.verify(&pk0, &setup, &aux);
            },
            BatchSize::SmallInput,
        );
    }
}
