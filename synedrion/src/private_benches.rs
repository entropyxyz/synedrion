use criterion::{black_box, BatchSize, Bencher};
use rand_core::CryptoRngCore;

use crate::{
    cggmp21::{
        conversion::secret_scalar_from_signed,
        sigma::{
            AffGProof, AffGPublicInputs, AffGSecretInputs, DecProof, DecPublicInputs, DecSecretInputs, FacProof,
            ModProof, PrmProof, SchCommitment, SchProof, SchSecret,
        },
        PaillierProduction112, ProductionParams112,
    },
    curve::{Point, Scalar},
    paillier::{Ciphertext, PaillierParams, PublicKeyPaillier, RPParams, RPSecret, Randomizer, SecretKeyPaillierWire},
    tools::Secret,
    uint::SecretSigned,
    SchemeParams,
};

type Params = ProductionParams112;
type Paillier = <Params as SchemeParams>::Paillier;
type PUint = <<Params as SchemeParams>::Paillier as PaillierParams>::Uint;

pub mod fac_proof {
    use super::*;

    /// Benchmark Fac-proof construction
    pub fn fac_proof_prove<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        let mut rng2 = rng.clone();
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();

                    let setup = RPParams::random(&mut rng);

                    let aux: &[u8] = b"abcde";
                    (sk, setup, aux)
                },
                |(sk, setup, aux)| black_box(FacProof::<Params>::new(&mut rng2, &sk, &setup, &aux)),
                BatchSize::SmallInput,
            );
        }
    }

    /// Benchmark Fac-proof verification
    pub fn fac_proof_verify<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();

                    let setup = RPParams::random(&mut rng);

                    let aux: &[u8] = b"abcde";
                    let proof = FacProof::<Params>::new(&mut rng, &sk, &setup, &aux);
                    (proof, sk.public_key().clone(), setup, aux)
                },
                |(proof, pk0, setup, aux): (
                    FacProof<Params>,
                    PublicKeyPaillier<PaillierProduction112>,
                    RPParams<PaillierProduction112>,
                    &[u8],
                )| {
                    proof.verify(&pk0, &setup, &aux);
                },
                BatchSize::SmallInput,
            );
        }
    }
}

pub mod aff_g_proof {
    use super::*;

    #[allow(clippy::type_complexity)]
    fn proof_inputs(
        mut rng: impl CryptoRngCore + 'static,
    ) -> (
        (impl CryptoRngCore + 'static),
        SecretSigned<PUint>,
        SecretSigned<PUint>,
        Randomizer<Paillier>,
        Randomizer<Paillier>,
        PublicKeyPaillier<Paillier>,
        PublicKeyPaillier<Paillier>,
        Ciphertext<Paillier>,
        Ciphertext<Paillier>,
        Ciphertext<Paillier>,
        Point<P>,
        RPParams<Paillier>,
        &'static [u8],
    ) {
        let sk0 = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
        let pk0 = sk0.public_key().clone();

        let sk1 = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
        let pk1 = sk1.public_key().clone();

        let rp_params = RPParams::random(&mut rng);

        let aux: &[u8] = b"abcde";

        let x = SecretSigned::random_in_exponent_range(&mut rng, Params::L_BOUND);
        let y = SecretSigned::random_in_exponent_range(&mut rng, Params::LP_BOUND);

        let rho = Randomizer::random(&mut rng, &pk0);
        let rho_y = Randomizer::random(&mut rng, &pk1);
        let secret = SecretSigned::random_in_exponent_range(&mut rng, Params::L_BOUND);
        let cap_c = Ciphertext::new_with_randomizer(&pk0, &secret, &Randomizer::random(&mut rng, &pk0));
        let cap_d = &cap_c * &x + Ciphertext::new_with_randomizer(&pk0, &-&y, &rho);
        let cap_y = Ciphertext::new_with_randomizer(&pk1, &y, &rho_y);
        let cap_x = secret_scalar_from_signed::<Params>(&x).mul_by_generator();

        (
            rng, x, y, rho, rho_y, pk0, pk1, cap_c, cap_d, cap_y, cap_x, rp_params, aux,
        )
    }

    pub fn aff_g_proof_prove<R: CryptoRngCore + Clone + 'static>(rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let rng2 = rng.clone();
                    proof_inputs(rng2)
                },
                |(mut rng, x, y, rho, rho_y, pk0, pk1, cap_c, cap_d, cap_y, cap_x, rp_params, aux)| {
                    black_box(AffGProof::<Params>::new(
                        &mut rng,
                        AffGSecretInputs {
                            x: &x,
                            y: &y,
                            rho: &rho,
                            rho_y: &rho_y,
                        },
                        AffGPublicInputs {
                            pk0: &pk0,
                            pk1: &pk1,
                            cap_c: &cap_c,
                            cap_d: &cap_d,
                            cap_y: &cap_y,
                            cap_x: &cap_x,
                        },
                        &rp_params,
                        &aux,
                    ))
                },
                BatchSize::SmallInput,
            );
        }
    }
    pub fn aff_g_proof_verify<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let (_, x, y, rho, rho_y, pk0, pk1, cap_c, cap_d, cap_y, cap_x, rp_params, aux) =
                        proof_inputs(rng.clone());

                    let pub_inputs = AffGPublicInputs {
                        pk0: &pk0,
                        pk1: &pk1,
                        cap_c: &cap_c,
                        cap_d: &cap_d,
                        cap_y: &cap_y,
                        cap_x: &cap_x,
                    };

                    let proof = AffGProof::<Params>::new(
                        &mut rng,
                        AffGSecretInputs {
                            x: &x,
                            y: &y,
                            rho: &rho,
                            rho_y: &rho_y,
                        },
                        pub_inputs,
                        &rp_params,
                        b"abcde",
                    );

                    let inputs = (
                        pk0.clone(),
                        pk1.clone(),
                        cap_c.clone(),
                        cap_d.clone(),
                        cap_y.clone(),
                        cap_x,
                    );
                    let rp_params2 = rp_params.clone();
                    (proof, inputs, rp_params2, aux)
                },
                |(proof, inputs, rp_params, aux)| {
                    let pub_inputs = AffGPublicInputs {
                        pk0: &inputs.0,
                        pk1: &inputs.1,
                        cap_c: &inputs.2,
                        cap_d: &inputs.3,
                        cap_y: &inputs.4,
                        cap_x: &inputs.5,
                    };

                    black_box(proof.verify(pub_inputs, &rp_params, &aux))
                },
                BatchSize::SmallInput,
            );
        }
    }
}

pub mod aff_g_star_proof {
    use crate::cggmp21::sigma::{AffGStarProof, AffGStarPublicInputs, AffGStarSecretInputs};

    use super::*;

    #[allow(clippy::type_complexity)]
    fn proof_input(
        mut rng: impl CryptoRngCore,
    ) -> (
        impl CryptoRngCore,
        SecretSigned<PUint>,
        SecretSigned<PUint>,
        Randomizer<Paillier>,
        Randomizer<Paillier>,
        PublicKeyPaillier<Paillier>,
        PublicKeyPaillier<Paillier>,
        Ciphertext<Paillier>,
        Ciphertext<Paillier>,
        Ciphertext<Paillier>,
        Point<P>,
        &'static [u8],
    ) {
        let sk0 = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
        let pk0 = sk0.public_key();

        let sk1 = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
        let pk1 = sk1.public_key();

        let x = SecretSigned::random_in_exponent_range(&mut rng, Params::L_BOUND);
        let y = SecretSigned::random_in_exponent_range(&mut rng, Params::LP_BOUND);
        let rho = Randomizer::random(&mut rng, pk0);
        let mu = Randomizer::random(&mut rng, pk1);

        let secret = SecretSigned::random_in_exponent_range(&mut rng, Params::L_BOUND);
        let cap_c = Ciphertext::new(&mut rng, pk0, &secret);

        let cap_d = &cap_c * &x + Ciphertext::new_with_randomizer(pk0, &-&y, &rho);
        let cap_y = Ciphertext::new_with_randomizer(pk1, &y, &mu);
        let cap_x = secret_scalar_from_signed::<Params>(&x).mul_by_generator();

        (
            rng,
            x,
            y,
            rho,
            mu,
            pk0.clone(),
            pk1.clone(),
            cap_c,
            cap_d,
            cap_y,
            cap_x,
            b"abcde",
        )
    }

    pub fn aff_g_star_proof_prove<R: CryptoRngCore + Clone + 'static>(rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || proof_input(rng.clone()),
                |(mut rng, x, y, rho, mu, pk0, pk1, cap_c, cap_d, cap_y, cap_x, aux)| {
                    black_box(AffGStarProof::<Params>::new(
                        &mut rng,
                        AffGStarSecretInputs {
                            x: &x,
                            y: &y,
                            rho: &rho,
                            mu: &mu,
                        },
                        AffGStarPublicInputs {
                            pk0: &pk0,
                            pk1: &pk1,
                            cap_c: &cap_c,
                            cap_d: &cap_d,
                            cap_y: &cap_y,
                            cap_x: &cap_x,
                        },
                        &aux,
                    ))
                },
                BatchSize::SmallInput,
            );
        }
    }
    pub fn aff_g_star_proof_verify<R: CryptoRngCore + Clone + 'static>(rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let (mut rng, x, y, rho, mu, pk0, pk1, cap_c, cap_d, cap_y, cap_x, aux) = proof_input(rng.clone());
                    let proof = AffGStarProof::<Params>::new(
                        &mut rng,
                        AffGStarSecretInputs {
                            x: &x,
                            y: &y,
                            rho: &rho,
                            mu: &mu,
                        },
                        AffGStarPublicInputs {
                            pk0: &pk0,
                            pk1: &pk1,
                            cap_c: &cap_c,
                            cap_d: &cap_d,
                            cap_y: &cap_y,
                            cap_x: &cap_x,
                        },
                        &aux,
                    );
                    (proof, pk0, pk1, cap_c, cap_d, cap_y, cap_x, aux)
                },
                |(proof, pk0, pk1, cap_c, cap_d, cap_y, cap_x, aux)| {
                    black_box(proof.verify(
                        AffGStarPublicInputs {
                            pk0: &pk0,
                            pk1: &pk1,
                            cap_c: &cap_c,
                            cap_d: &cap_d,
                            cap_y: &cap_y,
                            cap_x: &cap_x,
                        },
                        &aux,
                    ))
                },
                BatchSize::SmallInput,
            );
        }
    }
}

pub mod dec_proof {
    use super::*;

    #[allow(clippy::type_complexity)]
    fn proof_input(
        mut rng: impl CryptoRngCore,
    ) -> (
        impl CryptoRngCore,
        SecretSigned<PUint>,
        SecretSigned<PUint>,
        Randomizer<Paillier>,
        PublicKeyPaillier<Paillier>,
        Ciphertext<Paillier>,
        Point<P>,
        Ciphertext<Paillier>,
        Point<P>,
        Point<P>,
        RPParams<Paillier>,
        &'static [u8],
    ) {
        let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
        let pk = sk.public_key();

        let setup = RPParams::random(&mut rng);
        let aux: &[u8] = b"abcde";

        let x = SecretSigned::random_in_exponent_range(&mut rng, Params::L_BOUND);
        let y = SecretSigned::random_in_exponent_range(&mut rng, Params::LP_BOUND);
        let rho = Randomizer::random(&mut rng, pk);

        let k = SecretSigned::random_in_exponent_range(&mut rng, Paillier::PRIME_BITS * 2 - 1);
        let cap_k = Ciphertext::new(&mut rng, pk, &k);
        let cap_d = Ciphertext::new_with_randomizer(pk, &y, &rho) + &cap_k * &-&x;

        let cap_x = secret_scalar_from_signed::<Params>(&x).mul_by_generator();

        let cap_g = Scalar::random(&mut rng).mul_by_generator();
        let cap_s = cap_g * secret_scalar_from_signed::<Params>(&y);

        (
            rng,
            x,
            y,
            rho,
            pk.clone(),
            cap_k,
            cap_x,
            cap_d,
            cap_s,
            cap_g,
            setup,
            aux,
        )
    }

    pub fn dec_proof_prove<R: CryptoRngCore + Clone + 'static>(rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || proof_input(rng.clone()),
                |(mut rng, x, y, rho, pk, cap_k, cap_x, cap_d, cap_s, cap_g, setup, aux)| {
                    black_box(DecProof::<Params>::new(
                        &mut rng,
                        DecSecretInputs {
                            x: &x,
                            y: &y,
                            rho: &rho,
                        },
                        DecPublicInputs {
                            pk0: &pk,
                            cap_k: &cap_k,
                            cap_x: &cap_x,
                            cap_d: &cap_d,
                            cap_s: &cap_s,
                            cap_g: &cap_g,
                        },
                        &setup,
                        &aux,
                    ))
                },
                BatchSize::SmallInput,
            );
        }
    }

    pub fn dec_proof_verify<R: CryptoRngCore + Clone + 'static>(rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let (mut rng, x, y, rho, pk, cap_k, cap_x, cap_d, cap_s, cap_g, setup, aux) =
                        proof_input(rng.clone());

                    let proof = DecProof::<Params>::new(
                        &mut rng,
                        DecSecretInputs {
                            x: &x,
                            y: &y,
                            rho: &rho,
                        },
                        DecPublicInputs {
                            pk0: &pk,
                            cap_k: &cap_k,
                            cap_x: &cap_x,
                            cap_d: &cap_d,
                            cap_s: &cap_s,
                            cap_g: &cap_g,
                        },
                        &setup,
                        &aux,
                    );
                    (proof, pk, cap_k, cap_x, cap_d, cap_s, cap_g, setup)
                },
                |(proof, pk, cap_k, cap_x, cap_d, cap_s, cap_g, rp_params)| {
                    let pub_inputs = DecPublicInputs {
                        pk0: &pk,
                        cap_k: &cap_k,
                        cap_x: &cap_x,
                        cap_d: &cap_d,
                        cap_s: &cap_s,
                        cap_g: &cap_g,
                    };
                    black_box(proof.verify(pub_inputs, &rp_params, b"abcde"));
                },
                BatchSize::SmallInput,
            );
        }
    }
}

pub mod elog_proof {
    use crate::cggmp21::sigma::{ElogProof, ElogPublicInputs, ElogSecretInputs};

    use super::*;
    pub fn elog_proof_prove<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let y = Secret::init_with(|| Scalar::random(&mut rng));
                    let lambda = Secret::init_with(|| Scalar::random(&mut rng));

                    let cap_l = lambda.mul_by_generator();
                    let cap_x = Scalar::random(&mut rng).mul_by_generator();
                    let cap_m = y.mul_by_generator() + cap_x * &lambda;
                    let h = Scalar::random(&mut rng).mul_by_generator();
                    let cap_y = h * &y;
                    (rng.clone(), y, lambda, cap_l, cap_m, cap_x, cap_y, h, b"abcde")
                },
                |(mut rng, y, lambda, cap_l, cap_m, cap_x, cap_y, h, aux)| {
                    black_box(ElogProof::<Params>::new(
                        &mut rng,
                        ElogSecretInputs { y: &y, lambda: &lambda },
                        ElogPublicInputs {
                            cap_l: &cap_l,
                            cap_m: &cap_m,
                            cap_x: &cap_x,
                            cap_y: &cap_y,
                            h: &h,
                        },
                        &aux,
                    ))
                },
                BatchSize::SmallInput,
            );
        }
    }
    pub fn elog_proof_verify<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let y = Secret::init_with(|| Scalar::random(&mut rng));
                    let lambda = Secret::init_with(|| Scalar::random(&mut rng));

                    let cap_l = lambda.mul_by_generator();
                    let cap_x = Scalar::random(&mut rng).mul_by_generator();
                    let cap_m = y.mul_by_generator() + cap_x * &lambda;
                    let h = Scalar::random(&mut rng).mul_by_generator();
                    let cap_y = h * &y;
                    let proof = ElogProof::<Params>::new(
                        &mut rng,
                        ElogSecretInputs { y: &y, lambda: &lambda },
                        ElogPublicInputs {
                            cap_l: &cap_l,
                            cap_m: &cap_m,
                            cap_x: &cap_x,
                            cap_y: &cap_y,
                            h: &h,
                        },
                        b"abcde",
                    );
                    (proof, cap_l, cap_m, cap_x, cap_y, h, b"abcde")
                },
                |(proof, cap_l, cap_m, cap_x, cap_y, h, aux)| {
                    black_box(proof.verify(
                        ElogPublicInputs {
                            cap_l: &cap_l,
                            cap_m: &cap_m,
                            cap_x: &cap_x,
                            cap_y: &cap_y,
                            h: &h,
                        },
                        &aux,
                    ))
                },
                BatchSize::SmallInput,
            );
        }
    }
}

pub mod enc_elg_proof {
    use crate::cggmp21::sigma::{EncElgProof, EncElgPublicInputs, EncElgSecretInputs};

    use super::*;
    pub fn enc_elg_proof_prove<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let pk = sk.public_key();

                    let setup = RPParams::random(&mut rng);

                    let aux: &[u8] = b"abcde";

                    let x = SecretSigned::random_in_exponent_range(&mut rng, Params::L_BOUND);
                    let rho = Randomizer::random(&mut rng, pk);
                    let a = Secret::init_with(|| Scalar::random(&mut rng));
                    let b = Secret::init_with(|| Scalar::random(&mut rng));

                    let cap_c = Ciphertext::new_with_randomizer(pk, &x, &rho);
                    let cap_a = a.mul_by_generator();
                    let cap_b = b.mul_by_generator();
                    let cap_x = (&a * &b + secret_scalar_from_signed::<Params>(&x)).mul_by_generator();

                    (
                        rng.clone(),
                        x,
                        rho,
                        b,
                        pk.clone(),
                        cap_c,
                        cap_a,
                        cap_b,
                        cap_x,
                        setup,
                        aux,
                    )
                },
                |(mut rng, x, rho, b, pk, cap_c, cap_a, cap_b, cap_x, setup, aux)| {
                    black_box(EncElgProof::<Params>::new(
                        &mut rng,
                        EncElgSecretInputs {
                            x: &x,
                            rho: &rho,
                            b: &b,
                        },
                        EncElgPublicInputs {
                            pk0: &pk,
                            cap_c: &cap_c,
                            cap_a: &cap_a,
                            cap_b: &cap_b,
                            cap_x: &cap_x,
                        },
                        &setup,
                        &aux,
                    ))
                },
                BatchSize::SmallInput,
            );
        }
    }
    pub fn enc_elg_proof_verify<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let pk = sk.public_key();

                    let setup = RPParams::random(&mut rng);

                    let aux: &[u8] = b"abcde";

                    let x = SecretSigned::random_in_exponent_range(&mut rng, Params::L_BOUND);
                    let rho = Randomizer::random(&mut rng, pk);
                    let a = Secret::init_with(|| Scalar::random(&mut rng));
                    let b = Secret::init_with(|| Scalar::random(&mut rng));

                    let cap_c = Ciphertext::new_with_randomizer(pk, &x, &rho);
                    let cap_a = a.mul_by_generator();
                    let cap_b = b.mul_by_generator();
                    let cap_x = (&a * &b + secret_scalar_from_signed::<Params>(&x)).mul_by_generator();

                    let proof = EncElgProof::<Params>::new(
                        &mut rng,
                        EncElgSecretInputs {
                            x: &x,
                            rho: &rho,
                            b: &b,
                        },
                        EncElgPublicInputs {
                            pk0: pk,
                            cap_c: &cap_c,
                            cap_a: &cap_a,
                            cap_b: &cap_b,
                            cap_x: &cap_x,
                        },
                        &setup,
                        &aux,
                    );
                    (proof, pk.clone(), cap_c, cap_a, cap_b, cap_x, setup, aux)
                },
                |(proof, pk, cap_c, cap_a, cap_b, cap_x, setup, aux)| {
                    black_box(proof.verify(
                        EncElgPublicInputs {
                            pk0: &pk,
                            cap_c: &cap_c,
                            cap_a: &cap_a,
                            cap_b: &cap_b,
                            cap_x: &cap_x,
                        },
                        &setup,
                        &aux,
                    ))
                },
                BatchSize::SmallInput,
            );
        }
    }
}

pub mod paillier_blum_modulus_proof {
    use super::*;
    pub fn paillier_blum_modulus_proof_prove<R: CryptoRngCore + Clone + 'static>(
        mut rng: R,
    ) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let aux: &[u8] = b"abcde";

                    (rng.clone(), sk, aux)
                },
                |(mut rng, sk, aux)| black_box(ModProof::<Params>::new(&mut rng, &sk, &aux)),
                BatchSize::SmallInput,
            );
        }
    }

    pub fn paillier_blum_modulus_proof_verify<R: CryptoRngCore + Clone + 'static>(
        mut rng: R,
    ) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let aux: &[u8] = b"abcde";
                    let proof = ModProof::<Params>::new(&mut rng, &sk, &aux);
                    (proof, sk.public_key().clone(), aux)
                },
                |(proof, pk, aux)| black_box(proof.verify(&pk, &aux)),
                BatchSize::SmallInput,
            );
        }
    }
}

pub mod prm_proof {
    use super::*;

    pub fn prm_proof_prove<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let secret = RPSecret::random(&mut rng);
                    let setup = RPParams::random_with_secret(&mut rng, &secret);

                    let aux: &[u8] = b"abcde";

                    (rng.clone(), secret, setup, aux)
                },
                |(mut rng, secret, setup, aux)| black_box(PrmProof::<Params>::new(&mut rng, &secret, &setup, &aux)),
                BatchSize::SmallInput,
            );
        }
    }

    pub fn prm_proof_verify<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let secret = RPSecret::random(&mut rng);
                    let setup = RPParams::random_with_secret(&mut rng, &secret);

                    let aux: &[u8] = b"abcde";
                    let proof = PrmProof::<Params>::new(&mut rng, &secret, &setup, &aux);
                    (proof, setup, aux)
                },
                |(proof, setup, aux)| black_box(proof.verify(&setup, &aux)),
                BatchSize::SmallInput,
            );
        }
    }
}

pub mod sch_proof {
    use super::*;

    pub fn sch_proof_prove<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let secret = Secret::init_with(|| Scalar::random(&mut rng));
                    let public = secret.mul_by_generator();
                    let aux: &[u8] = b"abcde";

                    let proof_secret = SchSecret::random(&mut rng);
                    let commitment = SchCommitment::new(&proof_secret);
                    (proof_secret, secret, commitment, public, aux)
                },
                |(proof_secret, secret, commitment, public, aux)| {
                    black_box(SchProof::new(&proof_secret, &secret, &commitment, &public, &aux))
                },
                BatchSize::SmallInput,
            );
        }
    }

    pub fn sch_proof_verify<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let secret = Secret::init_with(|| Scalar::random(&mut rng));
                    let public = secret.mul_by_generator();
                    let aux: &[u8] = b"abcde";

                    let proof_secret = SchSecret::random(&mut rng);
                    let commitment = SchCommitment::new(&proof_secret);
                    let proof = SchProof::new(&proof_secret, &secret, &commitment, &public, &aux);
                    (proof, commitment, public, aux)
                },
                |(proof, commitment, public, aux)| black_box(proof.verify(&commitment, &public, &aux)),
                BatchSize::SmallInput,
            );
        }
    }
}
