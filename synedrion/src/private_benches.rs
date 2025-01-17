use criterion::{black_box, BatchSize, Bencher};
use rand_core::CryptoRngCore;

use crate::{
    cggmp21::{
        conversion::secret_scalar_from_signed,
        sigma::FacProof,
        sigma::ModProof,
        sigma::{AffGProof, AffGPublicInputs, AffGSecretInputs},
        sigma::{DecProof, DecPublicInputs, DecSecretInputs},
        sigma::{EncProof, EncPublicInputs, EncSecretInputs},
        sigma::{LogStarProof, LogStarPublicInputs, LogStarSecretInputs},
        sigma::{MulProof, MulPublicInputs, MulSecretInputs},
        sigma::{MulStarProof, MulStarPublicInputs, MulStarSecretInputs},
        PaillierProduction, ProductionParams,
    },
    curve::{Point, Scalar},
    paillier::{Ciphertext, PaillierParams, PublicKeyPaillier, RPParams, Randomizer, SecretKeyPaillierWire},
    uint::SecretSigned,
    SchemeParams,
};

type Params = ProductionParams;
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
        Point,
        RPParams<Paillier>,
        &'static [u8],
    ) {
        let sk0 = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
        let pk0 = sk0.public_key().clone();

        let sk1 = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
        let pk1 = sk1.public_key().clone();

        let rp_params = RPParams::random(&mut rng);

        let aux: &[u8] = b"abcde";

        let x = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
        let y = SecretSigned::random_in_exp_range(&mut rng, Params::LP_BOUND);

        let rho = Randomizer::random(&mut rng, &pk0);
        let rho_y = Randomizer::random(&mut rng, &pk1);
        let secret = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
        let cap_c = Ciphertext::new_with_randomizer_signed(&pk0, &secret, &Randomizer::random(&mut rng, &pk0));
        let cap_d = &cap_c * &x + Ciphertext::new_with_randomizer_signed(&pk0, &-&y, &rho);
        let cap_y = Ciphertext::new_with_randomizer_signed(&pk1, &y, &rho_y);
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

pub mod dec_proof {
    use super::*;
    pub fn dec_proof_prove<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let pk = sk.public_key();

                    let setup = RPParams::random(&mut rng);

                    let aux: &[u8] = b"abcde";
                    let y = SecretSigned::random_in_exp_range(&mut rng, Paillier::PRIME_BITS * 2 - 2);
                    let x = *secret_scalar_from_signed::<Params>(&y).expose_secret();

                    let rho = Randomizer::random(&mut rng, pk);
                    let cap_c = Ciphertext::new_with_randomizer_signed(pk, &y, &rho);

                    (rng.clone(), y, rho, pk.clone(), x, cap_c, setup, aux)
                },
                |(mut rng, y, rho, pk, x, cap_c, setup, aux)| {
                    black_box(DecProof::<Params>::new(
                        &mut rng,
                        DecSecretInputs { y: &y, rho: &rho },
                        DecPublicInputs {
                            pk0: &pk,
                            x: &x,
                            cap_c: &cap_c,
                        },
                        &setup,
                        &aux,
                    ))
                },
                BatchSize::SmallInput,
            );
        }
    }
    pub fn dec_proof_verify<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let pk = sk.public_key();

                    let setup = RPParams::random(&mut rng);

                    let aux: &[u8] = b"abcde";
                    let y = SecretSigned::random_in_exp_range(&mut rng, Paillier::PRIME_BITS * 2 - 2);
                    let x = *secret_scalar_from_signed::<Params>(&y).expose_secret();

                    let rho = Randomizer::random(&mut rng, pk);
                    let cap_c = Ciphertext::new_with_randomizer_signed(pk, &y, &rho);

                    let pub_inputs = DecPublicInputs {
                        pk0: pk,
                        x: &x,
                        cap_c: &cap_c,
                    };
                    let proof = DecProof::<Params>::new(
                        &mut rng,
                        DecSecretInputs { y: &y, rho: &rho },
                        pub_inputs,
                        &setup,
                        &aux,
                    );
                    (proof, pk.clone(), x, cap_c.clone(), setup)
                },
                |(proof, pk, x, cap_c, rp_params)| {
                    let pub_inputs = DecPublicInputs {
                        pk0: &pk,
                        x: &x,
                        cap_c: &cap_c,
                    };
                    black_box(proof.verify(pub_inputs, &rp_params, b"abcde"));
                },
                BatchSize::SmallInput,
            );
        }
    }
}

pub mod enc_proof {
    use super::*;
    pub fn enc_proof_prove<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let pk = sk.public_key();

                    let setup = RPParams::random(&mut rng);

                    let aux: &[u8] = b"abcde";

                    let secret = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
                    let randomizer = Randomizer::random(&mut rng, pk);
                    let ciphertext = Ciphertext::new_with_randomizer_signed(pk, &secret, &randomizer);
                    (rng.clone(), secret, randomizer, pk.clone(), ciphertext, setup, aux)
                },
                |(mut rng, secret, randomizer, pk, ciphertext, setup, aux)| {
                    black_box(EncProof::<Params>::new(
                        &mut rng,
                        EncSecretInputs {
                            k: &secret,
                            rho: &randomizer,
                        },
                        EncPublicInputs {
                            pk0: &pk,
                            cap_k: &ciphertext,
                        },
                        &setup,
                        &aux,
                    ))
                },
                BatchSize::SmallInput,
            );
        }
    }

    pub fn enc_proof_verify<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let pk = sk.public_key();

                    let setup = RPParams::random(&mut rng);

                    let aux: &[u8] = b"abcde";

                    let secret = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
                    let randomizer = Randomizer::random(&mut rng, pk);
                    let ciphertext = Ciphertext::new_with_randomizer_signed(pk, &secret, &randomizer);
                    let proof = EncProof::<Params>::new(
                        &mut rng,
                        EncSecretInputs {
                            k: &secret,
                            rho: &randomizer,
                        },
                        EncPublicInputs {
                            pk0: pk,
                            cap_k: &ciphertext,
                        },
                        &setup,
                        &aux,
                    );
                    (proof, pk.clone(), ciphertext, setup, aux)
                },
                |(proof, pk, ciphertext, setup, aux)| {
                    let pub_inputs = EncPublicInputs {
                        pk0: &pk,
                        cap_k: &ciphertext,
                    };
                    black_box(proof.verify(pub_inputs, &setup, &aux))
                },
                BatchSize::SmallInput,
            );
        }
    }
}

pub mod log_star_proof {
    use super::*;
    pub fn log_star_proof_prove<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let pk = sk.public_key();

                    let setup = RPParams::random(&mut rng);

                    let aux: &[u8] = b"abcde";

                    let g = Point::GENERATOR * Scalar::random(&mut rng);
                    let x = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
                    let rho = Randomizer::random(&mut rng, pk);
                    let cap_c = Ciphertext::new_with_randomizer_signed(pk, &x, &rho);
                    let cap_x = g * secret_scalar_from_signed::<Params>(&x);

                    (rng.clone(), x, rho, pk.clone(), cap_c, g, cap_x, setup, aux)
                },
                |(mut rng, x, rho, pk, cap_c, g, cap_x, setup, aux)| {
                    black_box(LogStarProof::<Params>::new(
                        &mut rng,
                        LogStarSecretInputs { x: &x, rho: &rho },
                        LogStarPublicInputs {
                            pk0: &pk,
                            cap_c: &cap_c,
                            g: &g,
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

    pub fn log_star_proof_verify<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let pk = sk.public_key();

                    let setup = RPParams::random(&mut rng);

                    let aux: &[u8] = b"abcde";

                    let g = Point::GENERATOR * Scalar::random(&mut rng);
                    let x = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
                    let rho = Randomizer::random(&mut rng, pk);
                    let cap_c = Ciphertext::new_with_randomizer_signed(pk, &x, &rho);
                    let cap_x = g * secret_scalar_from_signed::<Params>(&x);
                    let proof = LogStarProof::<Params>::new(
                        &mut rng,
                        LogStarSecretInputs { x: &x, rho: &rho },
                        LogStarPublicInputs {
                            pk0: pk,
                            cap_c: &cap_c,
                            g: &g,
                            cap_x: &cap_x,
                        },
                        &setup,
                        &aux,
                    );
                    (proof, pk.clone(), cap_c, g, cap_x, setup, aux)
                },
                |(proof, pk, cap_c, g, cap_x, setup, aux)| {
                    let pub_inputs = LogStarPublicInputs {
                        pk0: &pk,
                        cap_c: &cap_c,
                        g: &g,
                        cap_x: &cap_x,
                    };
                    black_box(proof.verify(pub_inputs, &setup, &aux))
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
                    (rng.clone(), proof, sk.public_key().clone(), aux)
                },
                |(mut rng, proof, pk, aux)| black_box(proof.verify(&mut rng, &pk, &aux)),
                BatchSize::SmallInput,
            );
        }
    }
}

pub mod mul_star_proof {
    use super::*;

    pub fn mul_star_proof_prove<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let pk = sk.public_key();

                    let setup = RPParams::random(&mut rng);

                    let aux: &[u8] = b"abcde";

                    let x = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
                    let secret = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
                    let rho = Randomizer::random(&mut rng, pk);
                    let cap_c = Ciphertext::new_with_randomizer_signed(pk, &secret, &Randomizer::random(&mut rng, pk));
                    let cap_d = (&cap_c * &x).mul_randomizer(&rho);
                    let cap_x = secret_scalar_from_signed::<Params>(&x).mul_by_generator();

                    (rng.clone(), x, rho, pk.clone(), cap_c, cap_d, cap_x, setup, aux)
                },
                |(mut rng, x, rho, pk, cap_c, cap_d, cap_x, setup, aux)| {
                    black_box(MulStarProof::<Params>::new(
                        &mut rng,
                        MulStarSecretInputs { x: &x, rho: &rho },
                        MulStarPublicInputs {
                            pk0: &pk,
                            cap_c: &cap_c,
                            cap_d: &cap_d,
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

    pub fn mul_star_proof_verify<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let pk = sk.public_key();

                    let setup = RPParams::random(&mut rng);

                    let aux: &[u8] = b"abcde";

                    let x = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
                    let secret = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
                    let rho = Randomizer::random(&mut rng, pk);
                    let cap_c = Ciphertext::new_with_randomizer_signed(pk, &secret, &Randomizer::random(&mut rng, pk));
                    let cap_d = (&cap_c * &x).mul_randomizer(&rho);
                    let cap_x = secret_scalar_from_signed::<Params>(&x).mul_by_generator();

                    let proof = MulStarProof::<Params>::new(
                        &mut rng,
                        MulStarSecretInputs { x: &x, rho: &rho },
                        MulStarPublicInputs {
                            pk0: pk,
                            cap_c: &cap_c,
                            cap_d: &cap_d,
                            cap_x: &cap_x,
                        },
                        &setup,
                        &aux,
                    );
                    (proof, pk.clone(), cap_c, cap_d, cap_x, setup, aux)
                },
                |(proof, pk, cap_c, cap_d, cap_x, setup, aux)| {
                    let pub_inputs = MulStarPublicInputs {
                        pk0: &pk,
                        cap_c: &cap_c,
                        cap_d: &cap_d,
                        cap_x: &cap_x,
                    };
                    black_box(proof.verify(pub_inputs, &setup, &aux))
                },
                BatchSize::SmallInput,
            );
        }
    }
}

pub mod paillier_mul_proof {
    use super::*;

    pub fn paillier_mul_proof_prove<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let pk = sk.public_key();

                    let aux: &[u8] = b"abcde";

                    let x = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
                    let y = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
                    let rho_x = Randomizer::random(&mut rng, pk);
                    let rho = Randomizer::random(&mut rng, pk);

                    let cap_x = Ciphertext::new_with_randomizer_signed(pk, &x, &rho_x);
                    let cap_y = Ciphertext::new_with_randomizer_signed(pk, &y, &Randomizer::random(&mut rng, pk));
                    let cap_c = (&cap_y * &x).mul_randomizer(&rho);

                    (rng.clone(), x, rho_x, rho, pk.clone(), cap_x, cap_y, cap_c, aux)
                },
                |(mut rng, x, rho_x, rho, pk, cap_x, cap_y, cap_c, aux)| {
                    black_box(MulProof::<Params>::new(
                        &mut rng,
                        MulSecretInputs {
                            x: &x,
                            rho_x: &rho_x,
                            rho: &rho,
                        },
                        MulPublicInputs {
                            pk: &pk,
                            cap_x: &cap_x,
                            cap_y: &cap_y,
                            cap_c: &cap_c,
                        },
                        &aux,
                    ))
                },
                BatchSize::SmallInput,
            );
        }
    }

    pub fn paillier_mul_proof_verify<R: CryptoRngCore + Clone + 'static>(mut rng: R) -> impl FnMut(&mut Bencher<'_>) {
        move |b: &mut Bencher<'_>| {
            b.iter_batched(
                || {
                    let sk = SecretKeyPaillierWire::<Paillier>::random(&mut rng).into_precomputed();
                    let pk = sk.public_key();

                    let aux: &[u8] = b"abcde";

                    let x = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
                    let y = SecretSigned::random_in_exp_range(&mut rng, Params::L_BOUND);
                    let rho_x = Randomizer::random(&mut rng, pk);
                    let rho = Randomizer::random(&mut rng, pk);

                    let cap_x = Ciphertext::new_with_randomizer_signed(pk, &x, &rho_x);
                    let cap_y = Ciphertext::new_with_randomizer_signed(pk, &y, &Randomizer::random(&mut rng, pk));
                    let cap_c = (&cap_y * &x).mul_randomizer(&rho);

                    let proof = MulProof::<Params>::new(
                        &mut rng,
                        MulSecretInputs {
                            x: &x,
                            rho_x: &rho_x,
                            rho: &rho,
                        },
                        MulPublicInputs {
                            pk: pk,
                            cap_x: &cap_x,
                            cap_y: &cap_y,
                            cap_c: &cap_c,
                        },
                        &aux,
                    );
                    (proof, pk.clone(), cap_x, cap_y, cap_c, aux)
                },
                |(proof, pk, cap_x, cap_y, cap_c, aux)| {
                    let pub_inputs = MulPublicInputs {
                        pk: &pk,
                        cap_x: &cap_x,
                        cap_y: &cap_y,
                        cap_c: &cap_c,
                    };
                    black_box(proof.verify(pub_inputs, &aux))
                },
                BatchSize::SmallInput,
            );
        }
    }
}
