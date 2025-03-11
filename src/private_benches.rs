use std::time::{Duration, Instant};

use rand_core::CryptoRngCore;

use crate::{
    cggmp21::conversion::secret_scalar_from_signed,
    curve::Scalar,
    k256::ProductionParams112,
    paillier::{Ciphertext, PaillierParams, RPParams, RPSecret, Randomizer, SecretKeyPaillier, SecretKeyPaillierWire},
    tools::Secret,
    uint::SecretSigned,
    zk::{
        AffGProof, AffGPublicInputs, AffGSecretInputs, AffGStarProof, AffGStarPublicInputs, AffGStarSecretInputs,
        DecProof, DecPublicInputs, DecSecretInputs, ElogProof, ElogPublicInputs, ElogSecretInputs, EncElgProof,
        EncElgPublicInputs, EncElgSecretInputs, FacProof, ModProof, PrmProof, SchCommitment, SchProof, SchSecret,
    },
    SchemeParams,
};

type Params = ProductionParams112;
type Paillier = <Params as SchemeParams>::Paillier;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Measure {
    Creation,
    Verification,
}

pub struct PreparedKey<P: SchemeParams> {
    sk: SecretKeyPaillier<P::Paillier>,
    rp_secret: RPSecret<P::Paillier>,
    rp_params: RPParams<P::Paillier>,
}

impl<P: SchemeParams> PreparedKey<P> {
    pub fn new(rng: &mut impl CryptoRngCore) -> Self {
        let sk = SecretKeyPaillierWire::<P::Paillier>::random(rng).into_precomputed();

        let rp_secret = RPSecret::random(rng);
        let rp_params = RPParams::random_with_secret(rng, &rp_secret);

        Self {
            sk,
            rp_secret,
            rp_params,
        }
    }
}

pub fn measure_aff_g(
    rng: &mut impl CryptoRngCore,
    key0: &PreparedKey<Params>,
    key1: &PreparedKey<Params>,
    iters: u64,
    measure: Measure,
) -> Duration {
    let sk0 = &key0.sk;
    let pk0 = sk0.public_key();

    let sk1 = &key1.sk;
    let pk1 = sk1.public_key();

    let rp_params = &key0.rp_params;

    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let aux: &[u8] = b"abcde";

        let x = SecretSigned::random_in_exponent_range(rng, Params::L_BOUND);
        let y = SecretSigned::random_in_exponent_range(rng, Params::LP_BOUND);

        let rho = Randomizer::random(rng, pk0);
        let rho_y = Randomizer::random(rng, pk1);
        let secret = SecretSigned::random_in_exponent_range(rng, Params::L_BOUND);
        let cap_c = Ciphertext::new_with_randomizer(pk0, &secret, &Randomizer::random(rng, pk0));
        let cap_d = &cap_c * &x + Ciphertext::new_with_randomizer(pk0, &-&y, &rho);
        let cap_y = Ciphertext::new_with_randomizer(pk1, &y, &rho_y);
        let cap_x = secret_scalar_from_signed::<Params>(&x).mul_by_generator();

        let secret = AffGSecretInputs {
            x: &x,
            y: &y,
            rho: &rho,
            rho_y: &rho_y,
        };
        let public = AffGPublicInputs {
            pk0,
            pk1,
            cap_c: &cap_c,
            cap_d: &cap_d,
            cap_y: &cap_y,
            cap_x: &cap_x,
        };

        let start = Instant::now();
        let proof = AffGProof::<Params>::new(rng, secret, public, rp_params, &aux);
        match measure {
            Measure::Creation => total += start.elapsed(),
            Measure::Verification => {
                let start = Instant::now();
                assert!(proof.verify(public, rp_params, &aux));
                total += start.elapsed();
            }
        }
    }
    total
}

pub fn measure_aff_g_star(
    rng: &mut impl CryptoRngCore,
    key0: &PreparedKey<Params>,
    key1: &PreparedKey<Params>,
    iters: u64,
    measure: Measure,
) -> Duration {
    let sk0 = &key0.sk;
    let pk0 = sk0.public_key();

    let sk1 = &key1.sk;
    let pk1 = sk1.public_key();

    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let aux: &[u8] = b"abcde";

        let x = SecretSigned::random_in_exponent_range(rng, Params::L_BOUND);
        let y = SecretSigned::random_in_exponent_range(rng, Params::LP_BOUND);
        let rho = Randomizer::random(rng, pk0);
        let mu = Randomizer::random(rng, pk1);

        let secret = SecretSigned::random_in_exponent_range(rng, Params::L_BOUND);
        let cap_c = Ciphertext::new(rng, pk0, &secret);

        let cap_d = &cap_c * &x + Ciphertext::new_with_randomizer(pk0, &-&y, &rho);
        let cap_y = Ciphertext::new_with_randomizer(pk1, &y, &mu);
        let cap_x = secret_scalar_from_signed::<Params>(&x).mul_by_generator();

        let secret = AffGStarSecretInputs {
            x: &x,
            y: &y,
            rho: &rho,
            mu: &mu,
        };
        let public = AffGStarPublicInputs {
            pk0,
            pk1,
            cap_c: &cap_c,
            cap_d: &cap_d,
            cap_y: &cap_y,
            cap_x: &cap_x,
        };

        let start = Instant::now();
        let proof = AffGStarProof::<Params>::new(rng, secret, public, &aux);
        match measure {
            Measure::Creation => total += start.elapsed(),
            Measure::Verification => {
                let start = Instant::now();
                assert!(proof.verify(public, &aux));
                total += start.elapsed();
            }
        }
    }
    total
}

pub fn measure_dec(rng: &mut impl CryptoRngCore, key: &PreparedKey<Params>, iters: u64, measure: Measure) -> Duration {
    let sk = &key.sk;
    let pk = sk.public_key();
    let rp_params = &key.rp_params;

    let num_parties: usize = 10;
    let ceil_log2_num_parties = (num_parties - 1).ilog2() + 1;

    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let aux: &[u8] = b"abcde";

        let x = SecretSigned::random_in_exponent_range(rng, Params::L_BOUND);
        let y = SecretSigned::random_in_exponent_range(
            rng,
            Params::LP_BOUND + Params::EPS_BOUND + 1 + ceil_log2_num_parties,
        );
        let rho = Randomizer::random(rng, pk);

        let k = SecretSigned::random_in_exponent_range(rng, Paillier::PRIME_BITS * 2 - 1);
        let cap_k = Ciphertext::new(rng, pk, &k);
        let cap_d = Ciphertext::new_with_randomizer(pk, &y, &rho) + &cap_k * &-&x;

        let cap_x = secret_scalar_from_signed::<Params>(&x).mul_by_generator();

        let cap_g = Scalar::random(rng).mul_by_generator();
        let cap_s = cap_g * secret_scalar_from_signed::<Params>(&y);

        let secret = DecSecretInputs {
            x: &x,
            y: &y,
            rho: &rho,
        };
        let public = DecPublicInputs {
            pk0: pk,
            cap_k: &cap_k,
            cap_x: &cap_x,
            cap_d: &cap_d,
            cap_s: &cap_s,
            cap_g: &cap_g,
            num_parties,
        };

        let start = Instant::now();
        let proof = DecProof::<Params>::new(rng, secret, public, rp_params, &aux);
        match measure {
            Measure::Creation => total += start.elapsed(),
            Measure::Verification => {
                let start = Instant::now();
                assert!(proof.verify(public, rp_params, &aux));
                total += start.elapsed();
            }
        }
    }
    total
}

pub fn measure_elog(rng: &mut impl CryptoRngCore, iters: u64, measure: Measure) -> Duration {
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let aux: &[u8] = b"abcde";

        let y = Secret::init_with(|| Scalar::random(rng));
        let lambda = Secret::init_with(|| Scalar::random(rng));

        let cap_l = lambda.mul_by_generator();
        let cap_x = Scalar::random(rng).mul_by_generator();
        let cap_m = y.mul_by_generator() + cap_x * &lambda;
        let h = Scalar::random(rng).mul_by_generator();
        let cap_y = h * &y;

        let secret = ElogSecretInputs { y: &y, lambda: &lambda };
        let public = ElogPublicInputs {
            cap_l: &cap_l,
            cap_m: &cap_m,
            cap_x: &cap_x,
            cap_y: &cap_y,
            h: &h,
        };

        let start = Instant::now();
        let proof = ElogProof::<Params>::new(rng, secret, public, &aux);
        match measure {
            Measure::Creation => total += start.elapsed(),
            Measure::Verification => {
                let start = Instant::now();
                assert!(proof.verify(public, &aux));
                total += start.elapsed();
            }
        }
    }
    total
}

pub fn measure_enc_elg(
    rng: &mut impl CryptoRngCore,
    key: &PreparedKey<Params>,
    iters: u64,
    measure: Measure,
) -> Duration {
    let sk = &key.sk;
    let pk = sk.public_key();
    let rp_params = &key.rp_params;

    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let aux: &[u8] = b"abcde";

        let x = SecretSigned::random_in_exponent_range(rng, Params::L_BOUND);
        let rho = Randomizer::random(rng, pk);
        let a = Secret::init_with(|| Scalar::random(rng));
        let b = Secret::init_with(|| Scalar::random(rng));

        let cap_c = Ciphertext::new_with_randomizer(pk, &x, &rho);
        let cap_a = a.mul_by_generator();
        let cap_b = b.mul_by_generator();
        let cap_x = (&a * &b + secret_scalar_from_signed::<Params>(&x)).mul_by_generator();

        let secret = EncElgSecretInputs {
            x: &x,
            rho: &rho,
            b: &b,
        };
        let public = EncElgPublicInputs {
            pk0: pk,
            cap_c: &cap_c,
            cap_a: &cap_a,
            cap_b: &cap_b,
            cap_x: &cap_x,
        };

        let start = Instant::now();
        let proof = EncElgProof::<Params>::new(rng, secret, public, rp_params, &aux);
        match measure {
            Measure::Creation => total += start.elapsed(),
            Measure::Verification => {
                let start = Instant::now();
                assert!(proof.verify(public, rp_params, &aux));
                total += start.elapsed();
            }
        }
    }
    total
}

pub fn measure_fac(rng: &mut impl CryptoRngCore, key: &PreparedKey<Params>, iters: u64, measure: Measure) -> Duration {
    let sk = &key.sk;
    let pk = sk.public_key();
    let rp_params = &key.rp_params;

    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let aux: &[u8] = b"abcde";

        let start = Instant::now();
        let proof = FacProof::<Params>::new(rng, sk, rp_params, &aux);
        match measure {
            Measure::Creation => total += start.elapsed(),
            Measure::Verification => {
                let start = Instant::now();
                assert!(proof.verify(pk, rp_params, &aux));
                total += start.elapsed();
            }
        }
    }
    total
}

pub fn measure_mod(rng: &mut impl CryptoRngCore, key: &PreparedKey<Params>, iters: u64, measure: Measure) -> Duration {
    let sk = &key.sk;
    let pk = sk.public_key();

    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let aux: &[u8] = b"abcde";

        let start = Instant::now();
        let proof = ModProof::<Params>::new(rng, sk, &aux);
        match measure {
            Measure::Creation => total += start.elapsed(),
            Measure::Verification => {
                let start = Instant::now();
                assert!(proof.verify(pk, &aux));
                total += start.elapsed();
            }
        }
    }
    total
}

pub fn measure_prm(rng: &mut impl CryptoRngCore, key: &PreparedKey<Params>, iters: u64, measure: Measure) -> Duration {
    let rp_secret = &key.rp_secret;
    let rp_params = &key.rp_params;

    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let aux: &[u8] = b"abcde";

        let start = Instant::now();
        let proof = PrmProof::<Params>::new(rng, rp_secret, rp_params, &aux);
        match measure {
            Measure::Creation => total += start.elapsed(),
            Measure::Verification => {
                let start = Instant::now();
                assert!(proof.verify(rp_params, &aux));
                total += start.elapsed();
            }
        }
    }
    total
}

pub fn measure_sch(rng: &mut impl CryptoRngCore, iters: u64, measure: Measure) -> Duration {
    let mut total = Duration::ZERO;
    for _ in 0..iters {
        let aux: &[u8] = b"abcde";

        let secret = Secret::init_with(|| Scalar::<Params>::random(rng));
        let public = secret.mul_by_generator();
        let proof_secret = SchSecret::random(rng);
        let commitment = SchCommitment::new(&proof_secret);

        let start = Instant::now();
        let proof = SchProof::new(&proof_secret, &secret, &commitment, &public, &aux);
        match measure {
            Measure::Creation => total += start.elapsed(),
            Measure::Verification => {
                let start = Instant::now();
                assert!(proof.verify(&commitment, &public, &aux));
                total += start.elapsed();
            }
        }
    }
    total
}
