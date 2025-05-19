use dudect_bencher::{BenchRng, Class, CtRunner};

use crypto_bigint::{NonZero, RandomMod};
use rand::Rng;
use rand_core::CryptoRngCore;

use crate::{
    k256::{PaillierProduction112, ProductionParams112},
    paillier::{PaillierParams, RPParams, SecretKeyPaillier, SecretKeyPaillierWire},
    tools::Secret,
    uint::{PublicSigned, SecretSigned},
    Extendable, MulWide, SchemeParams,
};

type Pai = PaillierProduction112;
type Prm = ProductionParams112;

/// Is `RPParams::commit` constant time?
pub fn rp_commit_both(runner: &mut CtRunner, rng: &mut BenchRng) {
    let input_len = 1000;
    let (rp_params, sk, inputs) = rp_inputs(rng, input_len);
    let value = sk.p_signed();
    for (class, randomizer) in inputs.into_iter() {
        runner.run_one(class, || rp_params.commit(&value, &randomizer));
    }
}

/// Is `RPParams::commit_zero_value` constant time?
pub fn rp_commit_zero_value(runner: &mut CtRunner, rng: &mut BenchRng) {
    let (rp_params, _, inputs) = rp_inputs(rng, 10_000);
    for (class, randomizer) in inputs.into_iter() {
        runner.run_one(class, || rp_params.commit_zero_value(&randomizer));
    }
}

/// Is `RPParams::commit_zero_randomizer` constant time?
pub fn rp_commit_zero_randomizer(runner: &mut CtRunner, rng: &mut BenchRng) {
    let rp_params: RPParams<Pai> = RPParams::random(rng);
    let modulus = SecretKeyPaillierWire::<Pai>::random(rng)
        .into_precomputed()
        .public_key()
        .modulus()
        .to_wide();

    // commit_zero_randomizer is constant time, so hard to set a value here. :)
    let input_len = 1000;
    let inputs = (0..input_len)
        .map(|_| {
            if rng.r#gen::<bool>() {
                (
                    Class::Left,
                    PublicSigned::new_positive(
                        <Pai as PaillierParams>::WideUint::random_mod(rng, &NonZero::new(modulus).unwrap()),
                        Pai::MODULUS_BITS,
                    )
                    .unwrap(),
                )
            } else {
                (
                    Class::Right,
                    PublicSigned::new_positive(<Pai as PaillierParams>::WideUint::ONE, Pai::MODULUS_BITS).unwrap(),
                )
            }
        })
        .collect::<Vec<(Class, PublicSigned<_>)>>();

    for (class, randomizer) in inputs.into_iter() {
        runner.run_one(class, || rp_params.commit_zero_randomizer(&randomizer));
    }
}

fn rp_inputs(
    rng: &mut impl CryptoRngCore,
    input_len: usize,
) -> (
    RPParams<Pai>,
    SecretKeyPaillier<Pai>,
    Vec<(Class, SecretSigned<<Prm as SchemeParams>::ExtraWideUint>)>,
) {
    let rp_params = RPParams::random(rng);
    let hat_cap_n = rp_params.modulus();
    let sk = SecretKeyPaillierWire::<Pai>::random(rng).into_precomputed();
    let pk = sk.public_key();
    let scale: <Pai as PaillierParams>::WideUint = pk.modulus().mul_wide(hat_cap_n);
    let bound = Prm::L_BOUND + Prm::EPS_BOUND + scale.bits_vartime();

    let inputs = (0..input_len)
        .map(|_| {
            if rng.r#gen::<bool>() {
                (
                    Class::Left,
                    SecretSigned::<<Pai as PaillierParams>::Uint>::random_in_exponent_range_scaled_wide(
                        rng,
                        Prm::L_BOUND + Prm::EPS_BOUND,
                        &scale,
                    ),
                )
            } else {
                (
                    Class::Right,
                    SecretSigned::<<Prm as SchemeParams>::ExtraWideUint>::new_positive(
                        Secret::init_with(|| <Prm as SchemeParams>::ExtraWideUint::ONE),
                        bound,
                    )
                    .unwrap(),
                )
            }
        })
        .collect();
    (rp_params, sk, inputs)
}
