//! Public exports for use in benchmarks.

//! Functions containing sequential executions of CGGMP21 protocols,
//! intended for benchmarking.

use alloc::boxed::Box;

use rand_core::CryptoRngCore;

use super::cggmp21::{
    key_init, key_refresh, presigning, signing, KeyShare, PresigningData, SchemeParams,
};
use crate::curve::Scalar;
use crate::rounds::{
    test_utils::{step_next_round, step_result, step_round},
    FirstRound, PartyIdx,
};

/// A sequential execution of the KeyGen protocol for all parties.
pub fn key_init<P: SchemeParams>(rng: &mut impl CryptoRngCore, num_parties: usize) {
    let mut shared_randomness = [0u8; 32];
    rng.fill_bytes(&mut shared_randomness);

    let r1 = (0..num_parties)
        .map(|idx| {
            key_init::Round1::<P>::new(
                rng,
                &shared_randomness,
                num_parties,
                PartyIdx::from_usize(idx),
                (),
            )
            .unwrap()
        })
        .collect();

    let r1a = step_round(rng, r1).unwrap();
    let r2 = step_next_round(rng, r1a).unwrap();
    let r2a = step_round(rng, r2).unwrap();
    let r3 = step_next_round(rng, r2a).unwrap();
    let r3a = step_round(rng, r3).unwrap();
    let _shares = step_result(rng, r3a).unwrap();
}

/// A sequential execution of the KeyRefresh/Auxiliary protocol for all parties.
pub fn key_refresh<P: SchemeParams>(rng: &mut impl CryptoRngCore, num_parties: usize) {
    let mut shared_randomness = [0u8; 32];
    rng.fill_bytes(&mut shared_randomness);

    let r1 = (0..num_parties)
        .map(|idx| {
            key_refresh::Round1::<P>::new(
                rng,
                &shared_randomness,
                num_parties,
                PartyIdx::from_usize(idx),
                (),
            )
            .unwrap()
        })
        .collect();

    let r1a = step_round(rng, r1).unwrap();
    let r2 = step_next_round(rng, r1a).unwrap();
    let r2a = step_round(rng, r2).unwrap();
    let r3 = step_next_round(rng, r2a).unwrap();
    let r3a = step_round(rng, r3).unwrap();
    let _changes = step_result(rng, r3a).unwrap();
}

/// A public struct to use for benchmarking of Presigning protocol,
/// to avoid exposing actual crate-private entities.
pub struct PresigningInputs<P: SchemeParams>(Box<[KeyShare<P>]>);

impl<P: SchemeParams> PresigningInputs<P> {
    /// Creates new test data to use in the Presigning and Signing benchmarks.
    pub fn new(rng: &mut impl CryptoRngCore, num_parties: usize) -> Self {
        Self(KeyShare::new_centralized(rng, num_parties, None))
    }
}

/// A sequential execution of the Presigning protocol for all parties.
pub fn presigning<P: SchemeParams>(rng: &mut impl CryptoRngCore, inputs: &PresigningInputs<P>) {
    let mut shared_randomness = [0u8; 32];
    rng.fill_bytes(&mut shared_randomness);

    let num_parties = inputs.0.len();
    let r1 = (0..num_parties)
        .map(|idx| {
            presigning::Round1::<P>::new(
                rng,
                &shared_randomness,
                num_parties,
                PartyIdx::from_usize(idx),
                inputs.0[idx].clone(),
            )
            .unwrap()
        })
        .collect();

    let r1a = step_round(rng, r1).unwrap();
    let r2 = step_next_round(rng, r1a).unwrap();
    let r2a = step_round(rng, r2).unwrap();
    let r3 = step_next_round(rng, r2a).unwrap();
    let r3a = step_round(rng, r3).unwrap();
    let _presigning_datas = step_result(rng, r3a).unwrap();
}

/// A public struct to use for benchmarking of Signing protocol,
/// to avoid exposing actual crate-private entities.
pub struct SigningInputs<P: SchemeParams>(Box<[PresigningData<P>]>);

impl<P: SchemeParams> SigningInputs<P> {
    /// Creates new test data to use in the Signing benchmark.
    pub fn new(rng: &mut impl CryptoRngCore, presigning_inputs: &PresigningInputs<P>) -> Self {
        Self(PresigningData::new_centralized(rng, &presigning_inputs.0))
    }
}

/// A sequential execution of the Presigning protocol for all parties.
pub fn signing<P: SchemeParams>(
    rng: &mut impl CryptoRngCore,
    presigning_inputs: &PresigningInputs<P>,
    signing_inputs: &SigningInputs<P>,
) {
    let mut shared_randomness = [0u8; 32];
    rng.fill_bytes(&mut shared_randomness);

    let message = Scalar::random(rng);

    let num_parties = signing_inputs.0.len();
    let r1 = (0..num_parties)
        .map(|idx| {
            signing::Round1::new(
                rng,
                &shared_randomness,
                num_parties,
                PartyIdx::from_usize(idx),
                signing::Inputs {
                    message,
                    presigning: signing_inputs.0[idx].clone(),
                    key_share: presigning_inputs.0[idx].to_precomputed(),
                },
            )
            .unwrap()
        })
        .collect();

    let r1a = step_round(rng, r1).unwrap();
    let _signatures = step_result(rng, r1a).unwrap();
}
