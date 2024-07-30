//! Public exports for use in benchmarks.

//! Functions containing sequential executions of CGGMP21 protocols,
//! intended for benchmarking.

use alloc::collections::{BTreeMap, BTreeSet};

use rand_core::CryptoRngCore;

use super::cggmp21::{
    key_init, key_refresh, presigning, signing, AuxInfo, KeyShare, PresigningData, SchemeParams,
};
use crate::curve::Scalar;
use crate::rounds::{
    test_utils::{step_next_round, step_result, step_round, Id, Without},
    FirstRound,
};

/// A sequential execution of the KeyGen protocol for all parties.
pub fn key_init<P: SchemeParams>(rng: &mut impl CryptoRngCore, num_parties: usize) {
    let mut shared_randomness = [0u8; 32];
    rng.fill_bytes(&mut shared_randomness);

    let ids = BTreeSet::from_iter((0..num_parties as u32).map(Id));

    let r1 = ids
        .iter()
        .map(|id| {
            let round = key_init::Round1::<P, Id>::new(
                rng,
                &shared_randomness,
                ids.clone().without(id),
                *id,
                (),
            )
            .unwrap();
            (*id, round)
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

    let ids = BTreeSet::from_iter((0..num_parties as u32).map(Id));

    let r1 = ids
        .iter()
        .map(|id| {
            let round = key_refresh::Round1::<P, Id>::new(
                rng,
                &shared_randomness,
                ids.clone().without(id),
                *id,
                (),
            )
            .unwrap();
            (*id, round)
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
pub struct PresigningInputs<P: SchemeParams> {
    ids: BTreeSet<Id>,
    key_shares: BTreeMap<Id, KeyShare<P, Id>>,
    aux_infos: BTreeMap<Id, AuxInfo<P, Id>>,
}

impl<P: SchemeParams> PresigningInputs<P> {
    /// Creates new test data to use in the Presigning and Signing benchmarks.
    pub fn new(rng: &mut impl CryptoRngCore, num_parties: usize) -> Self {
        let ids = BTreeSet::from_iter((0..num_parties as u32).map(Id));
        let key_shares = KeyShare::new_centralized(rng, &ids, None);
        let aux_infos = AuxInfo::new_centralized(rng, &ids);
        Self {
            ids,
            key_shares,
            aux_infos,
        }
    }
}

/// A sequential execution of the Presigning protocol for all parties.
pub fn presigning<P: SchemeParams>(rng: &mut impl CryptoRngCore, inputs: &PresigningInputs<P>) {
    let mut shared_randomness = [0u8; 32];
    rng.fill_bytes(&mut shared_randomness);

    let r1 = inputs
        .ids
        .iter()
        .map(|id| {
            let round = presigning::Round1::<P, Id>::new(
                rng,
                &shared_randomness,
                inputs.ids.clone().without(id),
                *id,
                (inputs.key_shares[id].clone(), inputs.aux_infos[id].clone()),
            )
            .unwrap();
            (*id, round)
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
pub struct SigningInputs<P: SchemeParams> {
    ids: BTreeSet<Id>,
    presigning_datas: BTreeMap<Id, PresigningData<P, Id>>,
}

impl<P: SchemeParams> SigningInputs<P> {
    /// Creates new test data to use in the Signing benchmark.
    pub fn new(rng: &mut impl CryptoRngCore, presigning_inputs: &PresigningInputs<P>) -> Self {
        Self {
            ids: presigning_inputs.ids.clone(),
            presigning_datas: PresigningData::new_centralized(
                rng,
                &presigning_inputs.key_shares,
                &presigning_inputs.aux_infos,
            ),
        }
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

    let r1 = signing_inputs
        .ids
        .iter()
        .map(|id| {
            let round = signing::Round1::new(
                rng,
                &shared_randomness,
                signing_inputs.ids.clone().without(id),
                *id,
                signing::Inputs {
                    message,
                    presigning: signing_inputs.presigning_datas[id].clone(),
                    key_share: presigning_inputs.key_shares[id].clone(),
                    aux_info: presigning_inputs.aux_infos[id].clone(),
                },
            )
            .unwrap();
            (*id, round)
        })
        .collect();

    let r1a = step_round(rng, r1).unwrap();
    let _signatures = step_result(rng, r1a).unwrap();
}
