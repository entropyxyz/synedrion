//! Functions containing sequential executions of CGGMP21 protocols,
//! intended for benchmarking.

use rand_core::CryptoRngCore;

use super::{
    protocols::{
        key_init, key_refresh, presigning, signing,
        test_utils::{step_next_round, step_result, step_round},
        FirstRound, PartyIdx, PresigningData,
    },
    KeyShare, SchemeParams,
};
use crate::curve::Scalar;

/// A sequential execution of the KeyGen protocol for all parties.
pub fn keygen<P: SchemeParams>(rng: &mut impl CryptoRngCore, num_parties: usize) {
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

/// A sequential execution of the Presigning protocol for all parties.
pub fn presigning<P: SchemeParams>(rng: &mut impl CryptoRngCore, key_shares: &[KeyShare<P>]) {
    let mut shared_randomness = [0u8; 32];
    rng.fill_bytes(&mut shared_randomness);

    let num_parties = key_shares.len();
    let r1 = (0..num_parties)
        .map(|idx| {
            presigning::Round1::<P>::new(
                rng,
                &shared_randomness,
                num_parties,
                PartyIdx::from_usize(idx),
                key_shares[idx].clone(),
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

/// A sequential execution of the Presigning protocol for all parties.
pub fn signing<P: SchemeParams>(rng: &mut impl CryptoRngCore, key_shares: &[KeyShare<P>]) {
    let mut shared_randomness = [0u8; 32];
    rng.fill_bytes(&mut shared_randomness);

    let presigning_datas = PresigningData::new_centralized(rng, key_shares);

    let message = Scalar::random(rng);

    let num_parties = presigning_datas.len();
    let r1 = (0..num_parties)
        .map(|idx| {
            signing::Round1::new(
                rng,
                &shared_randomness,
                num_parties,
                PartyIdx::from_usize(idx),
                signing::Context {
                    message,
                    presigning: presigning_datas[idx].clone(),
                    key_share: key_shares[idx].to_precomputed(),
                },
            )
            .unwrap()
        })
        .collect();

    let r1a = step_round(rng, r1).unwrap();
    let _signatures = step_result(rng, r1a).unwrap();
}
