//! Functions containing sequential executions of CGGMP21 protocols,
//! intended for benchmarking.

use rand_core::CryptoRngCore;

use super::{
    protocols::{
        auxiliary, keygen, presigning, signing,
        test_utils::{assert_next_round, assert_result, step},
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
            keygen::Round1::<P>::new(
                rng,
                &shared_randomness,
                num_parties,
                PartyIdx::from_usize(idx),
                (),
            )
            .unwrap()
        })
        .collect();

    let r2 = assert_next_round(step(rng, r1).unwrap()).unwrap();
    let r3 = assert_next_round(step(rng, r2).unwrap()).unwrap();
    let _shares = assert_result(step(rng, r3).unwrap()).unwrap();
}

/// A sequential execution of the KeyRefresh/Auxiliary protocol for all parties.
pub fn key_refresh<P: SchemeParams>(rng: &mut impl CryptoRngCore, num_parties: usize) {
    let mut shared_randomness = [0u8; 32];
    rng.fill_bytes(&mut shared_randomness);

    let r1 = (0..num_parties)
        .map(|idx| {
            auxiliary::Round1::<P>::new(
                rng,
                &shared_randomness,
                num_parties,
                PartyIdx::from_usize(idx),
                (),
            )
            .unwrap()
        })
        .collect();

    let r2 = assert_next_round(step(rng, r1).unwrap()).unwrap();
    let r3 = assert_next_round(step(rng, r2).unwrap()).unwrap();
    let _shares = assert_result(step(rng, r3).unwrap()).unwrap();
}

/// A sequential execution of the Presigning protocol for all parties.
pub fn presigning<P: SchemeParams>(rng: &mut impl CryptoRngCore, key_shares: &[KeyShare<P>]) {
    let mut shared_randomness = [0u8; 32];
    rng.fill_bytes(&mut shared_randomness);

    let num_parties = key_shares.len();
    let r1 = (0..num_parties)
        .map(|idx| {
            presigning::Round1Part1::<P>::new(
                rng,
                &shared_randomness,
                num_parties,
                PartyIdx::from_usize(idx),
                key_shares[idx].clone(),
            )
            .unwrap()
        })
        .collect();

    let r1p2 = assert_next_round(step(rng, r1).unwrap()).unwrap();
    let r2 = assert_next_round(step(rng, r1p2).unwrap()).unwrap();
    let r3 = assert_next_round(step(rng, r2).unwrap()).unwrap();
    let _presigning_datas = assert_result(step(rng, r3).unwrap()).unwrap();
}

/// A sequential execution of the Presigning protocol for all parties.
pub fn signing<P: SchemeParams>(rng: &mut impl CryptoRngCore, key_shares: &[KeyShare<P>]) {
    let mut shared_randomness = [0u8; 32];
    rng.fill_bytes(&mut shared_randomness);

    let presigning_datas = PresigningData::new_centralized(rng, key_shares);

    let message = Scalar::random(rng);
    let verifying_key = key_shares[0].verifying_key_as_point();

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
                    verifying_key,
                    presigning: presigning_datas[idx].clone(),
                },
            )
            .unwrap()
        })
        .collect();

    let _signatures = assert_result(step(rng, r1).unwrap()).unwrap();
}
