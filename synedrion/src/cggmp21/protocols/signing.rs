use alloc::string::String;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::{PartyIdx, PresigningData};
use super::generic::{
    BroadcastRound, DirectRound, FinalizableToResult, FinalizeError, FirstRound, InitError,
    ReceiveError, Round, ToResult,
};
use crate::curve::{Point, RecoverableSignature, Scalar};
use crate::tools::collections::{HoleRange, HoleVec};

pub struct Round1 {
    r: Scalar,
    s_part: Scalar,
    context: Context,
    num_parties: usize,
    party_idx: PartyIdx,
}

#[derive(Clone)]
pub(crate) struct Context {
    pub(crate) message: Scalar,
    pub(crate) verifying_key: Point,
    pub(crate) presigning: PresigningData,
}

impl FirstRound for Round1 {
    type Context = Context;
    fn new(
        _rng: &mut impl CryptoRngCore,
        _shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        context: Self::Context,
    ) -> Result<Self, InitError> {
        let r = context.presigning.nonce.x_coordinate();
        let s_part = context.presigning.ephemeral_scalar_share * context.message
            + r * context.presigning.product_share;
        Ok(Self {
            r,
            s_part,
            context,
            num_parties,
            party_idx,
        })
    }
}

impl Round for Round1 {
    type Type = ToResult;
    type Result = RecoverableSignature;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = None;
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round1Bcast {
    s_part: Scalar,
}

impl BroadcastRound for Round1 {
    const REQUIRES_CONSENSUS: bool = false;
    type Message = Round1Bcast;
    type Payload = Scalar;
    fn broadcast_destinations(&self) -> Option<HoleRange> {
        Some(HoleRange::new(self.num_parties, self.party_idx.as_usize()))
    }
    fn make_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        Ok(Round1Bcast {
            s_part: self.s_part,
        })
    }

    fn verify_broadcast(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        Ok(msg.s_part)
    }
}

impl DirectRound for Round1 {
    type Message = ();
    type Payload = ();
    type Artefact = ();
}

impl FinalizableToResult for Round1 {
    fn finalize_to_result(
        self,
        _rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        _dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        _dm_artefacts: Option<HoleVec<<Self as DirectRound>::Artefact>>,
    ) -> Result<Self::Result, FinalizeError> {
        let shares = bc_payloads.unwrap();
        let s: Scalar = shares.iter().sum();
        let s = s + self.s_part;

        // CHECK: should `s` be normalized here?

        let sig = RecoverableSignature::from_scalars(
            &self.r,
            &s,
            &self.context.verifying_key,
            &self.context.message,
        )
        .unwrap();

        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
    use rand_core::{OsRng, RngCore};

    use super::super::{
        common::PresigningData,
        test_utils::{step_result, step_round},
        FirstRound,
    };
    use super::{Context, Round1};
    use crate::cggmp21::{KeyShare, PartyIdx, TestParams};
    use crate::curve::Scalar;

    #[test]
    fn execute_signing() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let num_parties = 3;
        let key_shares = KeyShare::<TestParams>::new_centralized(&mut OsRng, num_parties, None);

        let presigning_datas = PresigningData::new_centralized(&mut OsRng, &key_shares);

        let message = Scalar::random(&mut OsRng);
        let verifying_key = key_shares[0].verifying_key_as_point();

        let r1 = (0..num_parties)
            .map(|idx| {
                Round1::new(
                    &mut OsRng,
                    &shared_randomness,
                    num_parties,
                    PartyIdx::from_usize(idx),
                    Context {
                        presigning: presigning_datas[idx].clone(),
                        message,
                        verifying_key,
                    },
                )
                .unwrap()
            })
            .collect();

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let signatures = step_result(&mut OsRng, r1a).unwrap();

        for signature in signatures {
            let (sig, rec_id) = signature.to_backend();

            let vkey = key_shares[0].verifying_key();

            // Check that the signature can be verified
            vkey.verify_prehash(&message.to_be_bytes(), &sig).unwrap();

            // Check that the key can be recovered
            let recovered_key =
                VerifyingKey::recover_from_prehash(&message.to_be_bytes(), &sig, rec_id).unwrap();
            assert_eq!(recovered_key, vkey);
        }
    }
}
