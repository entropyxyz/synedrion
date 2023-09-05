use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::{PartyIdx, PresigningData};
use super::generic::{
    BaseRound, FinalizeError, FinalizeSuccess, FirstRound, InitError, NonExistent, ReceiveError,
    Round, ToSendTyped,
};
use crate::curve::{Point, RecoverableSignature, Scalar};
use crate::tools::collections::HoleVec;

pub struct Round1 {
    r: Scalar,
    s_part: Scalar,
    context: Context,
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
        _num_parties: usize,
        _party_idx: PartyIdx,
        context: Self::Context,
    ) -> Result<Self, InitError> {
        let r = context.presigning.nonce.x_coordinate();
        let s_part = context.presigning.ephemeral_scalar_share * context.message
            + r * context.presigning.product_share;
        Ok(Self { r, s_part, context })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round1Bcast {
    s_part: Scalar,
}

impl BaseRound for Round1 {
    type Payload = Scalar;
    type Message = Round1Bcast;

    const ROUND_NUM: u8 = 1;
    const REQUIRES_BROADCAST_CONSENSUS: bool = false;

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        ToSendTyped::Broadcast(Round1Bcast {
            s_part: self.s_part,
        })
    }

    fn verify_received(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        Ok(msg.s_part)
    }
}

impl Round for Round1 {
    type NextRound = NonExistent<Self::Result>;
    type Result = RecoverableSignature;

    const NEXT_ROUND_NUM: Option<u8> = Some(2);

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let s: Scalar = payloads.iter().sum();
        let s = s + self.s_part;

        // CHECK: should `s` be normalized here?

        let sig = RecoverableSignature::from_scalars(
            &self.r,
            &s,
            &self.context.verifying_key,
            &self.context.message,
        )
        .unwrap();

        Ok(FinalizeSuccess::Result(sig))
    }
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
    use rand_core::{OsRng, RngCore};

    use super::super::{
        common::PresigningData,
        test_utils::{assert_result, step},
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

        let signatures = assert_result(step(&mut OsRng, r1).unwrap()).unwrap();

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
