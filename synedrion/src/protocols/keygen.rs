//! ECDSA key generation (Fig. 5).

use alloc::boxed::Box;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::{KeyShareSeed, PartyIdx, SchemeParams, SessionId};
use super::generic::{
    FinalizeError, FinalizeSuccess, FirstRound, NonExistent, ReceiveError, Round, ToSendTyped,
};
use crate::curve::{Point, Scalar};
use crate::sigma::sch::{SchCommitment, SchProof, SchSecret};
use crate::tools::collections::HoleVec;
use crate::tools::hashing::{Chain, Hash, HashOutput, Hashable};
use crate::tools::random::random_bits;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullData {
    // TODO: include SchemeParams here?
    session_id: SessionId,
    party_idx: PartyIdx,       // i
    rid: Box<[u8]>,            // rid_i
    public: Point,             // X_i
    commitment: SchCommitment, // A_i
    u: Box<[u8]>,              // u_i
}

impl FullData {
    fn hash(&self) -> HashOutput {
        Hash::new_with_dst(b"Keygen")
            .chain(&self.session_id)
            .chain(&self.party_idx)
            .chain(&self.rid)
            .chain(&self.public)
            .chain(&self.commitment)
            .chain(&self.u)
            .finalize()
    }
}

struct SecretData {
    // TODO: probably just a Scalar, since it will have a random mask added later,
    // and we cannot ensure it won't turn it into zero.
    key_share: Scalar,
    sch_secret: SchSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1Bcast {
    hash: HashOutput,
}

impl Hashable for Round1Bcast {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.hash)
    }
}

pub(crate) struct Round1<P: SchemeParams> {
    secret_data: SecretData,
    data: FullData,
    num_parties: usize,
    phantom: PhantomData<P>,
}

#[derive(Clone)]
pub(crate) struct Context {
    pub(crate) session_id: SessionId,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Context = Context;

    fn new(
        rng: &mut impl CryptoRngCore,
        num_parties: usize,
        party_idx: PartyIdx,
        context: Self::Context,
    ) -> Self {
        let secret = Scalar::random(rng);
        let public = secret.mul_by_generator();

        let rid = random_bits(P::SECURITY_PARAMETER);
        let proof_secret = SchSecret::random(rng);
        let commitment = SchCommitment::new(&proof_secret);
        let u = random_bits(P::SECURITY_PARAMETER);

        let data = FullData {
            session_id: context.session_id,
            party_idx,
            rid,
            public,
            commitment,
            u,
        };

        let secret_data = SecretData {
            key_share: secret,
            sch_secret: proof_secret,
        };

        Self {
            secret_data,
            data,
            num_parties,
            phantom: PhantomData,
        }
    }
}

impl<P: SchemeParams> Round for Round1<P> {
    type Payload = HashOutput;
    type Message = Round1Bcast;
    type NextRound = Round2<P>;
    type Result = KeyShareSeed;

    fn party_idx(&self) -> PartyIdx {
        self.data.party_idx
    }
    fn num_parties(&self) -> usize {
        self.num_parties
    }

    fn round_num() -> u8 {
        1
    }
    fn next_round_num() -> Option<u8> {
        Some(2)
    }
    fn requires_broadcast_consensus() -> bool {
        true
    }

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        let hash = self.data.hash();
        ToSendTyped::Broadcast(Round1Bcast { hash })
    }
    fn verify_received(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        Ok(msg.hash)
    }
    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        Ok(FinalizeSuccess::AnotherRound(Round2 {
            hashes: payloads,
            data: self.data,
            secret_data: self.secret_data,
            phantom: PhantomData,
        }))
    }
}

pub struct Round2<P: SchemeParams> {
    secret_data: SecretData,
    data: FullData,
    hashes: HoleVec<HashOutput>, // V_j
    phantom: PhantomData<P>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round2Bcast {
    data: FullData,
}

impl<P: SchemeParams> Round for Round2<P> {
    type Payload = FullData;
    type Message = Round2Bcast;
    type NextRound = Round3<P>;
    type Result = KeyShareSeed;

    fn party_idx(&self) -> PartyIdx {
        self.data.party_idx
    }
    fn num_parties(&self) -> usize {
        self.hashes.len()
    }
    fn round_num() -> u8 {
        2
    }
    fn next_round_num() -> Option<u8> {
        Some(3)
    }
    fn requires_broadcast_consensus() -> bool {
        false
    }

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        ToSendTyped::Broadcast(Round2Bcast {
            data: self.data.clone(),
        })
    }
    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        if &msg.data.hash() != self.hashes.get(from.as_usize()).unwrap() {
            return Err(ReceiveError::VerificationFail("Invalid hash".into()));
        }

        Ok(msg.data)
    }
    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        // XOR the vectors together
        // TODO: is there a better way?
        let mut rid = self.data.rid.clone();
        for data in payloads.iter() {
            for (i, x) in data.rid.iter().enumerate() {
                rid[i] ^= x;
            }
        }

        Ok(FinalizeSuccess::AnotherRound(Round3 {
            datas: payloads,
            data: self.data,
            rid,
            secret_data: self.secret_data,
            phantom: PhantomData,
        }))
    }
}

pub struct Round3<P: SchemeParams> {
    datas: HoleVec<FullData>,
    data: FullData,
    rid: Box<[u8]>,
    secret_data: SecretData,
    phantom: PhantomData<P>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round3Bcast {
    proof: SchProof,
}

impl<P: SchemeParams> Round for Round3<P> {
    type Payload = bool;
    type Message = Round3Bcast;
    type NextRound = NonExistent<Self::Result>;
    type Result = KeyShareSeed;

    fn party_idx(&self) -> PartyIdx {
        self.data.party_idx
    }
    fn num_parties(&self) -> usize {
        self.datas.len()
    }
    fn round_num() -> u8 {
        3
    }
    fn next_round_num() -> Option<u8> {
        None
    }
    fn requires_broadcast_consensus() -> bool {
        false
    }

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        let aux = (&self.data.session_id, &self.data.party_idx, &self.rid);
        let proof = SchProof::new(
            &self.secret_data.sch_secret,
            &self.secret_data.key_share.clone(),
            &self.data.commitment,
            &self.data.public,
            &aux,
        );
        ToSendTyped::Broadcast(Round3Bcast { proof })
    }
    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        let party_data = self.datas.get(from.as_usize()).unwrap();

        let aux = (&party_data.session_id, &party_data.party_idx, &self.rid);
        if !msg
            .proof
            .verify(&party_data.commitment, &party_data.public, &aux)
        {
            return Err(ReceiveError::VerificationFail(
                "Schnorr verification failed".into(),
            ));
        }
        Ok(true)
    }
    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let datas = self.datas.into_vec(self.data);
        let public_keys = datas.into_iter().map(|data| data.public).collect();
        Ok(FinalizeSuccess::Result(KeyShareSeed {
            public: public_keys,
            secret: self.secret_data.key_share,
        }))
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use rand_core::OsRng;

    use super::{Context, Round1};
    use crate::protocols::common::{PartyIdx, SessionId, TestSchemeParams};
    use crate::protocols::generic::{
        tests::{assert_next_round, assert_result, step},
        FirstRound,
    };

    #[test]
    fn execute_keygen() {
        let session_id = SessionId::random(&mut OsRng);
        let context = Context { session_id };

        let r1 = vec![
            Round1::<TestSchemeParams>::new(
                &mut OsRng,
                3,
                PartyIdx::from_usize(0),
                context.clone(),
            ),
            Round1::<TestSchemeParams>::new(
                &mut OsRng,
                3,
                PartyIdx::from_usize(1),
                context.clone(),
            ),
            Round1::<TestSchemeParams>::new(&mut OsRng, 3, PartyIdx::from_usize(2), context),
        ];

        let r2 = assert_next_round(step(&mut OsRng, r1).unwrap()).unwrap();
        let r3 = assert_next_round(step(&mut OsRng, r2).unwrap()).unwrap();
        let shares = assert_result(step(&mut OsRng, r3).unwrap()).unwrap();

        // Check that the sets of public keys are the same at each node

        let public_sets = shares.iter().map(|s| s.public.clone()).collect::<Vec<_>>();

        assert!(public_sets[1..].iter().all(|pk| pk == &public_sets[0]));

        // Check that the public keys correspond to the secret key shares
        let public_set = &public_sets[0];

        let public_from_secret = shares.iter().map(|s| s.secret.mul_by_generator()).collect();

        assert!(public_set == &public_from_secret);
    }
}
