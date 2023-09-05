//! ECDSA key generation (Fig. 5).

use alloc::boxed::Box;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::{KeyShareSeed, PartyIdx};
use super::generic::{
    BaseRound, FinalizeError, FinalizeSuccess, FirstRound, InitError, NonExistent, ReceiveError,
    Round, ToSendTyped,
};
use crate::cggmp21::{
    sigma::{SchCommitment, SchProof, SchSecret},
    SchemeParams,
};
use crate::curve::{Point, Scalar};
use crate::tools::collections::HoleVec;
use crate::tools::hashing::{Chain, Hash, HashOutput, Hashable};
use crate::tools::random::random_bits;
use crate::tools::serde_bytes;

// CHECK: note that we don't include `sid` (shared randomness) or `i` (party idx) here.
// Since `sid` is shared, every node already has it,
// so there's no need to include it in the message.
// And `i` we get as `from` when we receive a message.
// Although these will be still added to the hash and auxiliary params of proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullData {
    #[serde(with = "serde_bytes::as_base64")]
    rid: Box<[u8]>, // rid_i
    public: Point,             // X_i
    commitment: SchCommitment, // A_i
    #[serde(with = "serde_bytes::as_base64")]
    u: Box<[u8]>, // u_i
}

impl Hashable for FullData {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest
            .chain(&self.rid)
            .chain(&self.public)
            .chain(&self.commitment)
            .chain(&self.u)
    }
}

impl FullData {
    fn hash(&self, shared_randomness: &[u8], party_idx: PartyIdx) -> HashOutput {
        Hash::new_with_dst(b"Keygen")
            .chain(&shared_randomness)
            .chain(&party_idx)
            .chain(self)
            .finalize()
    }
}

struct Context {
    // TODO: probably just a Scalar, since it will have a random mask added later,
    // and we cannot ensure it won't turn it into zero.
    key_share: Scalar,
    sch_secret: SchSecret,
    shared_randomness: Box<[u8]>,
    party_idx: PartyIdx,
    data: FullData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1Bcast {
    hash: HashOutput,
}

pub(crate) struct Round1<P: SchemeParams> {
    context: Context,
    phantom: PhantomData<P>,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Context = ();

    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        _num_parties: usize,
        party_idx: PartyIdx,
        _context: Self::Context,
    ) -> Result<Self, InitError> {
        let secret = Scalar::random(rng);
        let public = secret.mul_by_generator();

        let rid = random_bits(P::SECURITY_PARAMETER);
        let proof_secret = SchSecret::random(rng);
        let commitment = SchCommitment::new(&proof_secret);
        let u = random_bits(P::SECURITY_PARAMETER);

        let data = FullData {
            rid,
            public,
            commitment,
            u,
        };

        let context = Context {
            party_idx,
            key_share: secret,
            sch_secret: proof_secret,
            shared_randomness: shared_randomness.into(),
            data,
        };

        Ok(Self {
            context,
            phantom: PhantomData,
        })
    }
}

impl<P: SchemeParams> BaseRound for Round1<P> {
    type Payload = HashOutput;
    type Message = Round1Bcast;

    const ROUND_NUM: u8 = 1;
    const REQUIRES_BROADCAST_CONSENSUS: bool = true;

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        let hash = self
            .context
            .data
            .hash(&self.context.shared_randomness, self.context.party_idx);
        ToSendTyped::Broadcast(Round1Bcast { hash })
    }
    fn verify_received(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        Ok(msg.hash)
    }
}

impl<P: SchemeParams> Round for Round1<P> {
    type NextRound = Round2<P>;
    type Result = KeyShareSeed;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);
    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        Ok(FinalizeSuccess::AnotherRound(Round2 {
            hashes: payloads,
            context: self.context,
            phantom: PhantomData,
        }))
    }
}

pub struct Round2<P: SchemeParams> {
    context: Context,
    hashes: HoleVec<HashOutput>, // V_j
    phantom: PhantomData<P>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round2Bcast {
    data: FullData,
}

impl<P: SchemeParams> BaseRound for Round2<P> {
    type Payload = FullData;
    type Message = Round2Bcast;

    const ROUND_NUM: u8 = 2;
    const REQUIRES_BROADCAST_CONSENSUS: bool = false;

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        ToSendTyped::Broadcast(Round2Bcast {
            data: self.context.data.clone(),
        })
    }
    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        if &msg.data.hash(&self.context.shared_randomness, from)
            != self.hashes.get(from.as_usize()).unwrap()
        {
            return Err(ReceiveError::VerificationFail("Invalid hash".into()));
        }

        Ok(msg.data)
    }
}

impl<P: SchemeParams> Round for Round2<P> {
    type NextRound = Round3<P>;
    type Result = KeyShareSeed;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);
    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        // XOR the vectors together
        // TODO: is there a better way?
        let mut rid = self.context.data.rid.clone();
        for data in payloads.iter() {
            for (i, x) in data.rid.iter().enumerate() {
                rid[i] ^= x;
            }
        }

        Ok(FinalizeSuccess::AnotherRound(Round3 {
            datas: payloads,
            context: self.context,
            rid,
            phantom: PhantomData,
        }))
    }
}

pub struct Round3<P: SchemeParams> {
    datas: HoleVec<FullData>,
    context: Context,
    rid: Box<[u8]>,
    phantom: PhantomData<P>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round3Bcast {
    proof: SchProof,
}

impl<P: SchemeParams> BaseRound for Round3<P> {
    type Payload = bool;
    type Message = Round3Bcast;

    const ROUND_NUM: u8 = 3;
    const REQUIRES_BROADCAST_CONSENSUS: bool = false;

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        let aux = (
            &self.context.shared_randomness,
            &self.context.party_idx,
            &self.rid,
        );
        let proof = SchProof::new(
            &self.context.sch_secret,
            &self.context.key_share.clone(),
            &self.context.data.commitment,
            &self.context.data.public,
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

        let aux = (&self.context.shared_randomness, &from, &self.rid);
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
}

impl<P: SchemeParams> Round for Round3<P> {
    type NextRound = NonExistent<Self::Result>;
    type Result = KeyShareSeed;
    const NEXT_ROUND_NUM: Option<u8> = None;
    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let datas = self.datas.into_vec(self.context.data);
        let public_keys = datas.into_iter().map(|data| data.public).collect();
        Ok(FinalizeSuccess::Result(KeyShareSeed {
            secret_share: self.context.key_share,
            public_shares: public_keys,
        }))
    }
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, RngCore};

    use super::super::{
        test_utils::{assert_next_round, assert_result, step},
        FirstRound,
    };
    use super::Round1;
    use crate::cggmp21::{PartyIdx, TestParams};

    #[test]
    fn execute_keygen() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let num_parties = 3;
        let r1 = (0..num_parties)
            .map(|idx| {
                Round1::<TestParams>::new(
                    &mut OsRng,
                    &shared_randomness,
                    num_parties,
                    PartyIdx::from_usize(idx),
                    (),
                )
                .unwrap()
            })
            .collect();

        let r2 = assert_next_round(step(&mut OsRng, r1).unwrap()).unwrap();
        let r3 = assert_next_round(step(&mut OsRng, r2).unwrap()).unwrap();
        let shares = assert_result(step(&mut OsRng, r3).unwrap()).unwrap();

        // Check that the sets of public keys are the same at each node

        let public_sets = shares
            .iter()
            .map(|s| s.public_shares.clone())
            .collect::<Vec<_>>();

        assert!(public_sets[1..].iter().all(|pk| pk == &public_sets[0]));

        // Check that the public keys correspond to the secret key shares
        let public_set = &public_sets[0];

        let public_from_secret = shares
            .iter()
            .map(|s| s.secret_share.mul_by_generator())
            .collect();

        assert!(public_set == &public_from_secret);
    }
}
