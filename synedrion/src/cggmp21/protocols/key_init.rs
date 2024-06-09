//! KeyInit protocol, in the paper ECDSA Key-Generation (Fig. 5).
//! Note that this protocol only generates the key itself which is not enough to perform signing;
//! auxiliary parameters need to be generated as well (during the KeyRefresh protocol).

use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::{
    sigma::{SchCommitment, SchProof, SchSecret},
    KeyShare, SchemeParams,
};
use crate::curve::{Point, Scalar};
use crate::rounds::{
    no_direct_messages, FinalizableToNextRound, FinalizableToResult, FinalizeError, FirstRound,
    InitError, ProtocolResult, Round, ToNextRound, ToResult,
};
use crate::tools::bitvec::BitVec;
use crate::tools::hashing::{Chain, FofHasher, HashOutput};

/// Possible results of the KeyGen protocol.
#[derive(Debug, Clone, Copy)]
pub struct KeyInitResult<P: SchemeParams, I: Debug>(PhantomData<P>, PhantomData<I>);

impl<P: SchemeParams, I: Debug> ProtocolResult for KeyInitResult<P, I> {
    type Success = KeyShare<P, I>;
    type ProvableError = KeyInitError;
    type CorrectnessProof = ();
}

/// Possible verifiable errors of the KeyGen protocol.
#[derive(Debug, Clone, Copy)]
pub enum KeyInitError {
    /// A hash mismatch in Round 2.
    R2HashMismatch,
    /// Failed to verify `П^{sch}` in Round 3.
    R3InvalidSchProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublicData<P: SchemeParams> {
    cap_x: Point,
    cap_a: SchCommitment,
    rid: BitVec,
    u: BitVec,
    phantom: PhantomData<P>,
}

impl<P: SchemeParams> PublicData<P> {
    fn hash<I: Serialize>(&self, sid_hash: &HashOutput, id: I) -> HashOutput {
        FofHasher::new_with_dst(b"KeyInit")
            .chain(sid_hash)
            .chain(&id)
            .chain(self)
            .finalize()
    }
}

struct Context<P: SchemeParams, I> {
    other_ids: BTreeSet<I>,
    my_id: I,
    x: Scalar,
    tau: SchSecret,
    public_data: PublicData<P>,
    sid_hash: HashOutput,
}

pub struct Round1<P: SchemeParams, I> {
    context: Context<P, I>,
}

impl<P: SchemeParams, I: Clone + Ord + Serialize + Debug> FirstRound<I> for Round1<P, I> {
    type Inputs = ();

    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        other_ids: BTreeSet<I>,
        my_id: I,
        _inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        let mut all_ids = other_ids.clone();
        all_ids.insert(my_id.clone());

        let sid_hash = FofHasher::new_with_dst(b"SID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .chain(&all_ids)
            .finalize();

        // The secret share
        let x = Scalar::random(rng);
        // The public share
        let cap_x = x.mul_by_generator();

        let rid = BitVec::random(rng, P::SECURITY_PARAMETER);
        let tau = SchSecret::random(rng);
        let cap_a = SchCommitment::new(&tau);
        let u = BitVec::random(rng, P::SECURITY_PARAMETER);

        let public_data = PublicData {
            cap_x,
            cap_a,
            rid,
            u,
            phantom: PhantomData,
        };

        let context = Context {
            other_ids,
            my_id,
            x,
            tau,
            public_data,
            sid_hash,
        };

        Ok(Self { context })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1Message {
    cap_v: HashOutput,
}

pub struct Round1Payload {
    cap_v: HashOutput,
}

impl<P: SchemeParams, I: Clone + Ord + Serialize + Debug> Round<I> for Round1<P, I> {
    type Type = ToNextRound;
    type Result = KeyInitResult<P, I>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);

    fn other_ids(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn my_id(&self) -> &I {
        &self.context.my_id
    }

    const REQUIRES_ECHO: bool = true;
    type BroadcastMessage = Round1Message;
    type DirectMessage = ();
    type Payload = Round1Payload;
    type Artifact = ();

    fn make_broadcast_message(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        let cap_v = self
            .context
            .public_data
            .hash(&self.context.sid_hash, self.my_id());
        Some(Round1Message { cap_v })
    }

    no_direct_messages!(I);

    fn verify_message(
        &self,
        _from: &I,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        Ok(Round1Payload {
            cap_v: broadcast_msg.cap_v,
        })
    }
}

impl<P: SchemeParams, I: Serialize + Ord + Clone + Debug> FinalizableToNextRound<I>
    for Round1<P, I>
{
    type NextRound = Round2<P, I>;
    fn finalize_to_next_round(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        _artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        Ok(Round2 {
            others_cap_v: payloads.into_iter().map(|(k, v)| (k, v.cap_v)).collect(),
            context: self.context,
            phantom: PhantomData,
        })
    }
}

pub struct Round2<P: SchemeParams, I> {
    context: Context<P, I>,
    others_cap_v: BTreeMap<I, HashOutput>,
    phantom: PhantomData<P>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicData<P>: Serialize"))]
#[serde(bound(deserialize = "PublicData<P>: for<'x> Deserialize<'x>"))]
pub struct Round2Message<P: SchemeParams> {
    data: PublicData<P>,
}

pub struct Round2Payload<P: SchemeParams> {
    data: PublicData<P>,
}

impl<P: SchemeParams, I: Serialize + Ord + Clone + Debug> Round<I> for Round2<P, I> {
    type Type = ToNextRound;
    type Result = KeyInitResult<P, I>;
    const ROUND_NUM: u8 = 2;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);

    fn other_ids(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn my_id(&self) -> &I {
        &self.context.my_id
    }

    type BroadcastMessage = Round2Message<P>;
    type DirectMessage = ();
    type Payload = Round2Payload<P>;
    type Artifact = ();

    fn make_broadcast_message(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        Some(Round2Message {
            data: self.context.public_data.clone(),
        })
    }

    no_direct_messages!(I);

    fn verify_message(
        &self,
        from: &I,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        if &broadcast_msg.data.hash(&self.context.sid_hash, from)
            != self.others_cap_v.get(from).unwrap()
        {
            return Err(KeyInitError::R2HashMismatch);
        }

        Ok(Round2Payload {
            data: broadcast_msg.data,
        })
    }
}

impl<P: SchemeParams, I: Serialize + Ord + Clone + Debug> FinalizableToNextRound<I>
    for Round2<P, I>
{
    type NextRound = Round3<P, I>;
    fn finalize_to_next_round(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        _artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let mut rid = self.context.public_data.rid.clone();
        for payload in payloads.values() {
            rid ^= &payload.data.rid;
        }

        Ok(Round3 {
            context: self.context,
            others_data: payloads.into_iter().map(|(k, v)| (k, v.data)).collect(),
            rid,
            phantom: PhantomData,
        })
    }
}

pub struct Round3<P: SchemeParams, I> {
    context: Context<P, I>,
    others_data: BTreeMap<I, PublicData<P>>,
    rid: BitVec,
    phantom: PhantomData<P>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round3Message {
    psi: SchProof,
}

impl<P: SchemeParams, I: Serialize + Ord + Clone + Debug> Round<I> for Round3<P, I> {
    type Type = ToResult;
    type Result = KeyInitResult<P, I>;
    const ROUND_NUM: u8 = 3;
    const NEXT_ROUND_NUM: Option<u8> = None;

    fn other_ids(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn my_id(&self) -> &I {
        &self.context.my_id
    }

    type BroadcastMessage = Round3Message;
    type DirectMessage = ();
    type Payload = ();
    type Artifact = ();

    fn make_broadcast_message(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        let aux = (&self.context.sid_hash, self.my_id(), &self.rid);
        let psi = SchProof::new(
            &self.context.tau,
            &self.context.x,
            &self.context.public_data.cap_a,
            &self.context.public_data.cap_x,
            &aux,
        );
        Some(Round3Message { psi })
    }

    no_direct_messages!(I);

    fn verify_message(
        &self,
        from: &I,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        let data = self.others_data.get(from).unwrap();

        let aux = (&self.context.sid_hash, from, &self.rid);
        if !broadcast_msg.psi.verify(&data.cap_a, &data.cap_x, &aux) {
            return Err(KeyInitError::R3InvalidSchProof);
        }
        Ok(())
    }
}

impl<P: SchemeParams, I: Serialize + Clone + Ord + Debug> FinalizableToResult<I> for Round3<P, I> {
    fn finalize_to_result(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        _artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let my_id = self.my_id().clone();
        let mut public_shares = self
            .others_data
            .into_iter()
            .map(|(k, v)| (k, v.cap_x))
            .collect::<BTreeMap<_, _>>();
        public_shares.insert(my_id.clone(), self.context.public_data.cap_x);
        Ok(KeyShare {
            owner: my_id,
            secret_share: self.context.x,
            public_shares,
            phantom: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};

    use rand_core::{OsRng, RngCore};

    use super::Round1;
    use crate::cggmp21::TestParams;
    use crate::rounds::{
        test_utils::{step_next_round, step_result, step_round, Id, Without},
        FirstRound,
    };

    #[test]
    fn execute_keygen() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let ids = BTreeSet::from([Id(0), Id(1), Id(2)]);

        let r1 = ids
            .iter()
            .map(|id| {
                let round = Round1::<TestParams, Id>::new(
                    &mut OsRng,
                    &shared_randomness,
                    ids.clone().without(id),
                    *id,
                    (),
                )
                .unwrap();
                (*id, round)
            })
            .collect();

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let r2 = step_next_round(&mut OsRng, r1a).unwrap();
        let r2a = step_round(&mut OsRng, r2).unwrap();
        let r3 = step_next_round(&mut OsRng, r2a).unwrap();
        let r3a = step_round(&mut OsRng, r3).unwrap();
        let shares = step_result(&mut OsRng, r3a).unwrap();

        // Check that the sets of public keys are the same at each node

        let public_sets = shares
            .iter()
            .map(|(id, share)| (*id, share.public_shares.clone()))
            .collect::<BTreeMap<_, _>>();

        assert!(public_sets.values().all(|pk| pk == &public_sets[&Id(0)]));

        // Check that the public keys correspond to the secret key shares
        let public_set = &public_sets[&Id(0)];

        let public_from_secret = shares
            .into_iter()
            .map(|(id, share)| (id, share.secret_share.mul_by_generator()))
            .collect();

        assert!(public_set == &public_from_secret);
    }
}
