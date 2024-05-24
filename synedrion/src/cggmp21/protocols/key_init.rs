//! KeyInit protocol, in the paper ECDSA Key-Generation (Fig. 5).
//! Note that this protocol only generates the key itself which is not enough to perform signing;
//! auxiliary parameters need to be generated as well (during the KeyRefresh protocol).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::{
    sigma::{SchCommitment, SchProof, SchSecret},
    KeyShare, SchemeParams,
};
use crate::curve::{Point, Scalar};
use crate::rounds::{
    all_parties_except, no_direct_messages, try_to_holevec, FinalizableToNextRound,
    FinalizableToResult, FinalizeError, FirstRound, InitError, PartyIdx, ProtocolResult, Round,
    ToNextRound, ToResult,
};
use crate::tools::bitvec::BitVec;
use crate::tools::collections::HoleVec;
use crate::tools::hashing::{Chain, Hash, HashOutput, Hashable};

/// Possible results of the KeyGen protocol.
#[derive(Debug, Clone, Copy)]
pub struct KeyInitResult<P: SchemeParams>(PhantomData<P>);

impl<P: SchemeParams> ProtocolResult for KeyInitResult<P> {
    type Success = KeyShare<P>;
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

impl<P: SchemeParams> Hashable for PublicData<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest
            .chain(&self.rid)
            .chain(&self.cap_x)
            .chain(&self.cap_a)
            .chain(&self.u)
    }
}

impl<P: SchemeParams> PublicData<P> {
    fn hash(&self, sid_hash: &HashOutput, party_idx: PartyIdx) -> HashOutput {
        Hash::new_with_dst(b"KeyInit")
            .chain(sid_hash)
            .chain(&party_idx)
            .chain(self)
            .finalize()
    }
}

struct Context<P: SchemeParams> {
    num_parties: usize,
    party_idx: PartyIdx,
    x: Scalar,
    tau: SchSecret,
    public_data: PublicData<P>,
    sid_hash: HashOutput,
}

pub struct Round1<P: SchemeParams> {
    context: Context<P>,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Inputs = ();

    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        _inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        let sid_hash = Hash::new_with_dst(b"SID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .chain(&(u32::try_from(num_parties).unwrap()))
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
            num_parties,
            party_idx,
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

impl<P: SchemeParams> Round for Round1<P> {
    type Type = ToNextRound;
    type Result = KeyInitResult<P>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);

    fn num_parties(&self) -> usize {
        self.context.num_parties
    }

    fn party_idx(&self) -> PartyIdx {
        self.context.party_idx
    }

    const REQUIRES_ECHO: bool = true;
    type BroadcastMessage = Round1Message;
    type DirectMessage = ();
    type Payload = Round1Payload;
    type Artifact = ();

    fn message_destinations(&self) -> Vec<PartyIdx> {
        all_parties_except(self.num_parties(), self.party_idx())
    }

    fn make_broadcast_message(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        let cap_v = self
            .context
            .public_data
            .hash(&self.context.sid_hash, self.party_idx());
        Some(Round1Message { cap_v })
    }

    no_direct_messages!();

    fn verify_message(
        &self,
        _from: PartyIdx,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        Ok(Round1Payload {
            cap_v: broadcast_msg.cap_v,
        })
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round1<P> {
    type NextRound = Round2<P>;
    fn finalize_to_next_round(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        _artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        Ok(Round2 {
            others_cap_v: try_to_holevec(payloads, self.num_parties(), self.party_idx())
                .unwrap()
                .map(|payload| payload.cap_v),
            context: self.context,
            phantom: PhantomData,
        })
    }
}

pub struct Round2<P: SchemeParams> {
    context: Context<P>,
    others_cap_v: HoleVec<HashOutput>,
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

impl<P: SchemeParams> Round for Round2<P> {
    type Type = ToNextRound;
    type Result = KeyInitResult<P>;
    const ROUND_NUM: u8 = 2;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);

    fn num_parties(&self) -> usize {
        self.context.num_parties
    }

    fn party_idx(&self) -> PartyIdx {
        self.context.party_idx
    }

    type BroadcastMessage = Round2Message<P>;
    type DirectMessage = ();
    type Payload = Round2Payload<P>;
    type Artifact = ();

    fn message_destinations(&self) -> Vec<PartyIdx> {
        all_parties_except(self.num_parties(), self.party_idx())
    }

    fn make_broadcast_message(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        Some(Round2Message {
            data: self.context.public_data.clone(),
        })
    }

    no_direct_messages!();

    fn verify_message(
        &self,
        from: PartyIdx,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        if &broadcast_msg.data.hash(&self.context.sid_hash, from)
            != self.others_cap_v.get(from.as_usize()).unwrap()
        {
            return Err(KeyInitError::R2HashMismatch);
        }

        Ok(Round2Payload {
            data: broadcast_msg.data,
        })
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round2<P> {
    type NextRound = Round3<P>;
    fn finalize_to_next_round(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        _artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let payloads = try_to_holevec(payloads, self.num_parties(), self.party_idx()).unwrap();

        let others_data = payloads.map(|payload| payload.data);

        let mut rid = self.context.public_data.rid.clone();
        for data in others_data.iter() {
            rid ^= &data.rid;
        }

        Ok(Round3 {
            context: self.context,
            others_data,
            rid,
            phantom: PhantomData,
        })
    }
}

pub struct Round3<P: SchemeParams> {
    context: Context<P>,
    others_data: HoleVec<PublicData<P>>,
    rid: BitVec,
    phantom: PhantomData<P>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round3Message {
    psi: SchProof,
}

impl<P: SchemeParams> Round for Round3<P> {
    type Type = ToResult;
    type Result = KeyInitResult<P>;
    const ROUND_NUM: u8 = 3;
    const NEXT_ROUND_NUM: Option<u8> = None;

    fn num_parties(&self) -> usize {
        self.context.num_parties
    }

    fn party_idx(&self) -> PartyIdx {
        self.context.party_idx
    }

    type BroadcastMessage = Round3Message;
    type DirectMessage = ();
    type Payload = ();
    type Artifact = ();

    fn message_destinations(&self) -> Vec<PartyIdx> {
        all_parties_except(self.num_parties(), self.party_idx())
    }

    fn make_broadcast_message(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        let aux = (&self.context.sid_hash, &self.party_idx(), &self.rid);
        let psi = SchProof::new(
            &self.context.tau,
            &self.context.x,
            &self.context.public_data.cap_a,
            &self.context.public_data.cap_x,
            &aux,
        );
        Some(Round3Message { psi })
    }

    no_direct_messages!();

    fn verify_message(
        &self,
        from: PartyIdx,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        let data = self.others_data.get(from.as_usize()).unwrap();

        let aux = (&self.context.sid_hash, &from, &self.rid);
        if !broadcast_msg.psi.verify(&data.cap_a, &data.cap_x, &aux) {
            return Err(KeyInitError::R3InvalidSchProof);
        }
        Ok(())
    }
}

impl<P: SchemeParams> FinalizableToResult for Round3<P> {
    fn finalize_to_result(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        _artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let index = self.party_idx();
        let all_data = self.others_data.into_vec(self.context.public_data);
        let all_cap_x = all_data.into_iter().map(|data| data.cap_x).collect();
        Ok(KeyShare {
            index,
            secret_share: self.context.x,
            public_shares: all_cap_x,
            phantom: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, RngCore};

    use super::Round1;
    use crate::cggmp21::TestParams;
    use crate::rounds::{
        test_utils::{step_next_round, step_result, step_round},
        FirstRound, PartyIdx,
    };

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

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let r2 = step_next_round(&mut OsRng, r1a).unwrap();
        let r2a = step_round(&mut OsRng, r2).unwrap();
        let r3 = step_next_round(&mut OsRng, r2a).unwrap();
        let r3a = step_round(&mut OsRng, r3).unwrap();
        let shares = step_result(&mut OsRng, r3a).unwrap();

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
