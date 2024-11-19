//! KeyInit protocol, in the paper ECDSA Key-Generation (Fig. 5).
//! Note that this protocol only generates the key itself which is not enough to perform signing;
//! auxiliary parameters need to be generated as well (during the KeyRefresh protocol).

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};

use manul::protocol::{
    Artifact, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EntryPoint, FinalizeOutcome, LocalError,
    NormalBroadcast, PartyId, Payload, Protocol, ProtocolError, ProtocolMessagePart, ProtocolValidationError,
    ReceiveError, Round, RoundId, Serializer,
};
use rand_core::CryptoRngCore;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};

use super::{
    entities::KeyShare,
    params::SchemeParams,
    sigma::{SchCommitment, SchProof, SchSecret},
};
use crate::{
    curve::{Point, Scalar},
    tools::{
        bitvec::BitVec,
        hashing::{Chain, FofHasher, HashOutput},
        DowncastMap, Without,
    },
};

/// A protocol that generates shares of a new secret key on each node.
#[derive(Debug)]
pub struct KeyInitProtocol<P: SchemeParams, I: Debug>(PhantomData<(P, I)>);

impl<P: SchemeParams, I: PartyId> Protocol for KeyInitProtocol<P, I> {
    type Result = KeyShare<P, I>;
    type ProtocolError = KeyInitError;
}

/// Possible verifiable errors of the KeyGen protocol.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum KeyInitError {
    /// A hash mismatch in Round 2.
    R2HashMismatch,
    /// Failed to verify `П^{sch}` in Round 3.
    R3InvalidSchProof,
}

impl ProtocolError for KeyInitError {
    fn description(&self) -> String {
        unimplemented!()
    }

    fn required_direct_messages(&self) -> BTreeSet<RoundId> {
        unimplemented!()
    }

    fn required_echo_broadcasts(&self) -> BTreeSet<RoundId> {
        unimplemented!()
    }

    fn required_combined_echos(&self) -> BTreeSet<RoundId> {
        unimplemented!()
    }

    fn verify_messages_constitute_error(
        &self,
        _deserializer: &Deserializer,
        _echo_broadcast: &EchoBroadcast,
        _normal_broadcat: &NormalBroadcast,
        _direct_message: &DirectMessage,
        _echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
        _normal_broadcasts: &BTreeMap<RoundId, NormalBroadcast>,
        _direct_messages: &BTreeMap<RoundId, DirectMessage>,
        _combined_echos: &BTreeMap<RoundId, Vec<EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        unimplemented!()
    }
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

/// An entry point for the [`KeyInitProtocol`].
#[derive(Debug, Clone)]
pub struct KeyInit<P, I> {
    all_ids: BTreeSet<I>,
    phantom: PhantomData<P>,
}

impl<P, I: PartyId> KeyInit<P, I> {
    /// Creates a new entry point given the set of the participants' IDs
    /// (including this node's).
    pub fn new(all_ids: BTreeSet<I>) -> Result<Self, LocalError> {
        Ok(Self {
            all_ids,
            phantom: PhantomData,
        })
    }
}

impl<P: SchemeParams, I: PartyId> EntryPoint<I> for KeyInit<P, I> {
    type Protocol = KeyInitProtocol<P, I>;

    fn make_round(
        self,
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        id: &I,
    ) -> Result<BoxedRound<I, Self::Protocol>, LocalError> {
        if !self.all_ids.contains(id) {
            return Err(LocalError::new("The given node IDs must contain this node's ID"));
        }

        let other_ids = self.all_ids.clone().without(id);

        let sid_hash = FofHasher::new_with_dst(b"SID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .chain(&self.all_ids)
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
            my_id: id.clone(),
            x,
            tau,
            public_data,
            sid_hash,
        };

        Ok(BoxedRound::new_dynamic(Round1 { context }))
    }
}

#[derive(Debug)]
struct Context<P: SchemeParams, I> {
    other_ids: BTreeSet<I>,
    my_id: I,
    x: Scalar,
    tau: SchSecret,
    public_data: PublicData<P>,
    sid_hash: HashOutput,
}

#[derive(Debug)]
struct Round1<P: SchemeParams, I> {
    context: Context<P, I>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Round1Message {
    cap_v: HashOutput,
}

struct Round1Payload {
    cap_v: HashOutput,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round1<P, I> {
    type Protocol = KeyInitProtocol<P, I>;

    fn id(&self) -> RoundId {
        RoundId::new(1)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::from([RoundId::new(2)])
    }

    fn message_destinations(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn expecting_messages_from(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        let cap_v = self
            .context
            .public_data
            .hash(&self.context.sid_hash, &self.context.my_id);
        EchoBroadcast::new(serializer, Round1Message { cap_v })
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        _from: &I,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        normal_broadcast.assert_is_none()?;
        direct_message.assert_is_none()?;
        let echo = echo_broadcast.deserialize::<Round1Message>(deserializer)?;
        Ok(Payload::new(Round1Payload { cap_v: echo.cap_v }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round1Payload>()?;
        let others_cap_v = payloads.into_iter().map(|(k, v)| (k, v.cap_v)).collect();
        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round2 {
            others_cap_v,
            context: self.context,
            phantom: PhantomData,
        })))
    }
}

#[derive(Debug)]
struct Round2<P: SchemeParams, I> {
    context: Context<P, I>,
    others_cap_v: BTreeMap<I, HashOutput>,
    phantom: PhantomData<P>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicData<P>: Serialize"))]
#[serde(bound(deserialize = "PublicData<P>: for<'x> Deserialize<'x>"))]
struct Round2Message<P: SchemeParams> {
    data: PublicData<P>,
}

struct Round2Payload<P: SchemeParams> {
    data: PublicData<P>,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round2<P, I> {
    type Protocol = KeyInitProtocol<P, I>;

    fn id(&self) -> RoundId {
        RoundId::new(2)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::from([RoundId::new(3)])
    }

    fn message_destinations(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn expecting_messages_from(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        EchoBroadcast::new(
            serializer,
            Round2Message {
                data: self.context.public_data.clone(),
            },
        )
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        from: &I,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        normal_broadcast.assert_is_none()?;
        direct_message.assert_is_none()?;
        let echo = echo_broadcast.deserialize::<Round2Message<P>>(deserializer)?;
        let cap_v = self
            .others_cap_v
            .get(from)
            .ok_or_else(|| LocalError::new(format!("Missing `V` for {from:?}")))?;

        if &echo.data.hash(&self.context.sid_hash, from) != cap_v {
            return Err(ReceiveError::protocol(KeyInitError::R2HashMismatch));
        }

        Ok(Payload::new(Round2Payload { data: echo.data }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let mut rid = self.context.public_data.rid.clone();

        let payloads = payloads.downcast_all::<Round2Payload<P>>()?;

        for payload in payloads.values() {
            rid ^= &payload.data.rid;
        }

        let others_data = payloads.into_iter().map(|(k, v)| (k, v.data)).collect();

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round3 {
            context: self.context,
            others_data,
            rid,
            phantom: PhantomData,
        })))
    }
}

#[derive(Debug)]
struct Round3<P: SchemeParams, I> {
    context: Context<P, I>,
    others_data: BTreeMap<I, PublicData<P>>,
    rid: BitVec,
    phantom: PhantomData<P>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Round3Message {
    psi: SchProof,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round3<P, I> {
    type Protocol = KeyInitProtocol<P, I>;

    fn id(&self) -> RoundId {
        RoundId::new(3)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    fn may_produce_result(&self) -> bool {
        true
    }

    fn message_destinations(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn expecting_messages_from(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn make_normal_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<NormalBroadcast, LocalError> {
        let aux = (&self.context.sid_hash, &self.context.my_id, &self.rid);
        let psi = SchProof::new(
            &self.context.tau,
            &self.context.x,
            &self.context.public_data.cap_a,
            &self.context.public_data.cap_x,
            &aux,
        );
        NormalBroadcast::new(serializer, Round3Message { psi })
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        from: &I,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        echo_broadcast.assert_is_none()?;
        direct_message.assert_is_none()?;

        let bc = normal_broadcast.deserialize::<Round3Message>(deserializer)?;

        let data = self
            .others_data
            .get(from)
            .ok_or_else(|| LocalError::new(format!("Missing data for {from:?}")))?;

        let aux = (&self.context.sid_hash, from, &self.rid);
        if !bc.psi.verify(&data.cap_a, &data.cap_x, &aux) {
            return Err(ReceiveError::protocol(KeyInitError::R3InvalidSchProof));
        }
        Ok(Payload::empty())
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let my_id = self.context.my_id.clone();
        let mut public_shares = self
            .others_data
            .into_iter()
            .map(|(k, v)| (k, v.cap_x))
            .collect::<BTreeMap<_, _>>();
        public_shares.insert(my_id.clone(), self.context.public_data.cap_x);
        Ok(FinalizeOutcome::Result(KeyShare {
            owner: my_id,
            secret_share: SecretBox::new(Box::new(self.context.x)),
            public_shares,
            phantom: PhantomData,
        }))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};

    use manul::{
        dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
        session::signature::Keypair,
    };
    use rand_core::OsRng;
    use secrecy::ExposeSecret;

    use super::KeyInit;
    use crate::cggmp21::TestParams;

    #[test]
    fn execute_keygen() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
        let id0 = signers[0].verifying_key();

        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key())
            .collect::<BTreeSet<_>>();
        let entry_points = signers
            .into_iter()
            .map(|signer| {
                let entry_point = KeyInit::<TestParams, TestVerifier>::new(all_ids.clone()).unwrap();
                (signer, entry_point)
            })
            .collect::<Vec<_>>();

        let shares = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
            .unwrap()
            .results()
            .unwrap();

        // Check that the sets of public keys are the same at each node

        let public_sets = shares
            .iter()
            .map(|(id, share)| (*id, share.public_shares.clone()))
            .collect::<BTreeMap<_, _>>();

        assert!(public_sets.values().all(|pk| pk == &public_sets[&id0]));

        // Check that the public keys correspond to the secret key shares
        let public_set = &public_sets[&id0];

        let public_from_secret = shares
            .into_iter()
            .map(|(id, share)| (id, share.secret_share.expose_secret().mul_by_generator()))
            .collect();

        assert!(public_set == &public_from_secret);
    }
}
