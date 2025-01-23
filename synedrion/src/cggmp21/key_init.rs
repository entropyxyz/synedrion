//! KeyInit protocol, in the paper ECDSA Key-Generation (Fig. 6).
//! Note that this protocol only generates the key itself which is not enough to perform signing;
//! auxiliary parameters need to be generated as well (during the KeyRefresh protocol).

use alloc::collections::{BTreeMap, BTreeSet};
use core::{
    fmt::{self, Debug, Display},
    marker::PhantomData,
};

use manul::protocol::{
    Artifact, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EntryPoint, FinalizeOutcome, LocalError,
    MessageValidationError, NormalBroadcast, PartyId, Payload, Protocol, ProtocolError, ProtocolMessage,
    ProtocolMessagePart, ProtocolValidationError, ReceiveError, RequiredMessageParts, RequiredMessages, Round, RoundId,
    Serializer,
};
use rand_core::CryptoRngCore;
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
        protocol_shortcuts::{verify_that, DeserializeAll, DowncastMap, GetRound, MapValues, SafeGet, Without},
        Secret,
    },
};

/// A protocol that generates shares of a new secret key on each node.
#[derive(Debug)]
pub struct KeyInitProtocol<P: SchemeParams, I: Debug>(PhantomData<(P, I)>);

impl<P: SchemeParams, I: PartyId> Protocol<I> for KeyInitProtocol<P, I> {
    type Result = KeyShare<P, I>;
    type ProtocolError = KeyInitError<P>;

    fn verify_direct_message_is_invalid(
        _deserializer: &Deserializer,
        round_id: &RoundId,
        message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        if round_id == &1 || round_id == &2 || round_id == &3 {
            message.verify_is_some()
        } else {
            Err(MessageValidationError::InvalidEvidence("Invalid round number".into()))
        }
    }

    fn verify_echo_broadcast_is_invalid(
        deserializer: &Deserializer,
        round_id: &RoundId,
        message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        match round_id {
            r if r == &1 => message.verify_is_not::<Round1EchoBroadcast>(deserializer),
            r if r == &2 => message.verify_is_not::<Round2EchoBroadcast<P>>(deserializer),
            r if r == &3 => message.verify_is_some(),
            _ => Err(MessageValidationError::InvalidEvidence("Invalid round number".into())),
        }
    }

    fn verify_normal_broadcast_is_invalid(
        deserializer: &Deserializer,
        round_id: &RoundId,
        message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError> {
        match round_id {
            r if r == &1 => message.verify_is_some(),
            r if r == &2 => message.verify_is_some(),
            r if r == &3 => message.verify_is_not::<Round3Broadcast>(deserializer),
            _ => Err(MessageValidationError::InvalidEvidence("Invalid round number".into())),
        }
    }
}

/// Possible verifiable errors of the KeyGen protocol.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KeyInitError<P> {
    error: KeyInitErrorEnum,
    phantom: PhantomData<P>,
}

impl<P> Display for KeyInitError<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.error)
    }
}

impl<P> KeyInitError<P> {
    fn new(error: KeyInitErrorEnum) -> Self {
        Self {
            error,
            phantom: PhantomData,
        }
    }
}

#[derive(displaydoc::Display, Debug, Clone, Copy, Serialize, Deserialize)]
enum KeyInitErrorEnum {
    /// A hash mismatch in Round 2.
    R2HashMismatch,
    /// Failed to verify `П^sch` in Round 3.
    R3InvalidSchProof,
}

impl<P: SchemeParams, I: PartyId> ProtocolError<I> for KeyInitError<P> {
    type AssociatedData = ();

    fn required_messages(&self) -> RequiredMessages {
        match self.error {
            KeyInitErrorEnum::R2HashMismatch => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast(),
                Some([(1.into(), RequiredMessageParts::echo_broadcast())].into()),
                None,
            ),
            KeyInitErrorEnum::R3InvalidSchProof => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast())].into()),
                Some([2.into()].into()),
            ),
        }
    }

    fn verify_messages_constitute_error(
        &self,
        deserializer: &Deserializer,
        guilty_party: &I,
        shared_randomness: &[u8],
        _associated_data: &Self::AssociatedData,
        message: ProtocolMessage,
        previous_messages: BTreeMap<RoundId, ProtocolMessage>,
        combined_echos: BTreeMap<RoundId, BTreeMap<I, EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        let sid_hash = FofHasher::new_with_dst(b"SID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .finalize();

        match self.error {
            KeyInitErrorEnum::R2HashMismatch => {
                let r1_message = previous_messages
                    .get_round(1)?
                    .echo_broadcast
                    .deserialize::<Round1EchoBroadcast>(deserializer)?;
                let r2_message = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P>>(deserializer)?;
                verify_that(r2_message.data.hash(&sid_hash, guilty_party) != r1_message.cap_v)
            }
            KeyInitErrorEnum::R3InvalidSchProof => {
                let r2_messages = combined_echos
                    .get_round(2)?
                    .deserialize_all::<Round2EchoBroadcast<P>>(deserializer)?;
                let r2_message = previous_messages
                    .get_round(2)?
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P>>(deserializer)?;
                let r3_message = message.normal_broadcast.deserialize::<Round3Broadcast>(deserializer)?;

                let mut rho = r2_message.data.rho;
                for message in r2_messages.values() {
                    rho ^= &message.data.rho;
                }

                let aux = (&sid_hash, guilty_party, &rho);
                verify_that(
                    !r3_message
                        .psi
                        .verify(&r2_message.data.cap_a, &r2_message.data.cap_x, &aux),
                )
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PublicData<P: SchemeParams> {
    pub(super) cap_x: Point,
    pub(super) cap_a: SchCommitment,
    pub(super) rho: BitVec,
    pub(super) u: BitVec,
    pub(super) phantom: PhantomData<P>,
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

    fn entry_round_id() -> RoundId {
        1.into()
    }

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
            .finalize();

        // The secret share
        let x = Secret::init_with(|| Scalar::random(rng));
        // The public share
        let cap_x = x.mul_by_generator();

        let rho = BitVec::random(rng, P::SECURITY_PARAMETER);
        let tau = SchSecret::random(rng);
        let cap_a = SchCommitment::new(&tau);
        let u = BitVec::random(rng, P::SECURITY_PARAMETER);

        let public_data = PublicData {
            cap_x,
            cap_a,
            rho,
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
pub(super) struct Context<P: SchemeParams, I> {
    pub(super) other_ids: BTreeSet<I>,
    pub(super) my_id: I,
    pub(super) x: Secret<Scalar>,
    pub(super) tau: SchSecret,
    pub(super) public_data: PublicData<P>,
    pub(super) sid_hash: HashOutput,
}

#[derive(Debug)]
struct Round1<P: SchemeParams, I> {
    context: Context<P, I>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Round1EchoBroadcast {
    cap_v: HashOutput,
}

struct Round1Payload {
    cap_v: HashOutput,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round1<P, I> {
    type Protocol = KeyInitProtocol<P, I>;

    fn id(&self) -> RoundId {
        1.into()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [2.into()].into()
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
        EchoBroadcast::new(serializer, Round1EchoBroadcast { cap_v })
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        _from: &I,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        message.normal_broadcast.assert_is_none()?;
        message.direct_message.assert_is_none()?;
        let echo = message
            .echo_broadcast
            .deserialize::<Round1EchoBroadcast>(deserializer)?;
        Ok(Payload::new(Round1Payload { cap_v: echo.cap_v }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round1Payload>()?;
        let others_cap_v = payloads.map_values(|payload| payload.cap_v);
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
pub(super) struct Round2EchoBroadcast<P: SchemeParams> {
    pub(super) data: PublicData<P>,
}

struct Round2Payload<P: SchemeParams> {
    data: PublicData<P>,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round2<P, I> {
    type Protocol = KeyInitProtocol<P, I>;

    fn id(&self) -> RoundId {
        2.into()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [3.into()].into()
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
            Round2EchoBroadcast {
                data: self.context.public_data.clone(),
            },
        )
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &I,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        message.normal_broadcast.assert_is_none()?;
        message.direct_message.assert_is_none()?;
        let echo = message
            .echo_broadcast
            .deserialize::<Round2EchoBroadcast<P>>(deserializer)?;
        let cap_v = self.others_cap_v.safe_get("vector `V`", from)?;

        if &echo.data.hash(&self.context.sid_hash, from) != cap_v {
            return Err(ReceiveError::protocol(KeyInitError::new(
                KeyInitErrorEnum::R2HashMismatch,
            )));
        }

        Ok(Payload::new(Round2Payload { data: echo.data }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let mut rho = self.context.public_data.rho.clone();

        let payloads = payloads.downcast_all::<Round2Payload<P>>()?;

        for payload in payloads.values() {
            rho ^= &payload.data.rho;
        }

        let others_data = payloads.map_values(|payload| payload.data);

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round3 {
            context: self.context,
            others_data,
            rho,
            phantom: PhantomData,
        })))
    }
}

#[derive(Debug)]
pub(super) struct Round3<P: SchemeParams, I> {
    pub(super) context: Context<P, I>,
    pub(super) others_data: BTreeMap<I, PublicData<P>>,
    pub(super) rho: BitVec,
    pub(super) phantom: PhantomData<P>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Round3Broadcast {
    pub(super) psi: SchProof,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round3<P, I> {
    type Protocol = KeyInitProtocol<P, I>;

    fn id(&self) -> RoundId {
        3.into()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [].into()
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
        let aux = (&self.context.sid_hash, &self.context.my_id, &self.rho);
        let psi = SchProof::new(
            &self.context.tau,
            &self.context.x,
            &self.context.public_data.cap_a,
            &self.context.public_data.cap_x,
            &aux,
        );
        NormalBroadcast::new(serializer, Round3Broadcast { psi })
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &I,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        message.echo_broadcast.assert_is_none()?;
        message.direct_message.assert_is_none()?;
        let bc = message.normal_broadcast.deserialize::<Round3Broadcast>(deserializer)?;

        let data = self.others_data.safe_get("other nodes' public data", from)?;

        let aux = (&self.context.sid_hash, from, &self.rho);
        if !bc.psi.verify(&data.cap_a, &data.cap_x, &aux) {
            return Err(ReceiveError::protocol(KeyInitError::new(
                KeyInitErrorEnum::R3InvalidSchProof,
            )));
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
        let mut public_shares = self.others_data.map_values(|data| data.cap_x);
        public_shares.insert(my_id.clone(), self.context.public_data.cap_x);

        // This can fail if the shares add up to zero.
        // Can't really protect from it, and it should be extremely rare.
        // If that happens one can only restart the whole thing.
        let key_share = KeyShare::<P, I>::new(my_id, self.context.x, public_shares)?;

        Ok(FinalizeOutcome::Result(key_share))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use manul::{
        dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
        signature::Keypair,
    };
    use rand_core::OsRng;

    use super::KeyInit;
    use crate::{cggmp21::TestParams, tools::protocol_shortcuts::MapValues};

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
        let public_sets = shares.map_values_ref(|share| share.public_shares().clone());
        assert!(public_sets.values().all(|pk| pk == &public_sets[&id0]));

        // Check that the public keys correspond to the secret key shares
        let public_set = &public_sets[&id0];
        let public_from_secret = shares.map_values_ref(|share| share.secret_share().mul_by_generator());
        assert!(public_set == &public_from_secret);
    }
}
