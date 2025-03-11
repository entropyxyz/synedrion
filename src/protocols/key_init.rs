//! KeyInit protocol, in the paper ECDSA Key-Generation (Fig. 6).
//! Note that this protocol only generates the key itself which is not enough to perform signing;
//! auxiliary parameters need to be generated as well (during the KeyRefresh protocol).

use alloc::boxed::Box;
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
use serde_encoded_bytes::{Hex, SliceLike};

use crate::{
    curve::{Point, Scalar},
    entities::KeyShare,
    params::SchemeParams,
    tools::{
        bitvec::BitVec,
        hashing::{Chain, XofHasher},
        protocol_shortcuts::{verify_that, DeserializeAll, DowncastMap, GetRound, MapValues, SafeGet, Without},
        Secret,
    },
    zk::{SchCommitment, SchProof, SchSecret},
};

/// A protocol that generates shares of a new secret key on each node.
#[derive(Debug)]
pub struct KeyInitProtocol<P: SchemeParams, Id: Debug>(PhantomData<(P, Id)>);

impl<P: SchemeParams, Id: PartyId> Protocol<Id> for KeyInitProtocol<P, Id> {
    type Result = KeyShare<P, Id>;
    type ProtocolError = KeyInitError<P>;

    fn verify_direct_message_is_invalid(
        _deserializer: &Deserializer,
        round_id: &RoundId,
        message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        match round_id {
            r if r == &1 => message.verify_is_some(),
            r if r == &2 => message.verify_is_some(),
            r if r == &3 => message.verify_is_some(),
            _ => Err(MessageValidationError::InvalidEvidence("Invalid round number".into())),
        }
    }

    fn verify_echo_broadcast_is_invalid(
        deserializer: &Deserializer,
        round_id: &RoundId,
        message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        match round_id {
            r if r == &1 => message.verify_is_not::<Round1EchoBroadcast>(deserializer),
            r if r == &2 => message.verify_is_not::<Round2EchoBroadcast>(deserializer),
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
            r if r == &2 => message.verify_is_not::<Round2NormalBroadcast<P>>(deserializer),
            r if r == &3 => message.verify_is_not::<Round3NormalBroadcast<P>>(deserializer),
            _ => Err(MessageValidationError::InvalidEvidence("Invalid round number".into())),
        }
    }
}

/// Possible verifiable errors of the KeyGen protocol.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KeyInitError<P> {
    error: Error,
    phantom: PhantomData<P>,
}

impl<P: SchemeParams> Display for KeyInitError<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", self.error)
    }
}

impl<P: SchemeParams> From<Error> for KeyInitError<P> {
    fn from(source: Error) -> Self {
        Self {
            error: source,
            phantom: PhantomData,
        }
    }
}

#[derive(displaydoc::Display, Debug, Clone, Copy, Serialize, Deserialize)]
enum Error {
    /// Round 2: the previously sent hash does not match the public data.
    R2HashMismatch,
    /// Round 3: failed to verify `П^{{sch}}`.
    R3InvalidSchProof,
}

/// Associated data for KeyInit protocol.
#[derive(Debug, Clone)]
pub struct KeyInitAssociatedData<Id> {
    /// IDs of all participating nodes.
    pub ids: BTreeSet<Id>,
}

fn make_sid<P: SchemeParams, Id: PartyId>(
    shared_randomness: &[u8],
    associated_data: &KeyInitAssociatedData<Id>,
) -> Box<[u8]> {
    XofHasher::new_with_dst(b"KeyInit SID")
        .chain_type::<P::Curve>()
        .chain(&shared_randomness)
        .chain(&associated_data.ids)
        .finalize_boxed(P::SECURITY_BITS)
}

impl<P: SchemeParams, Id: PartyId> ProtocolError<Id> for KeyInitError<P> {
    type AssociatedData = KeyInitAssociatedData<Id>;

    fn required_messages(&self) -> RequiredMessages {
        match self.error {
            Error::R2HashMismatch => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast().and_normal_broadcast(),
                Some([(1.into(), RequiredMessageParts::echo_broadcast())].into()),
                None,
            ),
            Error::R3InvalidSchProof => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast())].into()),
                Some([2.into()].into()),
            ),
        }
    }

    fn verify_messages_constitute_error(
        &self,
        deserializer: &Deserializer,
        guilty_party: &Id,
        shared_randomness: &[u8],
        associated_data: &Self::AssociatedData,
        message: ProtocolMessage,
        previous_messages: BTreeMap<RoundId, ProtocolMessage>,
        combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        let sid = make_sid::<P, Id>(shared_randomness, associated_data);

        match self.error {
            Error::R2HashMismatch => {
                let r1_eb = previous_messages
                    .get_round(1)?
                    .echo_broadcast
                    .deserialize::<Round1EchoBroadcast>(deserializer)?;
                let r2_nb = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P>>(deserializer)?;
                let r2_eb = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast>(deserializer)?;
                let data = PublicData {
                    cap_x: r2_nb.cap_x,
                    cap_a: r2_nb.cap_a,
                    u: r2_nb.u,
                    rho: r2_eb.rho,
                };
                verify_that(data.hash(&sid, guilty_party) != r1_eb.cap_v)
            }
            Error::R3InvalidSchProof => {
                let r2_ebs = combined_echos
                    .get_round(2)?
                    .deserialize_all::<Round2EchoBroadcast>(deserializer)?;
                let r2_nb = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P>>(deserializer)?;
                let r2_eb = previous_messages
                    .get_round(2)?
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast>(deserializer)?;
                let r3_nb = message
                    .normal_broadcast
                    .deserialize::<Round3NormalBroadcast<P>>(deserializer)?;

                let mut rho = r2_eb.rho;
                for message in r2_ebs.values() {
                    rho ^= &message.rho;
                }

                let aux = (&sid, guilty_party, &rho);
                verify_that(!r3_nb.psi.verify(&r2_nb.cap_a, &r2_nb.cap_x, &aux))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PublicData<P: SchemeParams> {
    cap_x: Point<P>,
    pub(super) cap_a: SchCommitment<P>,
    rho: BitVec,
    u: BitVec,
}

impl<P> PublicData<P>
where
    P: SchemeParams,
{
    pub(super) fn hash<Id: Serialize>(&self, sid: &[u8], id: &Id) -> Box<[u8]> {
        XofHasher::new_with_dst(b"KeyInit")
            .chain(&sid)
            .chain(id)
            .chain(&self.cap_x)
            .chain(&self.cap_a)
            .chain(&self.rho)
            .chain(&self.u)
            .finalize_boxed(P::SECURITY_BITS)
    }
}

/// An entry point for the [`KeyInitProtocol`].
#[derive(Debug, Clone)]
pub struct KeyInit<P, Id> {
    all_ids: BTreeSet<Id>,
    phantom: PhantomData<P>,
}

impl<P, Id: PartyId> KeyInit<P, Id> {
    /// Creates a new entry point given the set of the participants' IDs
    /// (including this node's).
    pub fn new(all_ids: BTreeSet<Id>) -> Result<Self, LocalError> {
        Ok(Self {
            all_ids,
            phantom: PhantomData,
        })
    }
}

impl<P: SchemeParams, Id: PartyId> EntryPoint<Id> for KeyInit<P, Id> {
    type Protocol = KeyInitProtocol<P, Id>;

    fn entry_round_id() -> RoundId {
        1.into()
    }

    fn make_round(
        self,
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        if !self.all_ids.contains(id) {
            return Err(LocalError::new("The given node IDs must contain this node's ID"));
        }

        let other_ids = self.all_ids.clone().without(id);

        let sid = make_sid::<P, Id>(
            shared_randomness,
            &KeyInitAssociatedData {
                ids: self.all_ids.clone(),
            },
        );

        // The secret share
        let x = Secret::init_with(|| Scalar::random(rng));
        // The public share
        let cap_x = x.mul_by_generator();

        let rho = BitVec::random(rng, P::SECURITY_PARAMETER);
        let tau = SchSecret::random(rng);
        let cap_a = SchCommitment::new(&tau);
        let u = BitVec::random(rng, P::SECURITY_PARAMETER);

        let public_data = PublicData { cap_x, cap_a, rho, u };

        let context = Context {
            other_ids,
            my_id: id.clone(),
            x,
            tau,
            public_data,
            sid,
        };

        Ok(BoxedRound::new_dynamic(Round1 { context }))
    }
}

#[derive(Debug)]
pub(super) struct Context<P: SchemeParams, Id> {
    pub(super) other_ids: BTreeSet<Id>,
    pub(super) my_id: Id,
    pub(super) x: Secret<Scalar<P>>,
    pub(super) tau: SchSecret<P>,
    pub(super) public_data: PublicData<P>,
    pub(super) sid: Box<[u8]>,
}

#[derive(Debug)]
struct Round1<P: SchemeParams, Id> {
    context: Context<P, Id>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Round1EchoBroadcast {
    #[serde(with = "SliceLike::<Hex>")]
    cap_v: Box<[u8]>,
}

struct Round1Payload {
    cap_v: Box<[u8]>,
}

impl<P, Id> Round<Id> for Round1<P, Id>
where
    P: SchemeParams,
    Id: PartyId,
{
    type Protocol = KeyInitProtocol<P, Id>;

    fn id(&self) -> RoundId {
        1.into()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [2.into()].into()
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
    }

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        let cap_v = self.context.public_data.hash(&self.context.sid, &self.context.my_id);
        EchoBroadcast::new(serializer, Round1EchoBroadcast { cap_v })
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        _from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        message.normal_broadcast.assert_is_none()?;
        message.direct_message.assert_is_none()?;
        let echo_broadcast = message
            .echo_broadcast
            .deserialize::<Round1EchoBroadcast>(deserializer)?;
        Ok(Payload::new(Round1Payload {
            cap_v: echo_broadcast.cap_v,
        }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round1Payload>()?;
        let cap_vs = payloads.map_values(|payload| payload.cap_v);
        let next_round = Round2 {
            context: self.context,
            cap_vs,
        };
        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(next_round)))
    }
}

#[derive(Debug)]
struct Round2<P: SchemeParams, Id> {
    context: Context<P, Id>,
    cap_vs: BTreeMap<Id, Box<[u8]>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Round2EchoBroadcast {
    rho: BitVec,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "Point<P>: for<'x> Deserialize<'x>"))]
pub(super) struct Round2NormalBroadcast<P: SchemeParams> {
    cap_x: Point<P>,
    cap_a: SchCommitment<P>,
    pub(super) u: BitVec,
}

struct Round2Payload<P: SchemeParams> {
    cap_x: Point<P>,
    cap_a: SchCommitment<P>,
    rho: BitVec,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round2<P, Id> {
    type Protocol = KeyInitProtocol<P, Id>;

    fn id(&self) -> RoundId {
        2.into()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [3.into()].into()
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
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
                rho: self.context.public_data.rho.clone(),
            },
        )
    }

    fn make_normal_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<NormalBroadcast, LocalError> {
        NormalBroadcast::new(
            serializer,
            Round2NormalBroadcast {
                cap_x: self.context.public_data.cap_x,
                cap_a: self.context.public_data.cap_a.clone(),
                u: self.context.public_data.u.clone(),
            },
        )
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        message.direct_message.assert_is_none()?;
        let normal_broadcast = message
            .normal_broadcast
            .deserialize::<Round2NormalBroadcast<P>>(deserializer)?;
        let echo_broadcast = message
            .echo_broadcast
            .deserialize::<Round2EchoBroadcast>(deserializer)?;

        let cap_v = self.cap_vs.safe_get("vector `V`", from)?;
        let data = PublicData {
            cap_x: normal_broadcast.cap_x,
            cap_a: normal_broadcast.cap_a,
            u: normal_broadcast.u,
            rho: echo_broadcast.rho,
        };

        if &data.hash(&self.context.sid, from) != cap_v {
            return Err(ReceiveError::protocol(Error::R2HashMismatch.into()));
        }

        Ok(Payload::new(Round2Payload {
            cap_x: data.cap_x,
            rho: data.rho,
            cap_a: data.cap_a,
        }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round2Payload<P>>()?;

        let mut rho_combined = self.context.public_data.rho.clone();
        for payload in payloads.values() {
            rho_combined ^= &payload.rho;
        }

        let cap_xs = payloads.map_values_ref(|payload| payload.cap_x);
        let cap_as = payloads.map_values_ref(|payload| payload.cap_a.clone());

        let next_round = Round3 {
            context: self.context,
            cap_xs,
            cap_as,
            rho_combined,
        };

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(next_round)))
    }
}

#[derive(Debug)]
pub(super) struct Round3<P: SchemeParams, Id> {
    pub(super) context: Context<P, Id>,
    pub(super) cap_xs: BTreeMap<Id, Point<P>>,
    pub(super) cap_as: BTreeMap<Id, SchCommitment<P>>,
    pub(super) rho_combined: BitVec,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "SchProof<P>: for<'x> Deserialize<'x>"))]
pub(super) struct Round3NormalBroadcast<P: SchemeParams> {
    pub(super) psi: SchProof<P>,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round3<P, Id> {
    type Protocol = KeyInitProtocol<P, Id>;

    fn id(&self) -> RoundId {
        3.into()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [].into()
    }

    fn may_produce_result(&self) -> bool {
        true
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
    }

    fn make_normal_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<NormalBroadcast, LocalError> {
        let aux = (&self.context.sid, &self.context.my_id, &self.rho_combined);
        let psi = SchProof::new(
            &self.context.tau,
            &self.context.x,
            &self.context.public_data.cap_a,
            &self.context.public_data.cap_x,
            &aux,
        );
        NormalBroadcast::new(serializer, Round3NormalBroadcast { psi })
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        message.echo_broadcast.assert_is_none()?;
        message.direct_message.assert_is_none()?;
        let normal_broadcast = message
            .normal_broadcast
            .deserialize::<Round3NormalBroadcast<P>>(deserializer)?;

        let cap_a = self.cap_as.safe_get("`A` map", from)?;
        let cap_x = self.cap_xs.safe_get("`X` map", from)?;

        let aux = (&self.context.sid, from, &self.rho_combined);
        if !normal_broadcast.psi.verify(cap_a, cap_x, &aux) {
            return Err(ReceiveError::protocol(Error::R3InvalidSchProof.into()));
        }
        Ok(Payload::empty())
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let my_id = self.context.my_id.clone();
        let mut public_shares = self.cap_xs;
        public_shares.insert(my_id.clone(), self.context.public_data.cap_x);

        // This can fail if the shares add up to zero.
        // Can't really protect from it, and it should be extremely rare.
        // If that happens one can only restart the whole thing.
        let key_share = KeyShare::<P, Id>::new(my_id, self.context.x, public_shares)?;

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
    use crate::{dev::TestParams, tools::protocol_shortcuts::MapValues};

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
