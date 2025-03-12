//! AuxGen protocol, in the paper Auxiliary Info. & Key Refresh in Three Rounds (Fig. 7).
//!
//! This is a subset of the protocol that generates the auxiliary data, with share update bits removed.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use core::{
    fmt::{self, Debug, Display},
    marker::PhantomData,
};

use crypto_bigint::BitOps;
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
    entities::{AuxInfo, PublicAuxInfo, PublicAuxInfos, SecretAuxInfo},
    paillier::{
        PaillierParams, PublicKeyPaillier, PublicKeyPaillierWire, RPParams, RPParamsWire, RPSecret, SecretKeyPaillier,
        SecretKeyPaillierWire,
    },
    params::SchemeParams,
    tools::{
        bitvec::BitVec,
        hashing::{Chain, XofHasher},
        protocol_shortcuts::{verify_that, DeserializeAll, DowncastMap, GetRound, MapValues, SafeGet, Without},
    },
    zk::{FacProof, ModProof, PrmProof},
};

/// A protocol for generating auxiliary information for signing.
#[derive(Debug)]
pub struct AuxGenProtocol<P: SchemeParams, Id: PartyId>(PhantomData<(P, Id)>);

impl<P: SchemeParams, Id: PartyId> Protocol<Id> for AuxGenProtocol<P, Id> {
    type Result = AuxInfo<P, Id>;
    type ProtocolError = AuxGenError<P, Id>;

    fn verify_direct_message_is_invalid(
        deserializer: &Deserializer,
        round_id: &RoundId,
        message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        match round_id {
            r if r == &1 => message.verify_is_some(),
            r if r == &2 => message.verify_is_some(),
            r if r == &3 => message.verify_is_not::<Round3DirectMessage<P>>(deserializer),
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
            r if r == &2 => message.verify_is_not::<Round2NormalBroadcast<P>>(deserializer),
            r if r == &3 => message.verify_is_not::<Round3NormalBroadcast<P>>(deserializer),
            _ => Err(MessageValidationError::InvalidEvidence("Invalid round number".into())),
        }
    }
}

/// Provable AuxGen faults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    Error<Id>: Serialize,
"))]
#[serde(bound(deserialize = "
    Error<Id>: for<'x> Deserialize<'x>,
"))]
pub struct AuxGenError<P, Id> {
    error: Error<Id>,
    phantom: PhantomData<P>,
}

impl<P, Id> From<Error<Id>> for AuxGenError<P, Id> {
    fn from(source: Error<Id>) -> Self {
        Self {
            error: source,
            phantom: PhantomData,
        }
    }
}

impl<P, Id: PartyId> Display for AuxGenError<P, Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            match self.error {
                Error::R2HashMismatch => "Round 2: the previously sent hash does not match the public data.",
                Error::R2PaillierModulusTooSmall => "Round 2: Paillier modulus is too small.",
                Error::R2RPModulusTooSmall => "Round 2: ring-Pedersent modulus is too small.",
                Error::R2PrmFailed => "Round 2: `П^{prm}` verification failed.",
                Error::R3ModFailed => "Round 3: `П^{mod}` verification failed.",
                Error::R3FacFailed { .. } => "Round 3: `П^{fac}` verification failed.",
            }
        )
    }
}

/// AuxGen error
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Error<Id> {
    R2HashMismatch,
    R2PaillierModulusTooSmall,
    R2RPModulusTooSmall,
    R2PrmFailed,
    R3ModFailed,
    R3FacFailed {
        /// The index $i$ of the node that produced the evidence.
        reported_by: Id,
    },
}

/// Reconstruct `rid` from echoed messages
fn reconstruct_rid<P: SchemeParams, Id: PartyId>(
    deserializer: &Deserializer,
    previous_messages: &BTreeMap<RoundId, ProtocolMessage>,
    combined_echos: &BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
) -> Result<BitVec, ProtocolValidationError> {
    let r2_ebs = combined_echos
        .get_round(2)?
        .deserialize_all::<Round2EchoBroadcast<P>>(deserializer)?;
    let r2_eb = previous_messages
        .get_round(2)?
        .echo_broadcast
        .deserialize::<Round2EchoBroadcast<P>>(deserializer)?;
    let mut rid_combined = r2_eb.rid;
    for message in r2_ebs.values() {
        rid_combined ^= &message.rid;
    }
    Ok(rid_combined)
}

/// Associated data for AuxGen protocol.
#[derive(Debug, Clone)]
pub struct AuxGenAssociatedData<Id> {
    /// IDs of all participating nodes.
    pub ids: BTreeSet<Id>,
}

fn make_sid<P: SchemeParams, Id: PartyId>(
    shared_randomness: &[u8],
    associated_data: &AuxGenAssociatedData<Id>,
) -> Box<[u8]> {
    XofHasher::new_with_dst(b"AuxGen SID")
        .chain_type::<P::Curve>()
        .chain(&shared_randomness)
        .chain(&associated_data.ids)
        .finalize_boxed(P::SECURITY_BITS)
}

impl<P: SchemeParams, Id: PartyId> ProtocolError<Id> for AuxGenError<P, Id> {
    type AssociatedData = AuxGenAssociatedData<Id>;

    fn required_messages(&self) -> RequiredMessages {
        match self.error {
            Error::R2HashMismatch => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast().and_echo_broadcast(),
                Some([(1.into(), RequiredMessageParts::echo_broadcast())].into()),
                None,
            ),
            Error::R2PaillierModulusTooSmall => {
                RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None)
            }
            Error::R2RPModulusTooSmall => RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None),
            Error::R2PrmFailed => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast().and_normal_broadcast(),
                None,
                None,
            ),
            Error::R3ModFailed => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast())].into()),
                Some([2.into()].into()),
            ),
            Error::R3FacFailed { .. } => RequiredMessages::new(
                RequiredMessageParts::direct_message(),
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

        match &self.error {
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
                    .deserialize::<Round2EchoBroadcast<P>>(deserializer)?;

                let data = PublicData {
                    paillier_pk: r2_nb.paillier_pk.into_precomputed(),
                    rp_params: r2_eb.rp_params.to_precomputed(),
                    psi: r2_nb.psi,
                    rid: r2_eb.rid,
                    u: r2_nb.u,
                };
                verify_that(data.hash(&sid, guilty_party) != r1_eb.cap_v)
            }
            Error::R2PaillierModulusTooSmall => {
                let r2_nb = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P>>(deserializer)?;
                verify_that(
                    r2_nb.paillier_pk.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2,
                )
            }
            Error::R2RPModulusTooSmall => {
                let r2_eb = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P>>(deserializer)?;
                verify_that(
                    r2_eb.rp_params.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2,
                )
            }
            Error::R2PrmFailed => {
                let r2_eb = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P>>(deserializer)?;
                let r2_bc = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P>>(deserializer)?;
                let aux = (&sid, guilty_party);
                let rp_params = r2_eb.rp_params.to_precomputed();
                verify_that(!r2_bc.psi.verify(&rp_params, &aux))
            }
            Error::R3ModFailed => {
                let rid = reconstruct_rid::<P, _>(deserializer, &previous_messages, &combined_echos)?;
                let aux = (&sid, guilty_party, &rid);
                let r2_bc = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P>>(deserializer)?;
                let r3_bc = message
                    .normal_broadcast
                    .deserialize::<Round3NormalBroadcast<P>>(deserializer)?;
                let paillier_pk = r2_bc.paillier_pk.into_precomputed();
                verify_that(!r3_bc.psi_prime.verify(&paillier_pk, &aux))
            }
            Error::R3FacFailed { reported_by } => {
                let rid = reconstruct_rid::<P, _>(deserializer, &previous_messages, &combined_echos)?;
                let aux = (&sid, guilty_party, &rid);

                let r2_eb = combined_echos
                    .get_round(2)?
                    .try_get("combined echos for Round 2", reported_by)?
                    .deserialize::<Round2EchoBroadcast<P>>(deserializer)?;
                let r2_bc = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P>>(deserializer)?;
                let r3_dm = message
                    .direct_message
                    .deserialize::<Round3DirectMessage<P>>(deserializer)?;
                let paillier_pk = r2_bc.paillier_pk.into_precomputed();
                let rp_params = r2_eb.rp_params.to_precomputed();
                verify_that(!r3_dm.psi.verify(&paillier_pk, &rp_params, &aux))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct PublicData<P: SchemeParams> {
    pub(super) paillier_pk: PublicKeyPaillier<P::Paillier>, // $N_i$
    pub(super) rp_params: RPParams<P::Paillier>,            // $\hat{N}_i$, $s_i$, and $t_i$
    pub(super) psi: PrmProof<P>,
    rid: BitVec,
    u: BitVec,
}

impl<P: SchemeParams> PublicData<P> {
    pub(super) fn hash<Id: PartyId>(&self, sid: &[u8], id: &Id) -> Box<[u8]> {
        XofHasher::new_with_dst(b"KeyInit")
            .chain(&sid)
            .chain(id)
            .chain(&self.paillier_pk.clone().into_wire())
            .chain(&self.rp_params.to_wire())
            .chain(&self.psi)
            .chain(&self.rid)
            .chain(&self.u)
            .finalize_boxed(P::SECURITY_BITS)
    }
}

/// An entry point for the [`AuxGenProtocol`].
#[derive(Debug, Clone)]
pub struct AuxGen<P, Id> {
    all_ids: BTreeSet<Id>,
    phantom: PhantomData<P>,
}

impl<P, Id: PartyId> AuxGen<P, Id> {
    /// Creates a new entry point given the set of the participants' IDs
    /// (including this node's).
    pub fn new(all_ids: BTreeSet<Id>) -> Result<Self, LocalError> {
        Ok(Self {
            all_ids,
            phantom: PhantomData,
        })
    }
}

impl<P, Id> EntryPoint<Id> for AuxGen<P, Id>
where
    P: SchemeParams,
    Id: PartyId,
{
    type Protocol = AuxGenProtocol<P, Id>;

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
            &AuxGenAssociatedData {
                ids: self.all_ids.clone(),
            },
        );

        // Paillier secret key $p_i$, $q_i$
        let paillier_sk = SecretKeyPaillierWire::<P::Paillier>::random(rng);
        // Paillier public key $N_i$
        let paillier_pk = paillier_sk.public_key();

        // Ring-Pedersen secret $\lambda$.
        let rp_secret = RPSecret::random(rng);
        // Ring-Pedersen parameters ($N$, $s$, $t$) bundled in a single object.
        let rp_params = RPParams::random_with_secret(rng, &rp_secret);

        let aux = (&sid, id);
        let psi = PrmProof::<P>::new(rng, &rp_secret, &rp_params, &aux);

        let rid = BitVec::random(rng, P::SECURITY_PARAMETER);
        let u = BitVec::random(rng, P::SECURITY_PARAMETER);

        // Note: typo in the paper, $V$ hashes in $B_i$ which is not present in the '24 version of the paper.
        let public_data = PublicData {
            paillier_pk: paillier_pk.into_precomputed(),
            rp_params: rp_params.clone(),
            psi,
            rid,
            u,
        };

        let context = Context {
            paillier_sk: paillier_sk.into_precomputed(),
            rp_params,
            my_id: id.clone(),
            other_ids,
            sid,
        };

        let round = Round1 { context, public_data };

        Ok(BoxedRound::new_dynamic(round))
    }
}

#[derive(Debug)]
pub(super) struct Context<P: SchemeParams, Id> {
    paillier_sk: SecretKeyPaillier<P::Paillier>,
    rp_params: RPParams<P::Paillier>,
    pub(super) my_id: Id,
    other_ids: BTreeSet<Id>,
    pub(super) sid: Box<[u8]>,
}

#[derive(Debug)]
pub(super) struct Round1<P: SchemeParams, Id: PartyId> {
    pub(super) context: Context<P, Id>,
    pub(super) public_data: PublicData<P>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Round1EchoBroadcast {
    #[serde(with = "SliceLike::<Hex>")]
    pub(super) cap_v: Box<[u8]>,
}

struct Round1Payload {
    cap_v: Box<[u8]>,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round1<P, Id> {
    type Protocol = AuxGenProtocol<P, Id>;

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
        let message = Round1EchoBroadcast {
            cap_v: self.public_data.hash(&self.context.sid, &self.context.my_id),
        };
        EchoBroadcast::new(serializer, message)
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
        let payload = Round1Payload {
            cap_v: echo_broadcast.cap_v,
        };
        Ok(Payload::new(payload))
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
            public_data: self.public_data,
            cap_vs,
        };
        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(next_round)))
    }
}

#[derive(Debug)]
struct Round2<P: SchemeParams, Id: PartyId> {
    context: Context<P, Id>,
    public_data: PublicData<P>,
    cap_vs: BTreeMap<Id, Box<[u8]>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    PrmProof<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    PrmProof<P>: for<'x> Deserialize<'x>,
"))]
pub(super) struct Round2NormalBroadcast<P: SchemeParams> {
    pub(super) paillier_pk: PublicKeyPaillierWire<P::Paillier>, // $N_i$
    pub(super) psi: PrmProof<P>,
    u: BitVec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Round2EchoBroadcast<P: SchemeParams> {
    pub(super) rp_params: RPParamsWire<P::Paillier>, // $\hat{N}_i$, $s_i$, and $t_i$
    rid: BitVec,
}

#[derive(Debug)]
struct Round2Payload<P: SchemeParams> {
    paillier_pk: PublicKeyPaillier<P::Paillier>, // $N_i$
    rp_params: RPParams<P::Paillier>,            // $\hat{N}_i$, $s_i$, and $t_i$
    rid: BitVec,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round2<P, Id> {
    type Protocol = AuxGenProtocol<P, Id>;

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

    fn make_normal_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<NormalBroadcast, LocalError> {
        let message = Round2NormalBroadcast {
            paillier_pk: self.public_data.paillier_pk.clone().into_wire(),
            psi: self.public_data.psi.clone(),
            u: self.public_data.u.clone(),
        };
        NormalBroadcast::new(serializer, message)
    }

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        let message = Round2EchoBroadcast::<P> {
            rid: self.public_data.rid.clone(),
            rp_params: self.public_data.rp_params.to_wire(),
        };
        EchoBroadcast::new(serializer, message)
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        message.direct_message.assert_is_none()?;
        let echo_broadcast = message
            .echo_broadcast
            .deserialize::<Round2EchoBroadcast<P>>(deserializer)?;
        let normal_broadcast = message
            .normal_broadcast
            .deserialize::<Round2NormalBroadcast<P>>(deserializer)?;

        let data = PublicData {
            paillier_pk: normal_broadcast.paillier_pk.into_precomputed(),
            rp_params: echo_broadcast.rp_params.to_precomputed(),
            psi: normal_broadcast.psi,
            rid: echo_broadcast.rid,
            u: normal_broadcast.u,
        };

        let cap_v = self.cap_vs.safe_get("other nodes' `V`", from)?;

        if &data.hash(&self.context.sid, from) != cap_v {
            return Err(ReceiveError::protocol(Error::R2HashMismatch.into()));
        }

        if data.paillier_pk.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2 {
            return Err(ReceiveError::protocol(Error::R2PaillierModulusTooSmall.into()));
        }

        if data.rp_params.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2 {
            return Err(ReceiveError::protocol(Error::R2RPModulusTooSmall.into()));
        }

        let aux = (&self.context.sid, &from);
        if !data.psi.verify(&data.rp_params, &aux) {
            return Err(ReceiveError::protocol(Error::R2PrmFailed.into()));
        }

        let payload = Round2Payload::<P> {
            paillier_pk: data.paillier_pk,
            rp_params: data.rp_params,
            rid: data.rid,
        };

        Ok(Payload::new(payload))
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let mut payloads = payloads.downcast_all::<Round2Payload<P>>()?;

        let mut rid_combined = self.public_data.rid.clone();
        for payload in payloads.values() {
            rid_combined ^= &payload.rid;
        }

        let my_id = &self.context.my_id;
        let aux = (&self.context.sid, my_id, &rid_combined);
        let psi_prime = ModProof::new(rng, &self.context.paillier_sk, &aux);

        // Add in the payload with this node's info, for the sake of uniformity
        let my_r2_payload = Round2Payload::<P> {
            paillier_pk: self.public_data.paillier_pk,
            rp_params: self.public_data.rp_params,
            rid: self.public_data.rid,
        };
        payloads.insert(self.context.my_id.clone(), my_r2_payload);

        let next_round = Round3 {
            context: self.context,
            r2_payloads: payloads,
            rid_combined,
            psi_prime,
        };

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(next_round)))
    }
}

#[derive(Debug)]
struct Round3<P: SchemeParams, Id> {
    context: Context<P, Id>,
    rid_combined: BitVec,
    r2_payloads: BTreeMap<Id, Round2Payload<P>>,
    psi_prime: ModProof<P>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    ModProof<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    ModProof<P>: for<'x> Deserialize<'x>,
"))]
pub(super) struct Round3NormalBroadcast<P: SchemeParams> {
    pub(super) psi_prime: ModProof<P>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    FacProof<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    FacProof<P>: for<'x> Deserialize<'x>,
"))]
pub(super) struct Round3DirectMessage<P: SchemeParams> {
    pub(super) psi: FacProof<P>,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round3<P, Id> {
    type Protocol = AuxGenProtocol<P, Id>;

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
        let message = Round3NormalBroadcast {
            psi_prime: self.psi_prime.clone(),
        };
        NormalBroadcast::new(serializer, message)
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
        destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let my_id = &self.context.my_id;
        let aux = (&self.context.sid, my_id, &self.rid_combined);

        let r2_payload = self.r2_payloads.safe_get("Round 2 payloads", destination)?;

        let psi = FacProof::<P>::new(rng, &self.context.paillier_sk, &r2_payload.rp_params, &aux);

        let message = Round3DirectMessage { psi };
        let dm = DirectMessage::new(serializer, message)?;
        Ok((dm, None))
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        message.echo_broadcast.assert_is_none()?;
        let normal_broadcast = message
            .normal_broadcast
            .deserialize::<Round3NormalBroadcast<P>>(deserializer)?;
        let direct_message = message
            .direct_message
            .deserialize::<Round3DirectMessage<P>>(deserializer)?;

        let my_id = &self.context.my_id;

        let r2_payload = self.r2_payloads.safe_get("Round 2 payloads", from)?;

        let aux = (&self.context.sid, from, &self.rid_combined);
        if !normal_broadcast.psi_prime.verify(&r2_payload.paillier_pk, &aux) {
            return Err(ReceiveError::protocol(Error::R3ModFailed.into()));
        }

        if !direct_message
            .psi
            .verify(&r2_payload.paillier_pk, &self.context.rp_params, &aux)
        {
            return Err(ReceiveError::protocol(
                Error::R3FacFailed {
                    reported_by: my_id.clone(),
                }
                .into(),
            ));
        }

        Ok(Payload::empty())
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let my_id = &self.context.my_id;

        let public_aux = self.r2_payloads.map_values(|payload| PublicAuxInfo {
            paillier_pk: payload.paillier_pk.into_wire(),
            rp_params: payload.rp_params.to_wire(),
        });

        let secret_aux = SecretAuxInfo {
            paillier_sk: self.context.paillier_sk.into_wire(),
        };

        let aux_info = AuxInfo {
            owner: my_id.clone(),
            secret: secret_aux,
            public: PublicAuxInfos(public_aux),
        };

        Ok(FinalizeOutcome::Result(aux_info))
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

    use super::AuxGen;
    use crate::dev::TestParams;

    #[test]
    fn execute_aux_gen() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();

        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key())
            .collect::<BTreeSet<_>>();
        let entry_points = signers
            .into_iter()
            .map(|signer| {
                let entry_point = AuxGen::<TestParams, TestVerifier>::new(all_ids.clone()).unwrap();
                (signer, entry_point)
            })
            .collect::<Vec<_>>();

        let _aux_infos = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
            .unwrap()
            .results()
            .unwrap();
    }
}
