//! KeyRefresh protocol, in the paper Auxiliary Info. & Key Refresh in Three Rounds (Fig. 7).
//! This protocol generates an update to the secret key shares and new auxiliary parameters
//! for ZK proofs (e.g. Paillier keys).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use core::{
    fmt::{self, Debug, Display},
    marker::PhantomData,
};
use digest::typenum::Unsigned;
use primeorder::elliptic_curve::Curve;

use crypto_bigint::BitOps;
use manul::protocol::{
    Artifact, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EntryPoint, FinalizeOutcome, LocalError,
    MessageValidationError, NormalBroadcast, PartyId, Payload, Protocol, ProtocolError, ProtocolMessage,
    ProtocolMessagePart, ProtocolValidationError, ReceiveError, RequiredMessageParts, RequiredMessages, Round, RoundId,
    Serializer,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    entities::{AuxInfo, KeyShareChange, PublicAuxInfo, PublicAuxInfos, SecretAuxInfo},
    params::SchemeParams,
    sigma::{FacProof, ModProof, PrmProof, SchCommitment, SchProof, SchSecret},
};
use crate::{
    curve::{secret_split, Point, Scalar},
    paillier::{
        PaillierParams, PublicKeyPaillier, PublicKeyPaillierWire, RPParams, RPParamsWire, RPSecret, SecretKeyPaillier,
        SecretKeyPaillierWire,
    },
    tools::{
        bitvec::BitVec,
        hashing::{Chain, XofHasher},
        protocol_shortcuts::{verify_that, DeserializeAll, DowncastMap, GetRound, MapValues, SafeGet, Without},
        Secret,
    },
};

/// A protocol for generating auxiliary information for signing,
/// and a simultaneous generation of updates for the secret key shares.
#[derive(Debug)]
pub struct KeyRefreshProtocol<P: SchemeParams, Id: PartyId>(PhantomData<(P, Id)>);

impl<P, Id> Protocol<Id> for KeyRefreshProtocol<P, Id>
where
    P: SchemeParams,
    Id: PartyId,
{
    type Result = (KeyShareChange<P, Id>, AuxInfo<P, Id>);
    type ProtocolError = KeyRefreshError<P, Id>;

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
            r if r == &2 => message.verify_is_not::<Round2EchoBroadcast<P, Id>>(deserializer),
            r if r == &3 => message.verify_is_not::<Round3EchoBroadcast<P, Id>>(deserializer),
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
            r if r == &2 => message.verify_is_not::<Round2NormalBroadcast<P, Id>>(deserializer),
            r if r == &3 => message.verify_is_not::<Round3NormalBroadcast<P>>(deserializer),
            _ => Err(MessageValidationError::InvalidEvidence("Invalid round number".into())),
        }
    }
}

/// Provable KeyRefresh faults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    Error<P, Id>: Serialize,
"))]
#[serde(bound(deserialize = "
    Error<P, Id>: for<'x> Deserialize<'x>,
"))]
pub struct KeyRefreshError<P, Id>
where
    P: SchemeParams,
{
    error: Error<P, Id>,
}

impl<P, Id> From<Error<P, Id>> for KeyRefreshError<P, Id>
where
    P: SchemeParams,
{
    fn from(source: Error<P, Id>) -> Self {
        Self { error: source }
    }
}

impl<P, Id> Display for KeyRefreshError<P, Id>
where
    P: SchemeParams,
    Id: PartyId,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            match self.error {
                Error::R2HashMismatch => "Round 2: the previously sent hash does not match the public data.",
                Error::R2WrongIdsX => "Round 2: wrong IDs in public shares map.",
                Error::R2WrongIdsY => "Round 2: wrong IDs in Elgamal keys map.",
                Error::R2WrongIdsA => "Round 2: wrong IDs in Schnorr commitments map.",
                Error::R2PaillierModulusTooSmall => "Round 2: Paillier modulus is too small.",
                Error::R2RPModulusTooSmall => "Round 2: ring-Pedersent modulus is too small.",
                Error::R2NonZeroSumOfChanges => "Round 2: sum of share changes is not zero.",
                Error::R2PrmFailed => "Round 2: `П^{prm}` verification failed.",
                Error::R3ShareChangeMismatch { .. } =>
                    "Round 3: secret share change does not match the public commitment.",
                Error::R3ModFailed => "Round 3: `П^{mod}` verification failed.",
                Error::R3FacFailed { .. } => "Round 3: `П^{fac}` verification failed.",
                Error::R3WrongIdsHatPsi => "Round 3: Wrong IDs in Schnorr proofs map.",
                Error::R3SchFailed { .. } => "Round 3: `П^{sch}` verification failed.",
            }
        )
    }
}

/// KeyRefresh error
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "Id: for<'x> Deserialize<'x>"))]
enum Error<P, Id>
where
    P: SchemeParams,
{
    R2HashMismatch,
    R2WrongIdsX,
    R2WrongIdsY,
    R2WrongIdsA,
    R2PaillierModulusTooSmall,
    R2RPModulusTooSmall,
    R2NonZeroSumOfChanges,
    R2PrmFailed,
    R3ShareChangeMismatch {
        /// The index $i$ of the node that produced the evidence.
        reported_by: Id,
        /// $y_{i,j}$, where where $j$ is the index of the guilty party.
        y: Scalar<P>,
    },
    R3ModFailed,
    R3FacFailed {
        /// The index $i$ of the node that produced the evidence.
        reported_by: Id,
    },
    R3WrongIdsHatPsi,
    R3SchFailed {
        /// The index $k$ for which the verification of $\hat{\psi}_{j,k}$ failed
        /// (where $j$ is the index of the guilty party).
        failed_for: Id,
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
        .deserialize_all::<Round2EchoBroadcast<P, Id>>(deserializer)?;
    let r2_eb = previous_messages
        .get_round(2)?
        .echo_broadcast
        .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
    let mut rid_combined = r2_eb.rid;
    for message in r2_ebs.values() {
        rid_combined ^= &message.rid;
    }
    Ok(rid_combined)
}

/// Associated data for KeyRefresh protocol.
#[derive(Debug, Clone)]
pub struct KeyRefreshAssociatedData<Id> {
    /// IDs of all participating nodes.
    pub ids: BTreeSet<Id>,
}

fn make_sid<P: SchemeParams, Id: PartyId>(
    shared_randomness: &[u8],
    associated_data: &KeyRefreshAssociatedData<Id>,
) -> Box<[u8]> {
    XofHasher::new_with_dst(b"KeyRefresh SID")
        .chain_type::<P::Curve>()
        .chain(&shared_randomness)
        .chain(&associated_data.ids)
        .finalize_boxed(<P::Curve as Curve>::FieldBytesSize::USIZE)
}

impl<P: SchemeParams, Id: PartyId> ProtocolError<Id> for KeyRefreshError<P, Id> {
    type AssociatedData = KeyRefreshAssociatedData<Id>;

    fn required_messages(&self) -> RequiredMessages {
        match self.error {
            Error::R2HashMismatch => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast().and_echo_broadcast(),
                Some([(1.into(), RequiredMessageParts::echo_broadcast())].into()),
                None,
            ),
            Error::R2WrongIdsX => RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None),
            Error::R2WrongIdsY => RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None),
            Error::R2WrongIdsA => RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None),
            Error::R2PaillierModulusTooSmall => {
                RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None)
            }
            Error::R2RPModulusTooSmall => RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None),
            Error::R2NonZeroSumOfChanges => RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None),
            Error::R2PrmFailed => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast().and_normal_broadcast(),
                None,
                None,
            ),
            Error::R3ShareChangeMismatch { .. } => RequiredMessages::new(
                RequiredMessageParts::direct_message(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast())].into()),
                Some([2.into()].into()),
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
            Error::R3WrongIdsHatPsi => RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None),
            Error::R3SchFailed { .. } => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast(),
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
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                let r2_eb = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;

                let data = PublicData {
                    cap_xs: r2_nb.cap_xs,
                    cap_ys: r2_eb.cap_ys,
                    cap_as: r2_nb.cap_as,
                    paillier_pk: r2_nb.paillier_pk.into_precomputed(),
                    rp_params: r2_eb.rp_params.to_precomputed(),
                    psi: r2_nb.psi,
                    rid: r2_eb.rid,
                    u: r2_nb.u,
                };
                verify_that(data.hash(&sid, guilty_party) != r1_eb.cap_v)
            }
            Error::R2WrongIdsX => {
                let r2_nb = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                verify_that(r2_nb.cap_xs.keys().cloned().collect::<BTreeSet<_>>() != associated_data.ids)
            }
            Error::R2WrongIdsY => {
                let r2_eb = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                verify_that(r2_eb.cap_ys.keys().cloned().collect::<BTreeSet<_>>() != associated_data.ids)
            }
            Error::R2WrongIdsA => {
                let r2_nb = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                verify_that(r2_nb.cap_as.keys().cloned().collect::<BTreeSet<_>>() != associated_data.ids)
            }
            Error::R2PaillierModulusTooSmall => {
                let r2_nb = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                verify_that(
                    r2_nb.paillier_pk.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2,
                )
            }
            Error::R2RPModulusTooSmall => {
                let r2_eb = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                verify_that(
                    r2_eb.rp_params.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2,
                )
            }
            Error::R2NonZeroSumOfChanges => {
                let r2_nb = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                verify_that(r2_nb.cap_xs.values().sum::<Point<P>>() != Point::identity())
            }
            Error::R2PrmFailed => {
                let r2_eb = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r2_bc = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                let aux = (&sid, guilty_party);
                let rp_params = r2_eb.rp_params.to_precomputed();
                verify_that(!r2_bc.psi.verify(&rp_params, &aux))
            }
            Error::R3ShareChangeMismatch { reported_by, y } => {
                // Check that `y` attached to the evidence is correct
                // (that is, can be verified against something signed by `guilty_party`).
                // It is `y_{i,j}` where `i == reported_by` and `j == guilty_party`
                let r2_eb_i = combined_echos
                    .get_round(2)?
                    .try_get("combined echos for Round 2", reported_by)?
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let cap_y_ij = r2_eb_i.cap_ys.try_get("public Elgamal values", guilty_party)?;
                if &y.mul_by_generator() != cap_y_ij {
                    return Err(ProtocolValidationError::InvalidEvidence(
                        "The provided `y` is invalid".into(),
                    ));
                }

                let rid = reconstruct_rid::<P, _>(deserializer, &previous_messages, &combined_echos)?;

                let r2_eb = previous_messages
                    .get_round(2)?
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let cap_y_ji = r2_eb.cap_ys.try_get("public Elgamal values", reported_by)?;
                let mut reader = XofHasher::new_with_dst(b"KeyRefresh Round3")
                    .chain(&sid)
                    .chain(&rid)
                    .chain(guilty_party)
                    .chain(&(cap_y_ji * y))
                    .finalize_to_reader();
                let rho = Scalar::from_xof_reader(&mut reader);

                let r2_bc = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                let r3_dm = message
                    .direct_message
                    .deserialize::<Round3DirectMessage<P>>(deserializer)?;

                let x = r3_dm.cap_c - rho;
                let cap_x_ji = r2_bc.cap_xs.try_get("public key share changes", reported_by)?;
                verify_that(&x.mul_by_generator() != cap_x_ji)
            }
            Error::R3ModFailed => {
                let rid = reconstruct_rid::<P, _>(deserializer, &previous_messages, &combined_echos)?;
                let aux = (&sid, guilty_party, &rid);
                let r2_bc = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
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
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r2_bc = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                let r3_dm = message
                    .direct_message
                    .deserialize::<Round3DirectMessage<P>>(deserializer)?;
                let paillier_pk = r2_bc.paillier_pk.into_precomputed();
                let rp_params = r2_eb.rp_params.to_precomputed();
                verify_that(!r3_dm.psi.verify(&paillier_pk, &rp_params, &aux))
            }
            Error::R3WrongIdsHatPsi => {
                let r3_eb = message
                    .echo_broadcast
                    .deserialize::<Round3EchoBroadcast<P, Id>>(deserializer)?;
                verify_that(r3_eb.hat_psis.keys().cloned().collect::<BTreeSet<_>>() != associated_data.ids)
            }
            Error::R3SchFailed { failed_for } => {
                let rid = reconstruct_rid::<P, _>(deserializer, &previous_messages, &combined_echos)?;
                let aux = (&sid, guilty_party, &rid);

                let r2_bc = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                let r3_eb = message
                    .echo_broadcast
                    .deserialize::<Round3EchoBroadcast<P, Id>>(deserializer)?;

                let cap_a = r2_bc.cap_as.try_get("Schnorr commitments", failed_for)?;
                let cap_x = r2_bc.cap_xs.try_get("public share changes", failed_for)?;
                let hat_psi = r3_eb.hat_psis.try_get("Schnorr proofs", failed_for)?;
                verify_that(!hat_psi.verify(cap_a, cap_x, &aux))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct PublicData<P: SchemeParams, Id> {
    pub(super) cap_xs: BTreeMap<Id, Point<P>>, // $X_{i,j}$ where $i$ is this party's index
    pub(super) cap_ys: BTreeMap<Id, Point<P>>, // $Y_{i,j}$ where $i$ is this party's index
    pub(super) cap_as: BTreeMap<Id, SchCommitment<P>>, // $A_{i,j}$ where $i$ is this party's index
    pub(super) paillier_pk: PublicKeyPaillier<P::Paillier>, // $N_i$
    pub(super) rp_params: RPParams<P::Paillier>, // $\hat{N}_i$, $s_i$, and $t_i$
    pub(super) psi: PrmProof<P>,
    rid: BitVec,
    u: BitVec,
}

impl<P: SchemeParams, Id: PartyId> PublicData<P, Id> {
    pub(super) fn hash(&self, sid: &[u8], id: &Id) -> Box<[u8]> {
        XofHasher::new_with_dst(b"KeyInit")
            .chain(&sid)
            .chain(id)
            .chain(&self.cap_xs)
            .chain(&self.cap_ys)
            .chain(&self.cap_as)
            .chain(&self.paillier_pk.clone().into_wire())
            .chain(&self.rp_params.to_wire())
            .chain(&self.psi)
            .chain(&self.rid)
            .chain(&self.u)
            .finalize_boxed(<P::Curve as Curve>::FieldBytesSize::USIZE)
    }
}

/// An entry point for the [`KeyRefreshProtocol`].
#[derive(Debug, Clone)]
pub struct KeyRefresh<P, Id> {
    all_ids: BTreeSet<Id>,
    phantom: PhantomData<P>,
}

impl<P, Id: PartyId> KeyRefresh<P, Id> {
    /// Creates a new entry point given the set of the participants' IDs
    /// (including this node's).
    pub fn new(all_ids: BTreeSet<Id>) -> Result<Self, LocalError> {
        Ok(Self {
            all_ids,
            phantom: PhantomData,
        })
    }
}

impl<P: SchemeParams, Id: PartyId> EntryPoint<Id> for KeyRefresh<P, Id> {
    type Protocol = KeyRefreshProtocol<P, Id>;

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
            &KeyRefreshAssociatedData {
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

        // Ephemeral DH keys $y_{i,j}$ where $i$ is this party's index.
        let ys = self
            .all_ids
            .iter()
            .cloned()
            .map(|id| (id, Secret::init_with(|| Scalar::random(rng))))
            .collect::<BTreeMap<_, _>>();
        // Corresponding public keys $Y_{i,j}$.
        let cap_ys = ys.map_values_ref(|y| y.mul_by_generator());

        // Secret share updates for each node ($x_{i,j}$ where $i$ is this party's index).
        let split_zero = secret_split(rng, Secret::init_with(|| Scalar::ZERO), self.all_ids.len());
        let xs = self.all_ids.iter().cloned().zip(split_zero).collect::<BTreeMap<_, _>>();

        // Public counterparts of secret share updates ($X_i^j$ where $i$ is this party's index).
        let cap_xs = xs.map_values_ref(|x| x.mul_by_generator());

        // Schnorr proof secrets $\tau_j$
        let taus = self
            .all_ids
            .iter()
            .map(|id| (id.clone(), SchSecret::random(rng)))
            .collect::<BTreeMap<_, _>>();

        // Schnorr commitments for share changes ($A_{i,j}$ where $i$ is this party's index)
        let cap_as = taus.map_values_ref(SchCommitment::new);

        let rid = BitVec::random(rng, P::SECURITY_PARAMETER);
        let u = BitVec::random(rng, P::SECURITY_PARAMETER);

        // Note: typo in the paper, $V$ hashes in $B_i$ which is not present in the '24 version of the paper.
        let public_data = PublicData {
            cap_xs,
            cap_ys,
            cap_as,
            paillier_pk: paillier_pk.into_precomputed(),
            rp_params: rp_params.clone(),
            psi,
            rid,
            u,
        };

        let context = Context {
            paillier_sk: paillier_sk.into_precomputed(),
            rp_params,
            xs,
            ys,
            taus,
            my_id: id.clone(),
            other_ids,
            all_ids: self.all_ids,
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
    xs: BTreeMap<Id, Secret<Scalar<P>>>, // $x_{i,j}$ where $i$ is this party's index
    ys: BTreeMap<Id, Secret<Scalar<P>>>, // $y_{i,j}$ where $i$ is this party's index
    taus: BTreeMap<Id, SchSecret<P>>,
    pub(super) my_id: Id,
    other_ids: BTreeSet<Id>,
    all_ids: BTreeSet<Id>,
    pub(super) sid: Box<[u8]>,
}

#[derive(Debug)]
pub(super) struct Round1<P: SchemeParams, Id: PartyId> {
    pub(super) context: Context<P, Id>,
    pub(super) public_data: PublicData<P, Id>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Round1EchoBroadcast {
    pub(super) cap_v: Box<[u8]>,
}

struct Round1Payload {
    cap_v: Box<[u8]>,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round1<P, Id> {
    type Protocol = KeyRefreshProtocol<P, Id>;

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
    public_data: PublicData<P, Id>,
    cap_vs: BTreeMap<Id, Box<[u8]>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    PrmProof<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    PrmProof<P>: for<'x> Deserialize<'x>,
    SchCommitment<P>: for<'x> Deserialize<'x>,
"))]
pub(super) struct Round2NormalBroadcast<P: SchemeParams, Id: PartyId> {
    pub(super) cap_xs: BTreeMap<Id, Point<P>>, // $X_{i,j}$ where $i$ is this party's index
    pub(super) cap_as: BTreeMap<Id, SchCommitment<P>>, // $A_{i,j}$ where $i$ is this party's index
    pub(super) paillier_pk: PublicKeyPaillierWire<P::Paillier>, // $N_i$
    pub(super) psi: PrmProof<P>,
    u: BitVec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    Id: Serialize,
"))]
#[serde(bound(deserialize = "
    Id: for<'x> Deserialize<'x>,
"))]
pub(super) struct Round2EchoBroadcast<P: SchemeParams, Id: PartyId> {
    pub(super) rp_params: RPParamsWire<P::Paillier>, // $\hat{N}_i$, $s_i$, and $t_i$
    pub(super) cap_ys: BTreeMap<Id, Point<P>>,       // $Y_{i,j}$ where $i$ is this party's index
    rid: BitVec,
}

#[derive(Debug)]
struct Round2Payload<P: SchemeParams, Id> {
    cap_xs: BTreeMap<Id, Point<P>>,              // $X_{i,j}$ where $i$ is this party's index
    cap_as: BTreeMap<Id, SchCommitment<P>>,      // $A_{i,j}$ where $i$ is this party's index
    cap_ys: BTreeMap<Id, Point<P>>,              // $Y_{i,j}$ where $i$ is this party's index
    paillier_pk: PublicKeyPaillier<P::Paillier>, // $N_i$
    rp_params: RPParams<P::Paillier>,            // $\hat{N}_i$, $s_i$, and $t_i$
    rid: BitVec,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round2<P, Id> {
    type Protocol = KeyRefreshProtocol<P, Id>;

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
            cap_xs: self.public_data.cap_xs.clone(),
            cap_as: self.public_data.cap_as.clone(),
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
        let message = Round2EchoBroadcast::<P, Id> {
            cap_ys: self.public_data.cap_ys.clone(),
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
            .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
        let normal_broadcast = message
            .normal_broadcast
            .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;

        let data = PublicData {
            cap_xs: normal_broadcast.cap_xs,
            cap_ys: echo_broadcast.cap_ys,
            cap_as: normal_broadcast.cap_as,
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

        if data.cap_xs.keys().cloned().collect::<BTreeSet<_>>() != self.context.all_ids {
            return Err(ReceiveError::protocol(Error::R2WrongIdsX.into()));
        }

        if data.cap_ys.keys().cloned().collect::<BTreeSet<_>>() != self.context.all_ids {
            return Err(ReceiveError::protocol(Error::R2WrongIdsY.into()));
        }

        if data.cap_as.keys().cloned().collect::<BTreeSet<_>>() != self.context.all_ids {
            return Err(ReceiveError::protocol(Error::R2WrongIdsA.into()));
        }

        if data.paillier_pk.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2 {
            return Err(ReceiveError::protocol(Error::R2PaillierModulusTooSmall.into()));
        }

        if data.rp_params.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2 {
            return Err(ReceiveError::protocol(Error::R2RPModulusTooSmall.into()));
        }

        if data.cap_xs.values().sum::<Point<P>>() != Point::identity() {
            return Err(ReceiveError::protocol(Error::R2NonZeroSumOfChanges.into()));
        }

        let aux = (&self.context.sid, &from);
        if !data.psi.verify(&data.rp_params, &aux) {
            return Err(ReceiveError::protocol(Error::R2PrmFailed.into()));
        }

        let payload = Round2Payload::<P, Id> {
            cap_xs: data.cap_xs,
            cap_as: data.cap_as,
            cap_ys: data.cap_ys,
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
        let mut payloads = payloads.downcast_all::<Round2Payload<P, Id>>()?;

        let mut rid_combined = self.public_data.rid.clone();
        for payload in payloads.values() {
            rid_combined ^= &payload.rid;
        }

        let my_id = &self.context.my_id;
        let aux = (&self.context.sid, my_id, &rid_combined);
        let psi_prime = ModProof::new(rng, &self.context.paillier_sk, &aux);

        let mut hat_psis = BTreeMap::new();
        for id in self.context.all_ids.iter() {
            let x = self.context.xs.safe_get("secret share changes", id)?;
            let tau = self.context.taus.safe_get("Schnorr secrets", id)?;
            let cap_a = self.public_data.cap_as.safe_get("Schnorr commitments", id)?;
            let cap_x = self.public_data.cap_xs.safe_get("public share changes", id)?;
            let hat_psi = SchProof::new(tau, x, cap_a, cap_x, &aux);
            hat_psis.insert(id.clone(), hat_psi);
        }

        // Add in the payload with this node's info, for the sake of uniformity
        let my_r2_payload = Round2Payload::<P, Id> {
            cap_xs: self.public_data.cap_xs,
            cap_as: self.public_data.cap_as,
            cap_ys: self.public_data.cap_ys,
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
            hat_psis,
        };

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(next_round)))
    }
}

#[derive(Debug)]
struct Round3<P: SchemeParams, Id> {
    context: Context<P, Id>,
    rid_combined: BitVec,
    r2_payloads: BTreeMap<Id, Round2Payload<P, Id>>,
    psi_prime: ModProof<P>,
    hat_psis: BTreeMap<Id, SchProof<P>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    SchProof<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    SchProof<P>: for<'x> Deserialize<'x>,
    Id: for<'x> Deserialize<'x>,
"))]
pub(super) struct Round3EchoBroadcast<P: SchemeParams, Id: PartyId> {
    pub(super) hat_psis: BTreeMap<Id, SchProof<P>>,
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
    pub(super) cap_c: Scalar<P>,
}

struct Round3Payload<P: SchemeParams> {
    x: Secret<Scalar<P>>, // $x_j^i$, a secret share change received from the party $j$
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round3<P, Id> {
    type Protocol = KeyRefreshProtocol<P, Id>;

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

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        let message = Round3EchoBroadcast {
            hat_psis: self.hat_psis.clone(),
        };
        EchoBroadcast::new(serializer, message)
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

        let cap_y = r2_payload.cap_ys.safe_get("Elgamal public keys", my_id)?;
        let y = self.context.ys.safe_get("Elgamal secrets", destination)?;
        let mut reader = XofHasher::new_with_dst(b"KeyRefresh Round3")
            .chain(&self.context.sid)
            .chain(&self.rid_combined)
            .chain(my_id)
            .chain(&(cap_y * y))
            .finalize_to_reader();
        let rho = Scalar::from_xof_reader(&mut reader);
        let x = self.context.xs.safe_get("secret share changes", destination)?;
        let cap_c = *(x + &rho).expose_secret();

        let message = Round3DirectMessage { psi, cap_c };
        let dm = DirectMessage::new(serializer, message)?;
        Ok((dm, None))
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        let echo_broadcast = message
            .echo_broadcast
            .deserialize::<Round3EchoBroadcast<P, Id>>(deserializer)?;
        let normal_broadcast = message
            .normal_broadcast
            .deserialize::<Round3NormalBroadcast<P>>(deserializer)?;
        let direct_message = message
            .direct_message
            .deserialize::<Round3DirectMessage<P>>(deserializer)?;

        let my_id = &self.context.my_id;

        let r2_payload = self.r2_payloads.safe_get("Round 2 payloads", from)?;
        let cap_y = r2_payload.cap_ys.safe_get("Elgamal public keys", my_id)?;
        let y = self.context.ys.safe_get("Elgamal secrets", from)?;
        let mut reader = XofHasher::new_with_dst(b"KeyRefresh Round3")
            .chain(&self.context.sid)
            .chain(&self.rid_combined)
            .chain(from)
            .chain(&(cap_y * y))
            .finalize_to_reader();
        let rho = Scalar::from_xof_reader(&mut reader);

        let x = Secret::init_with(|| direct_message.cap_c - rho);
        let my_cap_x = r2_payload.cap_xs.safe_get("public share changes", my_id)?;
        if &x.mul_by_generator() != my_cap_x {
            return Err(ReceiveError::protocol(
                Error::R3ShareChangeMismatch {
                    reported_by: my_id.clone(),
                    y: *y.expose_secret(),
                }
                .into(),
            ));
        }

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

        if echo_broadcast.hat_psis.keys().cloned().collect::<BTreeSet<_>>() != self.context.all_ids {
            return Err(ReceiveError::protocol(Error::R3WrongIdsHatPsi.into()));
        }

        for (id, hat_psi) in echo_broadcast.hat_psis.iter() {
            let cap_a = r2_payload.cap_as.safe_get("Schnorr commitments", id)?;
            let cap_x = r2_payload.cap_xs.safe_get("Public share changes", id)?;
            if !hat_psi.verify(cap_a, cap_x, &aux) {
                return Err(ReceiveError::protocol(
                    Error::R3SchFailed { failed_for: id.clone() }.into(),
                ));
            }
        }

        Ok(Payload::new(Round3Payload { x }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round3Payload<P>>()?;

        let my_id = &self.context.my_id;

        // Share changes from other nodes
        let xs = payloads.map_values(|payload| payload.x);

        // Share change generated by this node
        let my_x = self.context.xs.safe_get("secret share changes", my_id)?;

        // The combined secret share change
        let x_star = xs.into_values().sum::<Secret<Scalar<P>>>() + my_x;

        // The combined public share changes for each node
        let mut cap_x_star = BTreeMap::new();

        for id_k in self.context.all_ids.iter() {
            let mut result = Point::identity();
            for payload in self.r2_payloads.values() {
                let cap_x = payload.cap_xs.safe_get("public share changes", id_k)?;
                result = result + *cap_x;
            }
            cap_x_star.insert(id_k.clone(), result);
        }

        let public_aux = self.r2_payloads.map_values(|payload| PublicAuxInfo {
            paillier_pk: payload.paillier_pk.into_wire(),
            rp_params: payload.rp_params.to_wire(),
        });

        let secret_aux = SecretAuxInfo {
            paillier_sk: self.context.paillier_sk.into_wire(),
        };

        let key_share_change = KeyShareChange {
            owner: my_id.clone(),
            secret_share_change: x_star,
            public_share_changes: cap_x_star,
        };

        let aux_info = AuxInfo {
            owner: my_id.clone(),
            secret: secret_aux,
            public: PublicAuxInfos(public_aux),
        };

        Ok(FinalizeOutcome::Result((key_share_change, aux_info)))
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

    use super::KeyRefresh;
    use crate::{cggmp21::TestParams, curve::Scalar, tools::protocol_shortcuts::MapValues};

    #[test]
    fn execute_key_refresh() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();

        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key())
            .collect::<BTreeSet<_>>();
        let entry_points = signers
            .into_iter()
            .map(|signer| {
                let entry_point = KeyRefresh::<TestParams, TestVerifier>::new(all_ids.clone()).unwrap();
                (signer, entry_point)
            })
            .collect::<Vec<_>>();

        let results = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
            .unwrap()
            .results()
            .unwrap();

        let changes = results.map_values(|(change, _aux_info)| change);

        // Check that public points correspond to secret scalars
        for (id, change) in changes.iter() {
            for other_change in changes.values() {
                assert_eq!(
                    change.secret_share_change.mul_by_generator(),
                    other_change.public_share_changes[id]
                );
            }
        }

        // The resulting sum of masks should be zero, since the combined secret key
        // should not change after applying the masks at each node.
        let mask_sum: Scalar<TestParams> = changes
            .values()
            .map(|change| change.secret_share_change.expose_secret())
            .sum();
        assert_eq!(mask_sum, Scalar::ZERO);
    }
}
