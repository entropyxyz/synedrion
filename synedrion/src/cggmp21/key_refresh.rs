//! KeyRefresh protocol, in the paper Auxiliary Info. & Key Refresh in Three Rounds (Fig. 7).
//! This protocol generates an update to the secret key shares and new auxiliary parameters
//! for ZK proofs (e.g. Paillier keys).

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
        hashing::{Chain, FofHasher, HashOutput, XofHasher},
        protocol_shortcuts::{verify_that, DeserializeAll, DowncastMap, GetRound, MapValues, SafeGet, Without},
        Secret,
    },
};

/// A protocol for generating auxiliary information for signing,
/// and a simultaneous generation of updates for the secret key shares.
#[derive(Debug)]
pub struct KeyRefreshProtocol<P: SchemeParams, I: PartyId>(PhantomData<(P, I)>);

impl<P: SchemeParams, I: PartyId> Protocol<I> for KeyRefreshProtocol<P, I> {
    type Result = (KeyShareChange<P, I>, AuxInfo<P, I>);
    type ProtocolError = KeyRefreshError<P, I>;

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
            r if r == &2 => message.verify_is_not::<Round2EchoBroadcast<P, I>>(deserializer),
            r if r == &3 => message.verify_is_not::<Round3EchoBroadcast<I>>(deserializer),
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
            r if r == &2 => message.verify_is_not::<Round2NormalBroadcast<P, I>>(deserializer),
            r if r == &3 => message.verify_is_not::<Round3Broadcast<P>>(deserializer),
            _ => Err(MessageValidationError::InvalidEvidence("Invalid round number".into())),
        }
    }
}

/// Provable KeyRefresh faults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    KeyRefreshErrorEnum<I>: Serialize,
"))]
#[serde(bound(deserialize = "
    KeyRefreshErrorEnum<I>: for<'x> Deserialize<'x>,
"))]
pub struct KeyRefreshError<P, I> {
    error: KeyRefreshErrorEnum<I>,
    phantom: PhantomData<P>,
}

impl<P, I> KeyRefreshError<P, I> {
    fn new(error: KeyRefreshErrorEnum<I>) -> Self {
        Self {
            error,
            phantom: PhantomData,
        }
    }
}

impl<P, I: PartyId> Display for KeyRefreshError<P, I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self.error)
    }
}

/// KeyRefresh error
#[derive(displaydoc::Display, Debug, Clone, Serialize, Deserialize)]
enum KeyRefreshErrorEnum<I> {
    /// Round2: public data hash mismatch
    R2HashMismatch,
    /// Round2: wrong IDs in public shares map
    R2WrongIdsX,
    /// Round2: wrong IDs in Elgamal keys map
    R2WrongIdsY,
    /// Round2: wrong IDs in Schnorr commitments map
    R2WrongIdsA,
    /// Round2: Paillier modulus is too small
    R2PaillierModulusTooSmall,
    /// Round2: ring-Pedersent modulus is too small
    R2RPModulusTooSmall,
    /// Round2: sum of share changes is not zero
    R2NonZeroSumOfChanges,
    /// Round2: P_prm verification failed
    R2PrmFailed,
    /// Round3: secret share change does not match the public commitment
    R3ShareChangeMismatch {
        /// The index $i$ of the node that produced the evidence.
        reported_by: I,
        /// $y_{i,j}$, where where $j$ is the index of the guilty party.
        y: Scalar,
    },
    /// Round3: P_mod verification failed
    R3ModFailed,
    /// Round3: P_fac verification failed
    R3FacFailed {
        /// The index $i$ of the node that produced the evidence.
        reported_by: I,
    },
    /// Round3: Wrong IDs in Schnorr proofs map
    R3WrongIdsHatPsi,
    /// Round3: P_sch verification failed
    R3SchFailed {
        /// The index $k$ for which the verification of $П^{sch}_{j,k}$ failed
        /// (where $j$ is the index of the guilty party).
        failed_for: I,
    },
}

/// Reconstruct `rid` from echoed messages
fn reconstruct_rid<P: SchemeParams, I: PartyId>(
    deserializer: &Deserializer,
    previous_messages: &BTreeMap<RoundId, ProtocolMessage>,
    combined_echos: &BTreeMap<RoundId, BTreeMap<I, EchoBroadcast>>,
) -> Result<BitVec, ProtocolValidationError> {
    let r2_messages = combined_echos
        .get_round(2)?
        .deserialize_all::<Round2EchoBroadcast<P, I>>(deserializer)?;
    let r2_echo = previous_messages
        .get_round(2)?
        .echo_broadcast
        .deserialize::<Round2EchoBroadcast<P, I>>(deserializer)?;
    let mut rid = r2_echo.rid_part;
    for message in r2_messages.values() {
        rid ^= &message.rid_part;
    }
    Ok(rid)
}

impl<P: SchemeParams, I: PartyId> ProtocolError<I> for KeyRefreshError<P, I> {
    type AssociatedData = BTreeSet<I>;

    fn required_messages(&self) -> RequiredMessages {
        match self.error {
            KeyRefreshErrorEnum::R2HashMismatch => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast(),
                Some([(1.into(), RequiredMessageParts::echo_broadcast())].into()),
                None,
            ),
            KeyRefreshErrorEnum::R2WrongIdsX => {
                RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None)
            }
            KeyRefreshErrorEnum::R2WrongIdsY => {
                RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None)
            }
            KeyRefreshErrorEnum::R2WrongIdsA => {
                RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None)
            }
            KeyRefreshErrorEnum::R2PaillierModulusTooSmall => {
                RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None)
            }
            KeyRefreshErrorEnum::R2RPModulusTooSmall => {
                RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None)
            }
            KeyRefreshErrorEnum::R2NonZeroSumOfChanges => {
                RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None)
            }
            KeyRefreshErrorEnum::R2PrmFailed => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast().and_normal_broadcast(),
                None,
                None,
            ),
            KeyRefreshErrorEnum::R3ShareChangeMismatch { .. } => RequiredMessages::new(
                RequiredMessageParts::direct_message(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast())].into()),
                Some([2.into()].into()),
            ),
            KeyRefreshErrorEnum::R3ModFailed => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast())].into()),
                Some([2.into()].into()),
            ),
            KeyRefreshErrorEnum::R3FacFailed { .. } => RequiredMessages::new(
                RequiredMessageParts::direct_message(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast())].into()),
                Some([2.into()].into()),
            ),
            KeyRefreshErrorEnum::R3WrongIdsHatPsi => {
                RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None)
            }
            KeyRefreshErrorEnum::R3SchFailed { .. } => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast())].into()),
                Some([2.into()].into()),
            ),
        }
    }

    fn verify_messages_constitute_error(
        &self,
        deserializer: &Deserializer,
        guilty_party: &I,
        shared_randomness: &[u8],
        associated_data: &Self::AssociatedData,
        message: ProtocolMessage,
        previous_messages: BTreeMap<RoundId, ProtocolMessage>,
        combined_echos: BTreeMap<RoundId, BTreeMap<I, EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        let sid_hash = FofHasher::new_with_dst(b"SID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .finalize();

        match &self.error {
            KeyRefreshErrorEnum::R2HashMismatch => {
                let r1_message = previous_messages
                    .get_round(1)?
                    .echo_broadcast
                    .deserialize::<Round1EchoBroadcast>(deserializer)?;
                let r2_message = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, I>>(deserializer)?;
                verify_that(r2_message.hash(&sid_hash, guilty_party) != r1_message.cap_v)
            }
            KeyRefreshErrorEnum::R2WrongIdsX => {
                let r2_message = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, I>>(deserializer)?;
                verify_that(&r2_message.cap_xs.keys().cloned().collect::<BTreeSet<_>>() != associated_data)
            }
            KeyRefreshErrorEnum::R2WrongIdsY => {
                let r2_message = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, I>>(deserializer)?;
                verify_that(&r2_message.cap_ys.keys().cloned().collect::<BTreeSet<_>>() != associated_data)
            }
            KeyRefreshErrorEnum::R2WrongIdsA => {
                let r2_message = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, I>>(deserializer)?;
                verify_that(&r2_message.cap_as.keys().cloned().collect::<BTreeSet<_>>() != associated_data)
            }
            KeyRefreshErrorEnum::R2PaillierModulusTooSmall => {
                let r2_message = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, I>>(deserializer)?;
                verify_that(
                    r2_message.paillier_pk.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2,
                )
            }
            KeyRefreshErrorEnum::R2RPModulusTooSmall => {
                let r2_message = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, I>>(deserializer)?;
                verify_that(
                    r2_message.rp_params.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2,
                )
            }
            KeyRefreshErrorEnum::R2NonZeroSumOfChanges => {
                let r2_message = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, I>>(deserializer)?;
                verify_that(r2_message.cap_xs.values().sum::<Point>() != Point::IDENTITY)
            }
            KeyRefreshErrorEnum::R2PrmFailed => {
                let r2_eb = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, I>>(deserializer)?;
                let r2_bc = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, I>>(deserializer)?;
                let aux = (&sid_hash, guilty_party);
                let rp_params = r2_eb.rp_params.to_precomputed();
                verify_that(!r2_bc.psi.verify(&rp_params, &aux))
            }
            KeyRefreshErrorEnum::R3ShareChangeMismatch { reported_by, y } => {
                // Check that `y` attached to the evidence is correct
                // (that is, can be verified against something signed by `guilty_party`).
                // It is `y_{i,j}` where `i == reported_by` and `j == guilty_party`
                let r2_message_i = combined_echos
                    .get_round(2)?
                    .try_get("combined echos for Round 2", reported_by)?
                    .deserialize::<Round2EchoBroadcast<P, I>>(deserializer)?;
                let cap_y_ij = r2_message_i.cap_ys.try_get("public Elgamal values", guilty_party)?;
                if &y.mul_by_generator() != cap_y_ij {
                    return Err(ProtocolValidationError::InvalidEvidence(
                        "The provided `y` is invalid".into(),
                    ));
                }

                let rid = reconstruct_rid::<P, _>(deserializer, &previous_messages, &combined_echos)?;

                let r2_echo = previous_messages
                    .get_round(2)?
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, I>>(deserializer)?;
                let cap_y_ji = r2_echo.cap_ys.try_get("public Elgamal values", reported_by)?;
                let mut reader = XofHasher::new_with_dst(b"KeyRefresh Round3")
                    .chain(&sid_hash)
                    .chain(&rid)
                    .chain(guilty_party)
                    .chain(&(cap_y_ji * y))
                    .finalize_to_reader();
                let rho = Scalar::from_xof_reader(&mut reader);

                let r2_bc = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, I>>(deserializer)?;
                let r3_message = message
                    .direct_message
                    .deserialize::<Round3DirectMessage<P>>(deserializer)?;

                let x = r3_message.cap_c - rho;
                let cap_x_ji = r2_bc.cap_xs.try_get("public key share changes", reported_by)?;
                verify_that(&x.mul_by_generator() != cap_x_ji)
            }
            KeyRefreshErrorEnum::R3ModFailed => {
                let rid = reconstruct_rid::<P, _>(deserializer, &previous_messages, &combined_echos)?;
                let aux = (&sid_hash, guilty_party, &rid);
                let r2_bc = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, I>>(deserializer)?;
                let r3_bc = message
                    .normal_broadcast
                    .deserialize::<Round3Broadcast<P>>(deserializer)?;
                let paillier_pk = r2_bc.paillier_pk.into_precomputed();
                verify_that(!r3_bc.psi_prime.verify(&paillier_pk, &aux))
            }
            KeyRefreshErrorEnum::R3FacFailed { reported_by } => {
                let rid = reconstruct_rid::<P, _>(deserializer, &previous_messages, &combined_echos)?;
                let aux = (&sid_hash, guilty_party, &rid);

                let r2_eb = combined_echos
                    .get_round(2)?
                    .try_get("combined echos for Round 2", reported_by)?
                    .deserialize::<Round2EchoBroadcast<P, I>>(deserializer)?;
                let r2_bc = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, I>>(deserializer)?;
                let r3_dm = message
                    .direct_message
                    .deserialize::<Round3DirectMessage<P>>(deserializer)?;
                let paillier_pk = r2_bc.paillier_pk.into_precomputed();
                let rp_params = r2_eb.rp_params.to_precomputed();
                verify_that(!r3_dm.psi.verify(&paillier_pk, &rp_params, &aux))
            }
            KeyRefreshErrorEnum::R3WrongIdsHatPsi => {
                let r3_eb = message
                    .echo_broadcast
                    .deserialize::<Round3EchoBroadcast<I>>(deserializer)?;
                verify_that(&r3_eb.hat_psis.keys().cloned().collect::<BTreeSet<_>>() != associated_data)
            }
            KeyRefreshErrorEnum::R3SchFailed { failed_for } => {
                let rid = reconstruct_rid::<P, _>(deserializer, &previous_messages, &combined_echos)?;
                let aux = (&sid_hash, guilty_party, &rid);

                let r2_bc = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, I>>(deserializer)?;
                let r3_eb = message
                    .echo_broadcast
                    .deserialize::<Round3EchoBroadcast<I>>(deserializer)?;

                let cap_a = r2_bc.cap_as.try_get("Schnorr commitments", failed_for)?;
                let cap_x = r2_bc.cap_xs.try_get("public share changes", failed_for)?;
                let hat_psi = r3_eb.hat_psis.try_get("Schnorr proofs", failed_for)?;
                verify_that(!hat_psi.verify(cap_a, cap_x, &aux))
            }
        }
    }
}

/// An entry point for the [`KeyRefreshProtocol`].
#[derive(Debug, Clone)]
pub struct KeyRefresh<P, I> {
    all_ids: BTreeSet<I>,
    phantom: PhantomData<P>,
}

impl<P, I: PartyId> KeyRefresh<P, I> {
    /// Creates a new entry point given the set of the participants' IDs
    /// (including this node's).
    pub fn new(all_ids: BTreeSet<I>) -> Result<Self, LocalError> {
        Ok(Self {
            all_ids,
            phantom: PhantomData,
        })
    }
}

impl<P: SchemeParams, I: PartyId> EntryPoint<I> for KeyRefresh<P, I> {
    type Protocol = KeyRefreshProtocol<P, I>;

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

        // Paillier secret key $p_i$, $q_i$
        let paillier_sk = SecretKeyPaillierWire::<P::Paillier>::random(rng);
        // Paillier public key $N_i$
        let paillier_pk = paillier_sk.public_key();

        // Ring-Pedersen secret $\lambda$.
        let rp_secret = RPSecret::random(rng);
        // Ring-Pedersen parameters ($N$, $s$, $t$) bundled in a single object.
        let rp_params = RPParams::random_with_secret(rng, &rp_secret);

        let aux = (&sid_hash, id);
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

        let rid_part = BitVec::random(rng, P::SECURITY_PARAMETER);
        let u = BitVec::random(rng, P::SECURITY_PARAMETER);

        // Note: typo in the paper, $V$ hashes in $B_i$ which is not present in the '24 version of the paper.
        let r2_normal_broadcast = Round2NormalBroadcast {
            cap_xs,
            cap_as,
            paillier_pk: paillier_pk.clone(),
            psi,
            u,
        };

        let r2_echo_broadcast = Round2EchoBroadcast {
            rp_params: rp_params.to_wire(),
            cap_ys,
            rid_part,
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
            sid_hash,
        };

        let round = Round1 {
            context,
            r2_normal_broadcast,
            r2_echo_broadcast,
        };

        Ok(BoxedRound::new_dynamic(round))
    }
}

#[derive(Debug)]
pub(super) struct Context<P: SchemeParams, I> {
    paillier_sk: SecretKeyPaillier<P::Paillier>,
    rp_params: RPParams<P::Paillier>,
    xs: BTreeMap<I, Secret<Scalar>>, // $x_{i,j}$ where $i$ is this party's index
    ys: BTreeMap<I, Secret<Scalar>>, // $y_{i,j}$ where $i$ is this party's index
    taus: BTreeMap<I, SchSecret>,
    pub(super) my_id: I,
    other_ids: BTreeSet<I>,
    all_ids: BTreeSet<I>,
    pub(super) sid_hash: HashOutput,
}

#[derive(Debug)]
pub(super) struct Round1<P: SchemeParams, I: PartyId> {
    pub(super) context: Context<P, I>,
    pub(super) r2_normal_broadcast: Round2NormalBroadcast<P, I>,
    pub(super) r2_echo_broadcast: Round2EchoBroadcast<P, I>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Round1EchoBroadcast {
    pub(super) cap_v: HashOutput,
}

struct Round1Payload {
    cap_v: HashOutput,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round1<P, I> {
    type Protocol = KeyRefreshProtocol<P, I>;

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
        let message = Round1EchoBroadcast {
            cap_v: self
                .r2_normal_broadcast
                .hash(&self.context.sid_hash, &self.context.my_id),
        };
        EchoBroadcast::new(serializer, message)
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        _from: &I,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
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
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round1Payload>()?;
        let others_cap_v = payloads.map_values(|payload| payload.cap_v);
        let next_round = Round2 {
            context: self.context,
            r2_echo_broadcast: self.r2_echo_broadcast,
            r2_normal_broadcast: self.r2_normal_broadcast,
            others_cap_v,
        };
        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(next_round)))
    }
}

#[derive(Debug)]
struct Round2<P: SchemeParams, I: PartyId> {
    context: Context<P, I>,
    r2_normal_broadcast: Round2NormalBroadcast<P, I>,
    r2_echo_broadcast: Round2EchoBroadcast<P, I>,
    others_cap_v: BTreeMap<I, HashOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    PrmProof<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    PrmProof<P>: for<'x> Deserialize<'x>,
"))]
pub(super) struct Round2NormalBroadcast<P: SchemeParams, I: PartyId> {
    pub(super) cap_xs: BTreeMap<I, Point>, // $X_{i,j}$ where $i$ is this party's index
    pub(super) cap_as: BTreeMap<I, SchCommitment>, // $A_{i,j}$ where $i$ is this party's index
    pub(super) paillier_pk: PublicKeyPaillierWire<P::Paillier>, // $N_i$
    pub(super) psi: PrmProof<P>,
    u: BitVec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    I: Serialize,
"))]
#[serde(bound(deserialize = "
    I: for<'x> Deserialize<'x>,
"))]
pub(super) struct Round2EchoBroadcast<P: SchemeParams, I: PartyId> {
    pub(super) rp_params: RPParamsWire<P::Paillier>, // $\hat{N}_i$, $s_i$, and $t_i$
    pub(super) cap_ys: BTreeMap<I, Point>,           // $Y_{i,j}$ where $i$ is this party's index
    rid_part: BitVec,
}

impl<P: SchemeParams, I: PartyId> Round2NormalBroadcast<P, I> {
    pub(super) fn hash(&self, sid_hash: &HashOutput, id: &I) -> HashOutput {
        FofHasher::new_with_dst(b"Auxiliary")
            .chain(sid_hash)
            .chain(id)
            .chain(self)
            .finalize()
    }
}

#[derive(Debug)]
struct Round2Payload<P: SchemeParams, I> {
    cap_xs: BTreeMap<I, Point>,                  // $X_{i,j}$ where $i$ is this party's index
    cap_as: BTreeMap<I, SchCommitment>,          // $A_{i,j}$ where $i$ is this party's index
    cap_ys: BTreeMap<I, Point>,                  // $Y_{i,j}$ where $i$ is this party's index
    paillier_pk: PublicKeyPaillier<P::Paillier>, // $N_i$
    rp_params: RPParams<P::Paillier>,            // $\hat{N}_i$, $s_i$, and $t_i$
    rid_part: BitVec,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round2<P, I> {
    type Protocol = KeyRefreshProtocol<P, I>;

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

    fn make_normal_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<NormalBroadcast, LocalError> {
        NormalBroadcast::new(serializer, self.r2_normal_broadcast.clone())
    }

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        EchoBroadcast::new(serializer, self.r2_echo_broadcast.clone())
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &I,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        message.direct_message.assert_is_none()?;
        let echo_broadcast = message
            .echo_broadcast
            .deserialize::<Round2EchoBroadcast<P, I>>(deserializer)?;
        let normal_broadcast = message
            .normal_broadcast
            .deserialize::<Round2NormalBroadcast<P, I>>(deserializer)?;

        let cap_v = self.others_cap_v.safe_get("other nodes' `V`", from)?;

        if &normal_broadcast.hash(&self.context.sid_hash, from) != cap_v {
            return Err(ReceiveError::protocol(KeyRefreshError::new(
                KeyRefreshErrorEnum::R2HashMismatch,
            )));
        }

        if normal_broadcast.cap_xs.keys().cloned().collect::<BTreeSet<_>>() != self.context.all_ids {
            return Err(ReceiveError::protocol(KeyRefreshError::new(
                KeyRefreshErrorEnum::R2WrongIdsX,
            )));
        }

        if echo_broadcast.cap_ys.keys().cloned().collect::<BTreeSet<_>>() != self.context.all_ids {
            return Err(ReceiveError::protocol(KeyRefreshError::new(
                KeyRefreshErrorEnum::R2WrongIdsY,
            )));
        }

        if normal_broadcast.cap_as.keys().cloned().collect::<BTreeSet<_>>() != self.context.all_ids {
            return Err(ReceiveError::protocol(KeyRefreshError::new(
                KeyRefreshErrorEnum::R2WrongIdsA,
            )));
        }

        let paillier_pk = normal_broadcast.paillier_pk.clone().into_precomputed();
        let rp_params = echo_broadcast.rp_params.to_precomputed();

        if paillier_pk.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2 {
            return Err(ReceiveError::protocol(KeyRefreshError::new(
                KeyRefreshErrorEnum::R2PaillierModulusTooSmall,
            )));
        }

        if rp_params.modulus().bits_vartime() < <P::Paillier as PaillierParams>::MODULUS_BITS - 2 {
            return Err(ReceiveError::protocol(KeyRefreshError::new(
                KeyRefreshErrorEnum::R2RPModulusTooSmall,
            )));
        }

        if normal_broadcast.cap_xs.values().sum::<Point>() != Point::IDENTITY {
            return Err(ReceiveError::protocol(KeyRefreshError::new(
                KeyRefreshErrorEnum::R2NonZeroSumOfChanges,
            )));
        }

        let aux = (&self.context.sid_hash, &from);
        if !normal_broadcast.psi.verify(&rp_params, &aux) {
            return Err(ReceiveError::protocol(KeyRefreshError::new(
                KeyRefreshErrorEnum::R2PrmFailed,
            )));
        }

        let payload = Round2Payload::<P, I> {
            cap_xs: normal_broadcast.cap_xs,
            cap_as: normal_broadcast.cap_as,
            cap_ys: echo_broadcast.cap_ys,
            paillier_pk: normal_broadcast.paillier_pk.into_precomputed(),
            rp_params: echo_broadcast.rp_params.to_precomputed(),
            rid_part: echo_broadcast.rid_part,
        };

        Ok(Payload::new(payload))
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let mut payloads = payloads.downcast_all::<Round2Payload<P, I>>()?;

        let mut rid = self.r2_echo_broadcast.rid_part.clone();
        for payload in payloads.values() {
            rid ^= &payload.rid_part;
        }

        // Add in the payload with this node's info, for the sake of uniformity
        let my_payload = Round2Payload::<P, I> {
            cap_xs: self.r2_normal_broadcast.cap_xs,
            cap_as: self.r2_normal_broadcast.cap_as,
            cap_ys: self.r2_echo_broadcast.cap_ys,
            paillier_pk: self.r2_normal_broadcast.paillier_pk.into_precomputed(),
            rp_params: self.r2_echo_broadcast.rp_params.to_precomputed(),
            rid_part: self.r2_echo_broadcast.rid_part,
        };
        payloads.insert(self.context.my_id.clone(), my_payload);

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round3::new(
            rng,
            self.context,
            payloads,
            rid,
        )?)))
    }
}

#[derive(Debug)]
struct Round3<P: SchemeParams, I> {
    context: Context<P, I>,
    rid: BitVec,
    r2_payloads: BTreeMap<I, Round2Payload<P, I>>,
    psi_prime: ModProof<P>,
    hat_psis: BTreeMap<I, SchProof>,
}

impl<P: SchemeParams, I: PartyId> Round3<P, I> {
    fn new(
        rng: &mut impl CryptoRngCore,
        context: Context<P, I>,
        r2_payloads: BTreeMap<I, Round2Payload<P, I>>,
        rid: BitVec,
    ) -> Result<Self, LocalError> {
        let my_id = &context.my_id;
        let aux = (&context.sid_hash, my_id, &rid);
        let psi_prime = ModProof::new(rng, &context.paillier_sk, &aux);

        let my_r2_payload = r2_payloads.safe_get("Round 2 payloads", my_id)?;

        let mut hat_psis = BTreeMap::new();
        for id in context.all_ids.iter() {
            let x = context.xs.safe_get("secret share changes", id)?;
            let tau = context.taus.safe_get("Schnorr secrets", id)?;
            let cap_a = my_r2_payload.cap_as.safe_get("Schnorr commitments", id)?;
            let cap_x = my_r2_payload.cap_xs.safe_get("public share changes", id)?;
            let hat_psi = SchProof::new(tau, x, cap_a, cap_x, &aux);
            hat_psis.insert(id.clone(), hat_psi);
        }

        Ok(Self {
            context,
            r2_payloads,
            rid,
            psi_prime,
            hat_psis,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    SchProof: Serialize,
"))]
#[serde(bound(deserialize = "
    SchProof: for<'x> Deserialize<'x>,
"))]
pub(super) struct Round3EchoBroadcast<I: PartyId> {
    pub(super) hat_psis: BTreeMap<I, SchProof>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    ModProof<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    ModProof<P>: for<'x> Deserialize<'x>,
"))]
pub(super) struct Round3Broadcast<P: SchemeParams> {
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
    pub(super) cap_c: Scalar,
}

struct Round3Payload {
    x: Secret<Scalar>, // $x_j^i$, a secret share change received from the party $j$
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round3<P, I> {
    type Protocol = KeyRefreshProtocol<P, I>;

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
        let message = Round3Broadcast {
            psi_prime: self.psi_prime.clone(),
        };
        NormalBroadcast::new(serializer, message)
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
        destination: &I,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let my_id = &self.context.my_id;
        let aux = (&self.context.sid_hash, my_id, &self.rid);

        let r2_payload = self.r2_payloads.safe_get("Round 2 payloads", destination)?;

        let psi = FacProof::<P>::new(rng, &self.context.paillier_sk, &r2_payload.rp_params, &aux);

        let cap_y = r2_payload.cap_ys.safe_get("Elgamal public keys", my_id)?;
        let y = self.context.ys.safe_get("Elgamal secrets", destination)?;
        let mut reader = XofHasher::new_with_dst(b"KeyRefresh Round3")
            .chain(&self.context.sid_hash)
            .chain(&self.rid)
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
        from: &I,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        let echo_broadcast = message
            .echo_broadcast
            .deserialize::<Round3EchoBroadcast<I>>(deserializer)?;
        let normal_broadcast = message
            .normal_broadcast
            .deserialize::<Round3Broadcast<P>>(deserializer)?;
        let direct_message = message
            .direct_message
            .deserialize::<Round3DirectMessage<P>>(deserializer)?;

        let my_id = &self.context.my_id;

        let r2_payload = self.r2_payloads.safe_get("Round 2 payloads", from)?;
        let cap_y = r2_payload.cap_ys.safe_get("Elgamal public keys", my_id)?;
        let y = self.context.ys.safe_get("Elgamal secrets", from)?;
        let mut reader = XofHasher::new_with_dst(b"KeyRefresh Round3")
            .chain(&self.context.sid_hash)
            .chain(&self.rid)
            .chain(from)
            .chain(&(cap_y * y))
            .finalize_to_reader();
        let rho = Scalar::from_xof_reader(&mut reader);

        let x = Secret::init_with(|| direct_message.cap_c - rho);
        let my_cap_x = r2_payload.cap_xs.safe_get("public share changes", my_id)?;
        if &x.mul_by_generator() != my_cap_x {
            return Err(ReceiveError::protocol(KeyRefreshError::new(
                KeyRefreshErrorEnum::R3ShareChangeMismatch {
                    reported_by: my_id.clone(),
                    y: *y.expose_secret(),
                },
            )));
        }

        let aux = (&self.context.sid_hash, from, &self.rid);
        if !normal_broadcast.psi_prime.verify(&r2_payload.paillier_pk, &aux) {
            return Err(ReceiveError::protocol(KeyRefreshError::new(
                KeyRefreshErrorEnum::R3ModFailed,
            )));
        }

        if !direct_message
            .psi
            .verify(&r2_payload.paillier_pk, &self.context.rp_params, &aux)
        {
            return Err(ReceiveError::protocol(KeyRefreshError::new(
                KeyRefreshErrorEnum::R3FacFailed {
                    reported_by: my_id.clone(),
                },
            )));
        }

        if echo_broadcast.hat_psis.keys().cloned().collect::<BTreeSet<_>>() != self.context.all_ids {
            return Err(ReceiveError::protocol(KeyRefreshError::new(
                KeyRefreshErrorEnum::R3WrongIdsHatPsi,
            )));
        }

        for (id, hat_psi) in echo_broadcast.hat_psis.iter() {
            let cap_a = r2_payload.cap_as.safe_get("Schnorr commitments", id)?;
            let cap_x = r2_payload.cap_xs.safe_get("Public share changes", id)?;
            if !hat_psi.verify(cap_a, cap_x, &aux) {
                return Err(ReceiveError::protocol(KeyRefreshError::new(
                    KeyRefreshErrorEnum::R3SchFailed { failed_for: id.clone() },
                )));
            }
        }

        Ok(Payload::new(Round3Payload { x }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round3Payload>()?;

        let my_id = &self.context.my_id;

        // Share changes from other nodes
        let xs = payloads.map_values(|payload| payload.x);

        // Share change generated by this node
        let my_x = self.context.xs.safe_get("secret share changes", my_id)?;

        // The combined secret share change
        let x_star = xs.into_values().sum::<Secret<Scalar>>() + my_x;

        // The combined public share changes for each node
        let mut cap_x_star = BTreeMap::new();

        for id_k in self.context.all_ids.iter() {
            let mut result = Point::IDENTITY;
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
            phantom: PhantomData,
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
        let mask_sum: Scalar = changes
            .values()
            .map(|change| change.secret_share_change.expose_secret())
            .sum();
        assert_eq!(mask_sum, Scalar::ZERO);
    }
}
