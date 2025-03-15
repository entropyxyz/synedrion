//! Combined
//! - ECDSA Pre-Signing protocol (Fig. 8) - Rounds 1-3.
//! - ECDSA Signing (Fig. 10) - Round 4.
//! - Failed Nonce error round (Fig. 9) - Round 5.
//! - Failed Chi error round (Section 4.3.1) - Round 6.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use core::{
    fmt::{self, Debug, Display},
    marker::PhantomData,
};

use elliptic_curve::{Curve, FieldBytes};
use manul::protocol::{
    Artifact, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EntryPoint, FinalizeOutcome, LocalError,
    MessageValidationError, NormalBroadcast, PartyId, Payload, Protocol, ProtocolError, ProtocolMessage,
    ProtocolMessagePart, ProtocolValidationError, ReceiveError, RequiredMessageParts, RequiredMessages, Round, RoundId,
    Serializer,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    curve::{Point, RecoverableSignature, Scalar},
    entities::{AuxInfo, AuxInfoPrecomputed, KeyShare, PublicAuxInfoPrecomputed, PublicAuxInfos, PublicKeyShares},
    paillier::{Ciphertext, CiphertextWire, PaillierParams, Randomizer},
    params::{secret_scalar_from_signed, secret_signed_from_scalar, SchemeParams},
    tools::{
        hashing::{Chain, XofHasher},
        protocol_shortcuts::{
            sum_non_empty, sum_non_empty_ref, verify_that, DeserializeAll, DowncastMap, GetRound, MapValues, SafeGet,
            Without,
        },
        Secret,
    },
    uint::SecretSigned,
    zk::{
        AffGProof, AffGPublicInputs, AffGSecretInputs, AffGStarProof, AffGStarPublicInputs, AffGStarSecretInputs,
        DecProof, DecPublicInputs, DecSecretInputs, ElogProof, ElogPublicInputs, ElogSecretInputs, EncElgProof,
        EncElgPublicInputs, EncElgSecretInputs,
    },
};

/// Prehashed message to sign.
// TODO: Type aliases are not enforced by the compiler, but they should be. Maybe one?
#[allow(type_alias_bounds)]
pub type PrehashedMessage<C: Curve> = FieldBytes<C>;

#[derive(Debug, Clone)]
struct PresigningData<P, Id>
where
    P: SchemeParams,
{
    cap_gamma_combined: Point<P>,             // $\Gamma$
    tilde_k: Secret<Scalar<P>>,               // $k / \delta$
    tilde_chi: Secret<Scalar<P>>,             // $chi / \delta$
    tilde_cap_deltas: BTreeMap<Id, Point<P>>, // $\Delta_j^{\delta^{-1}}$ for all $j$
    tilde_cap_ss: BTreeMap<Id, Point<P>>,     // $S_j^{\delta^{-1}}$ for all $j$
}

/// A protocol for creating all the data necessary for signing
/// that doesn't require knowing the actual message being signed.
#[derive(Debug, Clone, Copy)]
pub struct InteractiveSigningProtocol<P: SchemeParams, Id: Debug>(PhantomData<(P, Id)>);

impl<P: SchemeParams, Id: PartyId> Protocol<Id> for InteractiveSigningProtocol<P, Id> {
    type Result = RecoverableSignature<P>;
    type ProtocolError = InteractiveSigningError<P, Id>;

    fn verify_direct_message_is_invalid(
        deserializer: &Deserializer,
        round_id: &RoundId,
        message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        match round_id {
            r if r == &1 => message.verify_is_not::<Round1DirectMessage<P>>(deserializer),
            r if r == &2 => message.verify_is_some(),
            r if r == &3 => message.verify_is_some(),
            r if r == &4 => message.verify_is_some(),
            r if r == &5 => message.verify_is_some(),
            r if r == &6 => message.verify_is_some(),
            _ => Err(MessageValidationError::InvalidEvidence("Invalid round number".into())),
        }
    }

    fn verify_echo_broadcast_is_invalid(
        deserializer: &Deserializer,
        round_id: &RoundId,
        message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        match round_id {
            r if r == &1 => message.verify_is_not::<Round1EchoBroadcast<P>>(deserializer),
            r if r == &2 => message.verify_is_not::<Round2EchoBroadcast<P, Id>>(deserializer),
            r if r == &3 => message.verify_is_not::<Round3EchoBroadcast<P>>(deserializer),
            r if r == &4 => message.verify_is_some(),
            r if r == &5 => message.verify_is_not::<Round5EchoBroadcast<P, Id>>(deserializer),
            r if r == &6 => message.verify_is_not::<Round6EchoBroadcast<P, Id>>(deserializer),
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
            r if r == &4 => message.verify_is_not::<Round4NormalBroadcast<P>>(deserializer),
            r if r == &5 => message.verify_is_some(),
            r if r == &6 => message.verify_is_some(),
            _ => Err(MessageValidationError::InvalidEvidence("Invalid round number".into())),
        }
    }
}

/// Possible verifiable errors of the InteractiveSigning protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteractiveSigningError<P, Id> {
    error: Error<Id>,
    phantom: PhantomData<P>,
}

impl<P, Id: Debug> Display for InteractiveSigningError<P, Id> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}",
            match self.error {
                Error::R1EncElg0Failed => "Round 1: failed to verify `\\psi^0` (`П^{enc-elg}` proof).",
                Error::R1EncElg1Failed => "Round 1: failed to verify `\\psi^1` (`П^{enc-elg}` proof).",
                Error::R2WrongIdsD => "Round 2: wrong IDs in `D` map.",
                Error::R2WrongIdsF => "Round 2: wrong IDs in `F` map.",
                Error::R2WrongIdsPsi => "Round 2: wrong IDs in `\\psi` map (`П^{aff-g}` proofs for `D`).",
                Error::R2AffGPsiFailed { .. } => "Round 2: failed to verify `\\psi` (`П^{aff-g}` proof for `D`).",
                Error::R2AffGHatPsiFailed { .. } =>
                    "Round 2: failed to verify `\\hat{psi}` (`П^{aff-g}` proof for `\\hat{D}`).",
                Error::R2ElogFailed => "Round 2: failed to verify `П^{elog}` proof.",
                Error::R3ElogFailed => "Round 3: failed to verify `П^{elog}` proof.",
                Error::R4InvalidSignatureShare => "Round 4: signature share verification failed.",
                Error::R5DecFailed => "Round 5: `П^{dec}` proof verification failed.",
                Error::R5WrongIdsPsi => "Round 5: wrong IDs in `П^{aff-g*}` proof map.",
                Error::R5AffGStarFailed { .. } => "Round 5: `П^{aff-g*}` proof verification failed.",
                Error::R6DecFailed => "Round 6: `П^{dec}` proof verification failed.",
                Error::R6WrongIdsPsi => "Round 6: wrong IDs in `П^{aff-g*}` proof map.",
                Error::R6AffGStarFailed { .. } => "Round 6: `П^{aff-g*}` proof verification failed.",
            }
        )
    }
}

/// Possible verifiable errors of the InteractiveSigning protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum Error<Id> {
    R1EncElg0Failed,
    R1EncElg1Failed,
    R2WrongIdsD,
    R2WrongIdsF,
    R2WrongIdsPsi,
    R2AffGPsiFailed {
        /// The index $k$ for which the verification of $\psi_{k,j}$ failed
        /// (where $j$ is the index of the guilty party).
        failed_for: Id,
    },
    R2AffGHatPsiFailed {
        /// The index $k$ for which the verification of $\hat{\psi}_{k,j}$ failed
        /// (where $j$ is the index of the guilty party).
        failed_for: Id,
    },
    R2ElogFailed,
    R3ElogFailed,
    R4InvalidSignatureShare,
    R5DecFailed,
    R5WrongIdsPsi,
    R5AffGStarFailed {
        /// The index $\ell$ for which the verification of $\psi_{j,\ell}$ failed
        /// (where $j$ is the index of the guilty party).
        failed_for: Id,
    },
    R6DecFailed,
    R6WrongIdsPsi,
    R6AffGStarFailed {
        /// The index $\ell$ for which the verification of $\hat{\psi}_{j,\ell}$ failed
        /// (where $j$ is the index of the guilty party).
        failed_for: Id,
    },
}

impl<P, Id> From<Error<Id>> for InteractiveSigningError<P, Id> {
    fn from(source: Error<Id>) -> Self {
        Self {
            error: source,
            phantom: PhantomData,
        }
    }
}

/// Associated data for InteractiveSigning protocol.
#[derive(Debug, Clone)]
pub struct InteractiveSigningAssociatedData<P: SchemeParams, Id: PartyId> {
    /// Public shares of all participating nodes.
    pub shares: PublicKeyShares<P, Id>,
    /// Auxiliary data of all participating nodes.
    pub aux: PublicAuxInfos<P, Id>,
    /// The message to be signed.
    pub message: PrehashedMessage<P::Curve>,
}

impl<P: SchemeParams, Id: PartyId> InteractiveSigningAssociatedData<P, Id> {
    /// Creates the associated data for evidence verification of InteractiveSigning.
    pub fn new(
        message: PrehashedMessage<P::Curve>,
        public_key_shares: PublicKeyShares<P, Id>,
        public_aux_infos: PublicAuxInfos<P, Id>,
    ) -> Result<Self, LocalError> {
        let key_share_keys = public_key_shares.as_map().keys().collect::<BTreeSet<_>>();
        let aux_info_keys = public_aux_infos.as_map().keys().collect::<BTreeSet<_>>();

        if key_share_keys != aux_info_keys {
            return Err(LocalError::new(
                "The key share and the auxiliary info must have information for the same set of parties",
            ));
        }

        Ok(Self {
            shares: public_key_shares,
            aux: public_aux_infos,
            message,
        })
    }
}

fn make_epid<P: SchemeParams, Id: PartyId>(
    shared_randomness: &[u8],
    associated_data: &InteractiveSigningAssociatedData<P, Id>,
) -> Box<[u8]> {
    XofHasher::new_with_dst(b"InteractiveSigning EPID")
        .chain_type::<P::Curve>()
        .chain(&shared_randomness)
        .chain(&associated_data.shares)
        .chain(&associated_data.aux)
        .finalize_boxed(P::SECURITY_BITS)
}

impl<P: SchemeParams, Id: PartyId> ProtocolError<Id> for InteractiveSigningError<P, Id> {
    type AssociatedData = InteractiveSigningAssociatedData<P, Id>;

    fn required_messages(&self) -> RequiredMessages {
        match self.error {
            Error::R1EncElg0Failed => {
                RequiredMessages::new(RequiredMessageParts::echo_broadcast().and_direct_message(), None, None)
            }
            Error::R1EncElg1Failed => {
                RequiredMessages::new(RequiredMessageParts::echo_broadcast().and_direct_message(), None, None)
            }
            Error::R2WrongIdsD => RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None),
            Error::R2WrongIdsF => RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None),
            Error::R2WrongIdsPsi => RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None),
            Error::R2AffGPsiFailed { .. } => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast().and_normal_broadcast(),
                None,
                Some([1.into()].into()),
            ),
            Error::R2AffGHatPsiFailed { .. } => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast().and_normal_broadcast(),
                None,
                Some([1.into()].into()),
            ),
            Error::R2ElogFailed => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast().and_normal_broadcast(),
                Some([(1.into(), RequiredMessageParts::echo_broadcast())].into()),
                None,
            ),
            Error::R3ElogFailed => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast(),
                Some(
                    [
                        (1.into(), RequiredMessageParts::echo_broadcast()),
                        (2.into(), RequiredMessageParts::echo_broadcast()),
                    ]
                    .into(),
                ),
                None,
            ),
            Error::R4InvalidSignatureShare => RequiredMessages::new(
                RequiredMessageParts::normal_broadcast(),
                Some(
                    [
                        (2.into(), RequiredMessageParts::echo_broadcast()),
                        (3.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast()),
                    ]
                    .into(),
                ),
                Some([2.into(), 3.into()].into()),
            ),
            Error::R5DecFailed => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast(),
                Some(
                    [
                        (1.into(), RequiredMessageParts::echo_broadcast()),
                        (2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast()),
                        (3.into(), RequiredMessageParts::normal_broadcast()),
                    ]
                    .into(),
                ),
                Some([2.into()].into()),
            ),
            Error::R5WrongIdsPsi => RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None),
            Error::R5AffGStarFailed { .. } => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast(),
                Some([(2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast())].into()),
                Some([1.into(), 2.into()].into()),
            ),
            Error::R6DecFailed => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast(),
                Some(
                    [
                        (1.into(), RequiredMessageParts::echo_broadcast()),
                        (2.into(), RequiredMessageParts::echo_broadcast().and_normal_broadcast()),
                        (3.into(), RequiredMessageParts::normal_broadcast()),
                    ]
                    .into(),
                ),
                Some([2.into()].into()),
            ),
            Error::R6WrongIdsPsi => RequiredMessages::new(RequiredMessageParts::echo_broadcast(), None, None),
            Error::R6AffGStarFailed { .. } => RequiredMessages::new(
                RequiredMessageParts::echo_broadcast(),
                None,
                Some([1.into(), 2.into()].into()),
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
        let epid = make_epid::<P, Id>(shared_randomness, associated_data);

        match &self.error {
            Error::R1EncElg0Failed => {
                let r1_dm = message
                    .direct_message
                    .deserialize::<Round1DirectMessage<P>>(deserializer)?;
                let r1_eb = message
                    .echo_broadcast
                    .deserialize::<Round1EchoBroadcast<P>>(deserializer)?;

                let public_aux = &associated_data.aux.as_map().try_get("aux infos", guilty_party)?;
                let pk = public_aux.paillier_pk.clone().into_precomputed();
                let rp = public_aux.rp_params.to_precomputed();

                let aux = (&epid, guilty_party);

                verify_that(!r1_dm.psi0.verify(
                    EncElgPublicInputs {
                        pk0: &pk,
                        cap_c: &r1_eb.cap_k.to_precomputed(&pk),
                        cap_a: &r1_eb.cap_y,
                        cap_b: &r1_eb.cap_a1,
                        cap_x: &r1_eb.cap_a2,
                    },
                    &rp,
                    &aux,
                ))
            }
            Error::R1EncElg1Failed => {
                let r1_dm = message
                    .direct_message
                    .deserialize::<Round1DirectMessage<P>>(deserializer)?;
                let r1_eb = message
                    .echo_broadcast
                    .deserialize::<Round1EchoBroadcast<P>>(deserializer)?;

                let public_aux = &associated_data.aux.as_map().try_get("aux infos", guilty_party)?;
                let pk = public_aux.paillier_pk.clone().into_precomputed();
                let rp = public_aux.rp_params.to_precomputed();

                let aux = (&epid, guilty_party);

                verify_that(!r1_dm.psi1.verify(
                    EncElgPublicInputs {
                        pk0: &pk,
                        cap_c: &r1_eb.cap_g.to_precomputed(&pk),
                        cap_a: &r1_eb.cap_y,
                        cap_b: &r1_eb.cap_b1,
                        cap_x: &r1_eb.cap_b2,
                    },
                    &rp,
                    &aux,
                ))
            }
            Error::R2WrongIdsD => {
                let r2_nb = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                let expected_ids = associated_data
                    .aux
                    .as_map()
                    .keys()
                    .collect::<BTreeSet<_>>()
                    .without(&guilty_party);
                verify_that(r2_nb.cap_ds.keys().collect::<BTreeSet<_>>() != expected_ids)
            }
            Error::R2WrongIdsF => {
                let r2_eb = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let expected_ids = associated_data
                    .aux
                    .as_map()
                    .keys()
                    .collect::<BTreeSet<_>>()
                    .without(&guilty_party);
                verify_that(r2_eb.cap_fs.keys().collect::<BTreeSet<_>>() != expected_ids)
            }
            Error::R2WrongIdsPsi => {
                let r2_nb = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                let expected_ids = associated_data
                    .aux
                    .as_map()
                    .keys()
                    .collect::<BTreeSet<_>>()
                    .without(&guilty_party);
                verify_that(r2_nb.psis.keys().collect::<BTreeSet<_>>() != expected_ids)
            }
            Error::R2AffGPsiFailed { failed_for } => {
                let r1_eb = combined_echos
                    .get_round(1)?
                    .try_get("combined echos for Round 1", failed_for)?
                    .deserialize::<Round1EchoBroadcast<P>>(deserializer)?;
                let r2_eb = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r2_nb = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;

                let failed_for_aux = &associated_data.aux.as_map().try_get("aux infos", failed_for)?;
                let guilty_party_aux = &associated_data.aux.as_map().try_get("aux infos", guilty_party)?;

                let rp = failed_for_aux.rp_params.to_precomputed();
                let aux = (&epid, guilty_party);

                let for_pk = failed_for_aux.paillier_pk.clone().into_precomputed();
                let from_pk = guilty_party_aux.paillier_pk.clone().into_precomputed();

                let cap_k = r1_eb.cap_k.to_precomputed(&for_pk);
                let cap_d = r2_nb.cap_ds.safe_get("`D` map", failed_for)?.to_precomputed(&for_pk);
                let cap_f = r2_eb.cap_fs.safe_get("`F` map", failed_for)?.to_precomputed(&from_pk);

                let psi = r2_nb.psis.try_get("`psi` map", failed_for)?;
                verify_that(!psi.verify(
                    AffGPublicInputs {
                        pk0: &for_pk,
                        pk1: &from_pk,
                        cap_c: &cap_k,
                        cap_d: &cap_d,
                        cap_y: &cap_f,
                        cap_x: &r2_eb.cap_gamma,
                    },
                    &rp,
                    &aux,
                ))
            }
            Error::R2AffGHatPsiFailed { failed_for } => {
                let r1_eb = combined_echos
                    .get_round(1)?
                    .try_get("combined echos for Round 1", failed_for)?
                    .deserialize::<Round1EchoBroadcast<P>>(deserializer)?;
                let r2_eb = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r2_nb = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;

                let cap_x = associated_data.shares.as_map().try_get("shares", failed_for)?;

                let failed_for_aux = &associated_data.aux.as_map().try_get("aux infos", failed_for)?;
                let guilty_party_aux = &associated_data.aux.as_map().try_get("aux infos", guilty_party)?;

                let rp = failed_for_aux.rp_params.to_precomputed();
                let aux = (&epid, guilty_party);

                let for_pk = failed_for_aux.paillier_pk.clone().into_precomputed();
                let from_pk = guilty_party_aux.paillier_pk.clone().into_precomputed();

                let cap_k = r1_eb.cap_k.to_precomputed(&for_pk);
                let hat_cap_d = r2_nb
                    .hat_cap_ds
                    .safe_get("`\\hat{D}` map", failed_for)?
                    .to_precomputed(&for_pk);
                let hat_cap_f = r2_eb
                    .hat_cap_fs
                    .safe_get("`\\hat{F}` map", failed_for)?
                    .to_precomputed(&from_pk);

                let hat_psi = r2_nb.hat_psis.try_get("`\\hat{psi}` map", failed_for)?;
                verify_that(!hat_psi.verify(
                    AffGPublicInputs {
                        pk0: &for_pk,
                        pk1: &from_pk,
                        cap_c: &cap_k,
                        cap_d: &hat_cap_d,
                        cap_y: &hat_cap_f,
                        cap_x,
                    },
                    &rp,
                    &aux,
                ))
            }
            Error::R2ElogFailed => {
                let r1_eb = previous_messages
                    .get_round(1)?
                    .echo_broadcast
                    .deserialize::<Round1EchoBroadcast<P>>(deserializer)?;
                let r2_nb = message
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                let r2_eb = message
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let aux = (&epid, guilty_party);

                verify_that(!r2_nb.psi_elog.verify(
                    ElogPublicInputs {
                        cap_l: &r1_eb.cap_b1,
                        cap_m: &r1_eb.cap_b2,
                        cap_x: &r1_eb.cap_y,
                        cap_y: &r2_eb.cap_gamma,
                        h: &Point::generator(),
                    },
                    &aux,
                ))
            }
            Error::R3ElogFailed => {
                let r1_eb = previous_messages
                    .get_round(1)?
                    .echo_broadcast
                    .deserialize::<Round1EchoBroadcast<P>>(deserializer)?;
                let r2_eb = previous_messages
                    .get_round(2)?
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r3_nb = message
                    .normal_broadcast
                    .deserialize::<Round3NormalBroadcast<P>>(deserializer)?;
                let aux = (&epid, guilty_party);

                verify_that(!r3_nb.psi_prime.verify(
                    ElogPublicInputs {
                        cap_l: &r1_eb.cap_a1,
                        cap_m: &r1_eb.cap_a2,
                        cap_x: &r1_eb.cap_y,
                        cap_y: &r3_nb.cap_delta,
                        h: &r2_eb.cap_gamma,
                    },
                    &aux,
                ))
            }
            Error::R4InvalidSignatureShare => {
                let r2_ebs = combined_echos
                    .get_round(2)?
                    .deserialize_all::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r2_eb = previous_messages
                    .get_round(2)?
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r3_nb = previous_messages
                    .get_round(3)?
                    .normal_broadcast
                    .deserialize::<Round3NormalBroadcast<P>>(deserializer)?;
                let r3_ebs = combined_echos
                    .get_round(3)?
                    .deserialize_all::<Round3EchoBroadcast<P>>(deserializer)?;
                let r3_eb = previous_messages
                    .get_round(3)?
                    .echo_broadcast
                    .deserialize::<Round3EchoBroadcast<P>>(deserializer)?;
                let r4_nb = message
                    .normal_broadcast
                    .deserialize::<Round4NormalBroadcast<P>>(deserializer)?;

                let cap_gamma = r2_eb.cap_gamma + r2_ebs.values().map(|eb| eb.cap_gamma).sum();
                let nonce = cap_gamma.x_coordinate();
                let delta = r3_eb.delta + r3_ebs.values().map(|eb| eb.delta).sum::<Scalar<P>>();
                let delta_inv = Option::<Scalar<P>>::from(delta.invert())
                    .ok_or_else(|| ProtocolValidationError::InvalidEvidence("`delta` is not invertible".into()))?;
                let tilde_cap_delta = r3_nb.cap_delta * delta_inv;
                let tilde_cap_s = r3_nb.cap_s * delta_inv;
                let scalar_message = Scalar::from_reduced_bytes(associated_data.message.clone());

                verify_that(cap_gamma * r4_nb.sigma != tilde_cap_delta * scalar_message + tilde_cap_s * nonce)
            }
            Error::R5DecFailed => {
                let r1_eb = previous_messages
                    .get_round(1)?
                    .echo_broadcast
                    .deserialize::<Round1EchoBroadcast<P>>(deserializer)?;
                let r2_ebs = combined_echos
                    .get_round(2)?
                    .deserialize_all::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r2_nb = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                let r2_eb = previous_messages
                    .get_round(2)?
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r3_nb = previous_messages
                    .get_round(3)?
                    .normal_broadcast
                    .deserialize::<Round3NormalBroadcast<P>>(deserializer)?;
                let r5_eb = message
                    .echo_broadcast
                    .deserialize::<Round5EchoBroadcast<P, Id>>(deserializer)?;

                // Calculate `D_j` where `j = guilty_party`.
                // `D_j = sum_{l != j}(D_{l,j} + F_{j,l})
                //
                // r2_eb: contains D_{l,j}, F_{l,j} for l != j
                // => D_{l,j} = r2_eb.cap_ds[l]
                // r2_ebs[i], i != j: contains D_{l,i}, F_{l,i} for l != i
                // => F_{j,l} = r2_ebs[l].cap_fs[j]

                let public_aux = &associated_data.aux.as_map().try_get("aux infos", guilty_party)?;
                let pk = public_aux.paillier_pk.clone().into_precomputed();
                let rp = public_aux.rp_params.to_precomputed();
                let aux = (&epid, guilty_party);

                let ids = associated_data
                    .aux
                    .as_map()
                    .keys()
                    .collect::<BTreeSet<_>>()
                    .without(&guilty_party);

                let cap_d = sum_non_empty(
                    ids.iter()
                        .map(|id| Ok(r2_nb.cap_ds.try_get("`D` map", id)?.to_precomputed(&pk))),
                    ProtocolValidationError::InvalidEvidence("There must be at least two parties".into()),
                )? + sum_non_empty(
                    ids.iter().map(|id| {
                        Ok(r2_ebs
                            .try_get("Round 2 echo broadcasts", id)?
                            .cap_fs
                            .try_get("`F` map", guilty_party)?
                            .to_precomputed(&pk))
                    }),
                    ProtocolValidationError::InvalidEvidence("There must be at least two parties".into()),
                )?;

                let cap_k = r1_eb.cap_k.to_precomputed(&pk);

                verify_that(!r5_eb.psi_star.verify(
                    DecPublicInputs {
                        pk0: &pk,
                        cap_k: &cap_k,
                        cap_x: &r2_eb.cap_gamma,
                        cap_d: &cap_d,
                        cap_s: &r3_nb.cap_delta,
                        cap_g: &Point::generator(),
                        num_parties: associated_data.aux.num_parties(),
                    },
                    &rp,
                    &aux,
                ))
            }
            Error::R5WrongIdsPsi => {
                // TODO (#188): currently unreachable from tests
                let r5_nb = message
                    .normal_broadcast
                    .deserialize::<Round5EchoBroadcast<P, Id>>(deserializer)?;
                let expected_ids = associated_data
                    .aux
                    .as_map()
                    .keys()
                    .collect::<BTreeSet<_>>()
                    .without(&guilty_party);
                verify_that(r5_nb.psis.keys().collect::<BTreeSet<_>>() != expected_ids)
            }
            Error::R5AffGStarFailed { failed_for } => {
                // TODO (#188): currently unreachable from tests
                let r1_ebs = combined_echos
                    .get_round(1)?
                    .deserialize_all::<Round1EchoBroadcast<P>>(deserializer)?;
                let r2_ebs = combined_echos
                    .get_round(2)?
                    .deserialize_all::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r2_nb = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                let r2_eb = previous_messages
                    .get_round(2)?
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r5_eb = message
                    .echo_broadcast
                    .deserialize::<Round5EchoBroadcast<P, Id>>(deserializer)?;

                let failed_for_aux = &associated_data.aux.as_map().try_get("aux infos", failed_for)?;
                let guilty_party_aux = &associated_data.aux.as_map().try_get("aux infos", guilty_party)?;

                let failed_for_pk = failed_for_aux.paillier_pk.clone().into_precomputed();

                let guilty_party_pk = guilty_party_aux.paillier_pk.clone().into_precomputed();
                let aux = (&epid, guilty_party);

                // l = failed_for
                // j = guilty_party
                // i = reported_by

                let cap_d = r2_nb
                    .cap_ds
                    .try_get("`D` map", failed_for)?
                    .to_precomputed(&failed_for_pk);
                let cap_k = r1_ebs
                    .try_get("Round 1 echo broadcasts", failed_for)?
                    .cap_k
                    .to_precomputed(&failed_for_pk);
                let cap_f = r2_ebs
                    .try_get("Round 2 echo broadcasts", failed_for)?
                    .cap_fs
                    .try_get("`F` map", guilty_party)?
                    .to_precomputed(&guilty_party_pk);

                let psi = r5_eb.psis.try_get("`\\{psi}` map", failed_for)?;

                verify_that(!psi.verify(
                    AffGStarPublicInputs {
                        pk0: &guilty_party_pk,
                        pk1: &failed_for_pk,
                        cap_c: &cap_d,
                        cap_d: &cap_k,
                        cap_y: &cap_f,
                        cap_x: &r2_eb.cap_gamma,
                    },
                    &aux,
                ))
            }
            Error::R6DecFailed => {
                let r1_eb = previous_messages
                    .get_round(1)?
                    .echo_broadcast
                    .deserialize::<Round1EchoBroadcast<P>>(deserializer)?;
                let r2_ebs = combined_echos
                    .get_round(2)?
                    .deserialize_all::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r2_nb = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                let r2_eb = previous_messages
                    .get_round(2)?
                    .echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r3_nb = previous_messages
                    .get_round(3)?
                    .normal_broadcast
                    .deserialize::<Round3NormalBroadcast<P>>(deserializer)?;
                let r5_eb = message
                    .echo_broadcast
                    .deserialize::<Round5EchoBroadcast<P, Id>>(deserializer)?;

                // Calculate `\hat{D}_j` where `j = guilty_party`.
                // `\hat{D}_j = sum_{l != j}(\hat{D}_{l,j} + \hat{F}_{j,l})
                //
                // r2_eb: contains \hat{D}_{l,j}, \hat{F}_{l,j} for l != j
                // => \hat{D}_{l,j} = r2_eb.hat_cap_ds[l]
                // r2_ebs[i], i != j: contains \hat{D}_{l,i}, \hat{F}_{l,i} for l != i
                // => \hat{F}_{j,l} = r2_ebs[l].hat_cap_fs[j]

                let public_aux = &associated_data.aux.as_map().try_get("aux infos", guilty_party)?;
                let pk = public_aux.paillier_pk.clone().into_precomputed();
                let rp = public_aux.rp_params.to_precomputed();
                let aux = (&epid, guilty_party);

                let ids = associated_data
                    .aux
                    .as_map()
                    .keys()
                    .collect::<BTreeSet<_>>()
                    .without(&guilty_party);

                let hat_cap_d = sum_non_empty(
                    ids.iter()
                        .map(|id| Ok(r2_nb.hat_cap_ds.try_get("`\\hat{D}` map", id)?.to_precomputed(&pk))),
                    ProtocolValidationError::InvalidEvidence("There must be at least two parties".into()),
                )? + sum_non_empty(
                    ids.iter().map(|id| {
                        Ok(r2_ebs
                            .try_get("Round 2 echo broadcasts", id)?
                            .hat_cap_fs
                            .try_get("`\\hat{F}` map", guilty_party)?
                            .to_precomputed(&pk))
                    }),
                    ProtocolValidationError::InvalidEvidence("There must be at least two parties".into()),
                )?;

                let cap_k = r1_eb.cap_k.to_precomputed(&pk);

                let total_cap_gamma = r2_eb.cap_gamma + r2_ebs.values().map(|eb| eb.cap_gamma).sum();

                let cap_x = associated_data.shares.as_map().try_get("`X` map", guilty_party)?;

                verify_that(!r5_eb.psi_star.verify(
                    DecPublicInputs {
                        pk0: &pk,
                        cap_k: &cap_k,
                        cap_x,
                        cap_d: &hat_cap_d,
                        cap_s: &r3_nb.cap_s,
                        cap_g: &total_cap_gamma,
                        num_parties: associated_data.aux.num_parties(),
                    },
                    &rp,
                    &aux,
                ))
            }
            Error::R6WrongIdsPsi => {
                // TODO (#188): currently unreachable from tests
                let r6_nb = message
                    .normal_broadcast
                    .deserialize::<Round6EchoBroadcast<P, Id>>(deserializer)?;
                let expected_ids = associated_data
                    .aux
                    .as_map()
                    .keys()
                    .collect::<BTreeSet<_>>()
                    .without(&guilty_party);
                verify_that(r6_nb.hat_psis.keys().collect::<BTreeSet<_>>() != expected_ids)
            }
            Error::R6AffGStarFailed { failed_for } => {
                // TODO (#188): currently unreachable from tests
                let r1_ebs = combined_echos
                    .get_round(1)?
                    .deserialize_all::<Round1EchoBroadcast<P>>(deserializer)?;
                let r2_ebs = combined_echos
                    .get_round(2)?
                    .deserialize_all::<Round2EchoBroadcast<P, Id>>(deserializer)?;
                let r2_nb = previous_messages
                    .get_round(2)?
                    .normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
                let r6_eb = message
                    .echo_broadcast
                    .deserialize::<Round6EchoBroadcast<P, Id>>(deserializer)?;

                let failed_for_aux = &associated_data.aux.as_map().try_get("aux infos", failed_for)?;
                let guilty_party_aux = &associated_data.aux.as_map().try_get("aux infos", guilty_party)?;

                let failed_for_pk = failed_for_aux.paillier_pk.clone().into_precomputed();

                let guilty_party_pk = guilty_party_aux.paillier_pk.clone().into_precomputed();
                let aux = (&epid, guilty_party);

                let cap_x = associated_data.shares.as_map().try_get("shares", failed_for)?;

                // l = failed_for
                // j = guilty_party
                // i = reported_by

                let hat_cap_d = r2_nb
                    .hat_cap_ds
                    .try_get("`\\hat{D}` map", failed_for)?
                    .to_precomputed(&failed_for_pk);
                let cap_k = r1_ebs
                    .try_get("Round 1 echo broadcasts", failed_for)?
                    .cap_k
                    .to_precomputed(&failed_for_pk);
                let hat_cap_f = r2_ebs
                    .try_get("Round 2 echo broadcasts", failed_for)?
                    .hat_cap_fs
                    .try_get("`\\hat{F}` map", guilty_party)?
                    .to_precomputed(&guilty_party_pk);

                let hat_psi = r6_eb.hat_psis.try_get("`\\hat{\\psi}` map", failed_for)?;

                verify_that(!hat_psi.verify(
                    AffGStarPublicInputs {
                        pk0: &guilty_party_pk,
                        pk1: &failed_for_pk,
                        cap_c: &hat_cap_d,
                        cap_d: &cap_k,
                        cap_y: &hat_cap_f,
                        cap_x,
                    },
                    &aux,
                ))
            }
        }
    }
}

/// An entry point for the [`InteractiveSigningProtocol`].
#[derive(Debug, Clone)]
pub struct InteractiveSigning<P, Id>
where
    P: SchemeParams,
    Id: PartyId,
{
    key_share: KeyShare<P, Id>,
    aux_info: AuxInfo<P, Id>,
    message: PrehashedMessage<P::Curve>,
}

impl<P: SchemeParams, Id: PartyId> InteractiveSigning<P, Id> {
    /// Creates a new entry point given a share of the secret key.
    pub fn new(
        message: PrehashedMessage<P::Curve>,
        key_share: KeyShare<P, Id>,
        aux_info: AuxInfo<P, Id>,
    ) -> Result<Self, LocalError> {
        if key_share.owner() != aux_info.owner() {
            return Err(LocalError::new(
                "The key share and the auxiliary info must have secret parts belonging to the same party",
            ));
        }

        let key_share_keys = key_share.public_shares().keys().collect::<BTreeSet<_>>();
        let aux_info_keys = aux_info.public().as_map().keys().collect::<BTreeSet<_>>();

        if key_share_keys != aux_info_keys {
            tracing::info!("{:?}", key_share_keys);
            tracing::info!("{:?}", aux_info_keys);
            return Err(LocalError::new(
                "The key share and the auxiliary info must have information for the same set of parties",
            ));
        }

        Ok(Self {
            key_share,
            aux_info,
            message,
        })
    }
}

impl<P: SchemeParams, Id: PartyId> EntryPoint<Id> for InteractiveSigning<P, Id> {
    type Protocol = InteractiveSigningProtocol<P, Id>;

    fn entry_round_id() -> RoundId {
        1.into()
    }

    fn make_round(
        self,
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError> {
        let key_share = self.key_share;
        let aux_info = self.aux_info;

        if id != key_share.owner() || id != aux_info.owner() {
            return Err(LocalError::new(
                "ID mismatch between the signer, the key share and the aux info",
            ));
        }

        let all_ids = key_share.public_shares().keys().cloned().collect::<BTreeSet<_>>();
        let other_ids = all_ids.clone().without(id);

        let epid = make_epid::<P, Id>(
            shared_randomness,
            &InteractiveSigningAssociatedData {
                shares: key_share.public().clone(),
                aux: aux_info.public().clone(),
                message: self.message.clone(),
            },
        );

        let aux_info = aux_info.into_precomputed();

        // The share of an ephemeral scalar
        let k = Secret::init_with(|| Scalar::random(rng));
        // The share of the mask used to generate the inverse of the ephemeral scalar
        let gamma = Secret::init_with(|| Scalar::random(rng));

        let pk = aux_info.secret_aux.paillier_sk.public_key();

        let nu = Randomizer::<P::Paillier>::random(rng, pk);
        let cap_g = Ciphertext::new_with_randomizer(pk, &secret_signed_from_scalar::<P>(&gamma), &nu);

        let rho = Randomizer::<P::Paillier>::random(rng, pk);
        let cap_k = Ciphertext::new_with_randomizer(pk, &secret_signed_from_scalar::<P>(&k), &rho);

        let y = Secret::init_with(|| Scalar::random(rng));
        let cap_y = y.mul_by_generator();

        let a = Secret::init_with(|| Scalar::random(rng));
        let b = Secret::init_with(|| Scalar::random(rng));
        let cap_a1 = a.mul_by_generator();
        let cap_a2 = cap_y * &a + k.mul_by_generator();
        let cap_b1 = b.mul_by_generator();
        let cap_b2 = cap_y * &b + gamma.mul_by_generator();

        let r1_echo_broadcast = Round1EchoBroadcast {
            cap_k: cap_k.to_wire(),
            cap_g: cap_g.to_wire(),
            cap_y,
            cap_a1,
            cap_a2,
            cap_b1,
            cap_b2,
        };

        Ok(BoxedRound::new_dynamic(Round1 {
            context: Context {
                scalar_message: Scalar::from_reduced_bytes(self.message),
                epid,
                my_id: id.clone(),
                other_ids,
                all_ids,
                key_share,
                aux_info,
                k,
                gamma,
                a,
                b,
                rho,
                nu,
            },
            r1_echo_broadcast,
        }))
    }
}

#[derive(Debug)]
pub(super) struct Context<P, Id>
where
    P: SchemeParams,
    Id: PartyId,
{
    scalar_message: Scalar<P>,
    pub(super) epid: Box<[u8]>,
    pub(super) my_id: Id,
    other_ids: BTreeSet<Id>,
    all_ids: BTreeSet<Id>,
    key_share: KeyShare<P, Id>,
    pub(super) aux_info: AuxInfoPrecomputed<P, Id>,
    k: Secret<Scalar<P>>,
    pub(super) gamma: Secret<Scalar<P>>,
    a: Secret<Scalar<P>>,
    pub(super) b: Secret<Scalar<P>>,
    rho: Randomizer<P::Paillier>,
    nu: Randomizer<P::Paillier>,
}

impl<P, Id> Context<P, Id>
where
    P: SchemeParams,
    Id: PartyId,
{
    pub fn public_share(&self, i: &Id) -> Result<&Point<P>, LocalError> {
        self.key_share.public_shares().safe_get("public share", i)
    }

    pub fn public_aux(&self, i: &Id) -> Result<&PublicAuxInfoPrecomputed<P>, LocalError> {
        self.aux_info.public_aux.safe_get("public aux", i)
    }
}

#[derive(Debug)]
struct Round1<P, Id>
where
    P: SchemeParams,
    Id: PartyId,
{
    context: Context<P, Id>,
    r1_echo_broadcast: Round1EchoBroadcast<P>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "CiphertextWire<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "CiphertextWire<P::Paillier>: for<'x> Deserialize<'x>"))]
pub(super) struct Round1EchoBroadcast<P: SchemeParams> {
    pub(super) cap_k: CiphertextWire<P::Paillier>,
    pub(super) cap_g: CiphertextWire<P::Paillier>,
    pub(super) cap_y: Point<P>,
    pub(super) cap_a1: Point<P>,
    pub(super) cap_a2: Point<P>,
    pub(super) cap_b1: Point<P>,
    pub(super) cap_b2: Point<P>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "EncElgProof<P>: Serialize"))]
#[serde(bound(deserialize = "EncElgProof<P>: for<'x> Deserialize<'x>"))]
struct Round1DirectMessage<P: SchemeParams> {
    psi0: EncElgProof<P>,
    psi1: EncElgProof<P>,
}

#[derive(Debug)]
pub(super) struct Round1Payload<P: SchemeParams> {
    pub(super) cap_k: Ciphertext<P::Paillier>,
    cap_y: Point<P>,
    cap_a1: Point<P>,
    cap_a2: Point<P>,
    cap_b1: Point<P>,
    cap_b2: Point<P>,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round1<P, Id> {
    type Protocol = InteractiveSigningProtocol<P, Id>;

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
        EchoBroadcast::new(serializer, self.r1_echo_broadcast.clone())
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
        destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let aux = (&self.context.epid, &self.context.my_id);
        let pk = self.context.aux_info.secret_aux.paillier_sk.public_key();

        let psi0 = EncElgProof::new(
            rng,
            EncElgSecretInputs {
                x: &secret_signed_from_scalar::<P>(&self.context.k),
                rho: &self.context.rho,
                // Note that the paper does not mention `y` (Elgamal secret) as an input,
                // but it is required according to the definition of enc-elg protocol.
                b: &self.context.a,
            },
            EncElgPublicInputs {
                pk0: pk,
                cap_c: &self.r1_echo_broadcast.cap_k.to_precomputed(pk),
                cap_a: &self.r1_echo_broadcast.cap_y,
                cap_b: &self.r1_echo_broadcast.cap_a1,
                cap_x: &self.r1_echo_broadcast.cap_a2,
            },
            &self
                .context
                .aux_info
                .public_aux
                .safe_get("public aux", destination)?
                .rp_params,
            &aux,
        );

        let psi1 = EncElgProof::new(
            rng,
            EncElgSecretInputs {
                x: &secret_signed_from_scalar::<P>(&self.context.gamma),
                rho: &self.context.nu,
                b: &self.context.b,
            },
            EncElgPublicInputs {
                pk0: pk,
                cap_c: &self.r1_echo_broadcast.cap_g.to_precomputed(pk),
                cap_a: &self.r1_echo_broadcast.cap_y,
                cap_b: &self.r1_echo_broadcast.cap_b1,
                cap_x: &self.r1_echo_broadcast.cap_b2,
            },
            &self
                .context
                .aux_info
                .public_aux
                .safe_get("public aux", destination)?
                .rp_params,
            &aux,
        );

        Ok((
            DirectMessage::new(serializer, Round1DirectMessage::<P> { psi0, psi1 })?,
            None,
        ))
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        message.normal_broadcast.assert_is_none()?;

        let direct_message = message
            .direct_message
            .deserialize::<Round1DirectMessage<P>>(deserializer)?;
        let echo_broadcast = message
            .echo_broadcast
            .deserialize::<Round1EchoBroadcast<P>>(deserializer)?;

        let aux = (&self.context.epid, from);

        let public_aux = self.context.public_aux(&self.context.my_id)?;

        let from_pk = &self.context.public_aux(from)?.paillier_pk;

        let cap_k = echo_broadcast.cap_k.to_precomputed(from_pk);
        let cap_g = echo_broadcast.cap_g.to_precomputed(from_pk);

        if !direct_message.psi0.verify(
            EncElgPublicInputs {
                pk0: from_pk,
                cap_c: &cap_k,
                cap_a: &echo_broadcast.cap_y,
                cap_b: &echo_broadcast.cap_a1,
                cap_x: &echo_broadcast.cap_a2,
            },
            &public_aux.rp_params,
            &aux,
        ) {
            return Err(ReceiveError::protocol(Error::R1EncElg0Failed.into()));
        }

        if !direct_message.psi1.verify(
            EncElgPublicInputs {
                pk0: from_pk,
                cap_c: &cap_g,
                cap_a: &echo_broadcast.cap_y,
                cap_b: &echo_broadcast.cap_b1,
                cap_x: &echo_broadcast.cap_b2,
            },
            &public_aux.rp_params,
            &aux,
        ) {
            return Err(ReceiveError::protocol(Error::R1EncElg1Failed.into()));
        }

        Ok(Payload::new(Round1Payload::<P> {
            cap_k,
            cap_a1: echo_broadcast.cap_a1,
            cap_a2: echo_broadcast.cap_a2,
            cap_b1: echo_broadcast.cap_b1,
            cap_b2: echo_broadcast.cap_b2,
            cap_y: echo_broadcast.cap_y,
        }))
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let mut payloads = payloads.downcast_all::<Round1Payload<P>>()?;

        let pk = self.context.aux_info.secret_aux.paillier_sk.public_key();
        let my_payload = Round1Payload {
            cap_k: self.r1_echo_broadcast.cap_k.to_precomputed(pk),
            cap_a1: self.r1_echo_broadcast.cap_a1,
            cap_a2: self.r1_echo_broadcast.cap_a2,
            cap_b1: self.r1_echo_broadcast.cap_b1,
            cap_b2: self.r1_echo_broadcast.cap_b2,
            cap_y: self.r1_echo_broadcast.cap_y,
        };
        payloads.insert(self.context.my_id.clone(), my_payload);

        let cap_gamma = self.context.gamma.mul_by_generator();

        let aux = (&self.context.epid, &self.context.my_id);
        let psi_elog = ElogProof::new(
            rng,
            ElogSecretInputs {
                y: &self.context.gamma,
                lambda: &self.context.b,
            },
            // Note that the parameter order in the protocol description and in the ZK proof description do not match.
            ElogPublicInputs {
                cap_l: &self.r1_echo_broadcast.cap_b1,
                cap_m: &self.r1_echo_broadcast.cap_b2,
                cap_x: &self.r1_echo_broadcast.cap_y,
                cap_y: &cap_gamma,
                h: &Point::generator(),
            },
            &aux,
        );

        let cap_k = self.r1_echo_broadcast.cap_k.to_precomputed(pk);

        let betas = self
            .context
            .other_ids
            .iter()
            .map(|id| (id.clone(), SecretSigned::random_in_exponent_range(rng, P::LP_BOUND)))
            .collect::<BTreeMap<_, _>>();
        let rs = self
            .context
            .other_ids
            .iter()
            .map(|id| (id.clone(), Randomizer::random(rng, pk)))
            .collect::<BTreeMap<_, _>>();
        let mut ss = BTreeMap::new();
        for id in self.context.other_ids.iter() {
            let target_pk = &self.context.public_aux(id)?.paillier_pk;
            let s = Randomizer::random(rng, target_pk);
            ss.insert(id.clone(), s);
        }

        let hat_betas = self
            .context
            .other_ids
            .iter()
            .map(|id| (id.clone(), SecretSigned::random_in_exponent_range(rng, P::LP_BOUND)))
            .collect::<BTreeMap<_, _>>();
        let hat_rs = self
            .context
            .other_ids
            .iter()
            .map(|id| (id.clone(), Randomizer::random(rng, pk)))
            .collect::<BTreeMap<_, _>>();
        let mut hat_ss = BTreeMap::new();
        for id in self.context.other_ids.iter() {
            let target_pk = &self.context.public_aux(id)?.paillier_pk;
            let hat_s = Randomizer::random(rng, target_pk);
            hat_ss.insert(id.clone(), hat_s);
        }

        let gamma = secret_signed_from_scalar::<P>(&self.context.gamma);
        let x = secret_signed_from_scalar::<P>(self.context.key_share.secret_share());
        let cap_x = self.context.public_share(&self.context.my_id)?;

        let aux = (&self.context.epid, &self.context.my_id);
        let pk = self.context.aux_info.secret_aux.paillier_sk.public_key();

        let mut cap_ds = BTreeMap::new();
        let mut cap_fs = BTreeMap::new();
        let mut psis = BTreeMap::new();

        let mut hat_cap_ds = BTreeMap::new();
        let mut hat_cap_fs = BTreeMap::new();
        let mut hat_psis = BTreeMap::new();

        for id in self.context.other_ids.iter() {
            let rp = &self.context.public_aux(id)?.rp_params;
            let r1_payload = payloads.safe_get("Round 1 payloads", id)?;
            let target_pk = &self.context.public_aux(id)?.paillier_pk;

            let beta = betas.safe_get("`beta` map", id)?;
            let r = rs.safe_get("`r` map", id)?;
            let s = ss.safe_get("`s` map", id)?;

            let cap_f = Ciphertext::new_with_randomizer(pk, beta, r);
            let cap_d = &r1_payload.cap_k * &gamma + Ciphertext::new_with_randomizer(target_pk, &-beta, s);
            let psi = AffGProof::<P>::new(
                rng,
                AffGSecretInputs {
                    x: &gamma,
                    y: beta,
                    rho: s,
                    rho_y: r,
                },
                AffGPublicInputs {
                    pk0: target_pk,
                    pk1: pk,
                    cap_c: &r1_payload.cap_k,
                    cap_d: &cap_d,
                    cap_y: &cap_f,
                    cap_x: &cap_gamma,
                },
                rp,
                &aux,
            );

            let hat_beta = hat_betas.safe_get("`\\hat{beta}` map", id)?;
            let hat_r = hat_rs.safe_get("`\\hat{r}` map", id)?;
            let hat_s = hat_ss.safe_get("`\\hat{s}` map", id)?;

            let hat_cap_f = Ciphertext::new_with_randomizer(pk, hat_beta, hat_r);
            let hat_cap_d = &r1_payload.cap_k * &x + Ciphertext::new_with_randomizer(target_pk, &-hat_beta, hat_s);
            let hat_psi = AffGProof::new(
                rng,
                AffGSecretInputs {
                    x: &x,
                    y: hat_beta,
                    rho: hat_s,
                    rho_y: hat_r,
                },
                AffGPublicInputs {
                    pk0: target_pk,
                    pk1: pk,
                    cap_c: &r1_payload.cap_k,
                    cap_d: &hat_cap_d,
                    cap_y: &hat_cap_f,
                    cap_x,
                },
                rp,
                &aux,
            );

            cap_ds.insert(id.clone(), cap_d);
            cap_fs.insert(id.clone(), cap_f);
            psis.insert(id.clone(), psi);

            hat_cap_ds.insert(id.clone(), hat_cap_d);
            hat_cap_fs.insert(id.clone(), hat_cap_f);
            hat_psis.insert(id.clone(), hat_psi);
        }

        let next_round = Round2 {
            context: self.context,
            betas,
            rs,
            ss,
            hat_betas,
            hat_rs,
            hat_ss,
            r1_payloads: payloads,
            cap_k,
            cap_gamma,
            psi_elog,
            cap_ds,
            cap_fs,
            psis,
            hat_cap_ds,
            hat_cap_fs,
            hat_psis,
        };

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(next_round)))
    }
}

#[derive(Debug)]
pub(super) struct Round2<P: SchemeParams, Id: PartyId> {
    pub(super) context: Context<P, Id>,
    betas: BTreeMap<Id, SecretSigned<<P::Paillier as PaillierParams>::Uint>>,
    rs: BTreeMap<Id, Randomizer<P::Paillier>>,
    ss: BTreeMap<Id, Randomizer<P::Paillier>>,
    hat_betas: BTreeMap<Id, SecretSigned<<P::Paillier as PaillierParams>::Uint>>,
    hat_rs: BTreeMap<Id, Randomizer<P::Paillier>>,
    hat_ss: BTreeMap<Id, Randomizer<P::Paillier>>,
    r1_payloads: BTreeMap<Id, Round1Payload<P>>,
    cap_k: Ciphertext<P::Paillier>,
    pub(super) cap_gamma: Point<P>,
    psi_elog: ElogProof<P>,
    cap_ds: BTreeMap<Id, Ciphertext<P::Paillier>>,
    cap_fs: BTreeMap<Id, Ciphertext<P::Paillier>>,
    psis: BTreeMap<Id, AffGProof<P>>,
    hat_cap_ds: BTreeMap<Id, Ciphertext<P::Paillier>>,
    hat_cap_fs: BTreeMap<Id, Ciphertext<P::Paillier>>,
    hat_psis: BTreeMap<Id, AffGProof<P>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    ElogProof<P>: Serialize,
    AffGProof<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    ElogProof<P>: for<'x> Deserialize<'x>,
    AffGProof<P>: for<'x> Deserialize<'x>,
"))]
pub(super) struct Round2NormalBroadcast<P: SchemeParams, Id: PartyId> {
    pub(super) cap_ds: BTreeMap<Id, CiphertextWire<P::Paillier>>,
    pub(super) hat_cap_ds: BTreeMap<Id, CiphertextWire<P::Paillier>>,
    pub(super) psi_elog: ElogProof<P>,
    pub(super) psis: BTreeMap<Id, AffGProof<P>>,
    pub(super) hat_psis: BTreeMap<Id, AffGProof<P>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    CiphertextWire<P::Paillier>: Serialize,
"))]
#[serde(bound(deserialize = "
    CiphertextWire<P::Paillier>: for<'x> Deserialize<'x>,
"))]
pub(super) struct Round2EchoBroadcast<P: SchemeParams, Id: PartyId> {
    pub(super) cap_gamma: Point<P>,
    pub(super) cap_fs: BTreeMap<Id, CiphertextWire<P::Paillier>>,
    pub(super) hat_cap_fs: BTreeMap<Id, CiphertextWire<P::Paillier>>,
}

struct Round2Payload<P: SchemeParams, Id: PartyId> {
    cap_gamma: Point<P>,
    alpha: Secret<Scalar<P>>,
    hat_alpha: Secret<Scalar<P>>,
    cap_ds: BTreeMap<Id, Ciphertext<P::Paillier>>,
    cap_fs: BTreeMap<Id, Ciphertext<P::Paillier>>,
    hat_cap_ds: BTreeMap<Id, Ciphertext<P::Paillier>>,
    hat_cap_fs: BTreeMap<Id, Ciphertext<P::Paillier>>,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round2<P, Id> {
    type Protocol = InteractiveSigningProtocol<P, Id>;

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
        NormalBroadcast::new(
            serializer,
            Round2NormalBroadcast::<P, Id> {
                cap_ds: self.cap_ds.map_values_ref(|cap_d| cap_d.to_wire()),
                hat_cap_ds: self.hat_cap_ds.map_values_ref(|hat_cap_d| hat_cap_d.to_wire()),
                psi_elog: self.psi_elog.clone(),
                psis: self.psis.clone(),
                hat_psis: self.hat_psis.clone(),
            },
        )
    }

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        EchoBroadcast::new(
            serializer,
            Round2EchoBroadcast::<P, Id> {
                cap_gamma: self.cap_gamma,
                cap_fs: self.cap_fs.map_values_ref(|cap_f| cap_f.to_wire()),
                hat_cap_fs: self.hat_cap_fs.map_values_ref(|hat_cap_f| hat_cap_f.to_wire()),
            },
        )
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        let echo_broadcast = message
            .echo_broadcast
            .deserialize::<Round2EchoBroadcast<P, Id>>(deserializer)?;
        let normal_broadcast = message
            .normal_broadcast
            .deserialize::<Round2NormalBroadcast<P, Id>>(deserializer)?;
        message.direct_message.assert_is_none()?;

        let aux = (&self.context.epid, from);
        let from_pk = &self.context.public_aux(from)?.paillier_pk;

        let expected_ids = self.context.all_ids.clone().without(from);

        if normal_broadcast.cap_ds.keys().cloned().collect::<BTreeSet<_>>() != expected_ids {
            return Err(ReceiveError::protocol(Error::R2WrongIdsD.into()));
        }

        if echo_broadcast.cap_fs.keys().cloned().collect::<BTreeSet<_>>() != expected_ids {
            return Err(ReceiveError::protocol(Error::R2WrongIdsF.into()));
        }

        if normal_broadcast.psis.keys().cloned().collect::<BTreeSet<_>>() != expected_ids {
            return Err(ReceiveError::protocol(Error::R2WrongIdsPsi.into()));
        }

        let sender_payload = self.r1_payloads.safe_get("Round 1 payloads", from)?;

        let mut cap_ds = BTreeMap::new();
        let mut cap_fs = BTreeMap::new();
        for (id, psi) in normal_broadcast.psis.iter() {
            let rp = &self.context.public_aux(id)?.rp_params;
            let for_pk = &self.context.public_aux(id)?.paillier_pk;
            let for_payload = self.r1_payloads.safe_get("Round 1 payloads", id)?;
            let cap_d = normal_broadcast.cap_ds.safe_get("`D` map", id)?.to_precomputed(for_pk);
            let cap_f = echo_broadcast.cap_fs.safe_get("`F` map", id)?.to_precomputed(from_pk);

            if !psi.verify(
                AffGPublicInputs {
                    pk0: for_pk,
                    pk1: from_pk,
                    cap_c: &for_payload.cap_k,
                    cap_d: &cap_d,
                    cap_y: &cap_f,
                    cap_x: &echo_broadcast.cap_gamma,
                },
                rp,
                &aux,
            ) {
                return Err(ReceiveError::protocol(
                    Error::R2AffGPsiFailed { failed_for: id.clone() }.into(),
                ));
            }

            cap_ds.insert(id.clone(), cap_d);
            cap_fs.insert(id.clone(), cap_f);
        }

        let mut hat_cap_ds = BTreeMap::new();
        let mut hat_cap_fs = BTreeMap::new();
        for (id, hat_psi) in normal_broadcast.hat_psis.iter() {
            let rp = &self.context.public_aux(id)?.rp_params;
            let for_pk = &self.context.public_aux(id)?.paillier_pk;
            let for_payload = self.r1_payloads.safe_get("Round 1 payloads", id)?;
            let hat_cap_d = normal_broadcast
                .hat_cap_ds
                .safe_get("`D` map", id)?
                .to_precomputed(for_pk);
            let hat_cap_f = echo_broadcast
                .hat_cap_fs
                .safe_get("`F` map", id)?
                .to_precomputed(from_pk);

            let cap_x = self.context.public_share(from)?;

            if !hat_psi.verify(
                AffGPublicInputs {
                    pk0: for_pk,
                    pk1: from_pk,
                    cap_c: &for_payload.cap_k,
                    cap_d: &hat_cap_d,
                    cap_y: &hat_cap_f,
                    cap_x,
                },
                rp,
                &aux,
            ) {
                return Err(ReceiveError::protocol(
                    Error::R2AffGHatPsiFailed { failed_for: id.clone() }.into(),
                ));
            }

            hat_cap_ds.insert(id.clone(), hat_cap_d);
            hat_cap_fs.insert(id.clone(), hat_cap_f);
        }

        if !normal_broadcast.psi_elog.verify(
            ElogPublicInputs {
                cap_l: &sender_payload.cap_b1,
                cap_m: &sender_payload.cap_b2,
                cap_x: &sender_payload.cap_y,
                cap_y: &echo_broadcast.cap_gamma,
                h: &Point::generator(),
            },
            &aux,
        ) {
            return Err(ReceiveError::protocol(Error::R2ElogFailed.into()));
        }

        let alpha_uint = cap_ds
            .safe_get("`D` map", &self.context.my_id)?
            .decrypt(&self.context.aux_info.secret_aux.paillier_sk);
        let hat_alpha_uint = hat_cap_ds
            .safe_get("`\\hat{D}` map", &self.context.my_id)?
            .decrypt(&self.context.aux_info.secret_aux.paillier_sk);

        let alpha = secret_scalar_from_signed::<P>(&alpha_uint);
        let hat_alpha = secret_scalar_from_signed::<P>(&hat_alpha_uint);

        Ok(Payload::new(Round2Payload::<P, Id> {
            cap_gamma: echo_broadcast.cap_gamma,
            alpha,
            hat_alpha,
            cap_ds,
            cap_fs,
            hat_cap_ds,
            hat_cap_fs,
        }))
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round2Payload<P, Id>>()?;

        let mut cap_gammas = payloads.map_values_ref(|payload| payload.cap_gamma);
        cap_gammas.insert(self.context.my_id.clone(), self.cap_gamma);

        let cap_gamma_combined = cap_gammas.values().sum();
        let cap_delta = cap_gamma_combined * &self.context.k;

        let x = self.context.key_share.secret_share();

        let alpha_sum: Secret<Scalar<P>> = payloads.values().map(|payload| &payload.alpha).sum();
        let beta_sum: Secret<Scalar<P>> = self.betas.values().map(secret_scalar_from_signed::<P>).sum();
        let delta = *(&self.context.gamma * &self.context.k + alpha_sum + beta_sum).expose_secret();

        let hat_alpha_sum: Secret<Scalar<P>> = payloads.values().map(|payload| &payload.hat_alpha).sum();
        let hat_beta_sum: Secret<Scalar<P>> = self.hat_betas.values().map(secret_scalar_from_signed::<P>).sum();
        let chi = x * &self.context.k + hat_alpha_sum + hat_beta_sum;

        let cap_s = cap_gamma_combined * &chi;

        let aux = (&self.context.epid, &self.context.my_id);
        let my_r1_payload = self.r1_payloads.safe_get("Round 1 payloads", &self.context.my_id)?;
        let psi_prime = ElogProof::new(
            rng,
            ElogSecretInputs {
                y: &self.context.k,
                lambda: &self.context.a,
            },
            // Note that the parameter order in the protocol description and in the ZK proof description do not match.
            ElogPublicInputs {
                cap_l: &my_r1_payload.cap_a1,
                cap_m: &my_r1_payload.cap_a2,
                cap_x: &my_r1_payload.cap_y,
                cap_y: &cap_delta,
                h: &cap_gamma_combined,
            },
            &aux,
        );

        let r3_echo_broadcast = Round3EchoBroadcast { delta };

        let r3_normal_broadcast = Round3NormalBroadcast {
            cap_delta,
            psi_prime,
            cap_s,
        };

        let my_id = self.context.my_id.clone();

        // Build a full matrix of $D_{i,j}$ where the order of the indices follows that in the paper.
        // That is, $i$ is the index of the node $D$ was created *for*,
        // and $j$ is the index of the node it was created *by*.
        let mut cap_ds = BTreeMap::new();
        for (id_for, cap_d) in self.cap_ds {
            cap_ds.insert((id_for, my_id.clone()), cap_d);
        }
        for (id_from, payload) in payloads.iter() {
            for (id_for, cap_d) in payload.cap_ds.iter() {
                cap_ds.insert((id_for.clone(), id_from.clone()), cap_d.clone());
            }
        }

        // Same for $F_{i,j}.
        let mut cap_fs = BTreeMap::new();
        for (id_for, cap_f) in self.cap_fs {
            cap_fs.insert((id_for, my_id.clone()), cap_f);
        }
        for (id_from, payload) in payloads.iter() {
            for (id_for, cap_f) in payload.cap_fs.iter() {
                cap_fs.insert((id_for.clone(), id_from.clone()), cap_f.clone());
            }
        }

        // Same for $\hat{D}_{i,j}.
        let mut hat_cap_ds = BTreeMap::new();
        for (id_for, hat_cap_d) in self.hat_cap_ds {
            hat_cap_ds.insert((id_for, my_id.clone()), hat_cap_d);
        }
        for (id_from, payload) in payloads.iter() {
            for (id_for, hat_cap_d) in payload.hat_cap_ds.iter() {
                hat_cap_ds.insert((id_for.clone(), id_from.clone()), hat_cap_d.clone());
            }
        }

        // Same for $\hat{F}_{i,j}.
        let mut hat_cap_fs = BTreeMap::new();
        for (id_for, hat_cap_f) in self.hat_cap_fs {
            hat_cap_fs.insert((id_for, my_id.clone()), hat_cap_f);
        }
        for (id_from, payload) in payloads.iter() {
            for (id_for, hat_cap_f) in payload.hat_cap_fs.iter() {
                hat_cap_fs.insert((id_for.clone(), id_from.clone()), hat_cap_f.clone());
            }
        }

        let next_round = Round3 {
            context: self.context,
            cap_k: self.cap_k,
            cap_gamma_combined,
            chi,
            r1_payloads: self.r1_payloads,
            cap_gammas,
            cap_ds,
            cap_fs,
            hat_cap_ds,
            hat_cap_fs,
            r3_echo_broadcast,
            r3_normal_broadcast,
            betas: self.betas,
            rs: self.rs,
            ss: self.ss,
            hat_betas: self.hat_betas,
            hat_rs: self.hat_rs,
            hat_ss: self.hat_ss,
        };

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(next_round)))
    }
}

#[derive(Debug)]
pub(super) struct Round3<P: SchemeParams, Id: PartyId> {
    pub(super) context: Context<P, Id>,
    pub(super) cap_k: Ciphertext<P::Paillier>,
    pub(super) cap_gamma_combined: Point<P>,
    pub(super) chi: Secret<Scalar<P>>,
    pub(super) r1_payloads: BTreeMap<Id, Round1Payload<P>>,
    pub(super) cap_gammas: BTreeMap<Id, Point<P>>,
    pub(super) cap_ds: BTreeMap<(Id, Id), Ciphertext<P::Paillier>>, // $D_{i,j}$ for all $i, j$ where $i != j$.
    pub(super) cap_fs: BTreeMap<(Id, Id), Ciphertext<P::Paillier>>, // $F_{i,j}$ for all $i, j$ where $i != j$.
    pub(super) hat_cap_ds: BTreeMap<(Id, Id), Ciphertext<P::Paillier>>, // $\hat{D}_{i,j}$ for all $i, j$ where $i != j$.
    pub(super) hat_cap_fs: BTreeMap<(Id, Id), Ciphertext<P::Paillier>>, // $\hat{F}_{i,j}$ for all $i, j$ where $i != j$.
    pub(super) r3_echo_broadcast: Round3EchoBroadcast<P>,
    pub(super) r3_normal_broadcast: Round3NormalBroadcast<P>,
    pub(super) betas: BTreeMap<Id, SecretSigned<<P::Paillier as PaillierParams>::Uint>>,
    pub(super) rs: BTreeMap<Id, Randomizer<P::Paillier>>,
    pub(super) ss: BTreeMap<Id, Randomizer<P::Paillier>>,
    pub(super) hat_betas: BTreeMap<Id, SecretSigned<<P::Paillier as PaillierParams>::Uint>>,
    pub(super) hat_rs: BTreeMap<Id, Randomizer<P::Paillier>>,
    pub(super) hat_ss: BTreeMap<Id, Randomizer<P::Paillier>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "Scalar<P>: for<'x> Deserialize<'x>,"))]
pub(super) struct Round3EchoBroadcast<P: SchemeParams> {
    pub(super) delta: Scalar<P>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "ElogProof<P>: Serialize"))]
#[serde(bound(deserialize = "ElogProof<P>: for<'x> Deserialize<'x>"))]
pub(super) struct Round3NormalBroadcast<P: SchemeParams> {
    pub(super) cap_delta: Point<P>,
    psi_prime: ElogProof<P>,
    pub(super) cap_s: Point<P>,
}

pub(super) struct Round3Payload<P: SchemeParams> {
    pub(super) delta: Scalar<P>,
    cap_delta: Point<P>,
    pub(super) cap_s: Point<P>,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round3<P, Id> {
    type Protocol = InteractiveSigningProtocol<P, Id>;

    fn id(&self) -> RoundId {
        3.into()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [4.into(), 5.into(), 6.into()].into()
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
        EchoBroadcast::new(serializer, self.r3_echo_broadcast.clone())
    }

    fn make_normal_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<NormalBroadcast, LocalError> {
        NormalBroadcast::new(serializer, self.r3_normal_broadcast.clone())
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
            .deserialize::<Round3EchoBroadcast<P>>(deserializer)?;
        let normal_broadcast = message
            .normal_broadcast
            .deserialize::<Round3NormalBroadcast<P>>(deserializer)?;

        let aux = (&self.context.epid, from);
        let r1_payload = self.r1_payloads.safe_get("Round 1 payload", from)?;

        if !normal_broadcast.psi_prime.verify(
            ElogPublicInputs {
                cap_l: &r1_payload.cap_a1,
                cap_m: &r1_payload.cap_a2,
                cap_x: &r1_payload.cap_y,
                cap_y: &normal_broadcast.cap_delta,
                h: &self.cap_gamma_combined,
            },
            &aux,
        ) {
            return Err(ReceiveError::protocol(Error::R3ElogFailed.into()));
        }

        Ok(Payload::new(Round3Payload {
            delta: echo_broadcast.delta,
            cap_delta: normal_broadcast.cap_delta,
            cap_s: normal_broadcast.cap_s,
        }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let mut payloads = payloads.downcast_all::<Round3Payload<P>>()?;
        let my_payload = Round3Payload {
            delta: self.r3_echo_broadcast.delta,
            cap_delta: self.r3_normal_broadcast.cap_delta,
            cap_s: self.r3_normal_broadcast.cap_s,
        };
        payloads.insert(self.context.my_id.clone(), my_payload);

        let deltas = payloads.map_values_ref(|payload| payload.delta);

        let delta_combined = deltas.values().sum::<Scalar<P>>();
        let cap_delta = payloads.values().map(|payload| payload.cap_delta).sum();

        let cap_s = payloads.values().map(|payload| payload.cap_s).sum::<Point<P>>();
        let cap_x = self.context.key_share.verifying_key_as_point();

        if delta_combined.mul_by_generator() != cap_delta {
            let mut cap_ks = self.r1_payloads.map_values_ref(|payload| payload.cap_k.clone());
            cap_ks.insert(self.context.my_id.clone(), self.cap_k);

            let next_round = Round5 {
                context: self.context,
                deltas,
                betas: self.betas,
                ss: self.ss,
                rs: self.rs,
                cap_gammas: self.cap_gammas,
                cap_ks,
                cap_ds: self.cap_ds,
                cap_fs: self.cap_fs,
            };

            return Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(next_round)));
        }

        if cap_s != cap_x * delta_combined {
            let mut cap_ks = self.r1_payloads.map_values_ref(|payload| payload.cap_k.clone());
            cap_ks.insert(self.context.my_id.clone(), self.cap_k);

            let cap_ss = payloads.map_values_ref(|payload| payload.cap_s);

            let next_round = Round6 {
                context: self.context,
                cap_gamma_combined: self.cap_gamma_combined,
                hat_betas: self.hat_betas,
                hat_ss: self.hat_ss,
                hat_rs: self.hat_rs,
                cap_ks,
                cap_ss,
                hat_cap_ds: self.hat_cap_ds,
                hat_cap_fs: self.hat_cap_fs,
            };

            return Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(next_round)));
        }

        // Intentionally making delta = 0 would require coordination from all the participants,
        // so it is very unlikely to happen.
        let delta_combined_inv = Option::<Scalar<P>>::from(delta_combined.invert())
            .ok_or_else(|| LocalError::new("The combined delta is not invertible"))?;

        let presigning_data = PresigningData {
            cap_gamma_combined: self.cap_gamma_combined,
            tilde_k: &self.context.k * delta_combined_inv,
            tilde_chi: self.chi * delta_combined_inv,
            tilde_cap_deltas: payloads.map_values_ref(|payload| payload.cap_delta * delta_combined_inv),
            tilde_cap_ss: payloads.map_values_ref(|payload| payload.cap_s * delta_combined_inv),
        };

        let nonce = presigning_data.cap_gamma_combined.x_coordinate();
        let sigma = *(&presigning_data.tilde_k * self.context.scalar_message + &presigning_data.tilde_chi * nonce)
            .expose_secret();

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round4 {
            context: self.context,
            presigning_data,
            sigma,
        })))
    }
}

#[derive(Debug)]
struct Round4<P: SchemeParams, Id: PartyId> {
    context: Context<P, Id>,
    presigning_data: PresigningData<P, Id>,
    sigma: Scalar<P>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "Scalar<P>: for<'x> Deserialize<'x>,"))]
pub(super) struct Round4NormalBroadcast<P: SchemeParams> {
    pub(crate) sigma: Scalar<P>,
}

struct Round4Payload<P: SchemeParams> {
    sigma: Scalar<P>,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round4<P, Id> {
    type Protocol = InteractiveSigningProtocol<P, Id>;

    fn id(&self) -> RoundId {
        4.into()
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
        NormalBroadcast::new(serializer, Round4NormalBroadcast { sigma: self.sigma })
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
            .deserialize::<Round4NormalBroadcast<P>>(deserializer)?;

        let nonce = self.presigning_data.cap_gamma_combined.x_coordinate();
        let tilde_cap_delta = self
            .presigning_data
            .tilde_cap_deltas
            .safe_get("`\\tilde{Delta}` map", from)?;
        let tilde_cap_s = self.presigning_data.tilde_cap_ss.safe_get("`\\tilde{S}` map", from)?;
        if self.presigning_data.cap_gamma_combined * normal_broadcast.sigma
            != tilde_cap_delta * self.context.scalar_message + tilde_cap_s * nonce
        {
            return Err(ReceiveError::protocol(Error::R4InvalidSignatureShare.into()));
        }

        Ok(Payload::new(Round4Payload {
            sigma: normal_broadcast.sigma,
        }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round4Payload<P>>()?;

        let assembled_sigma = payloads.values().map(|payload| payload.sigma).sum::<Scalar<P>>() + self.sigma;

        let signature = RecoverableSignature::from_scalars(
            self.presigning_data.cap_gamma_combined.x_coordinate(),
            assembled_sigma,
            self.context.key_share.verifying_key_as_point(),
            self.context.scalar_message,
        );

        if let Some(signature) = signature {
            return Ok(FinalizeOutcome::Result(signature));
        }

        Err(LocalError::new("Failed!"))
    }
}

#[derive(Debug)]
pub(super) struct Round5<P: SchemeParams, Id: PartyId> {
    pub(super) context: Context<P, Id>,
    pub(super) deltas: BTreeMap<Id, Scalar<P>>,
    pub(super) betas: BTreeMap<Id, SecretSigned<<P::Paillier as PaillierParams>::Uint>>,
    pub(super) ss: BTreeMap<Id, Randomizer<P::Paillier>>,
    pub(super) rs: BTreeMap<Id, Randomizer<P::Paillier>>,
    pub(super) cap_gammas: BTreeMap<Id, Point<P>>,
    pub(super) cap_ks: BTreeMap<Id, Ciphertext<P::Paillier>>, // $K_i$ for all $i$ ($i$ is locally generated, others received)
    pub(super) cap_ds: BTreeMap<(Id, Id), Ciphertext<P::Paillier>>, // $D_{i,j}$ for $j != i$
    pub(super) cap_fs: BTreeMap<(Id, Id), Ciphertext<P::Paillier>>, // $F_{i,j}$ for $j != i$
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    DecProof<P>: Serialize,
    AffGStarProof<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    DecProof<P>: for<'x> Deserialize<'x>,
    AffGStarProof<P>: for<'x> Deserialize<'x>,
"))]
pub(super) struct Round5EchoBroadcast<P: SchemeParams, Id: PartyId> {
    pub(super) psi_star: DecProof<P>,
    pub(super) psis: BTreeMap<Id, AffGStarProof<P>>,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round5<P, Id> {
    type Protocol = InteractiveSigningProtocol<P, Id>;

    fn id(&self) -> RoundId {
        5.into()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [].into()
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
    }

    fn make_echo_broadcast(
        &self,
        rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        let my_id = self.context.my_id.clone();
        let aux = (&self.context.epid, &my_id);
        let pk = self.context.aux_info.secret_aux.paillier_sk.public_key();
        let rp = &self.context.public_aux(&self.context.my_id)?.rp_params;

        let ids = self.context.other_ids.clone();

        let cap_d = sum_non_empty_ref(
            ids.iter()
                .map(|id| self.cap_ds.safe_get("`D` map", &(my_id.clone(), id.clone()))),
            LocalError::new("There must be at least two parties"),
        )? + sum_non_empty_ref(
            ids.iter()
                .map(|id| self.cap_fs.safe_get("`F` map", &(id.clone(), my_id.clone()))),
            LocalError::new("There must be at least two parties"),
        )?;

        let cap_k = self.cap_ks.safe_get("`K` map", &self.context.my_id)?;

        let gamma = secret_signed_from_scalar::<P>(&self.context.gamma);
        let full_ciphertext = cap_k * &gamma + &cap_d;

        let rho = full_ciphertext.derive_randomizer(&self.context.aux_info.secret_aux.paillier_sk);

        // We could have calculated `\delta_i` as SecretSigned in Round 2, but that would require
        // keeping all the components as SecretSigned instead of Scalar as well.
        // Since it's only needed here it's easier to re-create it inplace.
        let delta_signed = full_ciphertext.decrypt(&self.context.aux_info.secret_aux.paillier_sk);

        let num_parties = self.context.all_ids.len();
        let ceil_log2_num_parties = (num_parties - 1).ilog2() + 1;
        let delta_signed = delta_signed
            .ensure_exponent_range(P::LP_BOUND + P::EPS_BOUND + 1 + ceil_log2_num_parties)
            .ok_or_else(|| LocalError::new("`delta` is not in the expected range"))?;

        // This is equal to what we would get from reducing `delta_signed` to Scalar.
        let delta = self.deltas.safe_get("`delta` map", &self.context.my_id)?;

        let psi_star = DecProof::new(
            rng,
            DecSecretInputs {
                // Note: the paper has incorrect order of arguments
                x: &gamma,
                y: &delta_signed,
                rho: &rho,
            },
            DecPublicInputs {
                pk0: pk,
                cap_k,
                cap_x: &self.context.gamma.mul_by_generator(),
                cap_d: &cap_d,
                cap_s: &delta.mul_by_generator(),
                cap_g: &Point::generator(),
                num_parties,
            },
            rp,
            &aux,
        );

        let mut psis = BTreeMap::new();
        for id in self.context.other_ids.iter() {
            let psi = AffGStarProof::new(
                rng,
                AffGStarSecretInputs {
                    x: &gamma,
                    y: self.betas.safe_get("`beta` map", id)?,
                    rho: self.ss.safe_get("`s` map", id)?,
                    mu: self.rs.safe_get("`r` map", id)?,
                },
                AffGStarPublicInputs {
                    pk0: &self.context.public_aux(id)?.paillier_pk,
                    pk1: pk,
                    cap_c: self.cap_ks.safe_get("`K` map", id)?,
                    cap_d: self.cap_ds.safe_get("`D` map", &(id.clone(), my_id.clone()))?,
                    cap_y: self.cap_fs.safe_get("`F` map", &(id.clone(), my_id.clone()))?,
                    cap_x: self.cap_gammas.safe_get("`Gamma` map", &my_id)?,
                },
                &aux,
            );

            psis.insert(id.clone(), psi);
        }

        EchoBroadcast::new(serializer, Round5EchoBroadcast::<P, Id> { psi_star, psis })
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        message.normal_broadcast.assert_is_none()?;
        message.direct_message.assert_is_none()?;
        let echo_broadcast = message
            .echo_broadcast
            .deserialize::<Round5EchoBroadcast<P, Id>>(deserializer)?;

        let my_id = self.context.my_id.clone();
        let aux = (&self.context.epid, from);

        let sender_pk = &self.context.public_aux(from)?.paillier_pk;
        let sender_rp = &self.context.public_aux(from)?.rp_params;

        let ids = self.context.all_ids.clone().without(from);

        let cap_d = sum_non_empty_ref(
            ids.iter()
                .map(|id| self.cap_ds.safe_get("`D` map", &(from.clone(), id.clone()))),
            LocalError::new("There must be at least two parties"),
        )? + sum_non_empty_ref(
            ids.iter()
                .map(|id| self.cap_fs.safe_get("`F` map", &(id.clone(), from.clone()))),
            LocalError::new("There must be at least two parties"),
        )?;

        if !echo_broadcast.psi_star.verify(
            DecPublicInputs {
                pk0: sender_pk,
                cap_k: self.cap_ks.safe_get("`K` map", from)?,
                cap_x: self.cap_gammas.safe_get("`Gamma` map", from)?,
                cap_d: &cap_d,
                cap_s: &self.deltas.safe_get("`delta` map", from)?.mul_by_generator(),
                cap_g: &Point::generator(),
                num_parties: self.context.all_ids.len(),
            },
            sender_rp,
            &aux,
        ) {
            return Err(ReceiveError::protocol(Error::R5DecFailed.into()));
        }

        let expected_ids = self.context.all_ids.clone().without(from);
        if echo_broadcast.psis.keys().cloned().collect::<BTreeSet<_>>() != expected_ids {
            return Err(ReceiveError::protocol(Error::R5WrongIdsPsi.into()));
        }

        for (id, psi) in echo_broadcast.psis.iter() {
            if id == &my_id {
                continue;
            }

            let pk = &self.context.public_aux(id)?.paillier_pk;
            if !psi.verify(
                AffGStarPublicInputs {
                    pk0: pk,
                    pk1: sender_pk,
                    cap_c: self.cap_ks.safe_get("`K` map", id)?,
                    cap_d: self.cap_ds.safe_get("`D` map", &(id.clone(), from.clone()))?,
                    cap_y: self.cap_fs.safe_get("`F` map", &(id.clone(), from.clone()))?,
                    cap_x: self.cap_gammas.safe_get("`Gamma` map", from)?,
                },
                &aux,
            ) {
                return Err(ReceiveError::protocol(
                    Error::R5AffGStarFailed { failed_for: id.clone() }.into(),
                ));
            }
        }

        Ok(Payload::empty())
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        Err(LocalError::new(
            "One of the messages should have been missing or invalid",
        ))
    }
}

#[derive(Debug)]
pub(super) struct Round6<P: SchemeParams, Id: PartyId> {
    pub(super) context: Context<P, Id>,
    pub(super) cap_gamma_combined: Point<P>,
    pub(super) hat_betas: BTreeMap<Id, SecretSigned<<P::Paillier as PaillierParams>::Uint>>,
    pub(super) hat_ss: BTreeMap<Id, Randomizer<P::Paillier>>,
    pub(super) hat_rs: BTreeMap<Id, Randomizer<P::Paillier>>,
    pub(super) cap_ks: BTreeMap<Id, Ciphertext<P::Paillier>>, // $K_i$ for all $i$ ($i$ is locally generated, others received)
    pub(super) cap_ss: BTreeMap<Id, Point<P>>,
    pub(super) hat_cap_ds: BTreeMap<(Id, Id), Ciphertext<P::Paillier>>, // $\hat{D}_{i,j}$ for $j != i$
    pub(super) hat_cap_fs: BTreeMap<(Id, Id), Ciphertext<P::Paillier>>, // $\hat{F}_{i,j}$ for $j != i$
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    DecProof<P>: Serialize,
    AffGStarProof<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    Id: for<'x> Deserialize<'x>,
    DecProof<P>: for<'x> Deserialize<'x>,
    AffGStarProof<P>: for<'x> Deserialize<'x>
"))]
pub(super) struct Round6EchoBroadcast<P: SchemeParams, Id: PartyId> {
    pub(super) hat_psi_star: DecProof<P>,
    pub(super) hat_psis: BTreeMap<Id, AffGStarProof<P>>,
}

impl<P: SchemeParams, Id: PartyId> Round<Id> for Round6<P, Id> {
    type Protocol = InteractiveSigningProtocol<P, Id>;

    fn id(&self) -> RoundId {
        6.into()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [].into()
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        &self.context.other_ids
    }

    fn make_echo_broadcast(
        &self,
        rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        let my_id = self.context.my_id.clone();
        let aux = (&self.context.epid, &my_id);
        let pk = self.context.aux_info.secret_aux.paillier_sk.public_key();
        let rp = &self.context.public_aux(&self.context.my_id)?.rp_params;

        let ids = self.context.other_ids.clone();

        let hat_cap_d = sum_non_empty_ref(
            ids.iter()
                .map(|id| self.hat_cap_ds.safe_get("`\\hat{D}` map", &(my_id.clone(), id.clone()))),
            LocalError::new("There must be at least two parties"),
        )? + sum_non_empty_ref(
            ids.iter()
                .map(|id| self.hat_cap_fs.safe_get("`\\hat{F}` map", &(id.clone(), my_id.clone()))),
            LocalError::new("There must be at least two parties"),
        )?;

        let cap_k = self.cap_ks.safe_get("`K` map", &self.context.my_id)?;

        let cap_xs = self.context.key_share.public_shares().clone();

        let x = secret_signed_from_scalar::<P>(self.context.key_share.secret_share());
        let full_ciphertext = cap_k * &x + &hat_cap_d;

        let rho = full_ciphertext.derive_randomizer(&self.context.aux_info.secret_aux.paillier_sk);

        // We could have calculated `\chi_i` as SecretSigned in Round 2, but that would require
        // keeping all the components as SecretSigned instead of Scalar as well.
        // Since it's only needed here it's easier to re-create it inplace.
        let chi_signed = full_ciphertext.decrypt(&self.context.aux_info.secret_aux.paillier_sk);

        let num_parties = self.context.all_ids.len();
        let ceil_log2_num_parties = (num_parties - 1).ilog2() + 1;
        let chi_signed = chi_signed
            .ensure_exponent_range(P::LP_BOUND + P::EPS_BOUND + 1 + ceil_log2_num_parties)
            .ok_or_else(|| LocalError::new("`delta` is not in the expected range"))?;

        let hat_psi_star = DecProof::new(
            rng,
            DecSecretInputs {
                // Note: the paper has incorrect order of arguments
                x: &x,
                y: &chi_signed,
                rho: &rho,
            },
            DecPublicInputs {
                pk0: pk,
                cap_k,
                cap_x: cap_xs.safe_get("`X` map", &self.context.my_id)?,
                cap_d: &hat_cap_d,
                cap_s: self.cap_ss.safe_get("`S` map", &self.context.my_id)?,
                cap_g: &self.cap_gamma_combined,
                num_parties,
            },
            rp,
            &aux,
        );

        let mut hat_psis = BTreeMap::new();
        for id in self.context.other_ids.iter() {
            let hat_psi = AffGStarProof::new(
                rng,
                AffGStarSecretInputs {
                    x: &x,
                    y: self.hat_betas.safe_get("`\\hat{beta}` map", id)?,
                    rho: self.hat_ss.safe_get("`\\hat{s}` map", id)?,
                    mu: self.hat_rs.safe_get("`\\hat{r}` map", id)?,
                },
                AffGStarPublicInputs {
                    pk0: &self.context.public_aux(id)?.paillier_pk,
                    pk1: pk,
                    cap_c: self.cap_ks.safe_get("``K` map", id)?,
                    cap_d: self
                        .hat_cap_ds
                        .safe_get("`\\hat{D}` map", &(id.clone(), my_id.clone()))?,
                    cap_y: self
                        .hat_cap_fs
                        .safe_get("`\\hat{F}` map", &(id.clone(), my_id.clone()))?,
                    cap_x: cap_xs.safe_get("`X` map", &my_id)?,
                },
                &aux,
            );

            assert!(hat_psi.verify(
                AffGStarPublicInputs {
                    pk0: &self.context.public_aux(id)?.paillier_pk,
                    pk1: pk,
                    cap_c: self.cap_ks.safe_get("``K` map", id)?,
                    cap_d: self
                        .hat_cap_ds
                        .safe_get("`\\hat{D}` map", &(id.clone(), my_id.clone()))?,
                    cap_y: self
                        .hat_cap_fs
                        .safe_get("`\\hat{F}` map", &(id.clone(), my_id.clone()))?,
                    cap_x: cap_xs.safe_get("`X` map", &my_id)?,
                },
                &aux,
            ));

            hat_psis.insert(id.clone(), hat_psi);
        }

        EchoBroadcast::new(serializer, Round6EchoBroadcast::<P, Id> { hat_psi_star, hat_psis })
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        message.normal_broadcast.assert_is_none()?;
        message.direct_message.assert_is_none()?;
        let echo_broadcast = message
            .echo_broadcast
            .deserialize::<Round6EchoBroadcast<P, Id>>(deserializer)?;

        let my_id = self.context.my_id.clone();
        let aux = (&self.context.epid, from);

        let sender_pk = &self.context.public_aux(from)?.paillier_pk;
        let sender_rp = &self.context.public_aux(from)?.rp_params;

        let ids = self.context.all_ids.clone().without(from);

        let hat_cap_d = sum_non_empty_ref(
            ids.iter()
                .map(|id| self.hat_cap_ds.safe_get("`\\hat{D}` map", &(from.clone(), id.clone()))),
            LocalError::new("There must be at least two parties"),
        )? + sum_non_empty_ref(
            ids.iter()
                .map(|id| self.hat_cap_fs.safe_get("`\\hat{F}` map", &(id.clone(), from.clone()))),
            LocalError::new("There must be at least two parties"),
        )?;

        let cap_xs = self.context.key_share.public_shares().clone();

        if !echo_broadcast.hat_psi_star.verify(
            DecPublicInputs {
                pk0: sender_pk,
                cap_k: self.cap_ks.safe_get("`K` map", from)?,
                cap_x: cap_xs.safe_get("`X` map", from)?,
                cap_d: &hat_cap_d,
                cap_s: self.cap_ss.safe_get("`S` map", from)?,
                cap_g: &self.cap_gamma_combined,
                num_parties: self.context.all_ids.len(),
            },
            sender_rp,
            &aux,
        ) {
            return Err(ReceiveError::protocol(Error::R6DecFailed.into()));
        }

        let expected_ids = self.context.all_ids.clone().without(from);
        if echo_broadcast.hat_psis.keys().cloned().collect::<BTreeSet<_>>() != expected_ids {
            return Err(ReceiveError::protocol(Error::R6WrongIdsPsi.into()));
        }

        for (id, hat_psi) in echo_broadcast.hat_psis.iter() {
            if id == &my_id {
                continue;
            }

            let pk = &self.context.public_aux(id)?.paillier_pk;
            if !hat_psi.verify(
                AffGStarPublicInputs {
                    pk0: pk,
                    pk1: sender_pk,
                    cap_c: self.cap_ks.safe_get("`K` map", id)?,
                    cap_d: self.hat_cap_ds.safe_get("`D` map", &(id.clone(), from.clone()))?,
                    cap_y: self.hat_cap_fs.safe_get("`F` map", &(id.clone(), from.clone()))?,
                    cap_x: cap_xs.safe_get("`X` map", from)?,
                },
                &aux,
            ) {
                return Err(ReceiveError::protocol(
                    Error::R6AffGStarFailed { failed_for: id.clone() }.into(),
                ));
            }
        }

        Ok(Payload::empty())
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<Id, Payload>,
        _artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError> {
        Err(LocalError::new(
            "One of the messages should have been missing or invalid",
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
    use elliptic_curve::FieldBytes;
    use manul::{
        dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
        signature::Keypair,
    };
    use rand_core::{OsRng, RngCore};

    use super::InteractiveSigning;
    use crate::{
        dev::TestParams,
        entities::{AuxInfo, KeyShare},
        SchemeParams,
    };
    type Curve = <TestParams as SchemeParams>::Curve;

    #[test]
    fn execute_interactive_signing() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers.iter().map(|signer| signer.verifying_key()).collect::<Vec<_>>();
        let ids_set = BTreeSet::from_iter(ids.clone());

        let key_shares = KeyShare::<TestParams, TestVerifier>::new_centralized(&mut OsRng, &ids_set, None);
        let aux_infos = AuxInfo::new_centralized(&mut OsRng, &ids_set);

        let mut message = FieldBytes::<Curve>::default();
        OsRng.fill_bytes(&mut message);

        let entry_points = signers
            .into_iter()
            .map(|signer| {
                let id = signer.verifying_key();
                let entry_point =
                    InteractiveSigning::new(message, key_shares[&id].clone(), aux_infos[&id].clone()).unwrap();
                (signer, entry_point)
            })
            .collect();

        let mut signatures = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
            .unwrap()
            .results()
            .unwrap();

        while let Some((_, signature)) = signatures.pop_first() {
            let (sig, rec_id) = signature.to_backend();
            let vkey = key_shares[&ids[0]].verifying_key();

            // Check that the signature can be verified
            vkey.verify_prehash(&message, &sig).unwrap();

            // Check that the key can be recovered
            let recovered_key = VerifyingKey::recover_from_prehash(message.as_ref(), &sig, rec_id).unwrap();
            assert_eq!(recovered_key, vkey);
        }
    }
}
