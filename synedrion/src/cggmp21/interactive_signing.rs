//! Merged Presigning and Signing protocols,
//! in the paper ECDSA Pre-Signing (Fig. 7) and Signing (Fig. 8).

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};

use manul::protocol::{
    Artifact, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EntryPoint, FinalizeOutcome, LocalError,
    MessageValidationError, NormalBroadcast, PartyId, Payload, Protocol, ProtocolError, ProtocolMessage,
    ProtocolMessagePart, ProtocolValidationError, ReceiveError, RequiredMessageParts, RequiredMessages, Round, RoundId,
    Serializer,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    conversion::{
        public_signed_from_scalar, secret_scalar_from_signed, secret_signed_from_scalar, secret_unsigned_from_scalar,
    },
    entities::{AuxInfo, AuxInfoPrecomputed, KeyShare, PresigningData, PresigningValues, PublicAuxInfoPrecomputed},
    params::SchemeParams,
    sigma::{
        AffGProof, AffGPublicInputs, AffGSecretInputs, DecProof, DecPublicInputs, DecSecretInputs, EncProof,
        EncPublicInputs, EncSecretInputs, LogStarProof, LogStarPublicInputs, LogStarSecretInputs, MulProof,
        MulPublicInputs, MulSecretInputs, MulStarProof, MulStarPublicInputs, MulStarSecretInputs,
    },
};
use crate::{
    curve::{Point, RecoverableSignature, Scalar},
    paillier::{Ciphertext, CiphertextWire, PaillierParams, Randomizer},
    tools::{
        hashing::{Chain, FofHasher, HashOutput},
        DowncastMap, Secret, Without,
    },
    uint::SecretSigned,
};

/// A protocol for creating all the data necessary for signing
/// that doesn't require knowing the actual message being signed.
#[derive(Debug, Clone, Copy)]
pub struct InteractiveSigningProtocol<P: SchemeParams, I: Debug>(PhantomData<(P, I)>);

impl<P: SchemeParams, I: PartyId> Protocol<I> for InteractiveSigningProtocol<P, I> {
    type Result = RecoverableSignature;
    type ProtocolError = InteractiveSigningError;

    fn verify_direct_message_is_invalid(
        _deserializer: &Deserializer,
        _round_id: &RoundId,
        _message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        unimplemented!()
    }

    fn verify_echo_broadcast_is_invalid(
        _deserializer: &Deserializer,
        _round_id: &RoundId,
        _message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        unimplemented!()
    }

    fn verify_normal_broadcast_is_invalid(
        _deserializer: &Deserializer,
        _round_id: &RoundId,
        _message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError> {
        unimplemented!()
    }
}

/// Possible verifiable errors of the Presigning protocol.
#[derive(displaydoc::Display, Debug, Clone, Serialize, Deserialize)]
pub enum InteractiveSigningError {
    /// An error in Round 1.
    Round1(String),
    /// An error in Round 2.
    Round2(String),
    /// An error in Round 3.
    Round3(String),
    /// An error in the signing error round.
    SigningError(String),
    /// `alpha` out of bounds
    OutOfBoundsAlpha,
    /// `hat_alpha` out of bounds
    OutOfBoundsHatAlpha,
}

impl<I> ProtocolError<I> for InteractiveSigningError {
    type AssociatedData = ();

    fn required_messages(&self) -> RequiredMessages {
        RequiredMessages::new(RequiredMessageParts::normal_broadcast(), None, None)
    }

    fn verify_messages_constitute_error(
        &self,
        _deserializer: &Deserializer,
        _guilty_party: &I,
        _shared_randomness: &[u8],
        _associated_data: &Self::AssociatedData,
        _message: ProtocolMessage,
        _previous_messages: BTreeMap<RoundId, ProtocolMessage>,
        _combined_echos: BTreeMap<RoundId, BTreeMap<I, EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        Ok(())
    }
}

/// Prehashed message to sign.
pub type PrehashedMessage = [u8; 32];

/// An entry point for the [`InteractiveSigningProtocol`].
#[derive(Debug)]
pub struct InteractiveSigning<P: SchemeParams, I: Ord> {
    key_share: KeyShare<P, I>,
    aux_info: AuxInfo<P, I>,
    prehashed_message: PrehashedMessage,
}

impl<P: SchemeParams, I: Ord> InteractiveSigning<P, I> {
    /// Creates a new entry point given a share of the secret key.
    pub fn new(prehashed_message: PrehashedMessage, key_share: KeyShare<P, I>, aux_info: AuxInfo<P, I>) -> Self {
        // TODO: check that both are consistent
        Self {
            prehashed_message,
            key_share,
            aux_info,
        }
    }
}

impl<P: SchemeParams, I: PartyId> EntryPoint<I> for InteractiveSigning<P, I> {
    type Protocol = InteractiveSigningProtocol<P, I>;

    fn entry_round_id() -> RoundId {
        1.into()
    }

    fn make_round(
        self,
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        id: &I,
    ) -> Result<BoxedRound<I, Self::Protocol>, LocalError> {
        let key_share = self.key_share;
        let aux_info = self.aux_info;

        if id != key_share.owner() || id != aux_info.owner() {
            return Err(LocalError::new(
                "ID mismatch between the signer, the key share and the aux info",
            ));
        }

        let other_ids = key_share
            .public_shares
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            .without(id);

        // This includes the info of $ssid$ in the paper
        // (scheme parameters + public data from all shares - hashed in `share_set_id`),
        // with the session randomness added.
        let ssid_hash = FofHasher::new_with_dst(b"ShareSetID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .chain(&key_share.public_shares)
            .chain(&aux_info.public_aux)
            .finalize();

        let aux_info = aux_info.into_precomputed();

        // TODO (#68): check that KeyShare is consistent with AuxInfo

        // The share of an ephemeral scalar
        let k = Secret::init_with(|| Scalar::random(rng));
        // The share of the mask used to generate the inverse of the ephemeral scalar
        let gamma = Secret::init_with(|| Scalar::random(rng));

        let pk = aux_info.secret_aux.paillier_sk.public_key();

        let nu = Randomizer::<P::Paillier>::random(rng, pk);
        let cap_g = Ciphertext::new_with_randomizer(pk, &secret_unsigned_from_scalar::<P>(&gamma), &nu);

        let rho = Randomizer::<P::Paillier>::random(rng, pk);
        let cap_k = Ciphertext::new_with_randomizer(pk, &secret_unsigned_from_scalar::<P>(&k), &rho);

        Ok(BoxedRound::new_dynamic(Round1 {
            context: Context {
                ssid_hash,
                my_id: id.clone(),
                message: Scalar::from_reduced_bytes(&self.prehashed_message),
                other_ids,
                key_share,
                aux_info,
                k,
                gamma,
                rho,
                nu,
            },
            cap_k,
            cap_g,
        }))
    }
}

#[derive(Debug)]
struct Context<P: SchemeParams, I: Ord> {
    ssid_hash: HashOutput,
    my_id: I,
    message: Scalar,
    other_ids: BTreeSet<I>,
    key_share: KeyShare<P, I>,
    aux_info: AuxInfoPrecomputed<P, I>,
    k: Secret<Scalar>,
    gamma: Secret<Scalar>,
    rho: Randomizer<P::Paillier>,
    nu: Randomizer<P::Paillier>,
}

impl<P, I> Context<P, I>
where
    P: SchemeParams,
    I: Ord + Debug,
{
    pub fn public_share(&self, i: &I) -> Result<&Point, LocalError> {
        self.key_share
            .public_shares
            .get(i)
            .ok_or_else(|| LocalError::new("Missing public_share for party Id {i:?}"))
    }

    pub fn public_aux(&self, i: &I) -> Result<&PublicAuxInfoPrecomputed<P>, LocalError> {
        self.aux_info
            .public_aux
            .get(i)
            .ok_or_else(|| LocalError::new(format!("Missing public_aux for party Id {i:?}")))
    }
}

#[derive(Debug)]
struct Round1<P: SchemeParams, I: Ord> {
    context: Context<P, I>,
    cap_k: Ciphertext<P::Paillier>,
    cap_g: Ciphertext<P::Paillier>,
}

impl<P: SchemeParams, I: Ord + Debug> Round1<P, I> {
    fn public_aux(&self, i: &I) -> Result<&PublicAuxInfoPrecomputed<P>, LocalError> {
        self.context
            .aux_info
            .public_aux
            .get(i)
            .ok_or_else(|| LocalError::new(format!("Missing public_aux for party Id {i:?}")))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "CiphertextWire<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "CiphertextWire<P::Paillier>: for<'x> Deserialize<'x>"))]
struct Round1BroadcastMessage<P: SchemeParams> {
    cap_k: CiphertextWire<P::Paillier>,
    cap_g: CiphertextWire<P::Paillier>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "EncProof<P>: Serialize"))]
#[serde(bound(deserialize = "EncProof<P>: for<'x> Deserialize<'x>"))]
struct Round1DirectMessage<P: SchemeParams> {
    psi0: EncProof<P>,
}

struct Round1Payload<P: SchemeParams> {
    cap_k: CiphertextWire<P::Paillier>,
    cap_g: CiphertextWire<P::Paillier>,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round1<P, I> {
    type Protocol = InteractiveSigningProtocol<P, I>;

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
        EchoBroadcast::new(
            serializer,
            Round1BroadcastMessage::<P> {
                cap_k: self.cap_k.to_wire(),
                cap_g: self.cap_g.to_wire(),
            },
        )
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
        destination: &I,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let aux = (&self.context.ssid_hash, &destination);
        let psi0 = EncProof::new(
            rng,
            EncSecretInputs {
                k: &secret_signed_from_scalar::<P>(&self.context.k),
                rho: &self.context.rho,
            },
            EncPublicInputs {
                pk0: self.context.aux_info.secret_aux.paillier_sk.public_key(),
                cap_k: &self.cap_k,
            },
            &self.public_aux(destination)?.rp_params,
            &aux,
        );

        Ok((DirectMessage::new(serializer, Round1DirectMessage::<P> { psi0 })?, None))
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &I,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        message.normal_broadcast.assert_is_none()?;

        let direct_message = message
            .direct_message
            .deserialize::<Round1DirectMessage<P>>(deserializer)?;
        let echo_broadcast = message
            .echo_broadcast
            .deserialize::<Round1BroadcastMessage<P>>(deserializer)?;

        let aux = (&self.context.ssid_hash, &self.context.my_id);

        let public_aux = self.public_aux(&self.context.my_id)?;

        let from_pk = &self.public_aux(from)?.paillier_pk;

        if !direct_message.psi0.verify(
            EncPublicInputs {
                pk0: from_pk,
                cap_k: &echo_broadcast.cap_k.to_precomputed(from_pk),
            },
            &public_aux.rp_params,
            &aux,
        ) {
            return Err(ReceiveError::protocol(InteractiveSigningError::Round1(
                "Failed to verify EncProof".into(),
            )));
        }

        Ok(Payload::new(Round1Payload::<P> {
            cap_k: echo_broadcast.cap_k,
            cap_g: echo_broadcast.cap_g,
        }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round1Payload<P>>()?;

        let (others_cap_k, others_cap_g): (BTreeMap<_, _>, BTreeMap<_, _>) = payloads
            .into_iter()
            .map(|(id, payload)| ((id.clone(), payload.cap_k), (id, payload.cap_g)))
            .unzip();

        let my_id = self.context.my_id.clone();

        let mut all_cap_k = others_cap_k
            .into_iter()
            .map(|(id, ciphertext)| {
                let paux = self.public_aux(&id)?;
                Ok((id, ciphertext.to_precomputed(&paux.paillier_pk)))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let mut all_cap_g = others_cap_g
            .into_iter()
            .map(|(id, ciphertext)| {
                let paux = self.public_aux(&id)?;
                let ciphertext_mod = ciphertext.to_precomputed(&paux.paillier_pk);
                Ok((id, ciphertext_mod))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        all_cap_k.insert(my_id.clone(), self.cap_k);
        all_cap_g.insert(my_id, self.cap_g);

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round2 {
            context: self.context,
            all_cap_k,
            all_cap_g,
        })))
    }
}

#[derive(Debug)]
struct Round2<P: SchemeParams, I: Ord> {
    context: Context<P, I>,
    all_cap_k: BTreeMap<I, Ciphertext<P::Paillier>>,
    all_cap_g: BTreeMap<I, Ciphertext<P::Paillier>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    CiphertextWire<P::Paillier>: Serialize,
    AffGProof<P>: Serialize,
    LogStarProof<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    CiphertextWire<P::Paillier>: for<'x> Deserialize<'x>,
    AffGProof<P>: for<'x> Deserialize<'x>,
    LogStarProof<P>: for<'x> Deserialize<'x>,
"))]
struct Round2Message<P: SchemeParams> {
    cap_gamma: Point,
    cap_d: CiphertextWire<P::Paillier>,
    hat_cap_d: CiphertextWire<P::Paillier>,
    cap_f: CiphertextWire<P::Paillier>,
    hat_cap_f: CiphertextWire<P::Paillier>,
    psi: AffGProof<P>,
    hat_psi: AffGProof<P>,
    hat_psi_prime: LogStarProof<P>,
}

#[derive(Debug, Clone)]
struct Round2Artifact<P: SchemeParams> {
    beta: SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    hat_beta: SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    r: Randomizer<P::Paillier>,
    s: Randomizer<P::Paillier>,
    hat_r: Randomizer<P::Paillier>,
    hat_s: Randomizer<P::Paillier>,
    cap_d: Ciphertext<P::Paillier>,
    cap_f: Ciphertext<P::Paillier>,
    hat_cap_d: Ciphertext<P::Paillier>,
    hat_cap_f: Ciphertext<P::Paillier>,
}

struct Round2Payload<P: SchemeParams> {
    cap_gamma: Point,
    alpha: SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    hat_alpha: SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    cap_d: Ciphertext<P::Paillier>,
    hat_cap_d: Ciphertext<P::Paillier>,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round2<P, I> {
    type Protocol = InteractiveSigningProtocol<P, I>;

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

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
        destination: &I,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let aux = (&self.context.ssid_hash, &self.context.my_id);

        let cap_gamma = self.context.gamma.mul_by_generator();
        let pk = self.context.aux_info.secret_aux.paillier_sk.public_key();

        let target_pk = &self.context.public_aux(destination)?.paillier_pk;

        let beta = SecretSigned::random_in_exp_range(rng, P::LP_BOUND);
        let hat_beta = SecretSigned::random_in_exp_range(rng, P::LP_BOUND);
        let r = Randomizer::random(rng, pk);
        let s = Randomizer::random(rng, target_pk);
        let hat_r = Randomizer::random(rng, pk);
        let hat_s = Randomizer::random(rng, target_pk);

        let gamma = secret_signed_from_scalar::<P>(&self.context.gamma);
        let x = secret_signed_from_scalar::<P>(&self.context.key_share.secret_share);

        let others_cap_k = self
            .all_cap_k
            .get(destination)
            .ok_or(LocalError::new("destination={destination:?} is missing in all_cap_k"))?;

        let cap_f = Ciphertext::new_with_randomizer_signed(pk, &beta, &r);
        let cap_d = others_cap_k * &gamma + Ciphertext::new_with_randomizer_signed(target_pk, &-&beta, &s);

        let hat_cap_f = Ciphertext::new_with_randomizer_signed(pk, &hat_beta, &hat_r);
        let hat_cap_d = others_cap_k * &secret_signed_from_scalar::<P>(&self.context.key_share.secret_share)
            + Ciphertext::new_with_randomizer_signed(target_pk, &-&hat_beta, &hat_s);

        let cap_g = self.all_cap_g.get(&self.context.my_id).ok_or(LocalError::new(format!(
            "my_id={:?} is missing in all_cap_g",
            &self.context.my_id
        )))?;

        let rp = &self.context.public_aux(destination)?.rp_params;

        let psi = AffGProof::new(
            rng,
            AffGSecretInputs {
                x: &gamma,
                y: &beta,
                rho: &s,
                rho_y: &r,
            },
            AffGPublicInputs {
                pk0: target_pk,
                pk1: pk,
                cap_c: others_cap_k,
                cap_d: &cap_d,
                cap_y: &cap_f,
                cap_x: &cap_gamma,
            },
            rp,
            &aux,
        );

        let hat_psi = AffGProof::new(
            rng,
            AffGSecretInputs {
                x: &x,
                y: &hat_beta,
                rho: &hat_s,
                rho_y: &hat_r,
            },
            AffGPublicInputs {
                pk0: target_pk,
                pk1: pk,
                cap_c: others_cap_k,
                cap_d: &hat_cap_d,
                cap_y: &hat_cap_f,
                cap_x: self.context.public_share(&self.context.my_id)?,
            },
            rp,
            &aux,
        );

        let hat_psi_prime = LogStarProof::new(
            rng,
            LogStarSecretInputs {
                x: &gamma,
                rho: &self.context.nu,
            },
            LogStarPublicInputs {
                pk0: pk,
                cap_c: cap_g,
                g: &Point::GENERATOR,
                cap_x: &cap_gamma,
            },
            rp,
            &aux,
        );

        let msg = DirectMessage::new(
            serializer,
            Round2Message::<P> {
                cap_gamma,
                cap_d: cap_d.to_wire(),
                cap_f: cap_f.to_wire(),
                hat_cap_d: hat_cap_d.to_wire(),
                hat_cap_f: hat_cap_f.to_wire(),
                psi,
                hat_psi,
                hat_psi_prime,
            },
        )?;

        let artifact = Artifact::new(Round2Artifact::<P> {
            beta,
            hat_beta,
            r,
            s,
            hat_r,
            hat_s,
            cap_d,
            cap_f,
            hat_cap_d,
            hat_cap_f,
        });

        Ok((msg, Some(artifact)))
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &I,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        message.echo_broadcast.assert_is_none()?;
        message.normal_broadcast.assert_is_none()?;
        let direct_message = message.direct_message.deserialize::<Round2Message<P>>(deserializer)?;

        let aux = (&self.context.ssid_hash, from);
        let pk = self.context.aux_info.secret_aux.paillier_sk.public_key();
        let from_pk = &self.context.public_aux(from)?.paillier_pk;

        let cap_x = self.context.public_share(from)?;

        let rp = &self.context.public_aux(&self.context.my_id)?.rp_params;

        let cap_d = direct_message.cap_d.to_precomputed(pk);
        let hat_cap_d = direct_message.hat_cap_d.to_precomputed(pk);

        let my_cap_k = self
            .all_cap_k
            .get(&self.context.my_id)
            .ok_or(LocalError::new("my_id={my_id:?} is missing in all_cap_k"))?;
        let cap_g = self
            .all_cap_g
            .get(from)
            .ok_or(LocalError::new("from={from:?} is missing in all_cap_g"))?;

        if !direct_message.psi.verify(
            AffGPublicInputs {
                pk0: pk,
                pk1: from_pk,
                cap_c: my_cap_k,
                cap_d: &cap_d,
                cap_y: &direct_message.cap_f.to_precomputed(from_pk),
                cap_x: &direct_message.cap_gamma,
            },
            rp,
            &aux,
        ) {
            return Err(ReceiveError::protocol(InteractiveSigningError::Round2(
                "Failed to verify AffGProof (psi)".into(),
            )));
        }

        if !direct_message.hat_psi.verify(
            AffGPublicInputs {
                pk0: pk,
                pk1: from_pk,
                cap_c: my_cap_k,
                cap_d: &hat_cap_d,
                cap_y: &direct_message.hat_cap_f.to_precomputed(from_pk),
                cap_x,
            },
            rp,
            &aux,
        ) {
            return Err(ReceiveError::protocol(InteractiveSigningError::Round2(
                "Failed to verify AffGProof (hat_psi)".into(),
            )));
        }

        if !direct_message.hat_psi_prime.verify(
            LogStarPublicInputs {
                pk0: from_pk,
                cap_c: cap_g,
                g: &Point::GENERATOR,
                cap_x: &direct_message.cap_gamma,
            },
            rp,
            &aux,
        ) {
            return Err(ReceiveError::protocol(InteractiveSigningError::Round2(
                "Failed to verify LogStarProof".into(),
            )));
        }

        let alpha = cap_d.decrypt_signed(&self.context.aux_info.secret_aux.paillier_sk);
        let hat_alpha = hat_cap_d.decrypt_signed(&self.context.aux_info.secret_aux.paillier_sk);

        // `alpha == x * y + z` where `0 <= x, y < q`, and `-2^l' <= z <= 2^l'`,
        // where `q` is the curve order.
        // We will need this bound later, so we're asserting it.
        let alpha = Option::from(alpha.ensure_bound(core::cmp::max(2 * P::L_BOUND, P::LP_BOUND) + 1))
            .ok_or_else(|| ReceiveError::protocol(InteractiveSigningError::OutOfBoundsAlpha))?;
        let hat_alpha = Option::from(hat_alpha.ensure_bound(core::cmp::max(2 * P::L_BOUND, P::LP_BOUND) + 1))
            .ok_or_else(|| ReceiveError::protocol(InteractiveSigningError::OutOfBoundsHatAlpha))?;

        Ok(Payload::new(Round2Payload::<P> {
            cap_gamma: direct_message.cap_gamma,
            alpha,
            hat_alpha,
            cap_d,
            hat_cap_d,
        }))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round2Payload<P>>()?;
        let artifacts = artifacts.downcast_all::<Round2Artifact<P>>()?;

        let cap_gamma =
            payloads.values().map(|payload| payload.cap_gamma).sum::<Point>() + self.context.gamma.mul_by_generator();

        let cap_delta = cap_gamma * &self.context.k;

        let alpha_sum: SecretSigned<_> = payloads.values().map(|payload| &payload.alpha).sum();
        let beta_sum: SecretSigned<_> = artifacts.values().map(|artifact| &artifact.beta).sum();
        let delta = secret_signed_from_scalar::<P>(&self.context.gamma)
            * secret_signed_from_scalar::<P>(&self.context.k)
            + &alpha_sum
            + &beta_sum;

        let hat_alpha_sum: SecretSigned<_> = payloads.values().map(|payload| &payload.hat_alpha).sum();
        let hat_beta_sum: SecretSigned<_> = artifacts.values().map(|artifact| &artifact.hat_beta).sum();
        let chi = secret_signed_from_scalar::<P>(&self.context.key_share.secret_share)
            * secret_signed_from_scalar::<P>(&self.context.k)
            + &hat_alpha_sum
            + &hat_beta_sum;

        let (cap_ds, hat_cap_ds) = payloads
            .into_iter()
            .map(|(id, payload)| ((id.clone(), payload.cap_d), (id, payload.hat_cap_d)))
            .unzip();

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round3 {
            context: self.context,
            delta,
            chi,
            cap_delta,
            cap_gamma,
            all_cap_k: self.all_cap_k,
            all_cap_g: self.all_cap_g,
            cap_ds,
            hat_cap_ds,
            round2_artifacts: artifacts,
        })))
    }
}

#[derive(Debug)]
struct Round3<P: SchemeParams, I: Ord> {
    context: Context<P, I>,
    delta: SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    chi: SecretSigned<<P::Paillier as PaillierParams>::Uint>,
    cap_delta: Point,
    cap_gamma: Point,
    all_cap_k: BTreeMap<I, Ciphertext<P::Paillier>>,
    all_cap_g: BTreeMap<I, Ciphertext<P::Paillier>>,
    cap_ds: BTreeMap<I, Ciphertext<P::Paillier>>,
    hat_cap_ds: BTreeMap<I, Ciphertext<P::Paillier>>,
    round2_artifacts: BTreeMap<I, Round2Artifact<P>>,
}

impl<P: SchemeParams, I: Ord + Debug> Round3<P, I> {
    fn public_aux(&self, i: &I) -> Result<&PublicAuxInfoPrecomputed<P>, LocalError> {
        self.context
            .aux_info
            .public_aux
            .get(i)
            .ok_or_else(|| LocalError::new(format!("Missing public_aux for party Id {i:?}")))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "LogStarProof<P>: Serialize"))]
#[serde(bound(deserialize = "LogStarProof<P>: for<'x> Deserialize<'x>"))]
struct Round3Message<P: SchemeParams> {
    delta: Secret<Scalar>,
    cap_delta: Point,
    psi_pprime: LogStarProof<P>,
}

struct Round3Payload {
    delta: Secret<Scalar>,
    cap_delta: Point,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round3<P, I> {
    type Protocol = InteractiveSigningProtocol<P, I>;

    fn id(&self) -> RoundId {
        3.into()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [4.into()].into()
    }

    fn message_destinations(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn expecting_messages_from(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
        destination: &I,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let aux = (&self.context.ssid_hash, &self.context.my_id);
        let pk = &self.context.aux_info.secret_aux.paillier_sk.public_key();

        let rp = &self.public_aux(destination)?.rp_params;

        let cap_k = self.all_cap_k.get(&self.context.my_id).ok_or(LocalError::new(format!(
            "my_id={:?} is missing in all_cap_k",
            &self.context.my_id
        )))?;

        let psi_pprime = LogStarProof::new(
            rng,
            LogStarSecretInputs {
                x: &secret_signed_from_scalar::<P>(&self.context.k),
                rho: &self.context.rho,
            },
            LogStarPublicInputs {
                pk0: pk,
                cap_c: cap_k,
                g: &self.cap_gamma,
                cap_x: &self.cap_delta,
            },
            rp,
            &aux,
        );

        let dm = DirectMessage::new(
            serializer,
            Round3Message::<P> {
                delta: secret_scalar_from_signed::<P>(&self.delta),
                cap_delta: self.cap_delta,
                psi_pprime,
            },
        )?;

        Ok((dm, None))
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &I,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        message.echo_broadcast.assert_is_none()?;
        message.normal_broadcast.assert_is_none()?;
        let direct_message = message.direct_message.deserialize::<Round3Message<P>>(deserializer)?;

        let aux = (&self.context.ssid_hash, &from);
        let from_pk = &self.public_aux(from)?.paillier_pk;

        let others_cap_k = self
            .all_cap_k
            .get(from)
            .ok_or(LocalError::new("from={from:?} is missing in all_cap_k"))?;

        let rp = &self.public_aux(&self.context.my_id)?.rp_params;

        if !direct_message.psi_pprime.verify(
            LogStarPublicInputs {
                pk0: from_pk,
                cap_c: others_cap_k,
                g: &self.cap_gamma,
                cap_x: &direct_message.cap_delta,
            },
            rp,
            &aux,
        ) {
            return Err(ReceiveError::protocol(InteractiveSigningError::Round3(
                "Failed to verify Log-Star proof".into(),
            )));
        }
        Ok(Payload::new(Round3Payload {
            delta: direct_message.delta,
            cap_delta: direct_message.cap_delta,
        }))
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round3Payload>()?;

        let (deltas, cap_deltas): (BTreeMap<_, _>, BTreeMap<_, _>) = payloads
            .into_iter()
            .map(|(id, payload)| ((id.clone(), payload.delta), (id, payload.cap_delta)))
            .unzip();

        let scalar_delta = secret_scalar_from_signed::<P>(&self.delta);
        let assembled_delta: Secret<Scalar> = &scalar_delta + deltas.values().sum::<Secret<Scalar>>();
        let assembled_cap_delta: Point = self.cap_delta + cap_deltas.values().sum();

        if assembled_delta.mul_by_generator() == assembled_cap_delta {
            let inv_delta = assembled_delta.invert().ok_or_else(|| {
                LocalError::new(concat![
                    "The assembled delta is zero. ",
                    "Either all other nodes are malicious, or it's a freak accident. ",
                    "Restart the protocol."
                ])
            })?;
            let nonce = (self.cap_gamma * inv_delta).x_coordinate();
            let my_id = self.context.my_id.clone();

            let values = self
                .round2_artifacts
                .into_iter()
                .map(|(id, artifact)| {
                    let cap_k = self
                        .all_cap_k
                        .get(&id)
                        .ok_or_else(|| LocalError::new("id={id:?} is missing in all_cap_k"))?
                        .clone();
                    let hat_cap_d_received = self
                        .hat_cap_ds
                        .get(&id)
                        .ok_or_else(|| LocalError::new("id={id:?} is missing in hat_cap_ds"))?
                        .clone();
                    let values = PresigningValues {
                        hat_beta: artifact.hat_beta,
                        hat_r: artifact.hat_r,
                        hat_s: artifact.hat_s,
                        cap_k,
                        hat_cap_d_received,
                        hat_cap_d: artifact.hat_cap_d,
                        hat_cap_f: artifact.hat_cap_f,
                    };
                    Ok((id, values))
                })
                .collect::<Result<_, LocalError>>()?;

            let presigning_data = PresigningData {
                nonce,
                ephemeral_scalar_share: self.context.k.clone(),
                product_share: secret_scalar_from_signed::<P>(&self.chi),
                product_share_nonreduced: self.chi,
                cap_k: self
                    .all_cap_k
                    .get(&my_id)
                    .ok_or_else(|| LocalError::new("m_id={my_id:?} is missing in all_cap_k"))?
                    .clone(),
                values,
            };

            return Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round4::new(
                self.context,
                presigning_data,
            ))));
        }

        // Construct the correctness proofs

        let sk = &self.context.aux_info.secret_aux.paillier_sk;
        let pk = sk.public_key();

        let aux = (&self.context.ssid_hash, &self.context.my_id);

        // Aff-g proofs

        let mut aff_g_proofs = Vec::new();

        let cap_gamma = self.context.gamma.mul_by_generator();

        for (id_j, (_, r2_artifacts)) in self.context.other_ids.iter().zip(self.round2_artifacts.iter()) {
            let cap_c = self
                .all_cap_k
                .get(id_j)
                .ok_or_else(|| LocalError::new("id_j={id_j:?} is missing in all_cap_k"))?;
            for id_l in self.context.other_ids.iter().filter(|id| *id != id_j) {
                let paux = self.public_aux(id_j)?;
                let target_pk = &paux.paillier_pk;
                let rp = &paux.rp_params;

                let beta = &r2_artifacts.beta;
                let r = &r2_artifacts.r;
                let s = &r2_artifacts.s;

                let p_aff_g = AffGProof::<P>::new(
                    rng,
                    AffGSecretInputs {
                        x: &secret_signed_from_scalar::<P>(&self.context.gamma),
                        y: beta,
                        rho: s,
                        rho_y: r,
                    },
                    AffGPublicInputs {
                        pk0: target_pk,
                        pk1: pk,
                        cap_c,
                        cap_d: &r2_artifacts.cap_d,
                        cap_y: &r2_artifacts.cap_f,
                        cap_x: &cap_gamma,
                    },
                    rp,
                    &aux,
                );

                assert!(p_aff_g.verify(
                    AffGPublicInputs {
                        pk0: target_pk,
                        pk1: pk,
                        cap_c,
                        cap_d: &r2_artifacts.cap_d,
                        cap_y: &r2_artifacts.cap_f,
                        cap_x: &cap_gamma
                    },
                    rp,
                    &aux,
                ));

                aff_g_proofs.push((id_j.clone(), id_l.clone(), p_aff_g));
            }
        }

        // Mul proof
        let my_id = &self.context.my_id;
        let rho = Randomizer::random(rng, pk);
        let cap_k = self
            .all_cap_k
            .get(my_id)
            .ok_or_else(|| LocalError::new("my_id={my_id:?} is missing in all_cap_k"))?;
        let cap_g = self
            .all_cap_g
            .get(my_id)
            .ok_or_else(|| LocalError::new("my_id={my_id:?} is missing in all_cap_g"))?;
        let cap_h = (cap_g * &secret_unsigned_from_scalar::<P>(&self.context.k)).mul_randomizer(&rho);

        let p_mul = MulProof::<P>::new(
            rng,
            MulSecretInputs {
                x: &secret_signed_from_scalar::<P>(&self.context.k),
                rho_x: &self.context.rho,
                rho: &rho,
            },
            MulPublicInputs {
                pk,
                cap_x: cap_k,
                cap_y: cap_g,
                cap_c: &cap_h,
            },
            &aux,
        );
        assert!(p_mul.verify(
            MulPublicInputs {
                pk,
                cap_x: cap_k,
                cap_y: cap_g,
                cap_c: &cap_h
            },
            &aux
        ));

        // Dec proof

        let mut ciphertext = cap_h.clone();

        for id_j in self.context.other_ids.iter() {
            let cap_d = self
                .cap_ds
                .get(id_j)
                .ok_or_else(|| LocalError::new(format!("Missing `D` for {id_j:?}")))?;
            let artifact_j = self
                .round2_artifacts
                .get(id_j)
                .ok_or_else(|| LocalError::new(format!("Missing Round 2 artifact for {id_j:?}")))?;
            ciphertext = ciphertext + cap_d + &artifact_j.cap_f;
        }

        let rho = ciphertext.derive_randomizer(sk);

        let mut dec_proofs = Vec::new();
        for id_j in self.context.other_ids.iter() {
            let p_dec = DecProof::<P>::new(
                rng,
                DecSecretInputs {
                    y: &self.delta,
                    rho: &rho,
                },
                DecPublicInputs {
                    pk0: pk,
                    x: scalar_delta.expose_secret(),
                    cap_c: &ciphertext,
                },
                &self.public_aux(id_j)?.rp_params,
                &aux,
            );
            assert!(p_dec.verify(
                DecPublicInputs {
                    pk0: pk,
                    x: scalar_delta.expose_secret(),
                    cap_c: &ciphertext
                },
                &self.public_aux(id_j)?.rp_params,
                &aux
            ));
            dec_proofs.push((id_j.clone(), p_dec));
        }

        unimplemented!()
    }
}

#[derive(Debug)]
struct Round4<P: SchemeParams, I: Ord> {
    context: Context<P, I>,
    presigning: PresigningData<P, I>,
    r: Scalar,
    sigma: Scalar,
}

impl<P, I> Round4<P, I>
where
    P: SchemeParams,
    I: PartyId,
{
    fn new(context: Context<P, I>, presigning: PresigningData<P, I>) -> Self {
        let r = presigning.nonce;
        let sigma =
            *(&presigning.ephemeral_scalar_share * context.message + &presigning.product_share * r).expose_secret();
        Self {
            context,
            presigning,
            r,
            sigma,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Round4Message {
    pub(crate) sigma: Scalar,
}

struct Round4Payload {
    sigma: Scalar,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round4<P, I> {
    type Protocol = InteractiveSigningProtocol<P, I>;

    fn id(&self) -> RoundId {
        4.into()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [5.into()].into()
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
        NormalBroadcast::new(serializer, Round4Message { sigma: self.sigma })
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        _from: &I,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        message.echo_broadcast.assert_is_none()?;
        message.direct_message.assert_is_none()?;
        let normal_broadcast = message.normal_broadcast.deserialize::<Round4Message>(deserializer)?;

        Ok(Payload::new(Round4Payload {
            sigma: normal_broadcast.sigma,
        }))
    }

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        let payloads = payloads.downcast_all::<Round4Payload>()?;

        let assembled_sigma = payloads.values().map(|payload| payload.sigma).sum::<Scalar>() + self.sigma;

        let signature = RecoverableSignature::from_scalars(
            &self.r,
            &assembled_sigma,
            &self.context.key_share.verifying_key_as_point(),
            &self.context.message,
        );

        if let Some(signature) = signature {
            return Ok(FinalizeOutcome::Result(signature));
        }

        let my_id = self.context.my_id.clone();
        let aux = (&self.context.ssid_hash, &my_id);

        let sk = &self.context.aux_info.secret_aux.paillier_sk;
        let pk = sk.public_key();

        // Aff-g proofs

        let mut aff_g_proofs = Vec::new();

        for id_j in self.context.other_ids.iter() {
            for id_l in self.context.other_ids.iter().filter(|id| *id != id_j) {
                let target_pk = &self.context.public_aux(id_j)?.paillier_pk;
                let rp = &self.context.public_aux(id_l)?.rp_params;

                let values = self
                    .presigning
                    .values
                    .get(id_j)
                    .ok_or_else(|| LocalError::new("Missing presigning values for {id_j:?}"))?;

                let p_aff_g = AffGProof::<P>::new(
                    rng,
                    AffGSecretInputs {
                        x: &secret_signed_from_scalar::<P>(&self.context.key_share.secret_share),
                        y: &values.hat_beta,
                        rho: &values.hat_s,
                        rho_y: &values.hat_r,
                    },
                    AffGPublicInputs {
                        pk0: target_pk,
                        pk1: pk,
                        cap_c: &values.cap_k,
                        cap_d: &values.hat_cap_d,
                        cap_y: &values.hat_cap_f,
                        cap_x: self.context.public_share(&my_id)?,
                    },
                    rp,
                    &aux,
                );

                assert!(p_aff_g.verify(
                    AffGPublicInputs {
                        pk0: target_pk,
                        pk1: pk,
                        cap_c: &values.cap_k,
                        cap_d: &values.hat_cap_d,
                        cap_y: &values.hat_cap_f,
                        cap_x: self.context.public_share(&my_id)?
                    },
                    rp,
                    &aux,
                ));

                aff_g_proofs.push((id_j.clone(), id_l.clone(), p_aff_g));
            }
        }

        // mul* proofs

        let x = &self.context.key_share.secret_share;
        let cap_x = self.context.public_share(&my_id)?;

        let rho = Randomizer::random(rng, pk);
        let hat_cap_h = (&self.presigning.cap_k * &secret_unsigned_from_scalar::<P>(x)).mul_randomizer(&rho);

        let aux = (&self.context.ssid_hash, &my_id);

        let mut mul_star_proofs = Vec::new();

        for id_l in self.context.other_ids.iter() {
            let paux = self.context.public_aux(id_l)?;
            let p_mul = MulStarProof::<P>::new(
                rng,
                MulStarSecretInputs {
                    x: &secret_signed_from_scalar::<P>(x),
                    rho: &rho,
                },
                MulStarPublicInputs {
                    pk0: pk,
                    cap_c: &self.presigning.cap_k,
                    cap_d: &hat_cap_h,
                    cap_x,
                },
                &paux.rp_params,
                &aux,
            );

            assert!(p_mul.verify(
                MulStarPublicInputs {
                    pk0: pk,
                    cap_c: &self.presigning.cap_k,
                    cap_d: &hat_cap_h,
                    cap_x
                },
                &paux.rp_params,
                &aux,
            ));

            mul_star_proofs.push((id_l.clone(), p_mul));
        }

        // dec proofs

        let mut ciphertext = hat_cap_h.clone();
        for id_j in self.context.other_ids.iter() {
            let values = &self
                .presigning
                .values
                .get(id_j)
                .ok_or_else(|| LocalError::new(format!("Missing presigning values for {id_j:?}")))?;
            ciphertext = ciphertext + &values.hat_cap_d_received + &values.hat_cap_f;
        }

        let r = self.presigning.nonce;
        let signed_r = public_signed_from_scalar::<P>(&r);
        let signed_message = public_signed_from_scalar::<P>(&self.context.message);

        let ciphertext = ciphertext * &signed_r + &self.presigning.cap_k * &signed_message;

        let rho = ciphertext.derive_randomizer(sk);
        // This is the same as `s_part` but if all the calculations were performed
        // without reducing modulo curve order.
        let s_part_nonreduced = secret_signed_from_scalar::<P>(&self.presigning.ephemeral_scalar_share)
            * signed_message
            + &self.presigning.product_share_nonreduced * signed_r;

        let mut dec_proofs = Vec::new();
        for id_l in self.context.other_ids.iter() {
            let paux = self.context.public_aux(id_l)?;
            let p_dec = DecProof::<P>::new(
                rng,
                DecSecretInputs {
                    y: &s_part_nonreduced,
                    rho: &rho,
                },
                DecPublicInputs {
                    pk0: pk,
                    x: &self.sigma,
                    cap_c: &ciphertext,
                },
                &paux.rp_params,
                &aux,
            );
            assert!(p_dec.verify(
                DecPublicInputs {
                    pk0: pk,
                    x: &self.sigma,
                    cap_c: &ciphertext
                },
                &paux.rp_params,
                &aux,
            ));
            dec_proofs.push((id_l.clone(), p_dec));
        }

        Ok(FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(
            SigningErrorRound { context: self.context },
        )))
    }
}

#[derive(Debug)]
struct SigningErrorRound<P: SchemeParams, I: PartyId> {
    context: Context<P, I>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SigningErrorMessage<P: SchemeParams, I: PartyId>(PhantomData<(P, I)>);

impl<P: SchemeParams, I: PartyId> Round<I> for SigningErrorRound<P, I> {
    type Protocol = InteractiveSigningProtocol<P, I>;

    fn id(&self) -> RoundId {
        5.into()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [].into()
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
        EchoBroadcast::new(serializer, SigningErrorMessage::<P, I>(PhantomData))
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        _from: &I,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        message.normal_broadcast.assert_is_none()?;
        message.direct_message.assert_is_none()?;
        let _echo_broadcast = message
            .echo_broadcast
            .deserialize::<SigningErrorMessage<P, I>>(deserializer)?;
        Err(ReceiveError::protocol(InteractiveSigningError::SigningError(
            "Signing error stub".into(),
        )))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        Err(LocalError::new(
            "One of the messages should have been missing or invalid",
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
    use manul::{
        dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
        signature::Keypair,
    };
    use rand_core::{OsRng, RngCore};

    use super::InteractiveSigning;
    use crate::cggmp21::{AuxInfo, KeyShare, TestParams};

    #[test]
    fn execute_interactive_signing() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers.iter().map(|signer| signer.verifying_key()).collect::<Vec<_>>();
        let ids_set = BTreeSet::from_iter(ids.clone());

        let key_shares = KeyShare::<TestParams, TestVerifier>::new_centralized(&mut OsRng, &ids_set, None);
        let aux_infos = AuxInfo::new_centralized(&mut OsRng, &ids_set);

        let mut message = [0u8; 32];
        OsRng.fill_bytes(&mut message);

        let entry_points = signers
            .into_iter()
            .map(|signer| {
                let id = signer.verifying_key();
                let entry_point = InteractiveSigning::new(message, key_shares[&id].clone(), aux_infos[&id].clone());
                (signer, entry_point)
            })
            .collect();

        let signatures = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
            .unwrap()
            .results()
            .unwrap();

        for signature in signatures.values() {
            let (sig, rec_id) = signature.to_backend();

            let vkey = key_shares[&ids[0]].verifying_key().unwrap();

            // Check that the signature can be verified
            vkey.verify_prehash(&message, &sig).unwrap();

            // Check that the key can be recovered
            let recovered_key = VerifyingKey::recover_from_prehash(&message, &sig, rec_id).unwrap();
            assert_eq!(recovered_key, vkey);
        }
    }
}
