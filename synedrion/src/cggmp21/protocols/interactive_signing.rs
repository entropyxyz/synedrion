//! Merged Presigning and Signing protocols,
//! in the paper ECDSA Pre-Signing (Fig. 7) and Signing (Fig. 8).

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
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use super::super::{
    entities::{AuxInfoPrecomputed, PresigningData, PresigningValues},
    sigma::{AffGProof, DecProof, EncProof, LogStarProof, MulProof, MulStarProof},
    AuxInfo, KeyShare, SchemeParams,
};
use crate::{
    curve::{Point, RecoverableSignature, Scalar},
    paillier::{Ciphertext, CiphertextMod, PaillierParams, Randomizer, RandomizerMod},
    tools::{
        hashing::{Chain, FofHasher, HashOutput},
        DowncastMap, Without,
    },
    uint::Signed,
};

/// A protocol for creating all the data necessary for signing
/// that doesn't require knowing the actual message being signed.
#[derive(Debug, Clone, Copy)]
pub struct InteractiveSigningProtocol<P: SchemeParams, I: Debug>(PhantomData<(P, I)>);

impl<P: SchemeParams, I: PartyId> Protocol for InteractiveSigningProtocol<P, I> {
    type Result = RecoverableSignature;
    type ProtocolError = InteractiveSigningError;
}

/// Possible verifiable errors of the Presigning protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InteractiveSigningError {
    /// An error in Round 1.
    Round1(String),
    /// An error in Round 2.
    Round2(String),
    /// An error in Round 3.
    Round3(String),
    /// An error in the signing error round.
    SigningError(String),
    OutOfBoundsAlpha,
    OutOfBoundsHatAlpha,
}

impl ProtocolError for InteractiveSigningError {
    fn description(&self) -> String {
        "".into()
    }

    fn required_direct_messages(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    fn required_echo_broadcasts(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    fn required_combined_echos(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
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

        let aux_info = aux_info.to_precomputed();

        // TODO (#68): check that KeyShare is consistent with AuxInfo

        // The share of an ephemeral scalar
        let k = Scalar::random(rng);
        // The share of the mask used to generate the inverse of the ephemeral scalar
        let gamma = Scalar::random(rng);

        let pk = aux_info.secret_aux.paillier_sk.public_key();

        let nu = RandomizerMod::<P::Paillier>::random(rng, pk);
        let cap_g = CiphertextMod::new_with_randomizer(pk, &P::uint_from_scalar(&gamma), &nu.retrieve());

        let rho = RandomizerMod::<P::Paillier>::random(rng, pk);
        let cap_k = CiphertextMod::new_with_randomizer(pk, &P::uint_from_scalar(&k), &rho.retrieve());

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
    k: Scalar,
    gamma: Scalar,
    rho: RandomizerMod<P::Paillier>,
    nu: RandomizerMod<P::Paillier>,
}

#[derive(Debug)]
struct Round1<P: SchemeParams, I: Ord> {
    context: Context<P, I>,
    cap_k: CiphertextMod<P::Paillier>,
    cap_g: CiphertextMod<P::Paillier>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "Ciphertext<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "Ciphertext<P::Paillier>: for<'x> Deserialize<'x>"))]
struct Round1BroadcastMessage<P: SchemeParams> {
    cap_k: Ciphertext<P::Paillier>,
    cap_g: Ciphertext<P::Paillier>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "EncProof<P>: Serialize"))]
#[serde(bound(deserialize = "EncProof<P>: for<'x> Deserialize<'x>"))]
struct Round1DirectMessage<P: SchemeParams> {
    psi0: EncProof<P>,
}

struct Round1Payload<P: SchemeParams> {
    cap_k: Ciphertext<P::Paillier>,
    cap_g: Ciphertext<P::Paillier>,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round1<P, I> {
    type Protocol = InteractiveSigningProtocol<P, I>;

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
        EchoBroadcast::new(
            serializer,
            Round1BroadcastMessage::<P> {
                cap_k: self.cap_k.retrieve(),
                cap_g: self.cap_g.retrieve(),
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
            &P::signed_from_scalar(&self.context.k),
            &self.context.rho,
            self.context.aux_info.secret_aux.paillier_sk.public_key(),
            &self.cap_k,
            &self.context.aux_info.public_aux[destination].rp_params,
            &aux,
        );

        Ok((DirectMessage::new(serializer, Round1DirectMessage::<P> { psi0 })?, None))
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

        let direct_message = direct_message.deserialize::<Round1DirectMessage<P>>(deserializer)?;
        let echo_broadcast = echo_broadcast.deserialize::<Round1BroadcastMessage<P>>(deserializer)?;

        let aux = (&self.context.ssid_hash, &self.context.my_id);

        let public_aux = &self.context.aux_info.public_aux[&self.context.my_id];

        let from_pk = &self.context.aux_info.public_aux[from].paillier_pk;

        if !direct_message.psi0.verify(
            from_pk,
            &echo_broadcast.cap_k.to_mod(from_pk),
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
                let ciphertext_mod = ciphertext.to_mod(&self.context.aux_info.public_aux[&id].paillier_pk);
                (id, ciphertext_mod)
            })
            .collect::<BTreeMap<_, _>>();
        all_cap_k.insert(my_id.clone(), self.cap_k);

        let mut all_cap_g = others_cap_g
            .into_iter()
            .map(|(id, ciphertext)| {
                let ciphertext_mod = ciphertext.to_mod(&self.context.aux_info.public_aux[&id].paillier_pk);
                (id, ciphertext_mod)
            })
            .collect::<BTreeMap<_, _>>();
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
    all_cap_k: BTreeMap<I, CiphertextMod<P::Paillier>>,
    all_cap_g: BTreeMap<I, CiphertextMod<P::Paillier>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    Ciphertext<P::Paillier>: Serialize,
    AffGProof<P>: Serialize,
    LogStarProof<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    Ciphertext<P::Paillier>: for<'x> Deserialize<'x>,
    AffGProof<P>: for<'x> Deserialize<'x>,
    LogStarProof<P>: for<'x> Deserialize<'x>,
"))]
struct Round2Message<P: SchemeParams> {
    cap_gamma: Point,
    cap_d: Ciphertext<P::Paillier>,
    hat_cap_d: Ciphertext<P::Paillier>,
    cap_f: Ciphertext<P::Paillier>,
    hat_cap_f: Ciphertext<P::Paillier>,
    psi: AffGProof<P>,
    hat_psi: AffGProof<P>,
    hat_psi_prime: LogStarProof<P>,
}

#[derive(Debug, Clone)]
struct Round2Artifact<P: SchemeParams> {
    beta: SecretBox<Signed<<P::Paillier as PaillierParams>::Uint>>,
    hat_beta: SecretBox<Signed<<P::Paillier as PaillierParams>::Uint>>,
    r: Randomizer<P::Paillier>,
    s: Randomizer<P::Paillier>,
    hat_r: Randomizer<P::Paillier>,
    hat_s: Randomizer<P::Paillier>,
    cap_d: CiphertextMod<P::Paillier>,
    cap_f: CiphertextMod<P::Paillier>,
    hat_cap_d: CiphertextMod<P::Paillier>,
    hat_cap_f: CiphertextMod<P::Paillier>,
}

struct Round2Payload<P: SchemeParams> {
    cap_gamma: Point,
    alpha: Signed<<P::Paillier as PaillierParams>::Uint>,
    hat_alpha: Signed<<P::Paillier as PaillierParams>::Uint>,
    cap_d: CiphertextMod<P::Paillier>,
    hat_cap_d: CiphertextMod<P::Paillier>,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round2<P, I> {
    type Protocol = InteractiveSigningProtocol<P, I>;

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

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
        destination: &I,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        let aux = (&self.context.ssid_hash, &self.context.my_id);

        let cap_gamma = self.context.gamma.mul_by_generator();
        let pk = self.context.aux_info.secret_aux.paillier_sk.public_key();

        let target_pk = &self.context.aux_info.public_aux[destination].paillier_pk;

        let beta = SecretBox::new(Box::new(Signed::random_bounded_bits(rng, P::LP_BOUND)));
        let hat_beta = SecretBox::new(Box::new(Signed::random_bounded_bits(rng, P::LP_BOUND)));
        let r = RandomizerMod::random(rng, pk);
        let s = RandomizerMod::random(rng, target_pk);
        let hat_r = RandomizerMod::random(rng, pk);
        let hat_s = RandomizerMod::random(rng, target_pk);

        let cap_f = CiphertextMod::new_with_randomizer_signed(pk, beta.expose_secret(), &r.retrieve());
        let cap_d = &self.all_cap_k[destination] * P::signed_from_scalar(&self.context.gamma)
            + CiphertextMod::new_with_randomizer_signed(target_pk, &-beta.expose_secret(), &s.retrieve());

        let hat_cap_f = CiphertextMod::new_with_randomizer_signed(pk, hat_beta.expose_secret(), &hat_r.retrieve());
        let hat_cap_d = &self.all_cap_k[destination]
            * P::signed_from_scalar(self.context.key_share.secret_share.expose_secret())
            + CiphertextMod::new_with_randomizer_signed(target_pk, &-hat_beta.expose_secret(), &hat_s.retrieve());

        let public_aux = &self.context.aux_info.public_aux[destination];
        let rp = &public_aux.rp_params;

        let psi = AffGProof::new(
            rng,
            &P::signed_from_scalar(&self.context.gamma),
            &beta,
            s.clone(),
            r.clone(),
            target_pk,
            pk,
            &self.all_cap_k[destination],
            &cap_d,
            &cap_f,
            &cap_gamma,
            rp,
            &aux,
        );

        let hat_psi = AffGProof::new(
            rng,
            &P::signed_from_scalar(self.context.key_share.secret_share.expose_secret()),
            &hat_beta,
            hat_s.clone(),
            hat_r.clone(),
            target_pk,
            pk,
            &self.all_cap_k[destination],
            &hat_cap_d,
            &hat_cap_f,
            &self.context.key_share.public_shares[&self.context.my_id],
            rp,
            &aux,
        );

        let hat_psi_prime = LogStarProof::new(
            rng,
            &P::signed_from_scalar(&self.context.gamma),
            &self.context.nu,
            pk,
            &self.all_cap_g[&self.context.my_id],
            &Point::GENERATOR,
            &cap_gamma,
            rp,
            &aux,
        );

        let msg = DirectMessage::new(
            serializer,
            Round2Message::<P> {
                cap_gamma,
                cap_d: cap_d.retrieve(),
                cap_f: cap_f.retrieve(),
                hat_cap_d: hat_cap_d.retrieve(),
                hat_cap_f: hat_cap_f.retrieve(),
                psi,
                hat_psi,
                hat_psi_prime,
            },
        )?;

        let artifact = Artifact::new(Round2Artifact::<P> {
            beta,
            hat_beta,
            r: r.retrieve(),
            s: s.retrieve(),
            hat_r: hat_r.retrieve(),
            hat_s: hat_s.retrieve(),
            cap_d,
            cap_f,
            hat_cap_d,
            hat_cap_f,
        });

        Ok((msg, Some(artifact)))
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
        normal_broadcast.assert_is_none()?;
        let direct_message = direct_message.deserialize::<Round2Message<P>>(deserializer)?;

        let aux = (&self.context.ssid_hash, &from);
        let pk = &self.context.aux_info.secret_aux.paillier_sk.public_key();
        let from_pk = &self.context.aux_info.public_aux[from].paillier_pk;

        let cap_x = self.context.key_share.public_shares[from];

        let public_aux = &self.context.aux_info.public_aux[&self.context.my_id];
        let rp = &public_aux.rp_params;

        let cap_d = direct_message.cap_d.to_mod(pk);
        let hat_cap_d = direct_message.hat_cap_d.to_mod(pk);

        if !direct_message.psi.verify(
            pk,
            from_pk,
            &self.all_cap_k[&self.context.my_id],
            &cap_d,
            &direct_message.cap_f.to_mod(from_pk),
            &direct_message.cap_gamma,
            rp,
            &aux,
        ) {
            return Err(ReceiveError::protocol(InteractiveSigningError::Round2(
                "Failed to verify AffGProof (psi)".into(),
            )));
        }

        if !direct_message.hat_psi.verify(
            pk,
            from_pk,
            &self.all_cap_k[&self.context.my_id],
            &hat_cap_d,
            &direct_message.hat_cap_f.to_mod(from_pk),
            &cap_x,
            rp,
            &aux,
        ) {
            return Err(ReceiveError::protocol(InteractiveSigningError::Round2(
                "Failed to verify AffGProof (hat_psi)".into(),
            )));
        }

        if !direct_message.hat_psi_prime.verify(
            from_pk,
            &self.all_cap_g[from],
            &Point::GENERATOR,
            &direct_message.cap_gamma,
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
        let alpha = alpha
            .assert_bit_bound_usize(core::cmp::max(2 * P::L_BOUND, P::LP_BOUND) + 1)
            .ok_or_else(|| ReceiveError::protocol(InteractiveSigningError::OutOfBoundsAlpha))?;
        let hat_alpha = hat_alpha
            .assert_bit_bound_usize(core::cmp::max(2 * P::L_BOUND, P::LP_BOUND) + 1)
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

        let cap_delta = cap_gamma * self.context.k;

        let alpha_sum: Signed<_> = payloads.values().map(|p| p.alpha).sum();
        let beta_sum: Signed<_> = artifacts.values().map(|p| p.beta.expose_secret()).sum();
        let delta =
            P::signed_from_scalar(&self.context.gamma) * P::signed_from_scalar(&self.context.k) + alpha_sum + beta_sum;

        let hat_alpha_sum: Signed<_> = payloads.values().map(|payload| payload.hat_alpha).sum();
        let hat_beta_sum: Signed<_> = artifacts
            .values()
            .map(|artifact| artifact.hat_beta.expose_secret())
            .sum();
        let chi = P::signed_from_scalar(self.context.key_share.secret_share.expose_secret())
            * P::signed_from_scalar(&self.context.k)
            + hat_alpha_sum
            + hat_beta_sum;

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
    delta: Signed<<P::Paillier as PaillierParams>::Uint>,
    chi: Signed<<P::Paillier as PaillierParams>::Uint>,
    cap_delta: Point,
    cap_gamma: Point,
    all_cap_k: BTreeMap<I, CiphertextMod<P::Paillier>>,
    all_cap_g: BTreeMap<I, CiphertextMod<P::Paillier>>,
    cap_ds: BTreeMap<I, CiphertextMod<P::Paillier>>,
    hat_cap_ds: BTreeMap<I, CiphertextMod<P::Paillier>>,
    round2_artifacts: BTreeMap<I, Round2Artifact<P>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "LogStarProof<P>: Serialize"))]
#[serde(bound(deserialize = "LogStarProof<P>: for<'x> Deserialize<'x>"))]
struct Round3Message<P: SchemeParams> {
    delta: Scalar,
    cap_delta: Point,
    psi_pprime: LogStarProof<P>,
}

struct Round3Payload {
    delta: Scalar,
    cap_delta: Point,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round3<P, I> {
    type Protocol = InteractiveSigningProtocol<P, I>;

    fn id(&self) -> RoundId {
        RoundId::new(3)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::from([RoundId::new(4)])
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

        let public_aux = &self.context.aux_info.public_aux[destination];
        let rp = &public_aux.rp_params;

        let psi_pprime = LogStarProof::new(
            rng,
            &P::signed_from_scalar(&self.context.k),
            &self.context.rho,
            pk,
            &self.all_cap_k[&self.context.my_id],
            &self.cap_gamma,
            &self.cap_delta,
            rp,
            &aux,
        );

        let dm = DirectMessage::new(
            serializer,
            Round3Message::<P> {
                delta: P::scalar_from_signed(&self.delta),
                cap_delta: self.cap_delta,
                psi_pprime,
            },
        )?;

        Ok((dm, None))
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
        normal_broadcast.assert_is_none()?;
        let direct_message = direct_message.deserialize::<Round3Message<P>>(deserializer)?;

        let aux = (&self.context.ssid_hash, &from);
        let from_pk = &self.context.aux_info.public_aux[from].paillier_pk;

        let public_aux = &self.context.aux_info.public_aux[&self.context.my_id];
        let rp = &public_aux.rp_params;

        if !direct_message.psi_pprime.verify(
            from_pk,
            &self.all_cap_k[from],
            &self.cap_gamma,
            &direct_message.cap_delta,
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

        let scalar_delta = P::scalar_from_signed(&self.delta);
        let assembled_delta: Scalar = scalar_delta + deltas.values().sum::<Scalar>();
        let assembled_cap_delta: Point = self.cap_delta + cap_deltas.values().sum::<Point>();

        if assembled_delta.mul_by_generator() == assembled_cap_delta {
            let inv_delta: Scalar = Option::from(assembled_delta.invert()).ok_or_else(|| {
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
                    let values = PresigningValues {
                        hat_beta: artifact.hat_beta,
                        hat_r: artifact.hat_r,
                        hat_s: artifact.hat_s,
                        cap_k: self.all_cap_k[&id].clone(),
                        hat_cap_d_received: self.hat_cap_ds[&id].clone(),
                        hat_cap_d: artifact.hat_cap_d,
                        hat_cap_f: artifact.hat_cap_f,
                    };
                    (id, values)
                })
                .collect();

            let presigning_data = PresigningData {
                nonce,
                ephemeral_scalar_share: SecretBox::new(Box::new(self.context.k)),
                product_share: SecretBox::new(Box::new(P::scalar_from_signed(&self.chi))),
                product_share_nonreduced: self.chi,
                cap_k: self.all_cap_k[&my_id].clone(),
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

        for id_j in self.context.other_ids.iter() {
            let r2_artefacts = &self.round2_artifacts[id_j];

            for id_l in self.context.other_ids.iter().filter(|id| id != &id_j) {
                let target_pk = &self.context.aux_info.public_aux[id_j].paillier_pk;
                let rp = &self.context.aux_info.public_aux[id_l].rp_params;

                let beta = &self.round2_artifacts[id_j].beta;
                let r = &self.round2_artifacts[id_j].r;
                let s = &self.round2_artifacts[id_j].s;

                let p_aff_g = AffGProof::<P>::new(
                    rng,
                    &P::signed_from_scalar(&self.context.gamma),
                    beta,
                    s.to_mod(target_pk),
                    r.to_mod(pk),
                    target_pk,
                    pk,
                    &self.all_cap_k[id_j],
                    &r2_artefacts.cap_d,
                    &r2_artefacts.cap_f,
                    &cap_gamma,
                    rp,
                    &aux,
                );

                assert!(p_aff_g.verify(
                    target_pk,
                    pk,
                    &self.all_cap_k[id_j],
                    &r2_artefacts.cap_d,
                    &r2_artefacts.cap_f,
                    &cap_gamma,
                    rp,
                    &aux,
                ));

                aff_g_proofs.push((id_j.clone(), id_l.clone(), p_aff_g));
            }
        }

        // Mul proof

        let rho = RandomizerMod::random(rng, pk);
        let cap_h = (&self.all_cap_g[&self.context.my_id] * P::bounded_from_scalar(&self.context.k))
            .mul_randomizer(&rho.retrieve());

        let p_mul = MulProof::<P>::new(
            rng,
            &P::signed_from_scalar(&self.context.k),
            &self.context.rho,
            &rho,
            pk,
            &self.all_cap_k[&self.context.my_id],
            &self.all_cap_g[&self.context.my_id],
            &cap_h,
            &aux,
        );
        assert!(p_mul.verify(
            pk,
            &self.all_cap_k[&self.context.my_id],
            &self.all_cap_g[&self.context.my_id],
            &cap_h,
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
                &self.delta,
                &rho,
                pk,
                &scalar_delta,
                &ciphertext,
                &self.context.aux_info.public_aux[id_j].rp_params,
                &aux,
            );
            assert!(p_dec.verify(
                pk,
                &scalar_delta,
                &ciphertext,
                &self.context.aux_info.public_aux[id_j].rp_params,
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
        let sigma = presigning.ephemeral_scalar_share.expose_secret() * &context.message
            + r * presigning.product_share.expose_secret();
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
        RoundId::new(4)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::from([RoundId::new(5)])
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
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        _from: &I,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        echo_broadcast.assert_is_none()?;
        direct_message.assert_is_none()?;
        let normal_broadcast = normal_broadcast.deserialize::<Round4Message>(deserializer)?;

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
            for id_l in self.context.other_ids.iter().filter(|id| id != &id_j) {
                let target_pk = &self.context.aux_info.public_aux[id_j].paillier_pk;
                let rp = &self.context.aux_info.public_aux[id_l].rp_params;

                let values = self
                    .presigning
                    .values
                    .get(id_j)
                    .ok_or_else(|| LocalError::new(format!("Missing presigning values for {id_j:?}")))?;

                let p_aff_g = AffGProof::<P>::new(
                    rng,
                    &P::signed_from_scalar(self.context.key_share.secret_share.expose_secret()),
                    &values.hat_beta,
                    values.hat_s.to_mod(target_pk),
                    values.hat_r.to_mod(pk),
                    target_pk,
                    pk,
                    &values.cap_k,
                    &values.hat_cap_d,
                    &values.hat_cap_f,
                    &self.context.key_share.public_shares[&my_id],
                    rp,
                    &aux,
                );

                assert!(p_aff_g.verify(
                    target_pk,
                    pk,
                    &values.cap_k,
                    &values.hat_cap_d,
                    &values.hat_cap_f,
                    &self.context.key_share.public_shares[&my_id],
                    rp,
                    &aux,
                ));

                aff_g_proofs.push((id_j.clone(), id_l.clone(), p_aff_g));
            }
        }

        // mul* proofs

        let x = &self.context.key_share.secret_share;
        let cap_x = self.context.key_share.public_shares[&my_id];

        let rho = RandomizerMod::random(rng, pk);
        let hat_cap_h =
            (&self.presigning.cap_k * P::bounded_from_scalar(x.expose_secret())).mul_randomizer(&rho.retrieve());

        let aux = (&self.context.ssid_hash, &my_id);

        let mut mul_star_proofs = Vec::new();

        for id_l in self.context.other_ids.iter() {
            let p_mul = MulStarProof::<P>::new(
                rng,
                &P::signed_from_scalar(x.expose_secret()),
                &rho,
                pk,
                &self.presigning.cap_k,
                &hat_cap_h,
                &cap_x,
                &self.context.aux_info.public_aux[id_l].rp_params,
                &aux,
            );

            assert!(p_mul.verify(
                pk,
                &self.presigning.cap_k,
                &hat_cap_h,
                &cap_x,
                &self.context.aux_info.public_aux[id_l].rp_params,
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

        let ciphertext = ciphertext * P::bounded_from_scalar(&r)
            + &self.presigning.cap_k * P::bounded_from_scalar(&self.context.message);

        let rho = ciphertext.derive_randomizer(sk);
        // This is the same as `s_part` but if all the calculations were performed
        // without reducing modulo curve order.
        let s_part_nonreduced = P::signed_from_scalar(self.presigning.ephemeral_scalar_share.expose_secret())
            * P::signed_from_scalar(&self.context.message)
            + self.presigning.product_share_nonreduced * P::signed_from_scalar(&r);

        let mut dec_proofs = Vec::new();
        for id_l in self.context.other_ids.iter() {
            let p_dec = DecProof::<P>::new(
                rng,
                &s_part_nonreduced,
                &rho,
                pk,
                &self.sigma,
                &ciphertext,
                &self.context.aux_info.public_aux[id_l].rp_params,
                &aux,
            );
            assert!(p_dec.verify(
                pk,
                &self.sigma,
                &ciphertext,
                &self.context.aux_info.public_aux[id_l].rp_params,
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
        RoundId::new(5)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
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
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        _from: &I,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        normal_broadcast.assert_is_none()?;
        direct_message.assert_is_none()?;
        let _echo_broadcast = echo_broadcast.deserialize::<SigningErrorMessage<P, I>>(deserializer)?;
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
        session::signature::Keypair,
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
