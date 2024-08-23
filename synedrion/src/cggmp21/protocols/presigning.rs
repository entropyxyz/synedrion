//! Presigning protocol, in the paper ECDSA Pre-Signing (Fig. 7).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use super::super::{
    entities::{AuxInfoPrecomputed, PresigningValues},
    sigma::{AffGProof, DecProof, EncProof, LogStarProof, MulProof},
    AuxInfo, KeyShare, PresigningData, SchemeParams,
};
use crate::curve::{Point, Scalar};
use crate::paillier::{Ciphertext, CiphertextMod, PaillierParams, Randomizer, RandomizerMod};
use crate::rounds::{
    no_broadcast_messages, FinalizableToNextRound, FinalizableToResult, FinalizeError, FirstRound,
    InitError, ProtocolResult, Round, ToNextRound, ToResult,
};
use crate::tools::hashing::{Chain, FofHasher, HashOutput};
use crate::uint::Signed;

/// Possible results of the Presigning protocol.
#[derive(Debug)]
pub struct PresigningResult<P: SchemeParams, I: Debug>(PhantomData<P>, PhantomData<I>);

impl<P: SchemeParams, I: Debug> ProtocolResult for PresigningResult<P, I> {
    type Success = PresigningData<P, I>;
    type ProvableError = PresigningError;
    type CorrectnessProof = PresigningProof<P, I>;
}

/// Possible verifiable errors of the Presigning protocol.
#[derive(Debug, Clone)]
pub enum PresigningError {
    /// An error in Round 1.
    Round1(String),
    /// An error in Round 2.
    Round2(String),
    /// An error in Round 3.
    Round3(String),
}

struct Context<P: SchemeParams, I: Ord> {
    ssid_hash: HashOutput,
    my_id: I,
    other_ids: BTreeSet<I>,
    key_share: KeyShare<P, I>,
    aux_info: AuxInfoPrecomputed<P, I>,
    k: Scalar,
    gamma: Scalar,
    rho: RandomizerMod<P::Paillier>,
    nu: RandomizerMod<P::Paillier>,
}

pub struct Round1<P: SchemeParams, I: Ord> {
    context: Context<P, I>,
    cap_k: CiphertextMod<P::Paillier>,
    cap_g: CiphertextMod<P::Paillier>,
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> FirstRound<I> for Round1<P, I> {
    type Inputs = (KeyShare<P, I>, AuxInfo<P, I>);
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        other_ids: BTreeSet<I>,
        my_id: I,
        inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        let (key_share, aux_info) = inputs;

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

        // TODO (#68): check that KeyShare is consistent with num_parties/party_idx

        // The share of an ephemeral scalar
        let k = Scalar::random(rng);
        // The share of the mask used to generate the inverse of the ephemeral scalar
        let gamma = Scalar::random(rng);

        let pk = aux_info.secret_aux.paillier_sk.public_key();

        let nu = RandomizerMod::<P::Paillier>::random(rng, pk);
        let cap_g =
            CiphertextMod::new_with_randomizer(pk, &P::uint_from_scalar(&gamma), &nu.retrieve());

        let rho = RandomizerMod::<P::Paillier>::random(rng, pk);
        let cap_k =
            CiphertextMod::new_with_randomizer(pk, &P::uint_from_scalar(&k), &rho.retrieve());

        Ok(Self {
            context: Context {
                ssid_hash,
                my_id,
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
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "Ciphertext<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "Ciphertext<P::Paillier>: for<'x> Deserialize<'x>"))]
pub struct Round1BroadcastMessage<P: SchemeParams> {
    cap_k: Ciphertext<P::Paillier>,
    cap_g: Ciphertext<P::Paillier>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "EncProof<P>: Serialize"))]
#[serde(bound(deserialize = "EncProof<P>: for<'x> Deserialize<'x>"))]
pub struct Round1DirectMessage<P: SchemeParams> {
    psi0: EncProof<P>,
}

pub struct Round1Payload<P: SchemeParams> {
    cap_k: Ciphertext<P::Paillier>,
    cap_g: Ciphertext<P::Paillier>,
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> Round<I> for Round1<P, I> {
    type Type = ToNextRound;
    type Result = PresigningResult<P, I>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);

    fn other_ids(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn my_id(&self) -> &I {
        &self.context.my_id
    }

    const REQUIRES_ECHO: bool = true;
    type BroadcastMessage = Round1BroadcastMessage<P>;
    type DirectMessage = Round1DirectMessage<P>;
    type Payload = Round1Payload<P>;
    type Artifact = ();

    fn make_broadcast_message(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        Some(Round1BroadcastMessage {
            cap_k: self.cap_k.retrieve(),
            cap_g: self.cap_g.retrieve(),
        })
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &I,
    ) -> (Self::DirectMessage, Self::Artifact) {
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

        (Round1DirectMessage { psi0 }, ())
    }

    fn verify_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        from: &I,
        broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        let aux = (&self.context.ssid_hash, self.my_id());

        let public_aux = &self.context.aux_info.public_aux[self.my_id()];

        let from_pk = &self.context.aux_info.public_aux[from].paillier_pk;

        if !direct_msg.psi0.verify(
            from_pk,
            &broadcast_msg.cap_k.to_mod(from_pk),
            &public_aux.rp_params,
            &aux,
        ) {
            return Err(PresigningError::Round1("Failed to verify EncProof".into()));
        }

        Ok(Round1Payload {
            cap_k: broadcast_msg.cap_k,
            cap_g: broadcast_msg.cap_g,
        })
    }
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> FinalizableToNextRound<I>
    for Round1<P, I>
{
    type NextRound = Round2<P, I>;
    fn finalize_to_next_round(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        _artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let (others_cap_k, others_cap_g): (BTreeMap<_, _>, BTreeMap<_, _>) = payloads
            .into_iter()
            .map(|(id, payload)| ((id.clone(), payload.cap_k), (id, payload.cap_g)))
            .unzip();

        let my_id = self.my_id().clone();

        let mut all_cap_k = others_cap_k
            .into_iter()
            .map(|(id, ciphertext)| {
                let ciphertext_mod =
                    ciphertext.to_mod(&self.context.aux_info.public_aux[&id].paillier_pk);
                (id, ciphertext_mod)
            })
            .collect::<BTreeMap<_, _>>();
        all_cap_k.insert(my_id.clone(), self.cap_k);

        let mut all_cap_g = others_cap_g
            .into_iter()
            .map(|(id, ciphertext)| {
                let ciphertext_mod =
                    ciphertext.to_mod(&self.context.aux_info.public_aux[&id].paillier_pk);
                (id, ciphertext_mod)
            })
            .collect::<BTreeMap<_, _>>();
        all_cap_g.insert(my_id, self.cap_g);

        Ok(Round2 {
            context: self.context,
            all_cap_k,
            all_cap_g,
        })
    }
}

pub struct Round2<P: SchemeParams, I: Ord> {
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
pub struct Round2Message<P: SchemeParams> {
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
pub struct Round2Artifact<P: SchemeParams> {
    beta: SecretBox<Signed<<P::Paillier as PaillierParams>::Uint>>,
    hat_beta: SecretBox<Signed<<P::Paillier as PaillierParams>::Uint>>,
    r: SecretBox<Randomizer<P::Paillier>>,
    s: SecretBox<Randomizer<P::Paillier>>,
    hat_r: SecretBox<Randomizer<P::Paillier>>,
    hat_s: SecretBox<Randomizer<P::Paillier>>,
    cap_d: CiphertextMod<P::Paillier>,
    cap_f: CiphertextMod<P::Paillier>,
    hat_cap_d: CiphertextMod<P::Paillier>,
    hat_cap_f: CiphertextMod<P::Paillier>,
}

pub struct Round2Payload<P: SchemeParams> {
    cap_gamma: Point,
    alpha: Signed<<P::Paillier as PaillierParams>::Uint>,
    hat_alpha: Signed<<P::Paillier as PaillierParams>::Uint>,
    cap_d: CiphertextMod<P::Paillier>,
    hat_cap_d: CiphertextMod<P::Paillier>,
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> Round<I> for Round2<P, I> {
    type Type = ToNextRound;
    type Result = PresigningResult<P, I>;
    const ROUND_NUM: u8 = 2;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);

    fn other_ids(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn my_id(&self) -> &I {
        &self.context.my_id
    }

    type BroadcastMessage = ();
    type DirectMessage = Round2Message<P>;
    type Payload = Round2Payload<P>;
    type Artifact = Round2Artifact<P>;

    no_broadcast_messages!();

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &I,
    ) -> (Self::DirectMessage, Self::Artifact) {
        let aux = (&self.context.ssid_hash, &self.my_id());

        let cap_gamma = self.context.gamma.mul_by_generator();
        let pk = self.context.aux_info.secret_aux.paillier_sk.public_key();

        let target_pk = &self.context.aux_info.public_aux[destination].paillier_pk;

        let beta = Signed::random_bounded_bits(rng, P::LP_BOUND).secret_box();
        let hat_beta = Signed::random_bounded_bits(rng, P::LP_BOUND).secret_box();
        let r = RandomizerMod::random(rng, pk).secret_box();
        let s = RandomizerMod::random(rng, target_pk).secret_box();
        let hat_r = RandomizerMod::random(rng, pk).secret_box();
        let hat_s = RandomizerMod::random(rng, target_pk).secret_box();

        let cap_f = CiphertextMod::new_with_randomizer_signed(
            pk,
            beta.expose_secret(),
            &r.expose_secret().retrieve(),
        );
        let cap_d = &self.all_cap_k[destination] * P::signed_from_scalar(&self.context.gamma)
            + CiphertextMod::new_with_randomizer_signed(
                target_pk,
                &-beta.expose_secret(),
                &s.expose_secret().retrieve(),
            );

        let hat_cap_f = CiphertextMod::new_with_randomizer_signed(
            pk,
            hat_beta.expose_secret(),
            &hat_r.expose_secret().retrieve(),
        );
        let hat_cap_d = &self.all_cap_k[destination]
            * P::signed_from_scalar(self.context.key_share.secret_share.expose_secret())
            + CiphertextMod::new_with_randomizer_signed(
                target_pk,
                &-hat_beta.expose_secret(),
                &hat_s.expose_secret().retrieve(),
            );

        let public_aux = &self.context.aux_info.public_aux[destination];
        let rp = &public_aux.rp_params;

        let psi = AffGProof::new(
            rng,
            &P::signed_from_scalar(&self.context.gamma),
            &beta,
            s.expose_secret(), // TODO(dp): Fix AffGProof
            r.expose_secret(), // TODO(dp): Fix AffGProof
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
            hat_s.expose_secret(),
            hat_r.expose_secret(),
            target_pk,
            pk,
            &self.all_cap_k[destination],
            &hat_cap_d,
            &hat_cap_f,
            &self.context.key_share.public_shares[self.my_id()],
            rp,
            &aux,
        );

        let hat_psi_prime = LogStarProof::new(
            rng,
            &P::signed_from_scalar(&self.context.gamma),
            &self.context.nu,
            pk,
            &self.all_cap_g[self.my_id()],
            &Point::GENERATOR,
            &cap_gamma,
            rp,
            &aux,
        );

        let msg = Round2Message {
            cap_gamma,
            cap_d: cap_d.retrieve(),
            cap_f: cap_f.retrieve(),
            hat_cap_d: hat_cap_d.retrieve(),
            hat_cap_f: hat_cap_f.retrieve(),
            psi,
            hat_psi,
            hat_psi_prime,
        };

        let artifact = Round2Artifact {
            beta,
            hat_beta,
            r: r.expose_secret().retrieve().secret_box(), // TODO(dp): Ugggh, this is clunky af.
            s: s.expose_secret().retrieve().secret_box(),
            hat_r: hat_r.expose_secret().retrieve().secret_box(),
            hat_s: hat_s.expose_secret().retrieve().secret_box(),
            cap_d,
            cap_f,
            hat_cap_d,
            hat_cap_f,
        };

        (msg, artifact)
    }

    fn verify_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        from: &I,
        _broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        let aux = (&self.context.ssid_hash, &from);
        let pk = &self.context.aux_info.secret_aux.paillier_sk.public_key();
        let from_pk = &self.context.aux_info.public_aux[from].paillier_pk;

        let cap_x = self.context.key_share.public_shares[from];

        let public_aux = &self.context.aux_info.public_aux[self.my_id()];
        let rp = &public_aux.rp_params;

        let cap_d = direct_msg.cap_d.to_mod(pk);
        let hat_cap_d = direct_msg.hat_cap_d.to_mod(pk);

        if !direct_msg.psi.verify(
            pk,
            from_pk,
            &self.all_cap_k[self.my_id()],
            &cap_d,
            &direct_msg.cap_f.to_mod(from_pk),
            &direct_msg.cap_gamma,
            rp,
            &aux,
        ) {
            return Err(PresigningError::Round2(
                "Failed to verify AffGProof (psi)".into(),
            ));
        }

        if !direct_msg.hat_psi.verify(
            pk,
            from_pk,
            &self.all_cap_k[self.my_id()],
            &hat_cap_d,
            &direct_msg.hat_cap_f.to_mod(from_pk),
            &cap_x,
            rp,
            &aux,
        ) {
            return Err(PresigningError::Round2(
                "Failed to verify AffGProof (hat_psi)".into(),
            ));
        }

        if !direct_msg.hat_psi_prime.verify(
            from_pk,
            &self.all_cap_g[from],
            &Point::GENERATOR,
            &direct_msg.cap_gamma,
            rp,
            &aux,
        ) {
            return Err(PresigningError::Round2(
                "Failed to verify LogStarProof".into(),
            ));
        }

        let alpha = cap_d.decrypt_signed(&self.context.aux_info.secret_aux.paillier_sk);
        let hat_alpha = hat_cap_d.decrypt_signed(&self.context.aux_info.secret_aux.paillier_sk);

        // `alpha == x * y + z` where `0 <= x, y < q`, and `-2^l' <= z <= 2^l'`,
        // where `q` is the curve order.
        // We will need this bound later, so we're asserting it.
        let alpha = alpha
            .assert_bit_bound_usize(core::cmp::max(2 * P::L_BOUND, P::LP_BOUND) + 1)
            .unwrap();
        let hat_alpha = hat_alpha
            .assert_bit_bound_usize(core::cmp::max(2 * P::L_BOUND, P::LP_BOUND) + 1)
            .unwrap();

        Ok(Round2Payload {
            cap_gamma: direct_msg.cap_gamma,
            alpha,
            hat_alpha,
            cap_d,
            hat_cap_d,
        })
    }
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> FinalizableToNextRound<I>
    for Round2<P, I>
{
    type NextRound = Round3<P, I>;
    fn finalize_to_next_round(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let cap_gamma = payloads
            .values()
            .map(|payload| payload.cap_gamma)
            .sum::<Point>()
            + self.context.gamma.mul_by_generator();

        let cap_delta = cap_gamma * self.context.k;

        let alpha_sum: Signed<_> = payloads.values().map(|p| p.alpha).sum();
        let beta_sum: Signed<_> = artifacts.values().map(|p| p.beta.expose_secret()).sum();
        let delta = P::signed_from_scalar(&self.context.gamma)
            * P::signed_from_scalar(&self.context.k)
            + alpha_sum
            + beta_sum;

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

        Ok(Round3 {
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
        })
    }
}

pub struct Round3<P: SchemeParams, I: Ord> {
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
pub struct Round3Message<P: SchemeParams> {
    delta: Scalar,
    cap_delta: Point,
    psi_pprime: LogStarProof<P>,
}

pub struct Round3Payload {
    delta: Scalar,
    cap_delta: Point,
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> Round<I> for Round3<P, I> {
    type Type = ToResult;
    type Result = PresigningResult<P, I>;
    const ROUND_NUM: u8 = 3;
    const NEXT_ROUND_NUM: Option<u8> = None;

    fn other_ids(&self) -> &BTreeSet<I> {
        &self.context.other_ids
    }

    fn my_id(&self) -> &I {
        &self.context.my_id
    }

    type BroadcastMessage = ();
    type DirectMessage = Round3Message<P>;
    type Payload = Round3Payload;
    type Artifact = ();

    no_broadcast_messages!();

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &I,
    ) -> (Self::DirectMessage, Self::Artifact) {
        let aux = (&self.context.ssid_hash, &self.my_id());
        let pk = &self.context.aux_info.secret_aux.paillier_sk.public_key();

        let public_aux = &self.context.aux_info.public_aux[destination];
        let rp = &public_aux.rp_params;

        let psi_pprime = LogStarProof::new(
            rng,
            &P::signed_from_scalar(&self.context.k),
            &self.context.rho,
            pk,
            &self.all_cap_k[self.my_id()],
            &self.cap_gamma,
            &self.cap_delta,
            rp,
            &aux,
        );
        let message = Round3Message {
            delta: P::scalar_from_signed(&self.delta),
            cap_delta: self.cap_delta,
            psi_pprime,
        };

        (message, ())
    }

    fn verify_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        from: &I,
        _broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        let aux = (&self.context.ssid_hash, &from);
        let from_pk = &self.context.aux_info.public_aux[from].paillier_pk;

        let public_aux = &self.context.aux_info.public_aux[self.my_id()];
        let rp = &public_aux.rp_params;

        if !direct_msg.psi_pprime.verify(
            from_pk,
            &self.all_cap_k[from],
            &self.cap_gamma,
            &direct_msg.cap_delta,
            rp,
            &aux,
        ) {
            return Err(PresigningError::Round3(
                "Failed to verify Log-Star proof".into(),
            ));
        }
        Ok(Round3Payload {
            delta: direct_msg.delta,
            cap_delta: direct_msg.cap_delta,
        })
    }
}

/// A proof of a node's correct behavior for the Presigning protocol.
#[allow(dead_code)] // TODO (#43): this can be removed when error verification is added
#[derive(Debug, Clone)]
pub struct PresigningProof<P: SchemeParams, I> {
    aff_g_proofs: Vec<(I, I, AffGProof<P>)>,
    mul_proof: MulProof<P>,
    dec_proofs: Vec<(I, DecProof<P>)>,
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> FinalizableToResult<I> for Round3<P, I> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        _artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let (deltas, cap_deltas): (BTreeMap<_, _>, BTreeMap<_, _>) = payloads
            .into_iter()
            .map(|(id, payload)| ((id.clone(), payload.delta), (id, payload.cap_delta)))
            .unzip();

        let scalar_delta = P::scalar_from_signed(&self.delta);
        let assembled_delta: Scalar = scalar_delta + deltas.values().sum::<Scalar>();
        let assembled_cap_delta: Point = self.cap_delta + cap_deltas.values().sum::<Point>();

        if assembled_delta.mul_by_generator() == assembled_cap_delta {
            let nonce = (self.cap_gamma * assembled_delta.invert().unwrap()).x_coordinate();
            let my_id = self.my_id().clone();

            let values = self
                .round2_artifacts
                .into_iter()
                .map(|(id, artifact)| {
                    let values = PresigningValues {
                        hat_beta: artifact.hat_beta,
                        hat_r: artifact.hat_r.expose_secret().clone().secret_box(),
                        hat_s: artifact.hat_s.expose_secret().clone().secret_box(),
                        cap_k: self.all_cap_k[&id].clone(),
                        hat_cap_d_received: self.hat_cap_ds[&id].clone(),
                        hat_cap_d: artifact.hat_cap_d,
                        hat_cap_f: artifact.hat_cap_f,
                    };
                    (id, values)
                })
                .collect();

            return Ok(PresigningData {
                nonce,
                ephemeral_scalar_share: SecretBox::new(Box::new(self.context.k)),
                product_share: SecretBox::new(Box::new(P::scalar_from_signed(&self.chi))),
                product_share_nonreduced: self.chi,
                cap_k: self.all_cap_k[&my_id].clone(),
                values,
            });
        }

        // Construct the correctness proofs

        let sk = &self.context.aux_info.secret_aux.paillier_sk;
        let pk = sk.public_key();

        let aux = (&self.context.ssid_hash, &self.my_id());

        // Aff-g proofs

        let mut aff_g_proofs = Vec::new();

        let cap_gamma = self.context.gamma.mul_by_generator();

        for id_j in self.other_ids() {
            let r2_artefacts = &self.round2_artifacts[id_j];

            for id_l in self.other_ids().iter().filter(|id| id != &id_j) {
                let target_pk = &self.context.aux_info.public_aux[id_j].paillier_pk;
                let rp = &self.context.aux_info.public_aux[id_l].rp_params;

                let beta = &self.round2_artifacts[id_j].beta;
                let r = &self.round2_artifacts[id_j].r;
                let s = &self.round2_artifacts[id_j].s;

                let p_aff_g = AffGProof::<P>::new(
                    rng,
                    &P::signed_from_scalar(&self.context.gamma),
                    beta,
                    &s.expose_secret().to_mod(target_pk),
                    &r.expose_secret().to_mod(pk),
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
        let cap_h = (&self.all_cap_g[self.my_id()] * P::bounded_from_scalar(&self.context.k))
            .mul_randomizer(&rho.retrieve());

        let p_mul = MulProof::<P>::new(
            rng,
            &P::signed_from_scalar(&self.context.k),
            &self.context.rho,
            &rho,
            pk,
            &self.all_cap_k[self.my_id()],
            &self.all_cap_g[self.my_id()],
            &cap_h,
            &aux,
        );
        assert!(p_mul.verify(
            pk,
            &self.all_cap_k[self.my_id()],
            &self.all_cap_g[self.my_id()],
            &cap_h,
            &aux
        ));

        // Dec proof

        let mut ciphertext = cap_h.clone();

        for id_j in self.other_ids() {
            ciphertext = ciphertext
                + self.cap_ds.get(id_j).unwrap()
                + &self.round2_artifacts.get(id_j).unwrap().cap_f;
        }

        let rho = ciphertext.derive_randomizer(sk);

        let mut dec_proofs = Vec::new();
        for id_j in self.other_ids() {
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

        Err(FinalizeError::Proof(PresigningProof {
            aff_g_proofs,
            dec_proofs,
            mul_proof: p_mul,
        }))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use rand_core::{OsRng, RngCore};
    use secrecy::ExposeSecret;

    use super::Round1;
    use crate::cggmp21::{AuxInfo, KeyShare, TestParams};
    use crate::curve::Scalar;
    use crate::rounds::{
        test_utils::{step_next_round, step_result, step_round, Id, Without},
        FirstRound,
    };

    #[test]
    fn execute_presigning() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let ids = BTreeSet::from([Id(0), Id(1), Id(2)]);

        let key_shares = KeyShare::new_centralized(&mut OsRng, &ids, None);
        let aux_infos = AuxInfo::new_centralized(&mut OsRng, &ids);

        let r1 = ids
            .iter()
            .map(|id| {
                let round = Round1::<TestParams, Id>::new(
                    &mut OsRng,
                    &shared_randomness,
                    ids.clone().without(id),
                    *id,
                    (key_shares[id].clone(), aux_infos[id].clone()),
                )
                .unwrap();
                (*id, round)
            })
            .collect();

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let r2 = step_next_round(&mut OsRng, r1a).unwrap();
        let r2a = step_round(&mut OsRng, r2).unwrap();
        let r3 = step_next_round(&mut OsRng, r2a).unwrap();
        let r3a = step_round(&mut OsRng, r3).unwrap();
        let presigning_datas = step_result(&mut OsRng, r3a).unwrap();

        // Check that each node ends up with the same nonce.
        assert_eq!(
            presigning_datas[&Id(0)].nonce,
            presigning_datas[&Id(1)].nonce
        );
        assert_eq!(
            presigning_datas[&Id(0)].nonce,
            presigning_datas[&Id(2)].nonce
        );

        // Check that the additive shares were constructed in a consistent way.
        let k: Scalar = presigning_datas
            .values()
            .map(|data| data.ephemeral_scalar_share.expose_secret())
            .sum();
        let k_times_x: Scalar = presigning_datas
            .values()
            .map(|data| data.product_share.expose_secret())
            .sum();
        let x: Scalar = key_shares
            .values()
            .map(|share| share.secret_share.expose_secret())
            .sum();
        assert_eq!(x * k, k_times_x);
        assert_eq!(
            k.invert().unwrap().mul_by_generator().x_coordinate(),
            presigning_datas[&Id(0)].nonce
        );
    }
}
