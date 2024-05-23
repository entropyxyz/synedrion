//! Presigning protocol, in the paper ECDSA Pre-Signing (Fig. 7).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::super::{
    entities::AuxInfoPrecomputed,
    sigma::{AffGProof, DecProof, EncProof, LogStarProof, MulProof},
    AuxInfo, KeyShare, PresigningData, SchemeParams,
};
use crate::curve::{Point, Scalar};
use crate::paillier::{Ciphertext, CiphertextMod, PaillierParams, Randomizer, RandomizerMod};
use crate::rounds::{
    all_parties_except, no_broadcast_messages, try_to_holevec, FinalizableToNextRound,
    FinalizableToResult, FinalizeError, FirstRound, InitError, PartyIdx, ProtocolResult, Round,
    ToNextRound, ToResult,
};
use crate::tools::{
    collections::{HoleRange, HoleVec},
    hashing::{Chain, Hash, HashOutput},
};
use crate::uint::Signed;

/// Possible results of the Presigning protocol.
#[derive(Debug, Clone, Copy)]
pub struct PresigningResult<P: SchemeParams>(PhantomData<P>);

impl<P: SchemeParams> ProtocolResult for PresigningResult<P> {
    type Success = PresigningData<P>;
    type ProvableError = PresigningError;
    type CorrectnessProof = PresigningProof<P>;
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

struct Context<P: SchemeParams> {
    ssid_hash: HashOutput,
    key_share: KeyShare<P>,
    aux_info: AuxInfoPrecomputed<P>,
    k: Scalar,
    gamma: Scalar,
    rho: RandomizerMod<P::Paillier>,
    nu: RandomizerMod<P::Paillier>,
}

pub struct Round1<P: SchemeParams> {
    context: Context<P>,
    cap_k: CiphertextMod<P::Paillier>,
    cap_g: CiphertextMod<P::Paillier>,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Inputs = (KeyShare<P>, AuxInfo<P>);
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        _num_parties: usize,
        _party_idx: PartyIdx,
        inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        let (key_share, aux_info) = inputs;
        let aux_info = aux_info.to_precomputed();

        // This includes the info of $ssid$ in the paper
        // (scheme parameters + public data from all shares - hashed in `share_set_id`),
        // with the session randomness added.
        let ssid_hash = Hash::new_with_dst(b"ShareSetID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .chain_slice(&key_share.public_shares)
            .chain_slice(&aux_info.public_aux)
            .finalize();

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

impl<P: SchemeParams> Round for Round1<P> {
    type Type = ToNextRound;
    type Result = PresigningResult<P>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);

    fn num_parties(&self) -> usize {
        self.context.key_share.num_parties()
    }

    fn party_idx(&self) -> PartyIdx {
        self.context.key_share.party_index()
    }

    const REQUIRES_ECHO: bool = true;
    type BroadcastMessage = Round1BroadcastMessage<P>;
    type DirectMessage = Round1DirectMessage<P>;
    type Payload = Round1Payload<P>;
    type Artifact = ();

    fn message_destinations(&self) -> Vec<PartyIdx> {
        all_parties_except(
            self.context.key_share.num_parties(),
            self.context.key_share.party_index(),
        )
    }

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
        destination: PartyIdx,
    ) -> (Self::DirectMessage, Self::Artifact) {
        let aux = (&self.context.ssid_hash, &destination);
        let psi0 = EncProof::new(
            rng,
            &P::signed_from_scalar(&self.context.k),
            &self.context.rho,
            self.context.aux_info.secret_aux.paillier_sk.public_key(),
            &self.cap_k,
            &self.context.aux_info.public_aux[destination.as_usize()].rp_params,
            &aux,
        );

        (Round1DirectMessage { psi0 }, ())
    }

    fn verify_message(
        &self,
        from: PartyIdx,
        broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        let aux = (&self.context.ssid_hash, &self.party_idx());

        let public_aux = &self.context.aux_info.public_aux[self.party_idx().as_usize()];

        let from_pk = &self.context.aux_info.public_aux[from.as_usize()].paillier_pk;

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

impl<P: SchemeParams> FinalizableToNextRound for Round1<P> {
    type NextRound = Round2<P>;
    fn finalize_to_next_round(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        _artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let payloads = try_to_holevec(payloads, self.num_parties(), self.party_idx()).unwrap();

        let (others_cap_k, others_cap_g) = payloads
            .map(|payload| (payload.cap_k, payload.cap_g))
            .unzip();

        let others_cap_k = others_cap_k.map_enumerate(|(i, ciphertext)| {
            ciphertext.to_mod(&self.context.aux_info.public_aux[i].paillier_pk)
        });
        let others_cap_g = others_cap_g.map_enumerate(|(i, ciphertext)| {
            ciphertext.to_mod(&self.context.aux_info.public_aux[i].paillier_pk)
        });

        let all_cap_k = others_cap_k.into_vec(self.cap_k);
        let all_cap_g = others_cap_g.into_vec(self.cap_g);
        Ok(Round2 {
            context: self.context,
            all_cap_k,
            all_cap_g,
        })
    }
}

pub struct Round2<P: SchemeParams> {
    context: Context<P>,
    all_cap_k: Vec<CiphertextMod<P::Paillier>>,
    all_cap_g: Vec<CiphertextMod<P::Paillier>>,
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
    beta: Signed<<P::Paillier as PaillierParams>::Uint>, // TODO (#77): secret
    hat_beta: Signed<<P::Paillier as PaillierParams>::Uint>, // TODO (#77): secret
    r: Randomizer<P::Paillier>,                          // TODO (#77): secret
    s: Randomizer<P::Paillier>,                          // TODO (#77): secret
    hat_r: Randomizer<P::Paillier>,                      // TODO (#77): secret
    hat_s: Randomizer<P::Paillier>,                      // TODO (#77): secret
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

impl<P: SchemeParams> Round for Round2<P> {
    type Type = ToNextRound;
    type Result = PresigningResult<P>;
    const ROUND_NUM: u8 = 2;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);

    fn num_parties(&self) -> usize {
        self.context.key_share.num_parties()
    }

    fn party_idx(&self) -> PartyIdx {
        self.context.key_share.party_index()
    }

    type BroadcastMessage = ();
    type DirectMessage = Round2Message<P>;
    type Payload = Round2Payload<P>;
    type Artifact = Round2Artifact<P>;

    fn message_destinations(&self) -> Vec<PartyIdx> {
        all_parties_except(
            self.context.key_share.num_parties(),
            self.context.key_share.party_index(),
        )
    }

    no_broadcast_messages!();

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> (Self::DirectMessage, Self::Artifact) {
        let aux = (
            &self.context.ssid_hash,
            &self.context.key_share.party_index(),
        );

        let cap_gamma = self.context.gamma.mul_by_generator();
        let pk = &self.context.aux_info.secret_aux.paillier_sk.public_key();
        let idx = destination.as_usize();

        let target_pk = &self.context.aux_info.public_aux[idx].paillier_pk;

        let beta = Signed::random_bounded_bits(rng, P::LP_BOUND);
        let hat_beta = Signed::random_bounded_bits(rng, P::LP_BOUND);
        let r = RandomizerMod::random(rng, pk);
        let s = RandomizerMod::random(rng, target_pk);
        let hat_r = RandomizerMod::random(rng, pk);
        let hat_s = RandomizerMod::random(rng, target_pk);

        let cap_f = CiphertextMod::new_with_randomizer_signed(pk, &beta, &r.retrieve());
        let cap_d = &self.all_cap_k[idx] * P::signed_from_scalar(&self.context.gamma)
            + CiphertextMod::new_with_randomizer_signed(target_pk, &-beta, &s.retrieve());

        let hat_cap_f = CiphertextMod::new_with_randomizer_signed(pk, &hat_beta, &hat_r.retrieve());
        let hat_cap_d = &self.all_cap_k[idx]
            * P::signed_from_scalar(&self.context.key_share.secret_share)
            + CiphertextMod::new_with_randomizer_signed(target_pk, &-hat_beta, &hat_s.retrieve());

        let public_aux = &self.context.aux_info.public_aux[idx];
        let rp = &public_aux.rp_params;

        let psi = AffGProof::new(
            rng,
            &P::signed_from_scalar(&self.context.gamma),
            &beta,
            &s,
            &r,
            target_pk,
            pk,
            &self.all_cap_k[idx],
            &cap_d,
            &cap_f,
            &cap_gamma,
            rp,
            &aux,
        );

        let hat_psi = AffGProof::new(
            rng,
            &P::signed_from_scalar(&self.context.key_share.secret_share),
            &hat_beta,
            &hat_s,
            &hat_r,
            target_pk,
            pk,
            &self.all_cap_k[idx],
            &hat_cap_d,
            &hat_cap_f,
            &self.context.key_share.public_shares[self.party_idx().as_usize()],
            rp,
            &aux,
        );

        let hat_psi_prime = LogStarProof::new(
            rng,
            &P::signed_from_scalar(&self.context.gamma),
            &self.context.nu,
            pk,
            &self.all_cap_g[self.party_idx().as_usize()],
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
            r: r.retrieve(),
            s: s.retrieve(),
            hat_r: hat_r.retrieve(),
            hat_s: hat_s.retrieve(),
            cap_d,
            cap_f,
            hat_cap_d,
            hat_cap_f,
        };

        (msg, artifact)
    }

    fn verify_message(
        &self,
        from: PartyIdx,
        _broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        let aux = (&self.context.ssid_hash, &from);
        let pk = &self.context.aux_info.secret_aux.paillier_sk.public_key();
        let from_pk = &self.context.aux_info.public_aux[from.as_usize()].paillier_pk;

        let cap_x = self.context.key_share.public_shares[from.as_usize()];

        let public_aux =
            &self.context.aux_info.public_aux[self.context.key_share.party_index().as_usize()];
        let rp = &public_aux.rp_params;

        let cap_d = direct_msg.cap_d.to_mod(pk);
        let hat_cap_d = direct_msg.hat_cap_d.to_mod(pk);

        if !direct_msg.psi.verify(
            pk,
            from_pk,
            &self.all_cap_k[self.context.key_share.party_index().as_usize()],
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
            &self.all_cap_k[self.context.key_share.party_index().as_usize()],
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
            &self.all_cap_g[from.as_usize()],
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

impl<P: SchemeParams> FinalizableToNextRound for Round2<P> {
    type NextRound = Round3<P>;
    fn finalize_to_next_round(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let payloads = try_to_holevec(payloads, self.num_parties(), self.party_idx()).unwrap();
        let artifacts = try_to_holevec(artifacts, self.num_parties(), self.party_idx()).unwrap();

        let cap_gamma = payloads
            .iter()
            .map(|payload| payload.cap_gamma)
            .sum::<Point>()
            + self.context.gamma.mul_by_generator();

        let cap_delta = cap_gamma * self.context.k;

        let alpha_sum: Signed<_> = payloads.iter().map(|p| p.alpha).sum();
        let beta_sum: Signed<_> = artifacts.iter().map(|p| p.beta).sum();
        let delta = P::signed_from_scalar(&self.context.gamma)
            * P::signed_from_scalar(&self.context.k)
            + alpha_sum
            + beta_sum;

        let hat_alpha_sum: Signed<_> = payloads.iter().map(|payload| payload.hat_alpha).sum();
        let hat_beta_sum: Signed<_> = artifacts.iter().map(|artifact| artifact.hat_beta).sum();
        let chi = P::signed_from_scalar(&self.context.key_share.secret_share)
            * P::signed_from_scalar(&self.context.k)
            + hat_alpha_sum
            + hat_beta_sum;

        let cap_ds = payloads.map_ref(|payload| payload.cap_d.clone());
        let hat_cap_d = payloads.map_ref(|payload| payload.hat_cap_d.clone());

        Ok(Round3 {
            context: self.context,
            delta,
            chi,
            cap_delta,
            cap_gamma,
            all_cap_k: self.all_cap_k,
            all_cap_g: self.all_cap_g,
            cap_ds,
            hat_cap_d,
            round2_artifacts: artifacts,
        })
    }
}

pub struct Round3<P: SchemeParams> {
    context: Context<P>,
    delta: Signed<<P::Paillier as PaillierParams>::Uint>,
    chi: Signed<<P::Paillier as PaillierParams>::Uint>,
    cap_delta: Point,
    cap_gamma: Point,
    all_cap_k: Vec<CiphertextMod<P::Paillier>>,
    all_cap_g: Vec<CiphertextMod<P::Paillier>>,
    cap_ds: HoleVec<CiphertextMod<P::Paillier>>,
    hat_cap_d: HoleVec<CiphertextMod<P::Paillier>>,
    round2_artifacts: HoleVec<Round2Artifact<P>>,
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

impl<P: SchemeParams> Round for Round3<P> {
    type Type = ToResult;
    type Result = PresigningResult<P>;
    const ROUND_NUM: u8 = 3;
    const NEXT_ROUND_NUM: Option<u8> = None;

    fn num_parties(&self) -> usize {
        self.context.key_share.num_parties()
    }

    fn party_idx(&self) -> PartyIdx {
        self.context.key_share.party_index()
    }

    type BroadcastMessage = ();
    type DirectMessage = Round3Message<P>;
    type Payload = Round3Payload;
    type Artifact = ();

    fn message_destinations(&self) -> Vec<PartyIdx> {
        all_parties_except(
            self.context.key_share.num_parties(),
            self.context.key_share.party_index(),
        )
    }

    no_broadcast_messages!();

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> (Self::DirectMessage, Self::Artifact) {
        let aux = (
            &self.context.ssid_hash,
            &self.context.key_share.party_index(),
        );
        let pk = &self.context.aux_info.secret_aux.paillier_sk.public_key();
        let idx = destination.as_usize();

        let public_aux = &self.context.aux_info.public_aux[idx];
        let rp = &public_aux.rp_params;

        let psi_pprime = LogStarProof::new(
            rng,
            &P::signed_from_scalar(&self.context.k),
            &self.context.rho,
            pk,
            &self.all_cap_k[self.party_idx().as_usize()],
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
        from: PartyIdx,
        _broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        let aux = (&self.context.ssid_hash, &from);
        let from_pk = &self.context.aux_info.public_aux[from.as_usize()].paillier_pk;

        let public_aux =
            &self.context.aux_info.public_aux[self.context.key_share.party_index().as_usize()];
        let rp = &public_aux.rp_params;

        if !direct_msg.psi_pprime.verify(
            from_pk,
            &self.all_cap_k[from.as_usize()],
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
pub struct PresigningProof<P: SchemeParams> {
    aff_g_proofs: Vec<(PartyIdx, PartyIdx, AffGProof<P>)>,
    mul_proof: MulProof<P>,
    dec_proofs: Vec<(PartyIdx, DecProof<P>)>,
}

impl<P: SchemeParams> FinalizableToResult for Round3<P> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        _artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let payloads = try_to_holevec(
            payloads,
            self.context.key_share.num_parties(),
            self.context.key_share.party_index(),
        )
        .unwrap();
        let (deltas, cap_deltas) = payloads
            .map(|payload| (payload.delta, payload.cap_delta))
            .unzip();

        let scalar_delta = P::scalar_from_signed(&self.delta);
        let assembled_delta: Scalar = scalar_delta + deltas.iter().sum::<Scalar>();
        let assembled_cap_delta: Point = self.cap_delta + cap_deltas.iter().sum::<Point>();

        if assembled_delta.mul_by_generator() == assembled_cap_delta {
            let nonce = (self.cap_gamma * assembled_delta.invert().unwrap()).x_coordinate();

            let hat_beta = self.round2_artifacts.map_ref(|artifact| artifact.hat_beta);
            let hat_r = self
                .round2_artifacts
                .map_ref(|artifact| artifact.hat_r.clone());
            let hat_s = self
                .round2_artifacts
                .map_ref(|artifact| artifact.hat_s.clone());
            let hat_cap_d = self
                .round2_artifacts
                .map_ref(|artifact| artifact.hat_cap_d.clone());
            let hat_cap_f = self
                .round2_artifacts
                .map_ref(|artifact| artifact.hat_cap_f.clone());

            return Ok(PresigningData {
                nonce,
                ephemeral_scalar_share: self.context.k,
                product_share: P::scalar_from_signed(&self.chi),

                product_share_nonreduced: self.chi,
                hat_beta,
                hat_r,
                hat_s,
                cap_k: self.all_cap_k.into_boxed_slice(),
                hat_cap_d_received: self.hat_cap_d,
                hat_cap_d,
                hat_cap_f,
            });
        }

        let my_idx = self.context.key_share.party_index().as_usize();

        // Construct the correctness proofs

        let sk = &self.context.aux_info.secret_aux.paillier_sk;
        let pk = sk.public_key();
        let num_parties = self.context.key_share.num_parties();

        let aux = (
            &self.context.ssid_hash,
            &self.context.key_share.party_index(),
        );

        // Aff-g proofs

        let mut aff_g_proofs = Vec::new();

        let beta = self.round2_artifacts.map_ref(|artifact| artifact.beta);
        let r = self.round2_artifacts.map_ref(|artifact| artifact.r.clone());
        let s = self.round2_artifacts.map_ref(|artifact| artifact.s.clone());

        let cap_gamma = self.context.gamma.mul_by_generator();

        for j in HoleRange::new(num_parties, my_idx) {
            let r2_artefacts = self.round2_artifacts.get(j).unwrap();

            for l in HoleRange::new(num_parties, my_idx) {
                if l == j {
                    continue;
                }
                let target_pk = &self.context.aux_info.public_aux[j].paillier_pk;
                let rp = &self.context.aux_info.public_aux[l].rp_params;

                let p_aff_g = AffGProof::<P>::new(
                    rng,
                    &P::signed_from_scalar(&self.context.gamma),
                    beta.get(j).unwrap(),
                    &s.get(j).unwrap().to_mod(target_pk),
                    &r.get(j).unwrap().to_mod(pk),
                    target_pk,
                    pk,
                    &self.all_cap_k[j],
                    &r2_artefacts.cap_d,
                    &r2_artefacts.cap_f,
                    &cap_gamma,
                    rp,
                    &aux,
                );

                assert!(p_aff_g.verify(
                    target_pk,
                    pk,
                    &self.all_cap_k[j],
                    &r2_artefacts.cap_d,
                    &r2_artefacts.cap_f,
                    &cap_gamma,
                    rp,
                    &aux,
                ));

                aff_g_proofs.push((PartyIdx::from_usize(j), PartyIdx::from_usize(l), p_aff_g));
            }
        }

        // Mul proof

        let rho = RandomizerMod::random(rng, pk);
        let cap_h = (&self.all_cap_g[my_idx] * P::bounded_from_scalar(&self.context.k))
            .mul_randomizer(&rho.retrieve());

        let p_mul = MulProof::<P>::new(
            rng,
            &P::signed_from_scalar(&self.context.k),
            &self.context.rho,
            &rho,
            pk,
            &self.all_cap_k[my_idx],
            &self.all_cap_g[my_idx],
            &cap_h,
            &aux,
        );
        assert!(p_mul.verify(
            pk,
            &self.all_cap_k[my_idx],
            &self.all_cap_g[my_idx],
            &cap_h,
            &aux
        ));

        // Dec proof

        let range = HoleRange::new(self.context.key_share.num_parties(), my_idx);

        let mut ciphertext = cap_h.clone();

        for j in range {
            ciphertext = ciphertext
                + self.cap_ds.get(j).unwrap()
                + &self.round2_artifacts.get(j).unwrap().cap_f;
        }

        let rho = ciphertext.derive_randomizer(sk);

        let mut dec_proofs = Vec::new();
        for j in range {
            let p_dec = DecProof::<P>::new(
                rng,
                &self.delta,
                &rho,
                pk,
                &scalar_delta,
                &ciphertext,
                &self.context.aux_info.public_aux[j].rp_params,
                &aux,
            );
            assert!(p_dec.verify(
                pk,
                &scalar_delta,
                &ciphertext,
                &self.context.aux_info.public_aux[j].rp_params,
                &aux
            ));
            dec_proofs.push((PartyIdx::from_usize(j), p_dec));
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
    use rand_core::{OsRng, RngCore};

    use super::Round1;
    use crate::cggmp21::{AuxInfo, KeyShare, TestParams};
    use crate::curve::Scalar;
    use crate::rounds::{
        test_utils::{step_next_round, step_result, step_round},
        FirstRound, PartyIdx,
    };

    #[test]
    fn execute_presigning() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let num_parties = 3;
        let key_shares = KeyShare::new_centralized(&mut OsRng, num_parties, None);
        let aux_infos = AuxInfo::new_centralized(&mut OsRng, num_parties);
        let r1 = (0..num_parties)
            .map(|idx| {
                Round1::<TestParams>::new(
                    &mut OsRng,
                    &shared_randomness,
                    num_parties,
                    PartyIdx::from_usize(idx),
                    (key_shares[idx].clone(), aux_infos[idx].clone()),
                )
                .unwrap()
            })
            .collect();

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let r2 = step_next_round(&mut OsRng, r1a).unwrap();
        let r2a = step_round(&mut OsRng, r2).unwrap();
        let r3 = step_next_round(&mut OsRng, r2a).unwrap();
        let r3a = step_round(&mut OsRng, r3).unwrap();
        let presigning_datas = step_result(&mut OsRng, r3a).unwrap();

        // Check that each node ends up with the same nonce.
        assert_eq!(presigning_datas[0].nonce, presigning_datas[1].nonce);
        assert_eq!(presigning_datas[0].nonce, presigning_datas[2].nonce);

        // Check that the additive shares were constructed in a consistent way.
        let k: Scalar = presigning_datas
            .iter()
            .map(|data| data.ephemeral_scalar_share)
            .sum();
        let k_times_x: Scalar = presigning_datas.iter().map(|data| data.product_share).sum();
        let x: Scalar = key_shares.iter().map(|share| share.secret_share).sum();
        assert_eq!(x * k, k_times_x);
        assert_eq!(
            k.invert().unwrap().mul_by_generator().x_coordinate(),
            presigning_datas[0].nonce
        );
    }
}
