use alloc::boxed::Box;
use alloc::vec::Vec;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::{KeyShare, KeySharePrecomputed, PartyIdx, PresigningData};
use super::generic::{
    BaseRound, FinalizeError, FinalizeSuccess, FirstRound, InitError, NonExistent, ReceiveError,
    Round, ToSendTyped,
};
use crate::cggmp21::{
    sigma::{AffGProof, EncProof, LogStarProof},
    SchemeParams,
};
use crate::curve::{Point, Scalar};
use crate::paillier::{Ciphertext, PaillierParams};
use crate::tools::collections::{HoleRange, HoleVec, HoleVecAccum};
use crate::tools::hashing::{Chain, Hashable};
use crate::uint::{FromScalar, Signed};

fn uint_from_scalar<P: SchemeParams>(
    x: &Scalar,
) -> <<P as SchemeParams>::Paillier as PaillierParams>::DoubleUint {
    <<P as SchemeParams>::Paillier as PaillierParams>::DoubleUint::from_scalar(x)
}

pub struct Context<P: SchemeParams> {
    shared_randomness: Box<[u8]>,
    num_parties: usize,
    key_share: KeySharePrecomputed<P>,
    ephemeral_scalar_share: Scalar,
    gamma: Scalar,
    rho: <<P as SchemeParams>::Paillier as PaillierParams>::DoubleUint,
    nu: <<P as SchemeParams>::Paillier as PaillierParams>::DoubleUint,
}

// We are splitting Round 1 into two parts since it has to send both direct and broadcast
// messages. Our generic Round can only do either one or the other.
// So we are sending the broadcast first, and when the succeeds, send the direct ones.
// CHECK: this should not affect security.
// We could support sending both types of messages generically, but that would mean that most
// rounds would have empty implementations and unused types, since that behavior only happens
// in a few cases.
pub struct Round1Part1<P: SchemeParams> {
    context: Context<P>,
    k_ciphertext: Ciphertext<P::Paillier>,
    g_ciphertext: Ciphertext<P::Paillier>,
}

impl<P: SchemeParams> FirstRound for Round1Part1<P> {
    type Context = KeyShare<P>;
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        _party_idx: PartyIdx,
        context: Self::Context,
    ) -> Result<Self, InitError> {
        let key_share = context.to_precomputed();

        // TODO: check that KeyShare is consistent with num_parties/party_idx

        let ephemeral_scalar_share = Scalar::random(rng);
        let gamma = Scalar::random(rng);

        let pk = key_share.secret_aux.paillier_sk.public_key();

        let rho = Ciphertext::<P::Paillier>::randomizer(rng, pk);
        let nu = Ciphertext::<P::Paillier>::randomizer(rng, pk);

        let g_ciphertext = Ciphertext::new_with_randomizer(pk, &uint_from_scalar::<P>(&gamma), &nu);
        let k_ciphertext = Ciphertext::new_with_randomizer(
            pk,
            &uint_from_scalar::<P>(&ephemeral_scalar_share),
            &rho,
        );

        Ok(Self {
            context: Context {
                shared_randomness: shared_randomness.into(),
                num_parties,
                key_share,
                ephemeral_scalar_share,
                gamma,
                rho,
                nu,
            },
            k_ciphertext,
            g_ciphertext,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "Ciphertext<P>: Serialize"))]
#[serde(bound(deserialize = "Ciphertext<P>: for<'x> Deserialize<'x>"))]
pub struct Round1Bcast<P: PaillierParams> {
    k_ciphertext: Ciphertext<P>,
    g_ciphertext: Ciphertext<P>,
}

impl<P: PaillierParams> Hashable for Round1Bcast<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.k_ciphertext).chain(&self.g_ciphertext)
    }
}

impl<P: SchemeParams> BaseRound for Round1Part1<P> {
    type Payload = Round1Bcast<P::Paillier>;
    type Message = Round1Bcast<P::Paillier>;

    const ROUND_NUM: u8 = 1;
    const REQUIRES_BROADCAST_CONSENSUS: bool = true;

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        ToSendTyped::Broadcast(Round1Bcast {
            k_ciphertext: self.k_ciphertext.clone(),
            g_ciphertext: self.g_ciphertext.clone(),
        })
    }

    fn verify_received(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        Ok(msg)
    }
}

impl<P: SchemeParams> Round for Round1Part1<P> {
    type NextRound = Round1Part2<P>;
    type Result = PresigningData;

    const NEXT_ROUND_NUM: Option<u8> = Some(2);

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let (k_ciphertexts, g_ciphertexts) = payloads
            .map(|data| (data.k_ciphertext, data.g_ciphertext))
            .unzip();
        let k_ciphertexts = k_ciphertexts.into_vec(self.k_ciphertext);
        let g_ciphertexts = g_ciphertexts.into_vec(self.g_ciphertext);
        Ok(FinalizeSuccess::AnotherRound(Round1Part2 {
            context: self.context,
            k_ciphertexts,
            g_ciphertexts,
        }))
    }
}

pub struct Round1Part2<P: SchemeParams> {
    context: Context<P>,
    k_ciphertexts: Vec<Ciphertext<P::Paillier>>,
    g_ciphertexts: Vec<Ciphertext<P::Paillier>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "EncProof<P>: Serialize"))]
#[serde(bound(deserialize = "EncProof<P>: for<'x> Deserialize<'x>"))]
pub struct Round1Direct<P: SchemeParams>(EncProof<P>);

impl<P: SchemeParams> BaseRound for Round1Part2<P> {
    type Payload = ();
    type Message = Round1Direct<P>;

    const ROUND_NUM: u8 = 2;
    const REQUIRES_BROADCAST_CONSENSUS: bool = false;

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        let range = HoleRange::new(
            self.context.num_parties,
            self.context.key_share.index.as_usize(),
        );
        let messages = range
            .map(|idx| {
                let aux = (&self.context.shared_randomness, &PartyIdx::from_usize(idx));
                let proof = EncProof::random(
                    rng,
                    &Signed::from_scalar(&self.context.ephemeral_scalar_share),
                    &self.context.rho,
                    &self.context.key_share.secret_aux.paillier_sk,
                    &self.context.key_share.public_aux[idx].aux_rp_params,
                    &aux,
                );
                (PartyIdx::from_usize(idx), Round1Direct(proof))
            })
            .collect();
        ToSendTyped::Direct(messages)
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        let aux = (
            &self.context.shared_randomness,
            &self.context.key_share.index,
        );

        let public_aux =
            self.context.key_share.public_aux[self.context.key_share.index.as_usize()].clone();

        if msg.0.verify(
            &self.context.key_share.public_aux[from.as_usize()].paillier_pk,
            &self.k_ciphertexts[from.as_usize()],
            &public_aux.aux_rp_params,
            &aux,
        ) {
            Ok(())
        } else {
            Err(ReceiveError::VerificationFail(
                "Failed to verify EncProof".into(),
            ))
        }
    }
}

impl<P: SchemeParams> Round for Round1Part2<P> {
    type NextRound = Round2<P>;
    type Result = PresigningData;

    const NEXT_ROUND_NUM: Option<u8> = Some(3);

    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        _payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        Ok(FinalizeSuccess::AnotherRound(Round2::new(rng, self)))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "Ciphertext<P::Paillier>: Serialize,
    AffGProof<P>: Serialize,
    LogStarProof<P>: Serialize"))]
#[serde(bound(deserialize = "Ciphertext<P::Paillier>: for<'x> Deserialize<'x>,
    AffGProof<P>: for<'x> Deserialize<'x>,
    LogStarProof<P>: for<'x> Deserialize<'x>"))]
pub struct Round2Direct<P: SchemeParams> {
    gamma: Point,
    d: Ciphertext<P::Paillier>,
    d_hat: Ciphertext<P::Paillier>,
    f: Ciphertext<P::Paillier>,
    f_hat: Ciphertext<P::Paillier>,
    psi: AffGProof<P>,
    psi_hat: AffGProof<P>,
    psi_hat_prime: LogStarProof<P>,
}

pub struct Round2<P: SchemeParams> {
    context: Context<P>,
    k_ciphertexts: Vec<Ciphertext<P::Paillier>>,
    g_ciphertexts: Vec<Ciphertext<P::Paillier>>,
    // TODO: these are secret
    betas: HoleVec<Signed<<P::Paillier as PaillierParams>::DoubleUint>>,
    betas_hat: HoleVec<Signed<<P::Paillier as PaillierParams>::DoubleUint>>,
}

impl<P: SchemeParams> Round2<P> {
    fn new(rng: &mut impl CryptoRngCore, round1: Round1Part2<P>) -> Self {
        let mut betas = HoleVecAccum::new(
            round1.context.num_parties,
            round1.context.key_share.index.as_usize(),
        );
        let mut betas_hat = HoleVecAccum::new(
            round1.context.num_parties,
            round1.context.key_share.index.as_usize(),
        );

        let range = HoleRange::new(
            round1.context.num_parties,
            round1.context.key_share.index.as_usize(),
        );

        range.for_each(|idx| {
            let beta = Signed::random_bounded_bits(rng, P::LP_BOUND);
            let beta_hat = Signed::random_bounded_bits(rng, P::LP_BOUND);

            // TODO: can we do this without mutation?
            // Create the HoleVec with betas first?
            betas.insert(idx, beta).unwrap();
            betas_hat.insert(idx, beta_hat).unwrap();
        });

        Self {
            context: round1.context,
            k_ciphertexts: round1.k_ciphertexts,
            g_ciphertexts: round1.g_ciphertexts,
            betas: betas.finalize().unwrap(),
            betas_hat: betas_hat.finalize().unwrap(),
        }
    }
}

pub struct Round2Payload {
    gamma: Point,
    alpha: Scalar,
    alpha_hat: Scalar,
}

impl<P: SchemeParams> BaseRound for Round2<P> {
    type Payload = Round2Payload;
    type Message = Round2Direct<P>;

    const ROUND_NUM: u8 = 3;
    const REQUIRES_BROADCAST_CONSENSUS: bool = false;

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        let range = HoleRange::new(
            self.context.num_parties,
            self.context.key_share.index.as_usize(),
        );
        let aux = (
            &self.context.shared_randomness,
            &self.context.key_share.index,
        );

        let gamma = self.context.gamma.mul_by_generator();
        let pk = &self.context.key_share.secret_aux.paillier_sk.public_key();

        let messages = range
            .map(|idx| {
                let target_pk = &self.context.key_share.public_aux[idx].paillier_pk;

                let r = target_pk.random_group_elem_raw(rng);
                let s = target_pk.random_group_elem_raw(rng);
                let r_hat = target_pk.random_group_elem_raw(rng);
                let s_hat = target_pk.random_group_elem_raw(rng);

                let beta = self.betas.get(idx).unwrap();
                let beta_hat = self.betas_hat.get(idx).unwrap();

                let d = self.k_ciphertexts[idx]
                    .homomorphic_mul(target_pk, &Signed::from_scalar(&self.context.gamma))
                    .homomorphic_add(
                        target_pk,
                        &Ciphertext::new_with_randomizer_signed(target_pk, &-beta, &s),
                    );
                let f = Ciphertext::new_with_randomizer_signed(pk, beta, &r);

                let d_hat = self.k_ciphertexts[idx]
                    .homomorphic_mul(
                        target_pk,
                        &Signed::from_scalar(&self.context.key_share.secret_share),
                    )
                    .homomorphic_add(
                        target_pk,
                        &Ciphertext::new_with_randomizer_signed(target_pk, &-beta_hat, &s_hat),
                    );
                let f_hat = Ciphertext::new_with_randomizer_signed(pk, beta_hat, &r_hat);

                let public_aux = &self.context.key_share.public_aux[idx];
                let aux_rp = &public_aux.aux_rp_params;

                let psi = AffGProof::random(
                    rng,
                    &Signed::from_scalar(&self.context.gamma),
                    beta,
                    &s,
                    &r,
                    target_pk,
                    pk,
                    &self.k_ciphertexts[idx],
                    aux_rp,
                    &aux,
                );

                let psi_hat = AffGProof::random(
                    rng,
                    &Signed::from_scalar(&self.context.key_share.secret_share),
                    beta_hat,
                    &s_hat,
                    &r_hat,
                    target_pk,
                    pk,
                    &self.k_ciphertexts[idx],
                    aux_rp,
                    &aux,
                );

                let psi_hat_prime = LogStarProof::random(
                    rng,
                    &Signed::from_scalar(&self.context.gamma),
                    &self.context.nu,
                    pk,
                    &Point::GENERATOR,
                    aux_rp,
                    &aux,
                );

                let msg = Round2Direct {
                    gamma,
                    d,
                    f,
                    d_hat,
                    f_hat,
                    psi,
                    psi_hat,
                    psi_hat_prime,
                };

                (PartyIdx::from_usize(idx), msg)
            })
            .collect();
        ToSendTyped::Direct(messages)
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        let aux = (&self.context.shared_randomness, &from);
        let pk = &self.context.key_share.secret_aux.paillier_sk.public_key();
        let from_pk = &self.context.key_share.public_aux[from.as_usize()].paillier_pk;

        let big_x = self.context.key_share.public_shares[from.as_usize()];

        let public_aux =
            &self.context.key_share.public_aux[self.context.key_share.index.as_usize()];
        let aux_rp = &public_aux.aux_rp_params;

        if !msg.psi.verify(
            pk,
            from_pk,
            &self.k_ciphertexts[self.context.key_share.index.as_usize()],
            &msg.d,
            &msg.f,
            &msg.gamma,
            aux_rp,
            &aux,
        ) {
            return Err(ReceiveError::VerificationFail(
                "Failed to verify AffGProof (psi)".into(),
            ));
        }

        if !msg.psi_hat.verify(
            pk,
            from_pk,
            &self.k_ciphertexts[self.context.key_share.index.as_usize()],
            &msg.d_hat,
            &msg.f_hat,
            &big_x,
            aux_rp,
            &aux,
        ) {
            return Err(ReceiveError::VerificationFail(
                "Failed to verify AffGProof (psi_hat)".into(),
            ));
        }

        if !msg.psi_hat_prime.verify(
            from_pk,
            &self.g_ciphertexts[from.as_usize()],
            &Point::GENERATOR,
            &msg.gamma,
            aux_rp,
            &aux,
        ) {
            return Err(ReceiveError::VerificationFail(
                "Failed to verify LogStarProof".into(),
            ));
        }

        let alpha = msg
            .d
            .decrypt_signed(&self.context.key_share.secret_aux.paillier_sk)
            .to_scalar();
        let alpha_hat = msg
            .d_hat
            .decrypt_signed(&self.context.key_share.secret_aux.paillier_sk)
            .to_scalar();

        Ok(Round2Payload {
            gamma: msg.gamma,
            alpha,
            alpha_hat,
        })
    }
}

impl<P: SchemeParams> Round for Round2<P> {
    type NextRound = Round3<P>;
    type Result = PresigningData;

    const NEXT_ROUND_NUM: Option<u8> = Some(4);

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let gamma: Point = payloads.iter().map(|payload| payload.gamma).sum();
        let gamma = gamma + self.context.gamma.mul_by_generator();

        let big_delta = &gamma * &self.context.ephemeral_scalar_share;

        let alpha_sum: Scalar = payloads.iter().map(|payload| payload.alpha).sum();
        let alpha_hat_sum: Scalar = payloads.iter().map(|payload| payload.alpha_hat).sum();

        let beta_sum: Signed<_> = self.betas.iter().sum();
        let beta_hat_sum: Signed<_> = self.betas_hat.iter().sum();

        let delta = self.context.gamma * self.context.ephemeral_scalar_share
            + alpha_sum
            + beta_sum.to_scalar();
        let product_share = self.context.key_share.secret_share
            * self.context.ephemeral_scalar_share
            + alpha_hat_sum
            + beta_hat_sum.to_scalar();

        Ok(FinalizeSuccess::AnotherRound(Round3 {
            context: self.context,
            delta,
            product_share,
            big_delta,
            big_gamma: gamma,
            k_ciphertexts: self.k_ciphertexts,
        }))
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "LogStarProof<P>: Serialize"))]
#[serde(bound(deserialize = "LogStarProof<P>: for<'x> Deserialize<'x>"))]
pub struct Round3Bcast<P: SchemeParams> {
    delta: Scalar,
    big_delta: Point,
    psi_hat_pprime: LogStarProof<P>,
}

pub struct Round3<P: SchemeParams> {
    context: Context<P>,
    delta: Scalar,
    product_share: Scalar,
    big_delta: Point,
    big_gamma: Point,
    k_ciphertexts: Vec<Ciphertext<P::Paillier>>,
}

pub struct Round3Payload {
    delta: Scalar,
    big_delta: Point,
}

impl<P: SchemeParams> BaseRound for Round3<P> {
    type Payload = Round3Payload;
    type Message = Round3Bcast<P>;

    const ROUND_NUM: u8 = 4;
    const REQUIRES_BROADCAST_CONSENSUS: bool = false;

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        let range = HoleRange::new(
            self.context.num_parties,
            self.context.key_share.index.as_usize(),
        );
        let aux = (
            &self.context.shared_randomness,
            &self.context.key_share.index,
        );
        let pk = &self.context.key_share.secret_aux.paillier_sk.public_key();

        let messages = range
            .map(|idx| {
                let public_aux = &self.context.key_share.public_aux[idx];
                let aux_rp = &public_aux.aux_rp_params;

                let psi_hat_pprime = LogStarProof::random(
                    rng,
                    &Signed::from_scalar(&self.context.ephemeral_scalar_share),
                    &self.context.rho,
                    pk,
                    &self.big_gamma,
                    aux_rp,
                    &aux,
                );
                let message = Round3Bcast {
                    delta: self.delta,
                    big_delta: self.big_delta,
                    psi_hat_pprime,
                };
                (PartyIdx::from_usize(idx), message)
            })
            .collect();

        ToSendTyped::Direct(messages)
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        let aux = (&self.context.shared_randomness, &from);
        let from_pk = &self.context.key_share.public_aux[from.as_usize()].paillier_pk;

        let public_aux =
            &self.context.key_share.public_aux[self.context.key_share.index.as_usize()];
        let aux_rp = &public_aux.aux_rp_params;

        if !msg.psi_hat_pprime.verify(
            from_pk,
            &self.k_ciphertexts[from.as_usize()],
            &self.big_gamma,
            &msg.big_delta,
            aux_rp,
            &aux,
        ) {
            return Err(ReceiveError::VerificationFail(
                "Failed to verify Log-Star proof".into(),
            ));
        }
        Ok(Round3Payload {
            delta: msg.delta,
            big_delta: msg.big_delta,
        })
    }
}

impl<P: SchemeParams> Round for Round3<P> {
    type NextRound = NonExistent<Self::Result>;
    type Result = PresigningData;

    const NEXT_ROUND_NUM: Option<u8> = None;

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let (deltas, big_deltas) = payloads
            .map(|payload| (payload.delta, payload.big_delta))
            .unzip();

        let delta: Scalar = deltas.iter().sum();
        let delta = delta + self.delta;

        let big_delta: Point = big_deltas.iter().sum();
        let big_delta = big_delta + self.big_delta;

        if delta.mul_by_generator() != big_delta {
            return Err(FinalizeError::Unspecified("Invalid Delta".into()));
            // TODO: calculate the required proofs here according to the paper.
        }

        // TODO: seems like we only need the x-coordinate of this (as a Scalar)
        let nonce = &self.big_gamma * &delta.invert().unwrap();

        Ok(FinalizeSuccess::Result(PresigningData {
            nonce,
            ephemeral_scalar_share: self.context.ephemeral_scalar_share,
            product_share: self.product_share,
        }))
    }
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, RngCore};

    use super::super::{
        test_utils::{assert_next_round, assert_result, step},
        FirstRound,
    };
    use super::Round1Part1;
    use crate::cggmp21::{KeyShare, PartyIdx, TestParams};
    use crate::curve::{Point, Scalar};

    #[test]
    fn execute_presigning() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let num_parties = 3;
        let key_shares = KeyShare::new_centralized(&mut OsRng, num_parties, None);
        let r1 = (0..num_parties)
            .map(|idx| {
                Round1Part1::<TestParams>::new(
                    &mut OsRng,
                    &shared_randomness,
                    num_parties,
                    PartyIdx::from_usize(idx),
                    key_shares[idx].clone(),
                )
                .unwrap()
            })
            .collect();

        let r1p2 = assert_next_round(step(&mut OsRng, r1).unwrap()).unwrap();
        let r2 = assert_next_round(step(&mut OsRng, r1p2).unwrap()).unwrap();
        let r3 = assert_next_round(step(&mut OsRng, r2).unwrap()).unwrap();
        let presigning_datas = assert_result(step(&mut OsRng, r3).unwrap()).unwrap();

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
            &Point::GENERATOR * &k.invert().unwrap(),
            presigning_datas[0].nonce
        );
    }
}
