use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::common::{AuxDataPublic, PresigningData, SchemeParams, SessionId};
use super::generic::{BroadcastRound, DirectRound, NeedsConsensus, Round, ToSendTyped};
use crate::paillier::{
    encryption::Ciphertext,
    keys::{PublicKeyPaillier, SecretKeyPaillier},
    params::PaillierParams,
    uint::Retrieve,
};
use crate::sigma::aff_g::AffGProof;
use crate::sigma::enc::EncProof;
use crate::sigma::log_star::LogStarProof;
use crate::tools::collections::{HoleRange, HoleVec, HoleVecAccum, PartyIdx};
use crate::tools::group::{Point, Scalar};

#[derive(Clone)]
pub struct PublicContext<P: PaillierParams> {
    session_id: SessionId,
    num_parties: usize,
    party_idx: PartyIdx,
    aux_data: Box<[AuxDataPublic<P>]>,
    paillier_pk: PublicKeyPaillier<P>,
}

struct SecretData<P: PaillierParams> {
    key_share: Scalar, // `x_i`
    paillier_sk: SecretKeyPaillier<P>,
    k: Scalar,
    gamma: Scalar,
    rho: P::DoubleUint,
    nu: P::DoubleUint,
}

// We are splitting Round 1 into two parts since it has to send both direct and broadcast
// messages. Our generic Round can only do either one or the other.
// So we are sending the broadcast first, and when the succeeds, send the direct ones.
// CHECK: this should not affect security.
// We could support sending both types of messages generically, but that would mean that most
// rounds would have empty implementations and unused types, since that behavior only happens
// in a few cases.
pub struct Round1Part1<P: SchemeParams> {
    context: PublicContext<P::Paillier>,
    secret_data: SecretData<P::Paillier>,
    k_ciphertext: Ciphertext<P::Paillier>,
    g_ciphertext: Ciphertext<P::Paillier>,
}

impl<P: SchemeParams> Round1Part1<P> {
    pub fn new(
        rng: &mut (impl RngCore + CryptoRng),
        session_id: &SessionId,
        party_idx: PartyIdx,
        num_parties: usize,
        key_share: &Scalar,
        paillier_sk: &SecretKeyPaillier<P::Paillier>,
        aux_data: &[AuxDataPublic<P::Paillier>],
    ) -> Self {
        let k = Scalar::random(rng);
        let gamma = Scalar::random(rng);

        let pk = &aux_data[party_idx.as_usize()].paillier_pk;
        let rho = pk.random_invertible_group_elem(rng).retrieve();
        let nu = pk.random_invertible_group_elem(rng).retrieve();

        let g_ciphertext = Ciphertext::new_with_randomizer(pk, &gamma, &nu);
        let k_ciphertext = Ciphertext::new_with_randomizer(pk, &k, &rho);

        Self {
            context: PublicContext {
                session_id: session_id.clone(),
                num_parties,
                party_idx,
                paillier_pk: pk.clone(),
                aux_data: aux_data.to_vec().into_boxed_slice(),
            },
            secret_data: SecretData {
                key_share: *key_share,
                paillier_sk: paillier_sk.clone(),
                k,
                gamma,
                rho,
                nu,
            },
            k_ciphertext,
            g_ciphertext,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "Ciphertext<P>: Serialize")]
pub struct Round1Bcast<P: PaillierParams> {
    k_ciphertext: Ciphertext<P>,
    g_ciphertext: Ciphertext<P>,
}

impl<P: SchemeParams> Round for Round1Part1<P> {
    type Error = String;
    type Payload = Round1Bcast<P::Paillier>;
    type Message = Round1Bcast<P::Paillier>;
    type NextRound = Round1Part2<P>;

    fn to_send(&self, _rng: &mut (impl RngCore + CryptoRng)) -> ToSendTyped<Self::Message> {
        ToSendTyped::Broadcast(Round1Bcast {
            k_ciphertext: self.k_ciphertext.clone(),
            g_ciphertext: self.g_ciphertext.clone(),
        })
    }

    fn verify_received(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        Ok(msg)
    }

    fn finalize(self, payloads: HoleVec<Self::Payload>) -> Result<Self::NextRound, Self::Error> {
        let (k_ciphertexts, g_ciphertexts) = payloads
            .map(|data| (data.k_ciphertext, data.g_ciphertext))
            .unzip();
        let k_ciphertexts = k_ciphertexts.into_vec(self.k_ciphertext);
        let g_ciphertexts = g_ciphertexts.into_vec(self.g_ciphertext);
        Ok(Round1Part2 {
            context: self.context,
            secret_data: self.secret_data,
            k_ciphertexts,
            g_ciphertexts,
        })
    }
}

impl<P: SchemeParams> BroadcastRound for Round1Part1<P> {}

impl<P: SchemeParams> NeedsConsensus for Round1Part1<P> {}

pub struct Round1Part2<P: SchemeParams> {
    context: PublicContext<P::Paillier>,
    secret_data: SecretData<P::Paillier>,
    k_ciphertexts: Vec<Ciphertext<P::Paillier>>,
    g_ciphertexts: Vec<Ciphertext<P::Paillier>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "EncProof<P>: Serialize")]
pub struct Round1Direct<P: PaillierParams>(EncProof<P>);

impl<P: SchemeParams> Round for Round1Part2<P> {
    type Error = String;
    type Payload = ();
    type Message = Round1Direct<P::Paillier>;
    type NextRound = Round2<P>;

    fn to_send(&self, rng: &mut (impl RngCore + CryptoRng)) -> ToSendTyped<Self::Message> {
        let range = HoleRange::new(self.context.num_parties, self.context.party_idx);
        let aux = (&self.context.session_id, &self.context.party_idx);
        let k_ciphertext = &self.k_ciphertexts[self.context.party_idx.as_usize()];
        let messages = range
            .map(|idx| {
                let proof = EncProof::random(
                    rng,
                    &self.secret_data.k,
                    &self.secret_data.rho,
                    &self.context.paillier_pk,
                    k_ciphertext,
                    &aux,
                );
                (idx, Round1Direct(proof))
            })
            .collect();
        ToSendTyped::Direct(messages)
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        let aux = (&self.context.session_id, &self.context.party_idx);
        if msg.0.verify(
            &self.context.aux_data[from.as_usize()].paillier_pk,
            &self.k_ciphertexts[from.as_usize()],
            &aux,
        ) {
            Ok(())
        } else {
            Err("Failed to verify EncProof".to_string())
        }
    }

    fn finalize(self, _payloads: HoleVec<Self::Payload>) -> Result<Self::NextRound, Self::Error> {
        // TODO: seems like we will have to pass the RNG to finalize() methods as well.
        // In fact, if we pass an RNG here, we might not need one in to_send() -
        // the messages can be created right in the constructor
        // (but then we will need to return them separately as a tuple with the new round,
        // so we don't have to store them)
        use rand_core::OsRng;
        Ok(Round2::new(&mut OsRng, self))
    }
}

impl<P: SchemeParams> DirectRound for Round1Part2<P> {}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "Ciphertext<P>: Serialize, AffGProof<P>: Serialize, LogStarProof<P>: Serialize")]
pub struct Round2Direct<P: PaillierParams> {
    gamma: Point,
    d: Ciphertext<P>,
    d_hat: Ciphertext<P>,
    f: Ciphertext<P>,
    f_hat: Ciphertext<P>,
    psi: AffGProof<P>,
    psi_hat: AffGProof<P>,
    psi_hat_prime: LogStarProof<P>,
}

pub struct Round2<P: SchemeParams> {
    context: PublicContext<P::Paillier>,
    secret_data: SecretData<P::Paillier>,
    k_ciphertexts: Vec<Ciphertext<P::Paillier>>,
    g_ciphertexts: Vec<Ciphertext<P::Paillier>>,
    // TODO: these are secret
    betas: HoleVec<Scalar>,
    betas_hat: HoleVec<Scalar>,
}

impl<P: SchemeParams> Round2<P> {
    fn new(rng: &mut (impl RngCore + CryptoRng), round1: Round1Part2<P>) -> Self {
        let mut betas = HoleVecAccum::new(round1.context.num_parties, round1.context.party_idx);
        let mut betas_hat = HoleVecAccum::new(round1.context.num_parties, round1.context.party_idx);

        let range = HoleRange::new(round1.context.num_parties, round1.context.party_idx);

        range.for_each(|idx| {
            let beta = Scalar::random_in_range_j(rng);
            let beta_hat = Scalar::random_in_range_j(rng);

            // TODO: can we do this without mutation?
            // Create the HoleVec with betas first?
            betas.insert(idx, beta).unwrap();
            betas_hat.insert(idx, beta_hat).unwrap();
        });

        Self {
            context: round1.context,
            secret_data: round1.secret_data,
            k_ciphertexts: round1.k_ciphertexts,
            g_ciphertexts: round1.g_ciphertexts,
            betas: betas.finalize().unwrap(),
            betas_hat: betas_hat.finalize().unwrap(),
        }
    }
}

#[derive(Clone)]
pub struct Round2Payload {
    gamma: Point,
    alpha: Scalar,
    alpha_hat: Scalar,
}

impl<P: SchemeParams> Round for Round2<P> {
    type Error = String;
    type Payload = Round2Payload;
    type Message = Round2Direct<P::Paillier>;
    type NextRound = Round3<P>;

    fn to_send(&self, rng: &mut (impl RngCore + CryptoRng)) -> ToSendTyped<Self::Message> {
        let range = HoleRange::new(self.context.num_parties, self.context.party_idx);
        let aux = (&self.context.session_id, &self.context.party_idx);

        let gamma = self.secret_data.gamma.mul_by_generator();
        // TODO: technically it's already been precalculated somewhere earlier
        let big_x = self.secret_data.key_share.mul_by_generator();
        let pk = &self.context.paillier_pk;

        let messages = range
            .map(|idx| {
                let target_pk = &self.context.aux_data[idx.as_usize()].paillier_pk;

                let r = target_pk.random_group_elem_raw(rng);
                let s = target_pk.random_group_elem_raw(rng);
                let r_hat = target_pk.random_group_elem_raw(rng);
                let s_hat = target_pk.random_group_elem_raw(rng);

                let beta = self.betas.get(idx).unwrap();
                let beta_hat = self.betas_hat.get(idx).unwrap();

                let d = self.k_ciphertexts[idx.as_usize()]
                    .homomorphic_mul(target_pk, &self.secret_data.gamma)
                    .homomorphic_add(
                        target_pk,
                        &Ciphertext::new_with_randomizer(target_pk, &-beta, &s),
                    );
                let f = Ciphertext::new_with_randomizer(pk, beta, &r);

                let d_hat = self.k_ciphertexts[idx.as_usize()]
                    .homomorphic_mul(target_pk, &self.secret_data.key_share)
                    .homomorphic_add(
                        target_pk,
                        &Ciphertext::new_with_randomizer(target_pk, &-beta_hat, &s_hat),
                    );
                let f_hat = Ciphertext::new_with_randomizer(pk, beta_hat, &r_hat);

                let psi = AffGProof::random(
                    rng,
                    &self.secret_data.gamma,
                    &beta,
                    &s,
                    &r,
                    target_pk,
                    pk,
                    &self.k_ciphertexts[idx.as_usize()],
                    &d,
                    &f,
                    &gamma,
                    &aux,
                );

                let psi_hat = AffGProof::random(
                    rng,
                    &self.secret_data.key_share,
                    &beta_hat,
                    &s_hat,
                    &r_hat,
                    target_pk,
                    pk,
                    &self.k_ciphertexts[idx.as_usize()],
                    &d_hat,
                    &f_hat,
                    &big_x,
                    &aux,
                );

                let psi_hat_prime = LogStarProof::random(
                    rng,
                    &self.secret_data.gamma,
                    &self.secret_data.nu,
                    pk,
                    &self.k_ciphertexts[self.context.party_idx.as_usize()],
                    &Point::GENERATOR,
                    &gamma,
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

                (idx, msg)
            })
            .collect();
        ToSendTyped::Direct(messages)
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        let aux = (&self.context.session_id, &self.context.party_idx);
        let pk = &self.context.paillier_pk;
        let from_pk = &self.context.aux_data[from.as_usize()].paillier_pk;

        // TODO: technically it's already been precalculated somewhere earlier
        let big_x = self.secret_data.key_share.mul_by_generator();

        if !msg.psi.verify(
            &pk,
            &from_pk,
            &self.k_ciphertexts[self.context.party_idx.as_usize()],
            &msg.d,
            &msg.f,
            &msg.gamma,
            &aux,
        ) {
            return Err("Failed to verify EncProof".to_string());
        }

        if !msg.psi_hat.verify(
            &pk,
            &from_pk,
            &self.k_ciphertexts[self.context.party_idx.as_usize()],
            &msg.d_hat,
            &msg.f_hat,
            &big_x,
            &aux,
        ) {
            return Err("Failed to verify EncProof".to_string());
        }

        if !msg.psi_hat_prime.verify(
            &from_pk,
            &self.g_ciphertexts[from.as_usize()],
            &Point::GENERATOR,
            &msg.gamma,
            &aux,
        ) {
            return Err("Failed to verify EncProof".to_string());
        }

        let alpha = msg.d.decrypt(&self.secret_data.paillier_sk);
        let alpha_hat = msg.d_hat.decrypt(&self.secret_data.paillier_sk);

        Ok(Round2Payload {
            gamma: msg.gamma,
            alpha,
            alpha_hat,
        })
    }

    fn finalize(self, payloads: HoleVec<Self::Payload>) -> Result<Self::NextRound, Self::Error> {
        let gamma: Point = payloads.iter().map(|payload| payload.gamma).sum();
        let gamma = gamma + self.secret_data.gamma.mul_by_generator();

        let big_delta = &gamma * &self.secret_data.k;

        let alpha_sum: Scalar = payloads.iter().map(|payload| payload.alpha).sum();
        let alpha_hat_sum: Scalar = payloads.iter().map(|payload| payload.alpha_hat).sum();

        let beta_sum: Scalar = self.betas.iter().sum();
        let beta_hat_sum: Scalar = self.betas_hat.iter().sum();

        let delta = &self.secret_data.gamma * &self.secret_data.k + alpha_sum + beta_sum;
        let chi = &self.secret_data.key_share * &self.secret_data.k + alpha_hat_sum + beta_hat_sum;

        Ok(Round3 {
            context: self.context,
            secret_data: self.secret_data,
            delta,
            chi,
            big_delta,
            big_gamma: gamma,
            k_ciphertexts: self.k_ciphertexts,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "LogStarProof<P>: Serialize")]
pub struct Round3Bcast<P: PaillierParams> {
    delta: Scalar,
    big_delta: Point,
    psi_hat_pprime: LogStarProof<P>,
}

pub struct Round3<P: SchemeParams> {
    context: PublicContext<P::Paillier>,
    secret_data: SecretData<P::Paillier>,
    delta: Scalar,
    chi: Scalar,
    big_delta: Point,
    big_gamma: Point,
    k_ciphertexts: Vec<Ciphertext<P::Paillier>>,
}

#[derive(Clone)]
pub struct Round3Payload {
    delta: Scalar,
    big_delta: Point,
}

impl<P: SchemeParams> Round for Round3<P> {
    type Error = String;
    type Payload = Round3Payload;
    type Message = Round3Bcast<P::Paillier>;
    type NextRound = PresigningData;

    fn to_send(&self, rng: &mut (impl RngCore + CryptoRng)) -> ToSendTyped<Self::Message> {
        let range = HoleRange::new(self.context.num_parties, self.context.party_idx);
        let aux = (&self.context.session_id, &self.context.party_idx);
        let pk = &self.context.paillier_pk;

        let messages = range
            .map(|idx| {
                let psi_hat_pprime = LogStarProof::random(
                    rng,
                    &self.secret_data.k,
                    &self.secret_data.rho,
                    pk,
                    &self.k_ciphertexts[self.context.party_idx.as_usize()],
                    &self.big_gamma,
                    &self.big_delta,
                    &aux,
                );
                let message = Round3Bcast {
                    delta: self.delta,
                    big_delta: self.big_delta,
                    psi_hat_pprime,
                };
                (idx, message)
            })
            .collect();

        ToSendTyped::Direct(messages)
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        let aux = (&self.context.session_id, &self.context.party_idx);
        let from_pk = &self.context.aux_data[from.as_usize()].paillier_pk;
        if !msg.psi_hat_pprime.verify(
            &from_pk,
            &self.k_ciphertexts[from.as_usize()],
            &self.big_gamma,
            &msg.big_delta,
            &aux,
        ) {
            return Err("Failed to verify Log-Star proof".to_string());
        }
        Ok(Round3Payload {
            delta: msg.delta,
            big_delta: msg.big_delta,
        })
    }

    fn finalize(self, payloads: HoleVec<Self::Payload>) -> Result<Self::NextRound, Self::Error> {
        let (deltas, big_deltas) = payloads
            .map(|payload| (payload.delta, payload.big_delta))
            .unzip();

        let delta: Scalar = deltas.iter().sum();
        let delta = delta + self.delta;

        let big_delta: Point = big_deltas.iter().sum();
        let big_delta = big_delta + self.big_delta;

        // TODO: seems like we need to allow `finalize()` to result in an error.
        // For now we just panic.
        if delta.mul_by_generator() != big_delta {
            panic!("Deltas do not coincide");
            // TODO: calculate the required proofs here according to the paper.
        }

        // TODO: seems like we only need the x-coordinate of this (as a Scalar)
        let big_r = &self.big_gamma * &delta.invert().unwrap();

        Ok(PresigningData {
            big_r,
            k: self.secret_data.k,
            chi: self.chi,
        })
    }
}

#[cfg(test)]
mod tests {
    use rand_core::OsRng;

    use super::{AuxDataPublic, Round1Part1};
    use crate::paillier::uint::Zero;
    use crate::paillier::{PaillierParams, SecretKeyPaillier};
    use crate::protocols::common::{SchemeParams, SessionId, TestSchemeParams};
    use crate::protocols::generic::tests::step;
    use crate::tools::collections::PartyIdx;
    use crate::tools::group::{Point, Scalar};

    fn make_aux_data<P: PaillierParams>(sks: &[&SecretKeyPaillier<P>]) -> Box<[AuxDataPublic<P>]> {
        sks.into_iter()
            .map(|sk| AuxDataPublic {
                y: Point::GENERATOR,
                rp_generator: P::DoubleUint::ZERO,
                rp_power: P::DoubleUint::ZERO,
                paillier_pk: sk.public_key(),
            })
            .collect()
    }

    #[test]
    fn execute_presigning() {
        let session_id = SessionId::random();

        let sk1 =
            SecretKeyPaillier::<<TestSchemeParams as SchemeParams>::Paillier>::random(&mut OsRng);
        let sk2 =
            SecretKeyPaillier::<<TestSchemeParams as SchemeParams>::Paillier>::random(&mut OsRng);
        let sk3 =
            SecretKeyPaillier::<<TestSchemeParams as SchemeParams>::Paillier>::random(&mut OsRng);

        let x1 = Scalar::random(&mut OsRng);
        let x2 = Scalar::random(&mut OsRng);
        let x3 = Scalar::random(&mut OsRng);

        let aux = make_aux_data(&[&sk1, &sk2, &sk3]);

        let r1 = vec![
            Round1Part1::<TestSchemeParams>::new(
                &mut OsRng,
                &session_id,
                PartyIdx::from_usize(0),
                3,
                &x1,
                &sk1,
                &aux,
            ),
            Round1Part1::<TestSchemeParams>::new(
                &mut OsRng,
                &session_id,
                PartyIdx::from_usize(1),
                3,
                &x2,
                &sk2,
                &aux,
            ),
            Round1Part1::<TestSchemeParams>::new(
                &mut OsRng,
                &session_id,
                PartyIdx::from_usize(2),
                3,
                &x3,
                &sk3,
                &aux,
            ),
        ];

        let r1p2 = step(&mut OsRng, r1).unwrap();
        let r2 = step(&mut OsRng, r1p2).unwrap();
        let r3 = step(&mut OsRng, r2).unwrap();
        let presigning_datas = step(&mut OsRng, r3).unwrap();

        assert_eq!(presigning_datas[0].big_r, presigning_datas[1].big_r);
        assert_eq!(presigning_datas[0].big_r, presigning_datas[2].big_r);

        // TODO: what contracts do we expect?
    }
}
