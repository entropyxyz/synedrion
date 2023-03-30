use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crypto_bigint::Pow;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::common::{SchemeParams, SessionId};
use super::generic::{BroadcastRound, DirectRound, NeedsConsensus, Round, ToSendTyped};
use crate::paillier::{
    encryption::Ciphertext,
    keys::{PublicKeyPaillier, SecretKeyPaillier},
    params::PaillierParams,
    uint::{Retrieve, UintLike},
};
use crate::sigma::enc::EncProof;
use crate::sigma::fac::FacProof;
use crate::sigma::mod_::ModProof;
use crate::sigma::prm::PrmProof;
use crate::sigma::sch::{SchCommitment, SchProof, SchSecret};
use crate::tools::collections::{HoleRange, HoleVec, PartyIdx};
use crate::tools::group::{zero_sum_scalars, NonZeroScalar, Point, Scalar};
use crate::tools::hashing::{Chain, Hash};
use crate::tools::random::random_bits;

// TODO: this should be somehow obtained from AuxData and KeyShare
#[derive(Clone)]
pub struct AuxDataPublic<P: PaillierParams> {
    xs_public: Vec<Point>,
    ys_public: Vec<Point>,
    paillier_pks: Vec<PublicKeyPaillier<P>>,
    paillier_bases: Vec<P::DoubleUint>,
    paillier_publics: Vec<P::DoubleUint>,
}

#[derive(Clone)]
pub struct PublicContext<P: PaillierParams> {
    session_id: SessionId,
    num_parties: usize,
    party_idx: PartyIdx,
    aux_data: AuxDataPublic<P>,
    paillier_pk: PublicKeyPaillier<P>,
}

struct SecretData<P: PaillierParams> {
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
        aux_data: &AuxDataPublic<P::Paillier>,
    ) -> Self {
        let k = Scalar::random(rng);
        let gamma = Scalar::random(rng);

        let pk = &aux_data.paillier_pks[party_idx.as_usize()];
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
                aux_data: aux_data.clone(),
            },
            secret_data: SecretData { k, gamma, rho, nu },
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

    fn finalize(self, payloads: HoleVec<Self::Payload>) -> Self::NextRound {
        let (k_ciphertexts, g_ciphertexts) = payloads
            .map(|data| (data.k_ciphertext, data.g_ciphertext))
            .unzip();
        let k_ciphertexts = k_ciphertexts.into_vec(self.k_ciphertext);
        let g_ciphertexts = g_ciphertexts.into_vec(self.g_ciphertext);
        Round1Part2 {
            context: self.context,
            secret_data: self.secret_data,
            k_ciphertexts,
            g_ciphertexts,
        }
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
    type NextRound = ();

    fn to_send(&self, rng: &mut (impl RngCore + CryptoRng)) -> ToSendTyped<Self::Message> {
        let range = HoleRange::new(self.context.num_parties, self.context.party_idx);
        let aux = (&self.context.session_id, &self.context.party_idx);
        let k_ciphertext = &self.k_ciphertexts[self.context.party_idx.as_usize()];
        let messages = range
            .map(|idx| {
                let proof = EncProof::random(
                    rng,
                    &self.context.paillier_pk,
                    &self.secret_data.k,
                    &self.secret_data.rho,
                    &k_ciphertext,
                    &aux,
                );
                (idx, Round1Direct(proof))
            })
            .collect();
        ToSendTyped::Direct(messages)
    }

    fn verify_received(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        if msg.0.verify() {
            Ok(())
        } else {
            Err("Failed to verify EncProof".to_string())
        }
    }

    fn finalize(self, _payloads: HoleVec<Self::Payload>) -> Self::NextRound {
        ()
    }
}

impl<P: SchemeParams> DirectRound for Round1Part2<P> {}
