//! Signing using previously calculated presigning data, in the paper ECDSA Signing (Fig. 8).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::cggmp21::{
    sigma::{AffGProof, DecProof, MulStarProof},
    SchemeParams,
};
use crate::common::{KeySharePrecomputed, PresigningData};
use crate::curve::{RecoverableSignature, Scalar};
use crate::paillier::RandomizerMod;
use crate::rounds::{
    all_parties_except, no_direct_messages, try_to_holevec, FinalizableToResult, FinalizeError,
    FirstRound, InitError, PartyIdx, ProtocolResult, ReceiveError, Round, ToResult,
};
use crate::tools::{
    collections::HoleRange,
    hashing::{Chain, Hash, HashOutput},
};

/// Possible results of the Signing protocol.
#[derive(Debug, Clone, Copy)]
pub struct SigningResult<P: SchemeParams>(PhantomData<P>);

impl<P: SchemeParams> ProtocolResult for SigningResult<P> {
    type Success = RecoverableSignature;
    type ProvableError = ();
    type CorrectnessProof = SigningProof<P>;
}

/// A proof of a node's correct behavior for the Signing protocol.
#[allow(dead_code)] // TODO (#43): this can be removed when error verification is added
#[derive(Debug, Clone)]
pub struct SigningProof<P: SchemeParams> {
    aff_g_proofs: Vec<(PartyIdx, PartyIdx, AffGProof<P>)>,
    mul_star_proofs: Vec<(PartyIdx, MulStarProof<P>)>,
    dec_proofs: Vec<(PartyIdx, DecProof<P>)>,
}

pub struct Round1<P: SchemeParams> {
    ssid_hash: HashOutput,
    r: Scalar,
    sigma: Scalar,
    inputs: Inputs<P>,
    num_parties: usize,
    party_idx: PartyIdx,
}

#[derive(Clone)]
pub struct Inputs<P: SchemeParams> {
    pub message: Scalar,
    pub presigning: PresigningData<P>,
    pub key_share: KeySharePrecomputed<P>,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Inputs = Inputs<P>;
    fn new(
        _rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        // This includes the info of $ssid$ in the paper
        // (scheme parameters + public data from all shares - hashed in `share_set_id`),
        // with the session randomness added.
        let ssid_hash = Hash::new_with_dst(b"SSID")
            .chain(&shared_randomness)
            .chain(&inputs.key_share.share_set_id)
            .finalize();

        let r = inputs.presigning.nonce;
        let sigma = inputs.presigning.ephemeral_scalar_share * inputs.message
            + r * inputs.presigning.product_share;
        Ok(Self {
            ssid_hash,
            r,
            sigma,
            inputs,
            num_parties,
            party_idx,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round1Message {
    sigma: Scalar,
}

pub struct Round1Payload {
    sigma: Scalar,
}

impl<P: SchemeParams> Round for Round1<P> {
    type Type = ToResult;
    type Result = SigningResult<P>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = None;

    fn num_parties(&self) -> usize {
        self.num_parties
    }

    fn party_idx(&self) -> PartyIdx {
        self.party_idx
    }

    type BroadcastMessage = Round1Message;
    type DirectMessage = ();
    type Payload = Round1Payload;
    type Artifact = ();

    fn message_destinations(&self) -> Vec<PartyIdx> {
        all_parties_except(self.num_parties(), self.party_idx())
    }

    fn make_broadcast_message(&self, _rng: &mut impl CryptoRngCore) -> Self::BroadcastMessage {
        Round1Message { sigma: self.sigma }
    }

    no_direct_messages!();

    fn verify_message(
        &self,
        _from: PartyIdx,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        Ok(Round1Payload {
            sigma: broadcast_msg.sigma,
        })
    }
}

impl<P: SchemeParams> FinalizableToResult for Round1<P> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        _artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let payloads = try_to_holevec(payloads, self.num_parties, self.party_idx).unwrap();
        let others_sigma = payloads.map(|payload| payload.sigma);
        let assembled_sigma = others_sigma.iter().sum::<Scalar>() + self.sigma;

        let signature = RecoverableSignature::from_scalars(
            &self.r,
            &assembled_sigma,
            &self.inputs.key_share.verifying_key_as_point(),
            &self.inputs.message,
        );

        if let Some(signature) = signature {
            return Ok(signature);
        }

        let my_idx = self.party_idx.as_usize();
        let num_parties = self.num_parties;

        let aux = (&self.ssid_hash, &self.party_idx);

        let sk = &self.inputs.key_share.secret_aux.paillier_sk;
        let pk = sk.public_key();

        // Aff-g proofs

        let mut aff_g_proofs = Vec::new();

        for j in HoleRange::new(num_parties, my_idx) {
            for l in HoleRange::new(num_parties, my_idx) {
                if l == j {
                    continue;
                }
                let target_pk = &self.inputs.key_share.public_aux[j].paillier_pk;
                let rp = &self.inputs.key_share.public_aux[l].rp_params;

                let p_aff_g = AffGProof::<P>::new(
                    rng,
                    &P::signed_from_scalar(&self.inputs.key_share.secret_share),
                    self.inputs.presigning.hat_beta.get(j).unwrap(),
                    &self
                        .inputs
                        .presigning
                        .hat_s
                        .get(j)
                        .unwrap()
                        .to_mod(target_pk),
                    &self.inputs.presigning.hat_r.get(j).unwrap().to_mod(pk),
                    target_pk,
                    pk,
                    &self.inputs.presigning.cap_k[j],
                    self.inputs.presigning.hat_cap_d.get(j).unwrap(),
                    self.inputs.presigning.hat_cap_f.get(j).unwrap(),
                    &self.inputs.key_share.public_shares[my_idx],
                    rp,
                    &aux,
                );

                assert!(p_aff_g.verify(
                    target_pk,
                    pk,
                    &self.inputs.presigning.cap_k[j],
                    self.inputs.presigning.hat_cap_d.get(j).unwrap(),
                    self.inputs.presigning.hat_cap_f.get(j).unwrap(),
                    &self.inputs.key_share.public_shares[my_idx],
                    rp,
                    &aux,
                ));

                aff_g_proofs.push((PartyIdx::from_usize(j), PartyIdx::from_usize(l), p_aff_g));
            }
        }

        // mul* proofs

        let x = self.inputs.key_share.secret_share;
        let cap_x = self.inputs.key_share.public_shares[self.party_idx().as_usize()];

        let rho = RandomizerMod::random(rng, pk);
        let hat_cap_h = (&self.inputs.presigning.cap_k[my_idx] * P::bounded_from_scalar(&x))
            .mul_randomizer(&rho.retrieve());

        let aux = (&self.ssid_hash, &self.inputs.key_share.party_index());

        let mut mul_star_proofs = Vec::new();

        for l in HoleRange::new(num_parties, my_idx) {
            let p_mul = MulStarProof::<P>::new(
                rng,
                &P::signed_from_scalar(&x),
                &rho,
                pk,
                &self.inputs.presigning.cap_k[my_idx],
                &hat_cap_h,
                &cap_x,
                &self.inputs.key_share.public_aux[l].rp_params,
                &aux,
            );

            assert!(p_mul.verify(
                pk,
                &self.inputs.presigning.cap_k[my_idx],
                &hat_cap_h,
                &cap_x,
                &self.inputs.key_share.public_aux[l].rp_params,
                &aux,
            ));

            mul_star_proofs.push((PartyIdx::from_usize(l), p_mul));
        }

        // dec proofs

        let mut ciphertext = hat_cap_h.clone();
        for j in HoleRange::new(num_parties, my_idx) {
            ciphertext = ciphertext
                + self.inputs.presigning.hat_cap_d_received.get(j).unwrap()
                + self.inputs.presigning.hat_cap_f.get(j).unwrap();
        }

        let r = self.inputs.presigning.nonce;

        let ciphertext = ciphertext * P::bounded_from_scalar(&r)
            + &self.inputs.presigning.cap_k[my_idx] * P::bounded_from_scalar(&self.inputs.message);

        let rho = ciphertext.derive_randomizer(sk);
        // This is the same as `s_part` but if all the calculations were performed
        // without reducing modulo curve order.
        let s_part_nonreduced =
            P::signed_from_scalar(&self.inputs.presigning.ephemeral_scalar_share)
                * P::signed_from_scalar(&self.inputs.message)
                + self.inputs.presigning.product_share_nonreduced * P::signed_from_scalar(&r);

        let mut dec_proofs = Vec::new();
        for l in HoleRange::new(num_parties, my_idx) {
            let p_dec = DecProof::<P>::new(
                rng,
                &s_part_nonreduced,
                &rho,
                pk,
                &self.sigma,
                &ciphertext,
                &self.inputs.key_share.public_aux[l].rp_params,
                &aux,
            );
            assert!(p_dec.verify(
                pk,
                &self.sigma,
                &ciphertext,
                &self.inputs.key_share.public_aux[l].rp_params,
                &aux,
            ));
            dec_proofs.push((PartyIdx::from_usize(l), p_dec));
        }

        let proof = SigningProof {
            aff_g_proofs,
            mul_star_proofs,
            dec_proofs,
        };

        Err(FinalizeError::Proof(proof))
    }
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
    use rand_core::{OsRng, RngCore};

    use super::{Inputs, Round1};
    use crate::cggmp21::TestParams;
    use crate::common::{KeyShare, PresigningData};
    use crate::curve::Scalar;
    use crate::rounds::{
        test_utils::{step_result, step_round},
        FirstRound, PartyIdx,
    };

    #[test]
    fn execute_signing() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let num_parties = 3;
        let key_shares = KeyShare::<TestParams>::new_centralized(&mut OsRng, num_parties, None);

        let presigning_datas = PresigningData::new_centralized(&mut OsRng, &key_shares);

        let message = Scalar::random(&mut OsRng);

        let r1 = (0..num_parties)
            .map(|idx| {
                Round1::new(
                    &mut OsRng,
                    &shared_randomness,
                    num_parties,
                    PartyIdx::from_usize(idx),
                    Inputs {
                        presigning: presigning_datas[idx].clone(),
                        message,
                        key_share: key_shares[idx].to_precomputed(),
                    },
                )
                .unwrap()
            })
            .collect();

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let signatures = step_result(&mut OsRng, r1a).unwrap();

        for signature in signatures {
            let (sig, rec_id) = signature.to_backend();

            let vkey = key_shares[0].verifying_key();

            // Check that the signature can be verified
            vkey.verify_prehash(&message.to_bytes(), &sig).unwrap();

            // Check that the key can be recovered
            let recovered_key =
                VerifyingKey::recover_from_prehash(&message.to_bytes(), &sig, rec_id).unwrap();
            assert_eq!(recovered_key, vkey);
        }
    }
}
