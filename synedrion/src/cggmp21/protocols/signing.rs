//! Signing using previously calculated presigning data, in the paper ECDSA Signing (Fig. 8).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
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
    all_parties_except, try_to_holevec, BaseRound, BroadcastRound, DirectRound, Finalizable,
    FinalizableToResult, FinalizationRequirement, FinalizeError, FirstRound, InitError, PartyIdx,
    ProtocolResult, ReceiveError, ToResult,
};
use crate::tools::collections::HoleRange;

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
    r: Scalar,
    s_part: Scalar,
    context: Context<P>,
    num_parties: usize,
    party_idx: PartyIdx,
    shared_randomness: Box<[u8]>,
}

#[derive(Clone)]
pub(crate) struct Context<P: SchemeParams> {
    pub(crate) message: Scalar,
    pub(crate) presigning: PresigningData<P>,
    pub(crate) key_share: KeySharePrecomputed<P>,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Context = Context<P>;
    fn new(
        _rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        context: Self::Context,
    ) -> Result<Self, InitError> {
        let r = context.presigning.nonce.x_coordinate();
        let s_part = context.presigning.ephemeral_scalar_share * context.message
            + r * context.presigning.product_share;
        Ok(Self {
            r,
            s_part,
            context,
            num_parties,
            party_idx,
            shared_randomness: shared_randomness.into(),
        })
    }
}

impl<P: SchemeParams> BaseRound for Round1<P> {
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
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round1Bcast {
    s_part: Scalar,
}

impl<P: SchemeParams> BroadcastRound for Round1<P> {
    const REQUIRES_CONSENSUS: bool = false;
    type Message = Round1Bcast;
    type Payload = Scalar;
    fn broadcast_destinations(&self) -> Option<Vec<PartyIdx>> {
        Some(all_parties_except(self.num_parties(), self.party_idx()))
    }
    fn make_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        Ok(Round1Bcast {
            s_part: self.s_part,
        })
    }

    fn verify_broadcast(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        Ok(msg.s_part)
    }
}

impl<P: SchemeParams> DirectRound for Round1<P> {
    type Message = ();
    type Payload = ();
    type Artifact = ();
}

impl<P: SchemeParams> Finalizable for Round1<P> {
    fn requirement() -> FinalizationRequirement {
        FinalizationRequirement::AllBroadcasts
    }
}

impl<P: SchemeParams> FinalizableToResult for Round1<P> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: BTreeMap<PartyIdx, <Self as BroadcastRound>::Payload>,
        _dm_payloads: BTreeMap<PartyIdx, <Self as DirectRound>::Payload>,
        _dm_artifacts: BTreeMap<PartyIdx, <Self as DirectRound>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let shares = try_to_holevec(bc_payloads, self.num_parties, self.party_idx).unwrap();
        let s: Scalar = shares.iter().sum();
        let s = s + self.s_part;

        let sig = RecoverableSignature::from_scalars(
            &self.r,
            &s,
            &self.context.key_share.verifying_key_as_point(),
            &self.context.message,
        );

        if let Some(sig) = sig {
            return Ok(sig);
        }

        let my_idx = self.party_idx.as_usize();
        let num_parties = self.num_parties;

        let aux = (&self.shared_randomness, &self.party_idx);

        let sk = &self.context.key_share.secret_aux.paillier_sk;
        let pk = sk.public_key();

        // Aff-g proofs

        let mut aff_g_proofs = Vec::new();

        for j in HoleRange::new(num_parties, my_idx) {
            for l in HoleRange::new(num_parties, my_idx) {
                if l == j {
                    continue;
                }
                let target_pk = &self.context.key_share.public_aux[j].paillier_pk;
                let rp = &self.context.key_share.public_aux[l].rp_params;

                let p_aff_g = AffGProof::<P>::new(
                    rng,
                    &P::signed_from_scalar(&self.context.key_share.secret_share),
                    self.context.presigning.hat_beta.get(j).unwrap(),
                    &self
                        .context
                        .presigning
                        .hat_s
                        .get(j)
                        .unwrap()
                        .to_mod(target_pk),
                    &self.context.presigning.hat_r.get(j).unwrap().to_mod(pk),
                    target_pk,
                    pk,
                    &self.context.presigning.cap_k[j],
                    self.context.presigning.hat_cap_d.get(j).unwrap(),
                    self.context.presigning.hat_cap_f.get(j).unwrap(),
                    &self.context.key_share.public_shares[my_idx],
                    rp,
                    &aux,
                );

                assert!(p_aff_g.verify(
                    target_pk,
                    pk,
                    &self.context.presigning.cap_k[j],
                    self.context.presigning.hat_cap_d.get(j).unwrap(),
                    self.context.presigning.hat_cap_f.get(j).unwrap(),
                    &self.context.key_share.public_shares[my_idx],
                    rp,
                    &aux,
                ));

                aff_g_proofs.push((PartyIdx::from_usize(j), PartyIdx::from_usize(l), p_aff_g));
            }
        }

        // mul* proofs

        let x = self.context.key_share.secret_share;
        let cap_x = self.context.key_share.public_shares[self.party_idx().as_usize()];

        let rho = RandomizerMod::random(rng, pk);
        let hat_cap_h = (&self.context.presigning.cap_k[my_idx] * P::bounded_from_scalar(&x))
            .mul_randomizer(&rho.retrieve());

        let aux = (
            &self.shared_randomness,
            &self.context.key_share.party_index(),
        );

        let mut mul_star_proofs = Vec::new();

        for l in HoleRange::new(num_parties, my_idx) {
            let p_mul = MulStarProof::<P>::new(
                rng,
                &P::signed_from_scalar(&x),
                &rho,
                pk,
                &self.context.presigning.cap_k[my_idx],
                &hat_cap_h,
                &cap_x,
                &self.context.key_share.public_aux[l].rp_params,
                &aux,
            );

            assert!(p_mul.verify(
                pk,
                &self.context.presigning.cap_k[my_idx],
                &hat_cap_h,
                &cap_x,
                &self.context.key_share.public_aux[l].rp_params,
                &aux,
            ));

            mul_star_proofs.push((PartyIdx::from_usize(l), p_mul));
        }

        // dec proofs

        let mut ciphertext = hat_cap_h.clone();
        for j in HoleRange::new(num_parties, my_idx) {
            ciphertext = ciphertext
                + self.context.presigning.hat_cap_d_received.get(j).unwrap()
                + self.context.presigning.hat_cap_f.get(j).unwrap();
        }

        let r = self.context.presigning.nonce.x_coordinate();

        let ciphertext = ciphertext * P::bounded_from_scalar(&r)
            + &self.context.presigning.cap_k[my_idx]
                * P::bounded_from_scalar(&self.context.message);

        let rho = ciphertext.derive_randomizer(sk);
        // This is the same as `s_part` but if all the calculations were performed
        // without reducing modulo curve order.
        let s_part_nonreduced =
            P::signed_from_scalar(&self.context.presigning.ephemeral_scalar_share)
                * P::signed_from_scalar(&self.context.message)
                + self.context.presigning.product_share_nonreduced * P::signed_from_scalar(&r);

        let mut dec_proofs = Vec::new();
        for l in HoleRange::new(num_parties, my_idx) {
            let p_dec = DecProof::<P>::new(
                rng,
                &s_part_nonreduced,
                &rho,
                pk,
                &self.s_part,
                &ciphertext,
                &self.context.key_share.public_aux[l].rp_params,
                &aux,
            );
            assert!(p_dec.verify(
                pk,
                &self.s_part,
                &ciphertext,
                &self.context.key_share.public_aux[l].rp_params,
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

    use super::{Context, Round1};
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
                    Context {
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
