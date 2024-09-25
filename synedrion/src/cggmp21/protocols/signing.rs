//! Signing using previously calculated presigning data, in the paper ECDSA Signing (Fig. 8).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use super::super::{
    entities::AuxInfoPrecomputed,
    sigma::{AffGProof, DecProof, MulStarProof},
    AuxInfo, KeyShare, PresigningData, SchemeParams,
};
use crate::curve::{RecoverableSignature, Scalar};
use crate::paillier::RandomizerMod;
use crate::rounds::{
    no_direct_messages, FinalizableToResult, FinalizeError, FirstRound, InitError, ProtocolResult,
    Round, ToResult,
};
use crate::tools::hashing::{Chain, FofHasher, HashOutput};

/// Possible results of the Signing protocol.
#[derive(Debug)]
pub struct SigningResult<P: SchemeParams, I: Debug>(PhantomData<P>, PhantomData<I>);

impl<P: SchemeParams, I: Debug> ProtocolResult for SigningResult<P, I> {
    type Success = RecoverableSignature;
    type ProvableError = ();
    type CorrectnessProof = SigningProof<P, I>;
}

/// A proof of a node's correct behavior for the Signing protocol.
#[allow(dead_code)] // TODO (#43): this can be removed when error verification is added
#[derive(Debug, Clone)]
pub struct SigningProof<P: SchemeParams, I> {
    aff_g_proofs: Vec<(I, I, AffGProof<P>)>,
    mul_star_proofs: Vec<(I, MulStarProof<P>)>,
    dec_proofs: Vec<(I, DecProof<P>)>,
}

pub struct Round1<P: SchemeParams, I: Ord> {
    ssid_hash: HashOutput,
    r: Scalar,
    sigma: Scalar,
    inputs: Inputs<P, I>,
    aux_info: AuxInfoPrecomputed<P, I>,
    other_ids: BTreeSet<I>,
    my_id: I,
}

#[derive(Clone)]
pub struct Inputs<P: SchemeParams, I: Ord> {
    pub message: Scalar,
    pub presigning: PresigningData<P, I>,
    pub key_share: KeyShare<P, I>,
    pub aux_info: AuxInfo<P, I>,
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> FirstRound<I> for Round1<P, I> {
    type Inputs = Inputs<P, I>;
    fn new(
        _rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        other_ids: BTreeSet<I>,
        my_id: I,
        inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        // This includes the info of $ssid$ in the paper
        // (scheme parameters + public data from all shares - hashed in `share_set_id`),
        // with the session randomness added.
        let ssid_hash = FofHasher::new_with_dst(b"ShareSetID")
            .chain_type::<P>()
            .chain(&shared_randomness)
            .chain(&inputs.key_share.public_shares)
            .chain(&inputs.aux_info.public_aux)
            .finalize();

        let r = inputs.presigning.nonce;
        let sigma = inputs.presigning.ephemeral_scalar_share.expose_secret() * &inputs.message
            + r * inputs.presigning.product_share.expose_secret();
        Ok(Self {
            ssid_hash,
            r,
            sigma,
            aux_info: inputs.aux_info.clone().to_precomputed(),
            inputs,
            other_ids,
            my_id,
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

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> Round<I> for Round1<P, I> {
    type Type = ToResult;
    type Result = SigningResult<P, I>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = None;

    fn other_ids(&self) -> &BTreeSet<I> {
        &self.other_ids
    }

    fn my_id(&self) -> &I {
        &self.my_id
    }

    type BroadcastMessage = Round1Message;
    type DirectMessage = ();
    type Payload = Round1Payload;
    type Artifact = ();

    fn make_broadcast_message(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        Some(Round1Message { sigma: self.sigma })
    }

    no_direct_messages!(I);

    fn verify_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        _from: &I,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        Ok(Round1Payload {
            sigma: broadcast_msg.sigma,
        })
    }
}

impl<P: SchemeParams, I: Debug + Clone + Ord + Serialize> FinalizableToResult<I> for Round1<P, I> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        _artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let assembled_sigma = payloads
            .values()
            .map(|payload| payload.sigma)
            .sum::<Scalar>()
            + self.sigma;

        let signature = RecoverableSignature::from_scalars(
            &self.r,
            &assembled_sigma,
            &self.inputs.key_share.verifying_key_as_point(),
            &self.inputs.message,
        );

        if let Some(signature) = signature {
            return Ok(signature);
        }

        let my_id = self.my_id().clone();
        let aux = (&self.ssid_hash, &my_id);

        let sk = &self.aux_info.secret_aux.paillier_sk;
        let pk = sk.public_key();

        // Aff-g proofs

        let mut aff_g_proofs = Vec::new();

        for id_j in self.other_ids() {
            for id_l in self.other_ids().iter().filter(|id| id != &id_j) {
                let target_pk = &self.aux_info.public_aux[id_j].paillier_pk;
                let rp = &self.aux_info.public_aux[id_l].rp_params;

                let values = &self.inputs.presigning.values.get(id_j).unwrap();

                let p_aff_g = AffGProof::<P>::new(
                    rng,
                    &P::signed_from_scalar(self.inputs.key_share.secret_share.expose_secret()),
                    &values.hat_beta,
                    &values.hat_s.to_mod(target_pk),
                    &values.hat_r.to_mod(pk),
                    target_pk,
                    pk,
                    &values.cap_k,
                    &values.hat_cap_d,
                    &values.hat_cap_f,
                    &self.inputs.key_share.public_shares[&my_id],
                    rp,
                    &aux,
                );

                assert!(p_aff_g.verify(
                    target_pk,
                    pk,
                    &values.cap_k,
                    &values.hat_cap_d,
                    &values.hat_cap_f,
                    &self.inputs.key_share.public_shares[&my_id],
                    rp,
                    &aux,
                ));

                aff_g_proofs.push((id_j.clone(), id_l.clone(), p_aff_g));
            }
        }

        // mul* proofs

        let x = &self.inputs.key_share.secret_share;
        let cap_x = self.inputs.key_share.public_shares[&my_id];

        let rho = RandomizerMod::random(rng, pk);
        let hat_cap_h = (&self.inputs.presigning.cap_k * P::bounded_from_scalar(x.expose_secret()))
            .mul_randomizer(&rho.retrieve());

        let aux = (&self.ssid_hash, &my_id);

        let mut mul_star_proofs = Vec::new();

        for id_l in self.other_ids() {
            let p_mul = MulStarProof::<P>::new(
                rng,
                &P::signed_from_scalar(x.expose_secret()),
                &rho,
                pk,
                &self.inputs.presigning.cap_k,
                &hat_cap_h,
                &cap_x,
                &self.aux_info.public_aux[id_l].rp_params,
                &aux,
            );

            assert!(p_mul.verify(
                pk,
                &self.inputs.presigning.cap_k,
                &hat_cap_h,
                &cap_x,
                &self.aux_info.public_aux[id_l].rp_params,
                &aux,
            ));

            mul_star_proofs.push((id_l.clone(), p_mul));
        }

        // dec proofs

        let mut ciphertext = hat_cap_h.clone();
        for id_j in self.other_ids() {
            let values = &self.inputs.presigning.values.get(id_j).unwrap();
            ciphertext = ciphertext + &values.hat_cap_d_received + &values.hat_cap_f;
        }

        let r = self.inputs.presigning.nonce;

        let ciphertext = ciphertext * P::bounded_from_scalar(&r)
            + &self.inputs.presigning.cap_k * P::bounded_from_scalar(&self.inputs.message);

        let rho = ciphertext.derive_randomizer(sk);
        // This is the same as `s_part` but if all the calculations were performed
        // without reducing modulo curve order.
        let s_part_nonreduced = P::signed_from_scalar(
            self.inputs
                .presigning
                .ephemeral_scalar_share
                .expose_secret(),
        ) * P::signed_from_scalar(&self.inputs.message)
            + self.inputs.presigning.product_share_nonreduced * P::signed_from_scalar(&r);

        let mut dec_proofs = Vec::new();
        for id_l in self.other_ids() {
            let p_dec = DecProof::<P>::new(
                rng,
                &s_part_nonreduced,
                &rho,
                pk,
                &self.sigma,
                &ciphertext,
                &self.aux_info.public_aux[id_l].rp_params,
                &aux,
            );
            assert!(p_dec.verify(
                pk,
                &self.sigma,
                &ciphertext,
                &self.aux_info.public_aux[id_l].rp_params,
                &aux,
            ));
            dec_proofs.push((id_l.clone(), p_dec));
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
    use alloc::collections::{BTreeMap, BTreeSet};

    use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
    use rand_core::{OsRng, RngCore};

    use super::{Inputs, Round1};
    use crate::cggmp21::{AuxInfo, KeyShare, PresigningData, TestParams};
    use crate::curve::Scalar;
    use crate::rounds::FinalizeError;
    use crate::rounds::{
        test_utils::{step_result, step_round, Id, Without},
        FinalizableToResult, FirstRound,
    };
    use crate::{RecoverableSignature, SigningProof};

    struct TestContext {
        message: Scalar,
        randomness: [u8; 32],
        presigning_data: BTreeMap<Id, PresigningData<TestParams, Id>>,
        key_shares: BTreeMap<Id, KeyShare<TestParams, Id>>,
        aux_infos: BTreeMap<Id, AuxInfo<TestParams, Id>>,
    }
    impl TestContext {
        fn new(ids: &BTreeSet<Id>) -> Self {
            let mut randomness = [0u8; 32];
            OsRng.fill_bytes(&mut randomness);
            let key_shares = KeyShare::new_centralized(&mut OsRng, &ids, None);
            let aux_infos = AuxInfo::new_centralized(&mut OsRng, &ids);

            let presigning_data =
                PresigningData::new_centralized(&mut OsRng, &key_shares, &aux_infos);

            Self {
                message: Scalar::random(&mut OsRng),
                randomness,
                presigning_data,
                key_shares,
                aux_infos,
            }
        }
    }

    fn make_test_round1(
        shared_randomness: &[u8],
        ids: &BTreeSet<Id>,
        id: &Id,
        presigning_data: &BTreeMap<Id, PresigningData<TestParams, Id>>,
        message: Scalar,
        key_shares: &BTreeMap<Id, KeyShare<TestParams, Id>>,
        aux_infos: &BTreeMap<Id, AuxInfo<TestParams, Id>>,
    ) -> Round1<TestParams, Id> {
        Round1::<TestParams, Id>::new(
            &mut OsRng,
            &shared_randomness,
            ids.clone().without(id),
            *id,
            Inputs {
                presigning: presigning_data[id].clone(),
                message,
                key_share: key_shares[id].clone(),
                aux_info: aux_infos[id].clone(),
            },
        )
        .unwrap()
    }
    fn make_rounds(ctx: &TestContext, ids: &BTreeSet<Id>) -> BTreeMap<Id, Round1<TestParams, Id>> {
        ids.iter()
            .map(|id| {
                let round = make_test_round1(
                    &ctx.randomness,
                    ids,
                    id,
                    &ctx.presigning_data,
                    ctx.message,
                    &ctx.key_shares,
                    &ctx.aux_infos,
                );
                (*id, round)
            })
            .collect()
    }

    #[test]
    fn execute_signing() {
        let ids = BTreeSet::from([Id(0), Id(1), Id(2)]);
        let ctx = TestContext::new(&ids);

        let r1 = make_rounds(&ctx, &ids);

        let r1a = step_round(&mut OsRng, r1).unwrap();

        let signatures = step_result(&mut OsRng, r1a).unwrap();

        for signature in signatures.values() {
            check_sig(signature, &ctx.key_shares, &ctx.message);
        }
    }

    #[test]
    fn cheating_signer() {
        let ids = BTreeSet::from([Id(0), Id(1), Id(2)]);
        let ctx = TestContext::new(&ids);

        let r1 = make_rounds(&ctx, &ids);

        let mut r1a = step_round(&mut OsRng, r1).unwrap();

        // Manipulate second party's signature, causing finalize_to_result to fail
        r1a.get_mut(&Id(1)).and_then(|assr| {
            assr.round.r = Scalar::random_nonzero(&mut OsRng);
            Some(assr)
        });

        // First party is fine
        match r1a.pop_first() {
            Some((id, assr)) => {
                assert!(id == Id(0));
                let finalized =
                    assr.round
                        .finalize_to_result(&mut OsRng, assr.payloads, assr.artifacts);
                assert!(finalized.is_ok());
                check_sig(&finalized.unwrap(), &ctx.key_shares, &ctx.message);
            }
            None => unreachable!(),
        }
        // Second is bad
        match r1a.pop_first() {
            Some((id, assr)) => {
                assert!(id == Id(1));
                let finalized =
                    assr.round
                        .finalize_to_result(&mut OsRng, assr.payloads, assr.artifacts);
                assert!(finalized.is_err());
                assert!(
                    matches!(finalized, Err(err) if matches!(&err, FinalizeError::Proof(SigningProof{..})))
                );
            }
            None => unreachable!(),
        }
    }

    fn check_sig(
        signature: &RecoverableSignature,
        key_shares: &BTreeMap<Id, KeyShare<TestParams, Id>>,
        message: &Scalar,
    ) {
        let (sig, rec_id) = signature.to_backend();
        let vkey = key_shares[&Id(0)].verifying_key();

        // Check that the signature can be verified
        vkey.verify_prehash(&message.to_bytes(), &sig).unwrap();

        // Check that the key can be recovered
        let recovered_key =
            VerifyingKey::recover_from_prehash(&message.to_bytes(), &sig, rec_id).unwrap();

        assert_eq!(recovered_key, vkey);
    }
}
