use alloc::boxed::Box;
use alloc::vec::Vec;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::{KeyShareChange, PartyIdx, PublicAuxInfo, SecretAuxInfo};
use super::generic::{
    BaseRound, FinalizeError, FinalizeSuccess, FirstRound, InitError, NonExistent, ReceiveError,
    Round, ToSendTyped,
};
use crate::cggmp21::{
    sigma::{FacProof, ModProof, PrmProof, SchCommitment, SchProof, SchSecret},
    SchemeParams,
};
use crate::curve::{Point, Scalar};
use crate::paillier::{
    Ciphertext, PaillierParams, PublicKeyPaillier, PublicKeyPaillierPrecomputed, RPParams,
    RPParamsMod, RPSecret, SecretKeyPaillier, SecretKeyPaillierPrecomputed,
};
use crate::tools::collections::HoleVec;
use crate::tools::hashing::{Chain, Hash, HashOutput, Hashable};
use crate::tools::random::random_bits;
use crate::tools::serde_bytes;
use crate::uint::{FromScalar, UintLike};

fn uint_from_scalar<P: SchemeParams>(
    x: &Scalar,
) -> <<P as SchemeParams>::Paillier as PaillierParams>::DoubleUint {
    <<P as SchemeParams>::Paillier as PaillierParams>::DoubleUint::from_scalar(x)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PrmProof<P>: Serialize"))]
#[serde(bound(deserialize = "PrmProof<P>: for<'x> Deserialize<'x>"))]
pub struct FullData<P: SchemeParams> {
    xs_public: Vec<Point>,                           // $\bm{X}_i$
    sch_commitments_x: Vec<SchCommitment>,           // $\bm{A}_i$
    el_gamal_pk: Point,                              // $Y_i$,
    el_gamal_commitment: SchCommitment,              // $B_i$
    paillier_pk: PublicKeyPaillier<P::Paillier>,     // $N_i$
    aux_paillier_pk: PublicKeyPaillier<P::Paillier>, // $\hat{N}_i$
    rp_params: RPParams<P::Paillier>,                // $s_i$ and $t_i$
    prm_proof: PrmProof<P>,                          // $\hat{\psi}_i$
    aux_rp_params: RPParams<P::Paillier>, // setup parameters($s_i$ and $t_i$ for $\hat{N}$)
    aux_prm_proof: PrmProof<P>,           // a proof for the setup parameters
    #[serde(with = "serde_bytes::as_base64")]
    rho_bits: Box<[u8]>, // $\rho_i$
    #[serde(with = "serde_bytes::as_base64")]
    u_bits: Box<[u8]>, // $u_i$
}

// TODO: some of the fields may be unused
#[derive(Debug, Clone)]
pub struct FullDataPrecomp<P: SchemeParams> {
    data: FullData<P>,
    paillier_pk: PublicKeyPaillierPrecomputed<P::Paillier>, // $N_i$
    aux_paillier_pk: PublicKeyPaillierPrecomputed<P::Paillier>, // $\hat{N}_i$
    rp_params: RPParamsMod<P::Paillier>,                    // $s_i$ and $t_i$
    aux_rp_params: RPParamsMod<P::Paillier>, // setup parameters($s_i$ and $t_i$ for $\hat{N}$)
}

struct Context<P: SchemeParams> {
    paillier_sk: SecretKeyPaillierPrecomputed<P::Paillier>,
    aux_paillier_sk: SecretKeyPaillierPrecomputed<P::Paillier>,
    el_gamal_sk: Scalar,
    xs_secret: Vec<Scalar>,
    el_gamal_proof_secret: SchSecret,
    sch_secrets_x: Vec<SchSecret>,
    data_precomp: FullDataPrecomp<P>,
    party_idx: PartyIdx,
    shared_randomness: Box<[u8]>,
}

impl<P: SchemeParams> Hashable for FullData<P> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest
            .chain(&self.xs_public)
            .chain(&self.sch_commitments_x)
            .chain(&self.el_gamal_pk)
            .chain(&self.el_gamal_commitment)
            .chain(&self.paillier_pk)
            .chain(&self.aux_paillier_pk)
            .chain(&self.rp_params)
            .chain(&self.prm_proof)
            .chain(&self.aux_rp_params)
            .chain(&self.aux_prm_proof)
            .chain(&self.rho_bits)
            .chain(&self.u_bits)
    }
}

impl<P: SchemeParams> FullData<P> {
    fn hash(&self, shared_randomness: &[u8], party_idx: PartyIdx) -> HashOutput {
        Hash::new_with_dst(b"Auxiliary")
            .chain(&shared_randomness)
            .chain(&party_idx)
            .chain(self)
            .finalize()
    }
}

pub struct Round1<P: SchemeParams> {
    context: Context<P>,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Context = ();
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        _context: Self::Context,
    ) -> Result<Self, InitError> {
        let paillier_sk = SecretKeyPaillier::<P::Paillier>::random(rng).to_precomputed();
        let paillier_pk = paillier_sk.public_key();
        let el_gamal_sk = Scalar::random(rng);
        let el_gamal_pk = el_gamal_sk.mul_by_generator();

        let el_gamal_proof_secret = SchSecret::random(rng); // $\tau$
        let el_gamal_commitment = SchCommitment::new(&el_gamal_proof_secret); // $B_i$

        let xs_secret = Scalar::ZERO.split(rng, num_parties);
        let xs_public = xs_secret
            .iter()
            .cloned()
            .map(|x| x.mul_by_generator())
            .collect::<Vec<_>>();

        let rp_secret = RPSecret::random(rng, &paillier_sk);
        let rp_params = RPParamsMod::random_with_secret(rng, &rp_secret, paillier_pk);

        // CHECK: This is not a part of the KeyRefresh/Aux protocol in Fig.6, but according to
        // "Generating the Setup Parameter for the Range Proofs" in Section 2.3,
        // the verifier generates the auxiliary RP params (and the corresponding
        // P^{mod} and P^{prm} proofs), so this seems like the right place to do it.
        let aux_paillier_sk = SecretKeyPaillier::<P::Paillier>::random(rng).to_precomputed();
        let aux_paillier_pk = aux_paillier_sk.public_key();
        let aux_rp_secret = RPSecret::random(rng, &aux_paillier_sk);
        let aux_rp_params = RPParamsMod::random_with_secret(rng, &aux_rp_secret, aux_paillier_pk);

        let aux = (&shared_randomness, &party_idx);
        let prm_proof = PrmProof::<P>::random(rng, &paillier_sk, &rp_secret, &rp_params, &aux);

        let aux_prm_proof =
            PrmProof::<P>::random(rng, &aux_paillier_sk, &aux_rp_secret, &aux_rp_params, &aux);

        // $\tau_j$
        let sch_secrets_x: Vec<SchSecret> =
            (0..num_parties).map(|_| SchSecret::random(rng)).collect();

        // $A_i^j$
        let sch_commitments_x = sch_secrets_x.iter().map(SchCommitment::new).collect();

        let rho_bits = random_bits(rng, P::SECURITY_PARAMETER);
        let u_bits = random_bits(rng, P::SECURITY_PARAMETER);

        let data = FullData {
            xs_public: xs_public.clone(),
            sch_commitments_x,
            el_gamal_pk,
            el_gamal_commitment,
            paillier_pk: paillier_pk.to_minimal(),
            aux_paillier_pk: aux_paillier_pk.to_minimal(),
            rp_params: rp_params.retrieve(),
            aux_rp_params: aux_rp_params.retrieve(),
            prm_proof,
            aux_prm_proof,
            rho_bits: rho_bits.clone(),
            u_bits: u_bits.clone(),
        };

        let data_precomp = FullDataPrecomp {
            data,
            paillier_pk: paillier_pk.clone(),
            aux_paillier_pk: aux_paillier_pk.clone(),
            rp_params,
            aux_rp_params,
        };

        let context = Context {
            paillier_sk,
            aux_paillier_sk,
            el_gamal_sk,
            xs_secret,
            sch_secrets_x,
            el_gamal_proof_secret,
            data_precomp,
            party_idx,
            shared_randomness: shared_randomness.into(),
        };

        Ok(Self { context })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1Bcast {
    hash: HashOutput, // `V_j`
}

impl Hashable for Round1Bcast {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.hash)
    }
}

impl<P: SchemeParams> BaseRound for Round1<P> {
    type Payload = HashOutput;
    type Message = Round1Bcast;

    const ROUND_NUM: u8 = 1;
    const REQUIRES_BROADCAST_CONSENSUS: bool = true;

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        ToSendTyped::Broadcast(Round1Bcast {
            hash: self
                .context
                .data_precomp
                .data
                .hash(&self.context.shared_randomness, self.context.party_idx),
        })
    }

    fn verify_received(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        Ok(msg.hash)
    }
}

impl<P: SchemeParams> Round for Round1<P> {
    type NextRound = Round2<P>;
    type Result = KeyShareChange<P>;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);
    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        Ok(FinalizeSuccess::AnotherRound(Round2 {
            context: self.context,
            hashes: payloads,
        }))
    }
}

pub struct Round2<P: SchemeParams> {
    context: Context<P>,
    hashes: HoleVec<HashOutput>, // V_j
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "FullData<P>: Serialize"))]
#[serde(bound(deserialize = "FullData<P>: for<'x> Deserialize<'x>"))]
pub struct Round2Bcast<P: SchemeParams> {
    data: FullData<P>,
}

impl<P: SchemeParams> BaseRound for Round2<P> {
    type Payload = FullDataPrecomp<P>;
    type Message = Round2Bcast<P>;

    const ROUND_NUM: u8 = 2;
    const REQUIRES_BROADCAST_CONSENSUS: bool = false;

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        ToSendTyped::Broadcast(Round2Bcast {
            data: self.context.data_precomp.data.clone(),
        })
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        if &msg.data.hash(&self.context.shared_randomness, from)
            != self.hashes.get(from.as_usize()).unwrap()
        {
            return Err(ReceiveError::VerificationFail("Invalid hash".into()));
        }

        let paillier_pk = msg.data.paillier_pk.to_precomputed();

        if paillier_pk.modulus().bits_vartime() < 8 * P::SECURITY_PARAMETER {
            return Err(ReceiveError::VerificationFail(
                "Paillier modulus is too small".into(),
            ));
        }

        let sum_x: Point = msg.data.xs_public.iter().sum();
        if sum_x != Point::IDENTITY {
            return Err(ReceiveError::VerificationFail(
                "Sum of X points is not identity".into(),
            ));
        }

        let aux = (&self.context.shared_randomness, &from);

        let rp_params = msg.data.rp_params.to_mod(&paillier_pk);
        if !msg.data.prm_proof.verify(&rp_params, &aux) {
            return Err(ReceiveError::VerificationFail(
                "PRM verification failed".into(),
            ));
        }

        let aux_paillier_pk = msg.data.aux_paillier_pk.to_precomputed();
        let aux_rp_params = msg.data.aux_rp_params.to_mod(&aux_paillier_pk);
        if !msg.data.aux_prm_proof.verify(&aux_rp_params, &aux) {
            return Err(ReceiveError::VerificationFail(
                "PRM verification (setup parameters) failed".into(),
            ));
        }

        Ok(FullDataPrecomp {
            data: msg.data,
            paillier_pk,
            aux_paillier_pk,
            rp_params,
            aux_rp_params,
        })
    }
}

impl<P: SchemeParams> Round for Round2<P> {
    type NextRound = Round3<P>;
    type Result = KeyShareChange<P>;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);
    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        // XOR the vectors together
        // TODO: is there a better way?
        let mut rho = self.context.data_precomp.data.rho_bits.clone();
        for data in payloads.iter() {
            for (i, x) in data.data.rho_bits.iter().enumerate() {
                rho[i] ^= x;
            }
        }

        Ok(FinalizeSuccess::AnotherRound(Round3 {
            rho,
            context: self.context,
            datas: payloads,
        }))
    }
}

pub struct Round3<P: SchemeParams> {
    context: Context<P>,
    rho: Box<[u8]>,
    datas: HoleVec<FullDataPrecomp<P>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "ModProof<P>: Serialize,
    FacProof<P>: Serialize,
    Ciphertext<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "ModProof<P>: for<'x> Deserialize<'x>,
    FacProof<P>: for<'x> Deserialize<'x>,
    Ciphertext<P::Paillier>: for<'x> Deserialize<'x>"))]
pub struct FullData2<P: SchemeParams> {
    mod_proof: ModProof<P>,                  // `psi_j`
    aux_mod_proof: ModProof<P>,              // $P^{mod}$ for the setup parameters
    fac_proof: FacProof<P>,                  // `phi_j,i`
    sch_proof_y: SchProof,                   // `pi_i`
    paillier_enc_x: Ciphertext<P::Paillier>, // `C_j,i`
    sch_proof_x: SchProof,                   // `psi_i,j`
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "FullData2<P>: Serialize"))]
#[serde(bound(deserialize = "FullData2<P>: for<'x> Deserialize<'x>"))]
pub struct Round3Direct<P: SchemeParams> {
    data2: FullData2<P>,
}

impl<P: SchemeParams> BaseRound for Round3<P> {
    type Payload = Scalar;
    type Message = Round3Direct<P>;

    const ROUND_NUM: u8 = 3;
    const REQUIRES_BROADCAST_CONSENSUS: bool = false;

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        let aux = (
            &self.context.shared_randomness,
            &self.rho,
            &self.context.party_idx,
        );
        let mod_proof = ModProof::random(rng, &self.context.paillier_sk, &aux);

        let aux_mod_proof = ModProof::random(rng, &self.context.aux_paillier_sk, &aux);

        let sch_proof_y = SchProof::new(
            &self.context.el_gamal_proof_secret,
            &self.context.el_gamal_sk,
            &self.context.data_precomp.data.el_gamal_commitment,
            &self.context.data_precomp.data.el_gamal_pk,
            &aux,
        );

        let mut dms = Vec::new();
        for (party_idx, data) in self.datas.enumerate() {
            let fac_proof = FacProof::random(
                rng,
                &self.context.paillier_sk,
                &self.datas.get(party_idx).unwrap().aux_rp_params,
                &aux,
            );

            let x_secret = self.context.xs_secret[party_idx];
            let x_public = self.context.data_precomp.data.xs_public[party_idx];
            let ciphertext =
                Ciphertext::new(rng, &data.paillier_pk, &uint_from_scalar::<P>(&x_secret));

            let sch_proof_x = SchProof::new(
                &self.context.sch_secrets_x[party_idx],
                &x_secret,
                &self.context.data_precomp.data.sch_commitments_x[party_idx],
                &x_public,
                &aux,
            );

            let data2 = FullData2 {
                mod_proof: mod_proof.clone(),
                aux_mod_proof: aux_mod_proof.clone(),
                fac_proof,
                sch_proof_y: sch_proof_y.clone(),
                paillier_enc_x: ciphertext,
                sch_proof_x,
            };

            dms.push((PartyIdx::from_usize(party_idx), Round3Direct { data2 }));
        }

        ToSendTyped::Direct(dms)
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        let sender_data = &self.datas.get(from.as_usize()).unwrap();

        let x_secret = msg
            .data2
            .paillier_enc_x
            .decrypt(&self.context.paillier_sk)
            .to_scalar();

        if x_secret.mul_by_generator()
            != sender_data.data.xs_public[self.context.party_idx.as_usize()]
        {
            // TODO: paper has `\mu` calculation here.
            return Err(ReceiveError::VerificationFail("Mismatched secret x".into()));
        }

        let aux = (&self.context.shared_randomness, &self.rho, &from);

        if !msg.data2.mod_proof.verify(&sender_data.paillier_pk, &aux) {
            return Err(ReceiveError::VerificationFail(
                "Mod proof verification failed".into(),
            ));
        }

        if !msg
            .data2
            .aux_mod_proof
            .verify(&sender_data.aux_paillier_pk, &aux)
        {
            return Err(ReceiveError::VerificationFail(
                "Mod proof (setup parameters) verification failed".into(),
            ));
        }

        if !msg.data2.fac_proof.verify(
            &sender_data.paillier_pk,
            &self.context.data_precomp.aux_rp_params,
            &aux,
        ) {
            return Err(ReceiveError::VerificationFail(
                "Fac proof verification failed".into(),
            ));
        }

        if !msg.data2.sch_proof_y.verify(
            &sender_data.data.el_gamal_commitment,
            &sender_data.data.el_gamal_pk,
            &aux,
        ) {
            // CHECK: not sending the commitment the second time in `msg`,
            // since we already got it from the previous round.
            return Err(ReceiveError::VerificationFail(
                "Sch proof verification (Y) failed".into(),
            ));
        }

        if !msg.data2.sch_proof_x.verify(
            &sender_data.data.sch_commitments_x[self.context.party_idx.as_usize()],
            &sender_data.data.xs_public[self.context.party_idx.as_usize()],
            &aux,
        ) {
            // CHECK: not sending the commitment the second time in `msg`,
            // since we already got it from the previous round.
            return Err(ReceiveError::VerificationFail(
                "Sch proof verification (Y) failed".into(),
            ));
        }

        Ok(x_secret)
    }
}

impl<P: SchemeParams> Round for Round3<P> {
    type NextRound = NonExistent<Self::Result>;
    type Result = KeyShareChange<P>;
    const NEXT_ROUND_NUM: Option<u8> = None;
    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let secrets = payloads.into_vec(self.context.xs_secret[self.context.party_idx.as_usize()]);
        let secret_share_change = secrets.iter().sum();

        let datas = self.datas.into_vec(self.context.data_precomp);

        let public_share_changes = (0..datas.len())
            .map(|idx| datas.iter().map(|data| data.data.xs_public[idx]).sum())
            .collect::<Box<_>>();

        let public_aux = datas
            .into_iter()
            .map(|data| PublicAuxInfo {
                el_gamal_pk: data.data.el_gamal_pk,
                paillier_pk: data.paillier_pk.to_minimal(),
                aux_paillier_pk: data.aux_paillier_pk.to_minimal(),
                rp_params: data.rp_params.retrieve(),
                aux_rp_params: data.aux_rp_params.retrieve(),
            })
            .collect();

        let secret_aux = SecretAuxInfo {
            paillier_sk: self.context.paillier_sk.to_minimal(),
            el_gamal_sk: self.context.el_gamal_sk,
        };

        let key_share_change = KeyShareChange {
            index: self.context.party_idx,
            secret_share_change,
            public_share_changes,
            secret_aux,
            public_aux,
        };

        Ok(FinalizeSuccess::Result(key_share_change))
    }
}

#[cfg(test)]
mod tests {

    use rand_core::{OsRng, RngCore};

    use super::super::{
        test_utils::{assert_next_round, assert_result, step},
        FirstRound,
    };
    use super::Round1;
    use crate::cggmp21::{PartyIdx, TestParams};
    use crate::curve::Scalar;

    #[test]
    fn execute_auxiliary() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let num_parties = 3;
        let r1 = (0..num_parties)
            .map(|idx| {
                Round1::<TestParams>::new(
                    &mut OsRng,
                    &shared_randomness,
                    num_parties,
                    PartyIdx::from_usize(idx),
                    (),
                )
                .unwrap()
            })
            .collect();

        let r2 = assert_next_round(step(&mut OsRng, r1).unwrap()).unwrap();
        let r3 = assert_next_round(step(&mut OsRng, r2).unwrap()).unwrap();
        let results = assert_result(step(&mut OsRng, r3).unwrap()).unwrap();

        // Check that public points correspond to secret scalars
        for (idx, change) in results.iter().enumerate() {
            for other_change in results.iter() {
                assert_eq!(
                    change.secret_share_change.mul_by_generator(),
                    other_change.public_share_changes[idx]
                );
                assert_eq!(
                    change.secret_aux.el_gamal_sk.mul_by_generator(),
                    other_change.public_aux[idx].el_gamal_pk
                );
            }
        }

        // The resulting sum of masks should be zero, since the combined secret key
        // should not change after applying the masks at each node.
        let mask_sum: Scalar = results
            .iter()
            .map(|change| change.secret_share_change)
            .sum();
        assert_eq!(mask_sum, Scalar::ZERO);
    }
}
