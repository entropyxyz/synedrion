//! KeyRefresh protocol, in the paper Auxiliary Info. & Key Refresh in Three Rounds (Fig. 6).
//! This protocol generates an update to the secret key shares and new auxiliary parameters
//! for ZK proofs (e.g. Paillier keys).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::{KeyShareChange, PublicAuxInfo, SecretAuxInfo};
use crate::cggmp21::{
    sigma::{FacProof, ModProof, PrmProof, SchCommitment, SchProof, SchSecret},
    SchemeParams,
};
use crate::curve::{Point, Scalar};
use crate::paillier::{
    Ciphertext, PaillierParams, PublicKeyPaillier, PublicKeyPaillierPrecomputed, RPParams,
    RPParamsMod, RPSecret, Randomizer, SecretKeyPaillier, SecretKeyPaillierPrecomputed,
};
use crate::rounds::{
    all_parties_except, try_to_holevec, BaseRound, BroadcastRound, DirectRound, Finalizable,
    FinalizableToNextRound, FinalizableToResult, FinalizationRequirement, FinalizeError,
    FirstRound, InitError, PartyIdx, ProtocolResult, ReceiveError, ToNextRound, ToResult,
};
use crate::tools::collections::HoleVec;
use crate::tools::hashing::{Chain, Hash, HashOutput, Hashable};
use crate::tools::random::random_bits;
use crate::tools::serde_bytes;
use crate::uint::{FromScalar, UintLike};

fn uint_from_scalar<P: SchemeParams>(
    x: &Scalar,
) -> <<P as SchemeParams>::Paillier as PaillierParams>::Uint {
    <<P as SchemeParams>::Paillier as PaillierParams>::Uint::from_scalar(x)
}

/// Possible results of the KeyRefresh protocol.
#[derive(Debug, Clone, Copy)]
pub struct KeyRefreshResult<P: SchemeParams>(PhantomData<P>);

impl<P: SchemeParams> ProtocolResult for KeyRefreshResult<P> {
    type Success = KeyShareChange<P>;
    type ProvableError = KeyRefreshError<P>;
    type CorrectnessProof = ();
}

#[derive(Debug, Clone)]
pub struct KeyRefreshError<P: SchemeParams>(KeyRefreshErrorEnum<P>);

#[derive(Debug, Clone)]
enum KeyRefreshErrorEnum<P: SchemeParams> {
    Round2(String),
    Round3(String),
    // TODO (#43): this can be removed when error verification is added
    #[allow(dead_code)]
    Round3MismatchedSecret {
        cap_c: Ciphertext<P::Paillier>,
        x: Scalar,
        mu: Randomizer<P::Paillier>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PrmProof<P>: Serialize"))]
#[serde(bound(deserialize = "PrmProof<P>: for<'x> Deserialize<'x>"))]
pub struct FullData<P: SchemeParams> {
    xs_public: Vec<Point>,                       // $\bm{X}_i$
    sch_commitments_x: Vec<SchCommitment>,       // $\bm{A}_i$
    el_gamal_pk: Point,                          // $Y_i$,
    el_gamal_commitment: SchCommitment,          // $B_i$
    paillier_pk: PublicKeyPaillier<P::Paillier>, // $N_i$
    rp_params: RPParams<P::Paillier>,            // $s_i$ and $t_i$
    prm_proof: PrmProof<P>,                      // $\hat{\psi}_i$
    #[serde(with = "serde_bytes::as_base64")]
    rho_bits: Box<[u8]>, // $\rho_i$
    #[serde(with = "serde_bytes::as_base64")]
    u_bits: Box<[u8]>, // $u_i$
}

#[derive(Debug, Clone)]
pub struct FullDataPrecomp<P: SchemeParams> {
    data: FullData<P>,
    paillier_pk: PublicKeyPaillierPrecomputed<P::Paillier>, // $N_i$
    rp_params: RPParamsMod<P::Paillier>,                    // $s_i$ and $t_i$
}

struct Context<P: SchemeParams> {
    paillier_sk: SecretKeyPaillierPrecomputed<P::Paillier>,
    el_gamal_sk: Scalar,
    xs_secret: Vec<Scalar>,
    el_gamal_proof_secret: SchSecret,
    sch_secrets_x: Vec<SchSecret>,
    data_precomp: FullDataPrecomp<P>,
    party_idx: PartyIdx,
    num_parties: usize,
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
            .chain(&self.rp_params)
            .chain(&self.prm_proof)
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

        let aux = (&shared_randomness, &party_idx);
        let prm_proof = PrmProof::<P>::new(rng, &paillier_sk, &rp_secret, &rp_params, &aux);

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
            rp_params: rp_params.retrieve(),
            prm_proof,
            rho_bits: rho_bits.clone(),
            u_bits: u_bits.clone(),
        };

        let data_precomp = FullDataPrecomp {
            data,
            paillier_pk: paillier_pk.clone(),
            rp_params,
        };

        let context = Context {
            paillier_sk,
            el_gamal_sk,
            xs_secret,
            sch_secrets_x,
            el_gamal_proof_secret,
            data_precomp,
            party_idx,
            num_parties,
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
    type Type = ToNextRound;
    type Result = KeyRefreshResult<P>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);

    fn num_parties(&self) -> usize {
        self.context.num_parties
    }

    fn party_idx(&self) -> PartyIdx {
        self.context.party_idx
    }
}

impl<P: SchemeParams> DirectRound for Round1<P> {
    type Message = ();
    type Payload = ();
    type Artifact = ();
}

impl<P: SchemeParams> BroadcastRound for Round1<P> {
    const REQUIRES_CONSENSUS: bool = true;
    type Message = Round1Bcast;
    type Payload = HashOutput;

    fn broadcast_destinations(&self) -> Option<Vec<PartyIdx>> {
        Some(all_parties_except(
            self.context.num_parties,
            self.context.party_idx,
        ))
    }

    fn make_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        Ok(Round1Bcast {
            hash: self
                .context
                .data_precomp
                .data
                .hash(&self.context.shared_randomness, self.context.party_idx),
        })
    }

    fn verify_broadcast(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        Ok(msg.hash)
    }
}

impl<P: SchemeParams> Finalizable for Round1<P> {
    fn requirement() -> FinalizationRequirement {
        FinalizationRequirement::AllBroadcasts
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round1<P> {
    type NextRound = Round2<P>;
    fn finalize_to_next_round(
        self,
        _rng: &mut impl CryptoRngCore,
        bc_payloads: BTreeMap<PartyIdx, <Self as BroadcastRound>::Payload>,
        _dm_payloads: BTreeMap<PartyIdx, <Self as DirectRound>::Payload>,
        _dm_artifacts: BTreeMap<PartyIdx, <Self as DirectRound>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let num_parties = self.num_parties();
        let party_idx = self.party_idx();
        Ok(Round2 {
            context: self.context,
            hashes: try_to_holevec(bc_payloads, num_parties, party_idx).unwrap(),
        })
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
    type Type = ToNextRound;
    type Result = KeyRefreshResult<P>;
    const ROUND_NUM: u8 = 2;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);

    fn num_parties(&self) -> usize {
        self.context.num_parties
    }

    fn party_idx(&self) -> PartyIdx {
        self.context.party_idx
    }
}

impl<P: SchemeParams> DirectRound for Round2<P> {
    type Message = ();
    type Payload = ();
    type Artifact = ();
}

impl<P: SchemeParams> BroadcastRound for Round2<P> {
    const REQUIRES_CONSENSUS: bool = false;
    type Message = Round2Bcast<P>;
    type Payload = FullDataPrecomp<P>;

    fn broadcast_destinations(&self) -> Option<Vec<PartyIdx>> {
        Some(all_parties_except(
            self.context.num_parties,
            self.context.party_idx,
        ))
    }

    fn make_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        Ok(Round2Bcast {
            data: self.context.data_precomp.data.clone(),
        })
    }

    fn verify_broadcast(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        if &msg.data.hash(&self.context.shared_randomness, from)
            != self.hashes.get(from.as_usize()).unwrap()
        {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round2("Hash mismatch".into()),
            )));
        }

        let paillier_pk = msg.data.paillier_pk.to_precomputed();

        if paillier_pk.modulus().bits_vartime() < 8 * P::SECURITY_PARAMETER {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round2("Paillier modulus is too small".into()),
            )));
        }

        let sum_x: Point = msg.data.xs_public.iter().sum();
        if sum_x != Point::IDENTITY {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round2("Sum of X points is not identity".into()),
            )));
        }

        let aux = (&self.context.shared_randomness, &from);

        let rp_params = msg.data.rp_params.to_mod(&paillier_pk);
        if !msg.data.prm_proof.verify(&rp_params, &aux) {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round2("PRM verification failed".into()),
            )));
        }

        Ok(FullDataPrecomp {
            data: msg.data,
            paillier_pk,
            rp_params,
        })
    }
}

impl<P: SchemeParams> Finalizable for Round2<P> {
    fn requirement() -> FinalizationRequirement {
        FinalizationRequirement::AllBroadcasts
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round2<P> {
    type NextRound = Round3<P>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: BTreeMap<PartyIdx, <Self as BroadcastRound>::Payload>,
        _dm_payloads: BTreeMap<PartyIdx, <Self as DirectRound>::Payload>,
        _dm_artifacts: BTreeMap<PartyIdx, <Self as DirectRound>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let messages = try_to_holevec(bc_payloads, self.num_parties(), self.party_idx()).unwrap();
        // XOR the vectors together
        // TODO (#61): is there a better way?
        let mut rho = self.context.data_precomp.data.rho_bits.clone();
        for data in messages.iter() {
            for (i, x) in data.data.rho_bits.iter().enumerate() {
                rho[i] ^= x;
            }
        }

        Ok(Round3::new(rng, self.context, messages, rho))
    }
}

pub struct Round3<P: SchemeParams> {
    context: Context<P>,
    rho: Box<[u8]>,
    datas: HoleVec<FullDataPrecomp<P>>,
    mod_proof: ModProof<P>,
    sch_proof_y: SchProof,
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

impl<P: SchemeParams> Round3<P> {
    fn new(
        rng: &mut impl CryptoRngCore,
        context: Context<P>,
        datas: HoleVec<FullDataPrecomp<P>>,
        rho: Box<[u8]>,
    ) -> Self {
        let aux = (&context.shared_randomness, &rho, &context.party_idx);
        let mod_proof = ModProof::new(rng, &context.paillier_sk, &aux);

        let sch_proof_y = SchProof::new(
            &context.el_gamal_proof_secret,
            &context.el_gamal_sk,
            &context.data_precomp.data.el_gamal_commitment,
            &context.data_precomp.data.el_gamal_pk,
            &aux,
        );

        Self {
            context,
            datas,
            rho,
            mod_proof,
            sch_proof_y,
        }
    }
}

impl<P: SchemeParams> BaseRound for Round3<P> {
    type Type = ToResult;
    type Result = KeyRefreshResult<P>;
    const ROUND_NUM: u8 = 3;
    const NEXT_ROUND_NUM: Option<u8> = None;

    fn num_parties(&self) -> usize {
        self.context.num_parties
    }

    fn party_idx(&self) -> PartyIdx {
        self.context.party_idx
    }
}

impl<P: SchemeParams> BroadcastRound for Round3<P> {
    type Message = ();
    type Payload = ();
}

impl<P: SchemeParams> DirectRound for Round3<P> {
    type Message = Round3Direct<P>;
    type Payload = Scalar;
    type Artifact = ();

    fn direct_message_destinations(&self) -> Option<Vec<PartyIdx>> {
        Some(all_parties_except(
            self.context.num_parties,
            self.context.party_idx,
        ))
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artifact), String> {
        let aux = (
            &self.context.shared_randomness,
            &self.rho,
            &self.context.party_idx,
        );

        let idx = destination.as_usize();
        let data = self.datas.get(idx).unwrap();

        let fac_proof = FacProof::new(
            rng,
            &self.context.paillier_sk,
            &self.datas.get(idx).unwrap().rp_params,
            &aux,
        );

        let x_secret = self.context.xs_secret[idx];
        let x_public = self.context.data_precomp.data.xs_public[idx];
        let ciphertext = Ciphertext::new(rng, &data.paillier_pk, &uint_from_scalar::<P>(&x_secret));

        let sch_proof_x = SchProof::new(
            &self.context.sch_secrets_x[idx],
            &x_secret,
            &self.context.data_precomp.data.sch_commitments_x[idx],
            &x_public,
            &aux,
        );

        let data2 = FullData2 {
            mod_proof: self.mod_proof.clone(),
            fac_proof,
            sch_proof_y: self.sch_proof_y.clone(),
            paillier_enc_x: ciphertext,
            sch_proof_x,
        };

        Ok((Round3Direct { data2 }, ()))
    }

    fn verify_direct_message(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        let sender_data = &self.datas.get(from.as_usize()).unwrap();

        let x_secret = msg
            .data2
            .paillier_enc_x
            .decrypt(&self.context.paillier_sk)
            .to_scalar();

        if x_secret.mul_by_generator()
            != sender_data.data.xs_public[self.context.party_idx.as_usize()]
        {
            let mu = msg
                .data2
                .paillier_enc_x
                .derive_randomizer(&self.context.paillier_sk);
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round3MismatchedSecret {
                    cap_c: msg.data2.paillier_enc_x,
                    x: x_secret,
                    mu: mu.retrieve(),
                },
            )));
        }

        let aux = (&self.context.shared_randomness, &self.rho, &from);

        if !msg.data2.mod_proof.verify(&sender_data.paillier_pk, &aux) {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round3("Mod proof verification failed".into()),
            )));
        }

        if !msg.data2.fac_proof.verify(
            &sender_data.paillier_pk,
            &self.context.data_precomp.rp_params,
            &aux,
        ) {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round3("Fac proof verification failed".into()),
            )));
        }

        if !msg.data2.sch_proof_y.verify(
            &sender_data.data.el_gamal_commitment,
            &sender_data.data.el_gamal_pk,
            &aux,
        ) {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round3("Sch proof verification (Y) failed".into()),
            )));
        }

        if !msg.data2.sch_proof_x.verify(
            &sender_data.data.sch_commitments_x[self.context.party_idx.as_usize()],
            &sender_data.data.xs_public[self.context.party_idx.as_usize()],
            &aux,
        ) {
            return Err(ReceiveError::Provable(KeyRefreshError(
                KeyRefreshErrorEnum::Round3("Sch proof verification (X) failed".into()),
            )));
        }

        Ok(x_secret)
    }
}

impl<P: SchemeParams> Finalizable for Round3<P> {
    fn requirement() -> FinalizationRequirement {
        FinalizationRequirement::AllDms
    }
}

impl<P: SchemeParams> FinalizableToResult for Round3<P> {
    fn finalize_to_result(
        self,
        _rng: &mut impl CryptoRngCore,
        _bc_payloads: BTreeMap<PartyIdx, <Self as BroadcastRound>::Payload>,
        dm_payloads: BTreeMap<PartyIdx, <Self as DirectRound>::Payload>,
        _dm_artifacts: BTreeMap<PartyIdx, <Self as DirectRound>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let secrets = try_to_holevec(dm_payloads, self.num_parties(), self.party_idx())
            .unwrap()
            .into_vec(self.context.xs_secret[self.context.party_idx.as_usize()]);
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
                rp_params: data.rp_params.retrieve(),
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

        Ok(key_share_change)
    }
}

#[cfg(test)]
mod tests {

    use rand_core::{OsRng, RngCore};

    use super::Round1;
    use crate::cggmp21::TestParams;
    use crate::curve::Scalar;
    use crate::rounds::{
        test_utils::{step_next_round, step_result, step_round},
        FirstRound, PartyIdx,
    };

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

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let r2 = step_next_round(&mut OsRng, r1a).unwrap();
        let r2a = step_round(&mut OsRng, r2).unwrap();
        let r3 = step_next_round(&mut OsRng, r2a).unwrap();
        let r3a = step_round(&mut OsRng, r3).unwrap();
        let changes = step_result(&mut OsRng, r3a).unwrap();

        // Check that public points correspond to secret scalars
        for (idx, change) in changes.iter().enumerate() {
            for other_change in changes.iter() {
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
        let mask_sum: Scalar = changes
            .iter()
            .map(|change| change.secret_share_change)
            .sum();
        assert_eq!(mask_sum, Scalar::ZERO);
    }
}
