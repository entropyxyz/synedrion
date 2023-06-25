use alloc::boxed::Box;
use alloc::vec::Vec;

use crypto_bigint::Pow;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::{
    KeyShareChange, KeyShareChangePublic, KeyShareChangeSecret, PartyIdx, SchemeParams, SessionId,
};
use super::generic::{
    FinalizeError, FinalizeSuccess, FirstRound, NonExistent, ReceiveError, Round, ToSendTyped,
};
use crate::curve::{Point, Scalar};
use crate::paillier::{
    encryption::Ciphertext,
    keys::{PublicKeyPaillier, SecretKeyPaillier},
    params::PaillierParams,
    uint::{Retrieve, UintLike},
};
use crate::sigma::fac::FacProof;
use crate::sigma::mod_::ModProof;
use crate::sigma::prm::PrmProof;
use crate::sigma::sch::{SchCommitment, SchProof, SchSecret};
use crate::tools::collections::HoleVec;
use crate::tools::hashing::{Chain, Hash, HashOutput, Hashable};
use crate::tools::random::random_bits;

#[derive(Clone)]
pub struct Round1<P: SchemeParams> {
    data: FullData<P>,
    secret_data: SecretData<P>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullData<P: SchemeParams> {
    session_id: SessionId,                                     // $sid$
    party_idx: PartyIdx,                                       // $i$
    xs_public: Vec<Point>,                                     // $\bm{X}_i$
    sch_commitments_x: Vec<SchCommitment>,                     // $\bm{A}_i$
    y_public: Point,                                           // $Y_i$,
    sch_commitment_y: SchCommitment,                           // $B_i$
    paillier_pk: PublicKeyPaillier<P::Paillier>,               // $N_i$
    rp_power: <P::Paillier as PaillierParams>::DoubleUint,     // $s_i$
    rp_generator: <P::Paillier as PaillierParams>::DoubleUint, // $t_i$
    prm_proof: PrmProof<P::Paillier>,                          // $\hat{\psi}_i$
    rho_bits: Box<[u8]>,                                       // $\rho_i$
    u_bits: Box<[u8]>,                                         // $u_i$
}

#[derive(Clone)]
struct SecretData<P: SchemeParams> {
    paillier_sk: SecretKeyPaillier<P::Paillier>,
    y_secret: Scalar,
    xs_secret: Vec<Scalar>,
    sch_secret_y: SchSecret,
    sch_secrets_x: Vec<SchSecret>,
}

impl<P: SchemeParams> FullData<P> {
    fn hash(&self) -> HashOutput {
        Hash::new_with_dst(b"Auxiliary")
            .chain(&self.session_id)
            .chain(&self.party_idx)
            .chain(&self.xs_public)
            .chain(&self.sch_commitments_x)
            .chain(&self.y_public)
            .chain(&self.sch_commitment_y)
            .chain(&self.paillier_pk)
            .chain(&self.rp_power)
            .chain(&self.rp_generator)
            .chain(&self.prm_proof)
            .chain(&self.rho_bits)
            .chain(&self.u_bits)
            .finalize()
    }
}

pub(crate) struct Context {
    session_id: SessionId,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Context = Context;
    fn new(
        rng: &mut impl CryptoRngCore,
        num_parties: usize,
        party_idx: PartyIdx,
        context: &Self::Context,
    ) -> Self {
        let paillier_sk = SecretKeyPaillier::<P::Paillier>::random(rng);
        let paillier_pk = paillier_sk.public_key();
        let y_secret = Scalar::random(rng);
        let y_public = y_secret.mul_by_generator();

        let sch_secret_y = SchSecret::random(rng); // $\tau$
        let sch_commitment_y = SchCommitment::new(&sch_secret_y); // $B_i$

        let xs_secret = Scalar::ZERO.split(rng, num_parties);
        let xs_public = xs_secret
            .iter()
            .cloned()
            .map(|x| x.mul_by_generator())
            .collect();

        let r = paillier_pk.random_invertible_group_elem(rng);
        let lambda = paillier_sk.random_field_elem(rng);
        let rp_generator = r * r; // TODO: use `square()` when it's available
        let rp_power = rp_generator.pow(&lambda);

        let aux = (&context.session_id, &party_idx);
        let prm_proof = PrmProof::random(
            rng,
            &paillier_sk,
            &lambda,
            &rp_generator,
            &rp_power,
            &aux,
            P::SECURITY_PARAMETER,
        );

        // $\tau_j$
        let sch_secrets_x: Vec<SchSecret> =
            (0..num_parties).map(|_| SchSecret::random(rng)).collect();

        // $A_i^j$
        let sch_commitments_x = sch_secrets_x.iter().map(SchCommitment::new).collect();

        let rho_bits = random_bits(P::SECURITY_PARAMETER);
        let u_bits = random_bits(P::SECURITY_PARAMETER);

        let data = FullData {
            session_id: context.session_id.clone(),
            party_idx,
            xs_public,
            sch_commitments_x,
            y_public,
            sch_commitment_y,
            paillier_pk,
            rp_power: rp_power.retrieve(),
            rp_generator: rp_generator.retrieve(),
            prm_proof,
            rho_bits,
            u_bits,
        };

        let secret_data = SecretData {
            paillier_sk,
            y_secret,
            xs_secret,
            sch_secrets_x,
            sch_secret_y,
        };

        Self { data, secret_data }
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

impl<P: SchemeParams> Round for Round1<P> {
    type Payload = HashOutput;
    type Message = Round1Bcast;
    type NextRound = Round2<P>;
    type Result = KeyShareChange<P>;

    fn party_idx(&self) -> PartyIdx {
        self.data.party_idx
    }
    fn num_parties(&self) -> usize {
        self.data.xs_public.len()
    }

    fn round_num() -> u8 {
        1
    }
    fn next_round_num() -> Option<u8> {
        Some(2)
    }
    fn requires_broadcast_consensus() -> bool {
        true
    }

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        ToSendTyped::Broadcast(Round1Bcast {
            hash: self.data.hash(),
        })
    }

    fn verify_received(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        Ok(msg.hash)
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        Ok(FinalizeSuccess::AnotherRound(Round2 {
            data: self.data,
            secret_data: self.secret_data,
            hashes: payloads,
        }))
    }
}

#[derive(Clone)]
pub struct Round2<P: SchemeParams> {
    data: FullData<P>,
    secret_data: SecretData<P>,
    hashes: HoleVec<HashOutput>, // V_j
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "FullData<P>: Serialize"))]
#[serde(bound(deserialize = "FullData<P>: for<'x> Deserialize<'x>"))]
pub struct Round2Bcast<P: SchemeParams> {
    data: FullData<P>,
}

impl<P: SchemeParams> Round for Round2<P> {
    type Payload = FullData<P>;
    type Message = Round2Bcast<P>;
    type NextRound = Round3<P>;
    type Result = KeyShareChange<P>;

    fn party_idx(&self) -> PartyIdx {
        self.data.party_idx
    }
    fn num_parties(&self) -> usize {
        self.data.xs_public.len()
    }

    fn round_num() -> u8 {
        2
    }
    fn next_round_num() -> Option<u8> {
        Some(3)
    }
    fn requires_broadcast_consensus() -> bool {
        false
    }

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        ToSendTyped::Broadcast(Round2Bcast {
            data: self.data.clone(),
        })
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        if &msg.data.hash() != self.hashes.get(from.as_usize()).unwrap() {
            return Err(ReceiveError::VerificationFail("Invalid hash".into()));
        }

        if msg.data.paillier_pk.modulus().as_ref().bits() < 8 * P::SECURITY_PARAMETER {
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

        let aux = (&self.data.session_id, &from);
        if !msg.data.prm_proof.verify(
            &msg.data.paillier_pk,
            &msg.data.rp_generator,
            &msg.data.rp_power,
            &aux,
        ) {
            return Err(ReceiveError::VerificationFail(
                "PRM verification failed".into(),
            ));
        }

        Ok(msg.data)
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        // XOR the vectors together
        // TODO: is there a better way?
        let mut rho = self.data.rho_bits.clone();
        for data in payloads.iter() {
            for (i, x) in data.rho_bits.iter().enumerate() {
                rho[i] ^= x;
            }
        }

        Ok(FinalizeSuccess::AnotherRound(Round3 {
            rho,
            data: self.data,
            secret_data: self.secret_data,
            datas: payloads,
        }))
    }
}

#[derive(Clone)]
pub struct Round3<P: SchemeParams> {
    rho: Box<[u8]>,
    data: FullData<P>,
    secret_data: SecretData<P>,
    datas: HoleVec<FullData<P>>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "ModProof<P::Paillier>: Serialize,
    FacProof<P::Paillier>: Serialize,
    Ciphertext<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "ModProof<P::Paillier>: for<'x> Deserialize<'x>,
    FacProof<P::Paillier>: for<'x> Deserialize<'x>,
    Ciphertext<P::Paillier>: for<'x> Deserialize<'x>"))]
pub struct FullData2<P: SchemeParams> {
    mod_proof: ModProof<P::Paillier>,        // `psi_j`
    fac_proof: FacProof<P::Paillier>,        // `phi_j,i`
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

impl<P: SchemeParams> Round for Round3<P> {
    type Payload = Scalar;
    type Message = Round3Direct<P>;
    type NextRound = NonExistent<Self::Result>;
    type Result = KeyShareChange<P>;

    fn party_idx(&self) -> PartyIdx {
        self.data.party_idx
    }
    fn num_parties(&self) -> usize {
        self.data.xs_public.len()
    }

    fn round_num() -> u8 {
        3
    }
    fn next_round_num() -> Option<u8> {
        None
    }
    fn requires_broadcast_consensus() -> bool {
        false
    }

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        let aux = (&self.data.session_id, &self.rho, &self.data.party_idx);
        let mod_proof = ModProof::random(
            rng,
            &self.secret_data.paillier_sk,
            &aux,
            P::SECURITY_PARAMETER,
        );

        let sch_proof_y = SchProof::new(
            &self.secret_data.sch_secret_y,
            &self.secret_data.y_secret,
            &self.data.sch_commitment_y,
            &self.data.y_public,
            &aux,
        );

        let mut dms = Vec::new();
        for (party_idx, data) in self.datas.enumerate() {
            let fac_proof = FacProof::random(rng, &self.secret_data.paillier_sk, &aux);

            let x_secret = self.secret_data.xs_secret[party_idx];
            let x_public = self.data.xs_public[party_idx];
            let ciphertext = Ciphertext::new(rng, &data.paillier_pk, &x_secret);

            let sch_proof_x = SchProof::new(
                &self.secret_data.sch_secrets_x[party_idx],
                &x_secret,
                &self.data.sch_commitments_x[party_idx],
                &x_public,
                &aux,
            );

            let data2 = FullData2 {
                mod_proof: mod_proof.clone(),
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
            .decrypt(&self.secret_data.paillier_sk);

        if x_secret.mul_by_generator() != sender_data.xs_public[self.data.party_idx.as_usize()] {
            // TODO: paper has `\mu` calculation here.
            return Err(ReceiveError::VerificationFail("Mismatched secret x".into()));
        }

        let aux = (&self.data.session_id, &self.rho, &from);

        if !msg.data2.mod_proof.verify(&sender_data.paillier_pk, &aux) {
            return Err(ReceiveError::VerificationFail(
                "Mod proof verification failed".into(),
            ));
        }

        if !msg.data2.fac_proof.verify() {
            return Err(ReceiveError::VerificationFail(
                "Fac proof verification failed".into(),
            ));
        }

        if !msg
            .data2
            .sch_proof_y
            .verify(&sender_data.sch_commitment_y, &sender_data.y_public, &aux)
        {
            // CHECK: not sending the commitment the second time in `msg`,
            // since we already got it from the previous round.
            return Err(ReceiveError::VerificationFail(
                "Sch proof verification (Y) failed".into(),
            ));
        }

        if !msg.data2.sch_proof_x.verify(
            &sender_data.sch_commitments_x[self.data.party_idx.as_usize()],
            &sender_data.xs_public[self.data.party_idx.as_usize()],
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

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let secrets = payloads.into_vec(self.secret_data.xs_secret[self.data.party_idx.as_usize()]);
        let share_change = secrets.iter().sum();

        let datas = self.datas.into_vec(self.data);

        let public_share_changes: Vec<_> = (0..datas.len())
            .map(|idx| datas.iter().map(|data| data.xs_public[idx]).sum())
            .collect();

        let public = datas
            .into_iter()
            .enumerate()
            .map(|(idx, data)| KeyShareChangePublic {
                x: public_share_changes[idx],
                y: data.y_public,
                paillier_pk: data.paillier_pk,
                rp_generator: data.rp_generator,
                rp_power: data.rp_power,
            })
            .collect();

        let secret = KeyShareChangeSecret {
            secret: share_change,
            sk: self.secret_data.paillier_sk,
            y: self.secret_data.y_secret,
        };

        let key_share_change = KeyShareChange { secret, public };

        Ok(FinalizeSuccess::Result(key_share_change))
    }
}

#[cfg(test)]
mod tests {

    use rand_core::OsRng;

    use super::{Context, Round1};
    use crate::curve::Scalar;
    use crate::protocols::common::{PartyIdx, SessionId, TestSchemeParams};
    use crate::protocols::generic::{
        tests::{assert_next_round, assert_result, step},
        FirstRound,
    };

    #[test]
    fn execute_auxiliary() {
        let session_id = SessionId::random(&mut OsRng);

        let context = Context { session_id };

        let r1 = vec![
            Round1::<TestSchemeParams>::new(&mut OsRng, 3, PartyIdx::from_usize(0), &context),
            Round1::<TestSchemeParams>::new(&mut OsRng, 3, PartyIdx::from_usize(1), &context),
            Round1::<TestSchemeParams>::new(&mut OsRng, 3, PartyIdx::from_usize(2), &context),
        ];

        let r2 = assert_next_round(step(&mut OsRng, r1).unwrap()).unwrap();
        let r3 = assert_next_round(step(&mut OsRng, r2).unwrap()).unwrap();
        let results = assert_result(step(&mut OsRng, r3).unwrap()).unwrap();

        // Check that public points correspond to secret scalars
        for (idx, change) in results.iter().enumerate() {
            for other_change in results.iter() {
                assert_eq!(
                    change.secret.secret.mul_by_generator(),
                    other_change.public[idx].x
                );
                assert_eq!(
                    change.secret.y.mul_by_generator(),
                    other_change.public[idx].y
                );
            }
        }

        // The resulting sum of masks should be zero, since the combined secret key
        // should not change after applying the masks at each node.
        let mask_sum: Scalar = results.iter().map(|change| change.secret.secret).sum();
        assert_eq!(mask_sum, Scalar::ZERO);
    }
}
