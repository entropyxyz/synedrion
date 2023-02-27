use alloc::collections::BTreeMap;

use crypto_bigint::Pow;
use rand_core::OsRng;

use super::keygen::{PartyId, SessionInfo};
use super::generic::{ToSend, Round};
use crate::paillier::{
    encryption::Ciphertext,
    keys::{PublicKeyPaillier, SecretKeyPaillier},
    params::{PaillierParams, PaillierTest},
    uint::Uint,
};
use crate::sigma::fac::FacProof;
use crate::sigma::mod_::ModProof;
use crate::sigma::prm::PrmProof;
use crate::sigma::sch::{SchCommitment, SchProof, SchSecret};
use crate::tools::group::{zero_sum_scalars, NonZeroScalar, Point, Scalar};
use crate::tools::hashing::{Chain, Hash};
use crate::tools::random::random_bits;

pub trait SchemeParams: Clone {
    const SECURITY_PARAMETER: usize;
    type Paillier: PaillierParams;
}

#[derive(Clone)]
pub struct TestSchemeParams;

impl SchemeParams for TestSchemeParams {
    const SECURITY_PARAMETER: usize = 10;
    type Paillier = PaillierTest;
}

pub struct Round1<P: SchemeParams> {
    other_parties: Vec<PartyId>,
    data: FullData<P>,
    secret_data: SecretData<P>,
}

#[derive(Debug, Clone)]
pub struct FullData<P: SchemeParams> {
    session_info: SessionInfo,                                      // $sid$
    party_id: PartyId,                                              // $i$
    xs_public: BTreeMap<PartyId, Point>,                            // $\bm{X}_i$
    sch_commitments_x: BTreeMap<PartyId, SchCommitment>,            // $\bm{A}_i$
    y_public: Point,                                                // $Y_i$,
    sch_commitment_y: SchCommitment,                                // $B_i$
    paillier_pk: PublicKeyPaillier<P::Paillier>,                    // $N_i$
    paillier_public: <P::Paillier as PaillierParams>::GroupElement, // $s_i$
    paillier_base: <P::Paillier as PaillierParams>::GroupElement,   // $t_i$
    prm_proof: PrmProof<P::Paillier>,                               // $\hat{\psi}_i$
    rho_bits: Box<[u8]>,                                            // $\rho_i$
    u_bits: Box<[u8]>,                                              // $u_i$
}

struct SecretData<P: SchemeParams> {
    paillier_sk: SecretKeyPaillier<P::Paillier>,
    y_secret: NonZeroScalar,
    xs_secret: BTreeMap<PartyId, Scalar>,
    sch_secret_y: SchSecret,
    sch_secrets_x: BTreeMap<PartyId, SchSecret>,
}

impl<P: SchemeParams> FullData<P> {
    fn hash(&self) -> Box<[u8]> {
        Hash::new_with_dst(b"Auxiliary")
            .chain(&self.session_info)
            .chain(&self.party_id)
            .chain(&self.xs_public)
            .chain(&self.sch_commitments_x)
            .chain(&self.y_public)
            .chain(&self.sch_commitment_y)
            .chain(&self.paillier_pk)
            .chain(&self.paillier_public)
            .chain(&self.paillier_base)
            .chain(&self.prm_proof)
            .chain(&self.rho_bits)
            .chain(&self.u_bits)
            .finalize_boxed()
    }
}

impl<P: SchemeParams> Round1<P> {
    pub fn new(session_info: &SessionInfo, party_id: &PartyId) -> Self {
        let paillier_sk = SecretKeyPaillier::<P::Paillier>::random(&mut OsRng);
        let paillier_pk = paillier_sk.public_key();
        let y_secret = NonZeroScalar::random(&mut OsRng);
        let y_public = &Point::GENERATOR * &y_secret;

        let sch_secret_y = SchSecret::random(&mut OsRng); // $\tau$
        let sch_commitment_y = SchCommitment::new(&sch_secret_y); // $B_i$

        let xs_secret = zero_sum_scalars(&mut OsRng, session_info.parties.len());

        let xs_secret: BTreeMap<PartyId, Scalar> = session_info
            .parties
            .iter()
            .cloned()
            .zip(xs_secret.iter().cloned())
            .collect::<BTreeMap<_, _>>();

        let xs_public = xs_secret
            .clone()
            .into_iter()
            .map(|(party_id, x)| (party_id, &Point::GENERATOR * &x))
            .collect::<BTreeMap<_, _>>();

        let r = paillier_pk.random_invertible_group_elem(&mut OsRng);
        let lambda = paillier_sk.random_field_elem(&mut OsRng);
        let paillier_base = r * &r; // TODO: use `square()` when it's available
        let paillier_public = paillier_base.pow(&lambda);

        let aux = (session_info, party_id);
        let prm_proof = PrmProof::random(
            &mut OsRng,
            &paillier_sk,
            &lambda,
            &paillier_base,
            &paillier_public,
            &aux,
            session_info.kappa,
        );

        // $\tau_j$
        let sch_secrets_x = session_info
            .parties
            .iter()
            .map(|party| (party.clone(), SchSecret::random(&mut OsRng)))
            .collect::<BTreeMap<_, _>>();

        // $A_i^j$
        let sch_commitments_x = sch_secrets_x
            .iter()
            .map(|(party, secret)| (party.clone(), SchCommitment::new(secret)))
            .collect::<BTreeMap<_, _>>();

        let rho_bits = random_bits(session_info.kappa);
        let u_bits = random_bits(session_info.kappa);

        let other_parties = session_info.other_parties(party_id);

        let data = FullData {
            session_info: session_info.clone(),
            party_id: party_id.clone(),
            xs_public,
            sch_commitments_x,
            y_public,
            sch_commitment_y,
            paillier_pk,
            paillier_public,
            paillier_base,
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

        Self {
            other_parties,
            data,
            secret_data,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Round1Bcast {
    hash: Box<[u8]>, // `V_j`
}

impl<P: SchemeParams> Round for Round1<P> {
    type Id = PartyId;
    type Error = String;
    type Payload = Box<[u8]>;
    type Message = Round1Bcast;
    type NextRound = Round2<P>;

    fn to_send(&self) -> ToSend<Self::Id, Self::Message> {
        ToSend::Broadcast {
            message: Round1Bcast {
                hash: self.data.hash(),
            },
            ids: self.other_parties.clone(),
            needs_consensus: true,
        }
    }

    fn verify_received(
        &self,
        _from: &Self::Id,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        Ok(msg.hash)
    }

    fn finalize(self, payloads: BTreeMap<Self::Id, Self::Payload>) -> Self::NextRound {
        Round2 {
            data: self.data,
            secret_data: self.secret_data,
            hashes: payloads,
        }
    }
}

pub struct Round2<P: SchemeParams> {
    data: FullData<P>,
    secret_data: SecretData<P>,
    hashes: BTreeMap<PartyId, Box<[u8]>>, // V_j
}

#[derive(Clone)]
pub struct Round2Bcast<P: SchemeParams> {
    data: FullData<P>,
}

impl<P: SchemeParams> Round for Round2<P> {
    type Id = PartyId;
    type Error = String;
    type Payload = FullData<P>;
    type Message = Round2Bcast<P>;
    type NextRound = Round3<P>;

    fn to_send(&self) -> ToSend<Self::Id, Self::Message> {
        ToSend::Broadcast {
            message: Round2Bcast {
                data: self.data.clone(),
            },
            ids: self.hashes.keys().cloned().collect(),
            needs_consensus: false,
        }
    }

    fn verify_received(
        &self,
        from: &Self::Id,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        if &msg.data.hash() != self.hashes.get(from).unwrap() {
            return Err("Invalid hash".to_string());
        }

        if msg.data.paillier_pk.modulus().bits() < 8 * P::SECURITY_PARAMETER {
            return Err("Paillier modulus is too small".to_string());
        }

        let sum_x: Point = msg.data.xs_public.values().sum();
        if sum_x != Point::IDENTITY {
            return Err("Sum of X points is not identity".to_string());
        }

        let aux = (&self.data.session_info, from);
        if !msg
            .data
            .prm_proof
            .verify(&msg.data.paillier_base, &msg.data.paillier_public, &aux)
        {
            return Err("PRM verification failed".to_string());
        }

        Ok(msg.data)
    }

    fn finalize(self, payloads: BTreeMap<Self::Id, Self::Payload>) -> Self::NextRound {
        // XOR the vectors together
        // TODO: is there a better way?
        let mut rho = self.data.rho_bits.clone();
        for (_party_id, data) in payloads.iter() {
            for (i, x) in data.rho_bits.iter().enumerate() {
                rho[i] ^= x;
            }
        }

        Round3 {
            rho,
            data: self.data,
            secret_data: self.secret_data,
            datas: payloads,
        }
    }
}

pub struct Round3<P: SchemeParams> {
    rho: Box<[u8]>,
    data: FullData<P>,
    secret_data: SecretData<P>,
    datas: BTreeMap<PartyId, FullData<P>>,
}

#[derive(Clone)]
pub struct Round3Direct<P: SchemeParams> {
    data2: FullData2<P>,
}

impl<P: SchemeParams> Round for Round3<P> {
    type Id = PartyId;
    type Error = String;
    type Payload = Scalar;
    type Message = Round3Direct<P>;
    type NextRound = AuxData<P>;

    fn to_send(&self) -> ToSend<Self::Id, Self::Message> {
        let aux = (&self.data.session_info, &self.rho, &self.data.party_id);
        let mod_proof = ModProof::random(
            &mut OsRng,
            &self.secret_data.paillier_sk,
            &aux,
            P::SECURITY_PARAMETER,
        );

        let sch_proof_y = SchProof::new(
            &self.secret_data.sch_secret_y,
            &self.secret_data.y_secret.clone().into_scalar(),
            &self.data.sch_commitment_y,
            &self.data.y_public,
            &aux,
        );

        let mut dms = Vec::new();
        for (party_id, data) in self.datas.iter() {
            let fac_proof = FacProof::random(&mut OsRng, &self.secret_data.paillier_sk, &aux);

            let x_secret = self.secret_data.xs_secret[party_id];
            let x_public = self.data.xs_public[party_id];
            let ciphertext = Ciphertext::new(&data.paillier_pk, &x_secret);

            let sch_proof_x = SchProof::new(
                &self.secret_data.sch_secrets_x[party_id],
                &x_secret,
                &self.data.sch_commitments_x[party_id],
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

            dms.push((party_id.clone(), Round3Direct { data2 }));
        }

        ToSend::Direct(dms)
    }

    fn verify_received(
        &self,
        from: &Self::Id,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        let sender_data = &self.datas[from];

        let x_secret = msg
            .data2
            .paillier_enc_x
            .decrypt(&self.secret_data.paillier_sk)
            .unwrap();

        if &Point::GENERATOR * &x_secret != sender_data.xs_public[&self.data.party_id] {
            // TODO: paper has `\mu` calculation here.
            return Err("Mismatched secret x".to_string());
        }

        let aux = (&self.data.session_info, &self.rho, from);

        if !msg.data2.mod_proof.verify(&sender_data.paillier_pk, &aux) {
            return Err("Mod proof verification failed".to_string());
        }

        if !msg.data2.fac_proof.verify() {
            return Err("Fac proof verification failed".to_string());
        }

        if !msg
            .data2
            .sch_proof_y
            .verify(&sender_data.sch_commitment_y, &sender_data.y_public, &aux)
        {
            // CHECK: not sending the commitment the second time in `msg`,
            // since we already got it from the previous round.
            return Err("Sch proof verification (Y) failed".to_string());
        }

        if !msg.data2.sch_proof_x.verify(
            &sender_data.sch_commitments_x[&self.data.party_id],
            &sender_data.xs_public[&self.data.party_id],
            &aux,
        ) {
            // CHECK: not sending the commitment the second time in `msg`,
            // since we already got it from the previous round.
            return Err("Sch proof verification (Y) failed".to_string());
        }

        Ok(x_secret)
    }

    fn finalize(self, payloads: BTreeMap<Self::Id, Self::Payload>) -> Self::NextRound {
        let x_mask = payloads.values().sum();

        let xs_masks_public = self
            .datas
            .keys()
            .map(|party_id| {
                (
                    party_id.clone(),
                    self.datas
                        .values()
                        .map(|data| data.xs_public[party_id])
                        .sum(),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let ys_public = self
            .datas
            .iter()
            .map(|(party_id, data)| (party_id.clone(), data.y_public))
            .collect::<BTreeMap<_, _>>();

        let paillier_pks = self
            .datas
            .iter()
            .map(|(party_id, data)| (party_id.clone(), data.paillier_pk.clone()))
            .collect::<BTreeMap<_, _>>();

        let paillier_bases = self
            .datas
            .iter()
            .map(|(party_id, data)| (party_id.clone(), data.paillier_base))
            .collect::<BTreeMap<_, _>>();

        let paillier_publics = self
            .datas
            .iter()
            .map(|(party_id, data)| (party_id.clone(), data.paillier_public))
            .collect::<BTreeMap<_, _>>();

        AuxData {
            x_mask,
            y: self.secret_data.y_secret.clone(),
            paillier_sk: self.secret_data.paillier_sk,
            xs_masks_public,
            ys_public,
            paillier_pks,
            paillier_bases,
            paillier_publics,
        }
    }
}

#[derive(Clone)]
pub struct FullData2<P: SchemeParams> {
    mod_proof: ModProof<P::Paillier>,        // `psi_j`
    fac_proof: FacProof<P::Paillier>,        // `phi_j,i`
    sch_proof_y: SchProof,                   // `pi_i`
    paillier_enc_x: Ciphertext<P::Paillier>, // `C_j,i`
    sch_proof_x: SchProof,                   // `psi_i,j`
}

pub struct AuxData<P: SchemeParams> {
    // secret
    x_mask: Scalar,
    y: NonZeroScalar,
    paillier_sk: SecretKeyPaillier<P::Paillier>,

    // public
    xs_masks_public: BTreeMap<PartyId, Point>,
    ys_public: BTreeMap<PartyId, Point>,
    paillier_pks: BTreeMap<PartyId, PublicKeyPaillier<P::Paillier>>,
    paillier_bases: BTreeMap<PartyId, <P::Paillier as PaillierParams>::GroupElement>,
    paillier_publics: BTreeMap<PartyId, <P::Paillier as PaillierParams>::GroupElement>,
}

#[cfg(test)]
mod tests {

    use alloc::collections::BTreeMap;

    use super::*;
    use crate::protocols::keygen::PartyId;
    use crate::protocols::generic::tests::step;

    #[test]
    fn execute_auxiliary() {
        let parties = [PartyId(111), PartyId(222), PartyId(333)];

        let session_info = SessionInfo {
            parties: parties.to_vec(),
            kappa: 256,
        };

        let r1 = BTreeMap::from([
            (
                parties[0].clone(),
                Round1::<TestSchemeParams>::new(&session_info, &parties[0]),
            ),
            (
                parties[1].clone(),
                Round1::<TestSchemeParams>::new(&session_info, &parties[1]),
            ),
            (
                parties[2].clone(),
                Round1::<TestSchemeParams>::new(&session_info, &parties[2]),
            ),
        ]);

        let r2 = step(r1).unwrap();
        let r3 = step(r2).unwrap();
        let _aux_datas = step(r3).unwrap();

        // TODO: do some checks here
    }
}
