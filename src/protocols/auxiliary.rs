use alloc::collections::BTreeMap;

use crypto_bigint::{modular::Retrieve, Pow};
use rand_core::OsRng;

use super::keygen::{PartyId, SessionInfo};
use super::rounds;
use crate::paillier::{
    keys::{PublicKeyPaillier, SecretKeyPaillier},
    params::PaillierParams,
};
use crate::sigma::prm::{PrmCommitment, PrmProof, PrmSecret};
use crate::sigma::sch::{SchCommitment, SchSecret};
use crate::tools::collections::{HoleMap, OnInsert};
use crate::tools::group::{zero_sum_scalars, NonZeroScalar, Point};
use crate::tools::hashing::{Chain, Hash};
use crate::tools::random::random_bits;

pub trait SchemeParams {
    const SECURITY_PARAMETER: usize;
    type Paillier: PaillierParams;
}

pub struct Round1<P: SchemeParams> {
    data: FullData<P>,
}

#[derive(Debug, Clone)]
struct FullData<P: SchemeParams> {
    session_info: SessionInfo,                                      // $sid$
    party_id: PartyId,                                              // $i$
    xs_public: Vec<Point>,                                          // $\bm{X}_i$
    sch_commitments_a: BTreeMap<PartyId, SchCommitment>,            // $\bm{A}_i$
    y_public: Point,                                                // $Y_i$,
    sch_commitment_b: SchCommitment,                                // $B_i$
    paillier_pk: PublicKeyPaillier<P::Paillier>,                    // $N_i$
    paillier_public: <P::Paillier as PaillierParams>::GroupElement, // $s_i$
    paillier_base: <P::Paillier as PaillierParams>::GroupElement,   // $t_i$
    prm_proof: PrmProof<P::Paillier>,                               // $\hat{\psi}_i$
    rho_bits: Box<[u8]>,                                            // $\rho_i$
    u_bits: Box<[u8]>,                                              // $u_i$
}

impl<P: SchemeParams> FullData<P> {
    fn hash(&self) -> Box<[u8]> {
        Hash::new_with_dst(b"Auxiliary")
            .chain(&self.session_info)
            .chain(&self.party_id)
            .chain(&self.xs_public)
            .chain(&self.sch_commitments_a)
            .chain(&self.y_public)
            .chain(&self.sch_commitment_b)
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

        let sch_secret_b = SchSecret::random(&mut OsRng); // $\tau$
        let sch_commitment_b = SchCommitment::new(&sch_secret_b); // $B_i$

        let xs_secret = zero_sum_scalars(&mut OsRng, session_info.parties.len());
        let xs_public = xs_secret
            .iter()
            .map(|x| &Point::GENERATOR * x)
            .collect::<Vec<_>>();

        let r = paillier_pk.random_invertible_group_elem(&mut OsRng);
        let lambda = paillier_sk.random_field_elem(&mut OsRng);
        let paillier_base = r * &r; // TODO: use `square()` when it's available
        let paillier_public = paillier_base.pow(&lambda);

        let aux = (session_info, party_id);
        let prm_secret = PrmSecret::random(&mut OsRng, &paillier_sk, session_info.kappa);
        let prm_commitment = PrmCommitment::new(&prm_secret, &paillier_base);
        let prm_proof = PrmProof::new(
            &paillier_sk,
            &prm_secret,
            &lambda,
            &prm_commitment,
            &paillier_public,
            &aux,
        );

        // $\tau_j$
        let sch_secrets_a = session_info
            .parties
            .iter()
            .map(|party| (party.clone(), SchSecret::random(&mut OsRng)))
            .collect::<BTreeMap<_, _>>();

        // $A_i^j$
        let sch_commitments_a = sch_secrets_a
            .iter()
            .map(|(party, secret)| (party.clone(), SchCommitment::new(secret)))
            .collect::<BTreeMap<_, _>>();

        let rho_bits = random_bits(session_info.kappa);
        let u_bits = random_bits(session_info.kappa);

        let data = FullData {
            session_info: session_info.clone(),
            party_id: party_id.clone(),
            xs_public,
            sch_commitments_a,
            y_public,
            sch_commitment_b,
            paillier_pk,
            paillier_public,
            paillier_base,
            prm_proof,
            rho_bits,
            u_bits,
        };

        Self { data }
    }
}

#[derive(Debug, Clone)]
pub struct Round1Bcast {
    hash: Box<[u8]>, // `V_j`
}

impl<P: SchemeParams> rounds::RoundStart for Round1<P> {
    type Id = PartyId;
    type Error = String;
    type DirectMessage = ();
    type BroadcastMessage = Round1Bcast;
    type ReceivingState = Round1Receiving<P>;
    fn execute(
        &self,
    ) -> Result<
        (
            Self::ReceivingState,
            Vec<(Self::Id, Self::DirectMessage)>,
            Self::BroadcastMessage,
        ),
        Self::Error,
    > {
        let hash = self.data.hash();
        let bcast = Round1Bcast { hash: hash.clone() };
        let dms = Vec::new();
        let mut hashes = HoleMap::new(&self.data.session_info.parties);
        hashes.try_insert(&self.data.party_id, hash);

        Ok((
            Round1Receiving {
                hashes,
                phantom: core::marker::PhantomData,
            },
            dms,
            bcast,
        ))
    }
}

pub struct Round1Receiving<P: SchemeParams> {
    hashes: HoleMap<PartyId, Box<[u8]>>, // V_j
    phantom: core::marker::PhantomData<P>,
}

impl<P: SchemeParams> rounds::RoundReceiving for Round1Receiving<P> {
    type Id = PartyId;
    type NextState = ();
    type DirectMessage = ();
    type BroadcastMessage = Round1Bcast;
    type Error = String;
    type Round = Round1<P>;

    const BCAST_REQUIRES_CONSENSUS: bool = true;

    fn receive_bcast(
        &mut self,
        _round: &Self::Round,
        from: &Self::Id,
        msg: &Self::BroadcastMessage,
    ) -> rounds::OnReceive<Self::Error> {
        // TODO: check that msg.session_info == self.session_info
        match self.hashes.try_insert(from, msg.hash.clone()) {
            OnInsert::Ok => rounds::OnReceive::Ok,
            OnInsert::AlreadyExists => rounds::OnReceive::NonFatal("Repeating message".to_string()),
            OnInsert::OutOfBounds => {
                rounds::OnReceive::NonFatal("Invalid message: index out of bounds".to_string())
            }
        }
    }

    fn try_finalize(
        self,
        round: Self::Round,
    ) -> Result<rounds::OnFinalize<Self, Self::NextState>, Self::Error> {
        match self.hashes.try_finalize() {
            Ok(hashes) => {
                let r = ();
                Ok(rounds::OnFinalize::Finished(r))
            }
            Err(hashes) => {
                let r = Round1Receiving {
                    hashes,
                    phantom: self.phantom,
                };
                Ok(rounds::OnFinalize::NotFinished(r))
            }
        }
    }
}
