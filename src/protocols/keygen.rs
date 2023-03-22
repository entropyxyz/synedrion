//! ECDSA key generation (Fig. 5).

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::common::{SchemeParams, SessionId};
use super::generic::{BroadcastRound, NeedsConsensus, Round, ToSendTyped};
use crate::sigma::sch::{SchCommitment, SchProof, SchSecret};
use crate::tools::collections::{HoleVec, PartyIdx};
use crate::tools::group::{NonZeroScalar, Point, Scalar};
use crate::tools::hashing::{Chain, Hash};
use crate::tools::random::random_bits;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullData {
    // TODO: include SchemeParams here?
    session_id: SessionId,
    party_idx: PartyIdx,       // i
    rid: Box<[u8]>,            // rid_i
    public: Point,             // X_i
    commitment: SchCommitment, // A_i
    u: Box<[u8]>,              // u_i
}

impl FullData {
    fn hash(&self) -> Scalar {
        Hash::new_with_dst(b"Keygen")
            .chain(&self.session_id)
            .chain(&self.party_idx)
            .chain(&self.rid)
            .chain(&self.public)
            .chain(&self.commitment)
            .chain(&self.u)
            .finalize_to_scalar()
    }
}

#[derive(Clone)]
struct SecretData {
    key_share: NonZeroScalar,
    sch_secret: SchSecret,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Round1Bcast {
    hash: Scalar,
}

#[derive(Clone)]
pub(crate) struct Round1<P: SchemeParams> {
    secret_data: SecretData,
    data: FullData,
    phantom: PhantomData<P>,
}

impl<P: SchemeParams> Round1<P> {
    pub fn new(
        rng: &mut (impl RngCore + CryptoRng),
        session_id: &SessionId,
        party_idx: PartyIdx,
    ) -> Self {
        let secret = NonZeroScalar::random(rng);
        let public = &Point::GENERATOR * &secret;

        let rid = random_bits(P::SECURITY_PARAMETER);
        let proof_secret = SchSecret::random(rng);
        let commitment = SchCommitment::new(&proof_secret);
        let u = random_bits(P::SECURITY_PARAMETER);

        let data = FullData {
            session_id: session_id.clone(),
            party_idx,
            rid,
            public,
            commitment,
            u,
        };

        let secret_data = SecretData {
            key_share: secret,
            sch_secret: proof_secret,
        };

        Self {
            secret_data,
            data,
            phantom: PhantomData,
        }
    }
}

impl<P: SchemeParams> Round for Round1<P> {
    type Error = String;
    type Payload = Scalar;
    type Message = Round1Bcast;
    type NextRound = Round2<P>;

    fn to_send(&self, _rng: &mut (impl RngCore + CryptoRng)) -> ToSendTyped<Self::Message> {
        let hash = self.data.hash();
        ToSendTyped::Broadcast(Round1Bcast { hash })
    }
    fn verify_received(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        Ok(msg.hash)
    }
    fn finalize(self, payloads: HoleVec<Self::Payload>) -> Self::NextRound {
        Round2 {
            hashes: payloads,
            data: self.data,
            secret_data: self.secret_data,
            phantom: PhantomData,
        }
    }
}

impl<P: SchemeParams> BroadcastRound for Round1<P> {}

impl<P: SchemeParams> NeedsConsensus for Round1<P> {}

#[derive(Clone)]
pub struct Round2<P: SchemeParams> {
    secret_data: SecretData,
    data: FullData,
    hashes: HoleVec<Scalar>, // V_j
    phantom: PhantomData<P>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round2Bcast {
    data: FullData,
}

impl<P: SchemeParams> Round for Round2<P> {
    type Error = String;
    type Payload = FullData;
    type Message = Round2Bcast;
    type NextRound = Round3<P>;

    fn to_send(&self, _rng: &mut (impl RngCore + CryptoRng)) -> ToSendTyped<Self::Message> {
        ToSendTyped::Broadcast(Round2Bcast {
            data: self.data.clone(),
        })
    }
    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        if &msg.data.hash() != self.hashes.get(from).unwrap() {
            return Err("Invalid hash".to_string());
        }

        Ok(msg.data)
    }
    fn finalize(self, payloads: HoleVec<Self::Payload>) -> Self::NextRound {
        // XOR the vectors together
        // TODO: is there a better way?
        let mut rid = self.data.rid.clone();
        for data in payloads.iter() {
            for (i, x) in data.rid.iter().enumerate() {
                rid[i] ^= x;
            }
        }

        Round3 {
            datas: payloads,
            data: self.data,
            rid,
            secret_data: self.secret_data,
            phantom: PhantomData,
        }
    }
}

impl<P: SchemeParams> BroadcastRound for Round2<P> {}

#[derive(Clone)]
pub struct Round3<P: SchemeParams> {
    datas: HoleVec<FullData>,
    data: FullData,
    rid: Box<[u8]>,
    secret_data: SecretData,
    phantom: PhantomData<P>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round3Bcast {
    proof: SchProof,
}

impl<P: SchemeParams> Round for Round3<P> {
    type Error = String;
    type Payload = bool;
    type Message = Round3Bcast;
    type NextRound = KeyShare;

    fn to_send(&self, _rng: &mut (impl RngCore + CryptoRng)) -> ToSendTyped<Self::Message> {
        let aux = (&self.data.session_id, &self.data.party_idx, &self.rid);
        let proof = SchProof::new(
            &self.secret_data.sch_secret,
            &self.secret_data.key_share.clone().into_scalar(),
            &self.data.commitment,
            &self.data.public,
            &aux,
        );
        ToSendTyped::Broadcast(Round3Bcast { proof })
    }
    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        let party_data = self.datas.get(from).unwrap();

        let aux = (&party_data.session_id, &party_data.party_idx, &self.rid);
        if !msg
            .proof
            .verify(&party_data.commitment, &party_data.public, &aux)
        {
            return Err("Schnorr verification failed".to_string());
        }
        Ok(true)
    }
    fn finalize(self, _payloads: HoleVec<Self::Payload>) -> Self::NextRound {
        let datas = self.datas.into_vec(self.data);
        let public_keys = datas.into_iter().map(|data| data.public).collect();
        KeyShare {
            rid: self.rid,
            public: public_keys,
            secret: self.secret_data.key_share,
        }
    }
}

impl<P: SchemeParams> BroadcastRound for Round3<P> {}

#[derive(Clone)]
pub struct KeyShare {
    pub rid: Box<[u8]>,
    pub public: Vec<Point>,
    pub secret: NonZeroScalar,
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use rand_core::OsRng;

    use super::*;
    use crate::protocols::common::TestSchemeParams;
    use crate::protocols::generic::tests::step;

    #[test]
    fn execute_keygen() {
        let session_id = SessionId::random();

        let r1 = vec![
            Round1::<TestSchemeParams>::new(&mut OsRng, &session_id, PartyIdx::from_usize(0)),
            Round1::<TestSchemeParams>::new(&mut OsRng, &session_id, PartyIdx::from_usize(1)),
            Round1::<TestSchemeParams>::new(&mut OsRng, &session_id, PartyIdx::from_usize(2)),
        ];

        let r2 = step(&mut OsRng, r1).unwrap();
        let r3 = step(&mut OsRng, r2).unwrap();
        let shares = step(&mut OsRng, r3).unwrap();

        // Check that the sets of public keys are the same at each node

        let public_sets = shares.iter().map(|s| s.public.clone()).collect::<Vec<_>>();

        assert!(public_sets[1..].iter().all(|pk| pk == &public_sets[0]));

        // Check that the public keys correspond to the secret key shares
        let public_set = &public_sets[0];

        let public_from_secret = shares
            .iter()
            .map(|s| &Point::GENERATOR * &s.secret)
            .collect::<Vec<_>>();

        assert!(public_set == &public_from_secret);
    }
}
