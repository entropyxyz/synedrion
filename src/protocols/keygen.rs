//! ECDSA key generation (Fig. 5).

use alloc::collections::BTreeMap;

use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use super::rounds;
use crate::sigma::sch::{SchCommitment, SchProof, SchSecret};
use crate::tools::group::{NonZeroScalar, Point, Scalar};
use crate::tools::hashing::{Chain, Hash, Hashable};
use crate::tools::random::random_bits;

/// $\mathcal{P}_i$.
// Eventually this will be a node's public key which can be used as an address to send messages to.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PartyId(pub(crate) u32);

impl Hashable for PartyId {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.0)
    }
}

/// $sid$ ("session ID") in the paper
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    // `G`, `q`, and `g` (curve group, order, and the generator) are hardcoded,
    // so we're not saving them here.

    // TODO: should it be all parties, or only other parties (excluding the ones it's sent to?)
    // TODO: use BTreeSet instead (it is ordered)?
    // Or check that PartyIds are distinct on construction?
    // $\bm{P}$
    pub(crate) parties: Vec<PartyId>,

    /// Security parameter: `kappa = log2(curve order)`
    pub(crate) kappa: usize,
}

impl SessionInfo {
    pub fn other_parties(&self, id: &PartyId) -> Vec<PartyId> {
        self.parties
            .iter()
            .cloned()
            .filter(|pid| pid != id)
            .collect()
    }
}

impl Hashable for SessionInfo {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.parties).chain(&(self.kappa as u32))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullData {
    session_info: SessionInfo,
    party_id: PartyId,         // i
    rid: Box<[u8]>,            // rid_i
    public: Point,             // X_i
    commitment: SchCommitment, // A_i
    u: Box<[u8]>,              // u_i
}

impl FullData {
    fn hash(&self) -> Scalar {
        Hash::new_with_dst(b"Keygen")
            .chain(&self.session_info)
            .chain(&self.party_id)
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
pub struct Round1 {
    other_parties: Vec<PartyId>,
    secret_data: SecretData,
    data: FullData,
}

impl Round1 {
    pub fn new(session_info: &SessionInfo, party_id: &PartyId) -> Self {
        let secret = NonZeroScalar::random(&mut OsRng);
        let public = &Point::GENERATOR * &secret;

        let rid = random_bits(session_info.kappa);
        let proof_secret = SchSecret::random(&mut OsRng);
        let commitment = SchCommitment::new(&proof_secret);
        let u = random_bits(session_info.kappa);

        let other_parties = session_info.other_parties(party_id);

        let data = FullData {
            session_info: session_info.clone(),
            party_id: party_id.clone(),
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
            other_parties,
            secret_data,
            data,
        }
    }
}

impl rounds::Round for Round1 {
    type Id = PartyId;
    type Error = String;
    type Payload = Scalar;
    type Message = Round1Bcast;
    type NextRound = Round2;

    fn to_send(&self) -> rounds::ToSend<Self::Id, Self::Message> {
        let hash = self.data.hash();
        rounds::ToSend::Broadcast {
            ids: self.other_parties.clone(),
            message: Round1Bcast { hash },
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
            hashes: payloads,
            data: self.data,
            secret_data: self.secret_data,
        }
    }
}

#[derive(Clone)]
pub struct Round2 {
    secret_data: SecretData,
    data: FullData,
    hashes: BTreeMap<PartyId, Scalar>, // V_j
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Round2Bcast {
    data: FullData,
}

impl rounds::Round for Round2 {
    type Id = PartyId;
    type Error = String;
    type Payload = FullData;
    type Message = Round2Bcast;
    type NextRound = Round3;

    fn to_send(&self) -> rounds::ToSend<Self::Id, Self::Message> {
        rounds::ToSend::Broadcast {
            ids: self.hashes.keys().cloned().collect(),
            message: Round2Bcast {
                data: self.data.clone(),
            },
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

        Ok(msg.data)
    }
    fn finalize(self, payloads: BTreeMap<Self::Id, Self::Payload>) -> Self::NextRound {
        // XOR the vectors together
        // TODO: is there a better way?
        let mut rid = self.data.rid.clone();
        for (_party_id, data) in payloads.iter() {
            for (i, x) in data.rid.iter().enumerate() {
                rid[i] ^= x;
            }
        }

        Round3 {
            datas: payloads,
            data: self.data,
            rid,
            secret_data: self.secret_data,
        }
    }
}

pub struct Round3 {
    datas: BTreeMap<PartyId, FullData>,
    data: FullData,
    rid: Box<[u8]>,
    secret_data: SecretData,
}

#[derive(Clone)]
pub struct Round3Bcast {
    proof: SchProof,
}

impl rounds::Round for Round3 {
    type Id = PartyId;
    type Error = String;
    type Payload = bool;
    type Message = Round3Bcast;
    type NextRound = KeyShare;

    fn to_send(&self) -> rounds::ToSend<Self::Id, Self::Message> {
        let aux = (&self.data.session_info, &self.data.party_id, &self.rid);
        let proof = SchProof::new(
            &self.secret_data.sch_secret,
            &self.secret_data.key_share.clone().into_scalar(),
            &self.data.commitment,
            &self.data.public,
            &aux,
        );
        rounds::ToSend::Broadcast {
            ids: self.datas.keys().cloned().collect(),
            message: Round3Bcast { proof },
            needs_consensus: false,
        }
    }
    fn verify_received(
        &self,
        from: &Self::Id,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        let party_data = self.datas.get(from).unwrap();

        let aux = (&party_data.session_info, &party_data.party_id, &self.rid);
        if !msg
            .proof
            .verify(&party_data.commitment, &party_data.public, &aux)
        {
            return Err("Schnorr verification failed".to_string());
        }
        Ok(true)
    }
    fn finalize(self, _payloads: BTreeMap<Self::Id, Self::Payload>) -> Self::NextRound {
        let mut public_keys: BTreeMap<Self::Id, Point> = self
            .datas
            .into_iter()
            .map(|(party_id, data)| (party_id, data.public))
            .collect();
        public_keys.insert(self.data.party_id, self.data.public);
        KeyShare {
            rid: self.rid,
            public: public_keys,
            secret: self.secret_data.key_share,
        }
    }
}

pub struct KeyShare {
    pub rid: Box<[u8]>,
    pub public: BTreeMap<PartyId, Point>,
    pub secret: NonZeroScalar,
}

#[cfg(test)]
mod tests {

    use alloc::collections::BTreeMap;

    use crate::protocols::rounds::tests::step;

    use super::*;

    #[test]
    fn execute_keygen() {
        let parties = [PartyId(111), PartyId(222), PartyId(333)];

        let session_info = SessionInfo {
            parties: parties.to_vec(),
            kappa: 256,
        };

        let r1 = BTreeMap::from([
            (parties[0].clone(), Round1::new(&session_info, &parties[0])),
            (parties[1].clone(), Round1::new(&session_info, &parties[1])),
            (parties[2].clone(), Round1::new(&session_info, &parties[2])),
        ]);

        let r2 = step(r1).unwrap();
        let r3 = step(r2).unwrap();
        let shares = step(r3).unwrap();

        // Check that the sets of public keys are the same at each node

        let public_sets = shares
            .values()
            .map(|s| s.public.clone())
            .collect::<Vec<_>>();

        assert!(public_sets[1..].iter().all(|pk| pk == &public_sets[0]));

        // Check that the public keys correspond to the secret key shares
        let public_set = &public_sets[0];

        let public_from_secret = shares
            .into_iter()
            .map(|(id, s)| (id, &Point::GENERATOR * &s.secret))
            .collect::<BTreeMap<_, _>>();

        assert!(public_set == &public_from_secret);
    }
}
