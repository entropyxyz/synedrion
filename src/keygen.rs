use crate::collections::{HoleVec, OnInsert};
use crate::rounds;
use crate::sigma::schnorr::{SchnorrCommitment, SchnorrProof, SchnorrProofSecret};
/// ECDSA key generation (Fig. 5).
use crate::tools::group::{NonZeroScalar, Point, Scalar};
use crate::tools::hashing::{Hash, Hashable};
use crate::tools::random::random_bits;

/// $\mathcal{P}_i$.
// Eventually this will be a node's public key which can be used as an address to send messages to.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PartyId(usize);

impl Hashable for PartyId {
    fn chain(&self, digest: Hash) -> Hash {
        digest.chain(&self.0)
    }
}

type PartyNum = usize;

/// $sid$ in the paper, probably better called "scheme setup"
#[derive(Clone, Debug)]
pub struct Sid {
    // `G`, `q`, and `g` (curve group, order, and the generator) are hardcoded,
    // so we're not saving them here.

    // TODO: should it be all parties, or only other parties (excluding the ones it's sent to?)
    // TODO: use BTreeSet instead (it is ordered)?
    // Or check that PartyIds are distinct on construction?
    // $\bm{P}$
    parties: Vec<PartyId>,

    /// Security parameter: `kappa = log2(curve order)`
    kappa: usize,
}

impl Hashable for Sid {
    fn chain(&self, digest: Hash) -> Hash {
        let mut digest = digest;

        digest = digest.chain(&self.parties.len());
        for party_id in self.parties.iter() {
            digest = digest.chain(party_id);
        }
        digest.chain(&self.kappa)
    }
}

#[derive(Debug, Clone)]
pub struct Round1Bcast {
    party_num: PartyNum,
    hash: Scalar,
}

pub struct Round1 {
    secret: NonZeroScalar,
    proof_secret: SchnorrProofSecret,
    data: FullData,
}

impl Round1 {
    pub fn new(sid: &Sid, party_id: &PartyId) -> Self {
        let party_num = sid.parties.iter().position(|id| id == party_id).unwrap();

        let secret = NonZeroScalar::random();
        let public = &Point::GENERATOR * &secret;

        let rid = random_bits(sid.kappa);
        let proof_secret = SchnorrProofSecret::new();
        let commitment = proof_secret.commitment();
        let u = random_bits(sid.kappa);

        let data = FullData {
            sid: sid.clone(),
            party_num,
            rid,
            public,
            commitment,
            u,
        };

        Self {
            secret,
            proof_secret,
            data,
        }
    }
}

impl rounds::RoundStart for Round1 {
    type Id = PartyId;
    type Error = String;
    type DirectMessage = ();
    type BroadcastMessage = Round1Bcast;
    type ReceivingState = Round1Receiving;
    fn execute(
        &self,
    ) -> Result<
        (
            Self::ReceivingState,
            Vec<(PartyId, Self::DirectMessage)>,
            Self::BroadcastMessage,
        ),
        Self::Error,
    > {
        let hash = self.data.hash();
        let bcast = Round1Bcast {
            party_num: self.data.party_num,
            hash: hash.clone(),
        };
        let dms = Vec::new();
        let mut hashes = HoleVec::new(self.data.sid.parties.len());
        hashes.try_insert(self.data.party_num, hash);

        Ok((Round1Receiving { hashes }, dms, bcast))
    }
}

#[derive(Debug, Clone)]
struct FullData {
    sid: Sid,
    party_num: usize,              // i
    rid: Vec<u8>,                  // rid_i
    public: Point,                 // X_i
    commitment: SchnorrCommitment, // A_i
    u: Vec<u8>,                    // u_i
}

impl FullData {
    fn hash(&self) -> Scalar {
        Hash::new_with_dst(b"Keygen")
            .chain(&self.sid)
            .chain(&self.party_num)
            .chain(&self.rid)
            .chain(&self.public)
            .chain(&self.commitment)
            .chain(&self.u)
            .finalize_to_scalar()
    }
}

pub struct Round1Receiving {
    hashes: HoleVec<Scalar>, // V_j
}

impl rounds::RoundReceiving for Round1Receiving {
    type NextState = Round2;
    type DirectMessage = ();
    type BroadcastMessage = Round1Bcast;
    type Error = String;
    type Round = Round1;

    fn receive_bcast(
        &mut self,
        _round: &Self::Round,
        msg: &Self::BroadcastMessage,
    ) -> rounds::OnReceive<Self::Error> {
        // TODO: check that msg.sid == self.sid
        match self.hashes.try_insert(msg.party_num, msg.hash) {
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
                let r = Round2 {
                    data: round.data,
                    secret: round.secret,
                    proof_secret: round.proof_secret,
                    hashes,
                };
                Ok(rounds::OnFinalize::Finished(r))
            }
            Err(hashes) => {
                let r = Round1Receiving { hashes };
                Ok(rounds::OnFinalize::NotFinished(r))
            }
        }
    }
}

pub struct Round2 {
    secret: NonZeroScalar,
    proof_secret: SchnorrProofSecret,
    data: FullData,
    hashes: Vec<Scalar>, // V_j
}

pub struct Round2Bcast {
    data: FullData,
}

impl rounds::RoundStart for Round2 {
    type Id = PartyId;
    type Error = String;
    type DirectMessage = ();
    type BroadcastMessage = Round2Bcast;
    type ReceivingState = Round2Receiving;
    fn execute(
        &self,
    ) -> Result<
        (
            Self::ReceivingState,
            Vec<(PartyId, Self::DirectMessage)>,
            Self::BroadcastMessage,
        ),
        Self::Error,
    > {
        let bcast = Round2Bcast {
            data: self.data.clone(),
        };
        let dms = Vec::new();

        let num_parties = self.data.sid.parties.len();
        let mut datas = HoleVec::new(num_parties);
        datas.try_insert(self.data.party_num, self.data.clone());

        Ok((Round2Receiving { datas }, dms, bcast))
    }
}

pub struct Round2Receiving {
    datas: HoleVec<FullData>,
}

impl rounds::RoundReceiving for Round2Receiving {
    type NextState = Round3;
    type DirectMessage = ();
    type BroadcastMessage = Round2Bcast;
    type Error = String;
    type Round = Round2;

    fn receive_bcast(
        &mut self,
        round: &Self::Round,
        msg: &Self::BroadcastMessage,
    ) -> rounds::OnReceive<Self::Error> {
        // TODO: check that msg.sid == self.sid

        // TODO: check that index is in range
        if msg.data.hash() != round.hashes[msg.data.party_num] {
            return rounds::OnReceive::NonFatal("Invalid hash".to_string());
        }

        match self.datas.try_insert(msg.data.party_num, msg.data.clone()) {
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
        let datas = match self.datas.try_finalize() {
            Ok(datas) => datas,
            Err(datas) => {
                let r = Round2Receiving { datas };
                return Ok(rounds::OnFinalize::NotFinished(r));
            }
        };

        // XOR the vectors together
        // TODO: is there a better way?
        let mut rid = datas[0].rid.clone();
        for data in &datas[1..] {
            for (i, x) in data.rid.iter().enumerate() {
                rid[i] ^= x;
            }
        }

        let aux = (&round.data.sid, round.data.party_num, &round.data.rid);
        let proof = SchnorrProof::new(&round.proof_secret, &round.secret, &aux);

        Ok(rounds::OnFinalize::Finished(Round3 {
            datas,
            data: round.data,
            secret: round.secret,
            proof,
        }))
    }
}

pub struct Round3 {
    datas: Vec<FullData>,
    data: FullData, // TODO: duplicate of what we already have in `datas`
    secret: NonZeroScalar,
    proof: SchnorrProof,
}

pub struct Round3Bcast {
    party_num: usize,
    proof: SchnorrProof,
}

impl rounds::RoundStart for Round3 {
    type Id = PartyId;
    type Error = String;
    type DirectMessage = ();
    type BroadcastMessage = Round3Bcast;
    type ReceivingState = Round3Receiving;
    fn execute(
        &self,
    ) -> Result<
        (
            Self::ReceivingState,
            Vec<(PartyId, Self::DirectMessage)>,
            Self::BroadcastMessage,
        ),
        Self::Error,
    > {
        let mut parties_verified = vec![false; self.data.sid.parties.len()];
        parties_verified[self.data.party_num] = true;
        Ok((
            Round3Receiving { parties_verified },
            Vec::new(),
            Round3Bcast {
                party_num: self.data.party_num,
                proof: self.proof.clone(),
            },
        ))
    }
}

pub struct Round3Receiving {
    parties_verified: Vec<bool>,
}

impl rounds::RoundReceiving for Round3Receiving {
    type NextState = KeyShare;
    type DirectMessage = ();
    type BroadcastMessage = Round3Bcast;
    type Error = String;
    type Round = Round3;

    fn receive_bcast(
        &mut self,
        round: &Self::Round,
        msg: &Self::BroadcastMessage,
    ) -> rounds::OnReceive<Self::Error> {
        let party_data = &round.datas[msg.party_num];

        let aux = (&party_data.sid, party_data.party_num, &party_data.rid);
        if !msg
            .proof
            .verify(&party_data.commitment, &party_data.public, &aux)
        {
            return rounds::OnReceive::NonFatal("Schnorr verification failed".to_string());
        }

        self.parties_verified[msg.party_num] = true;

        rounds::OnReceive::Ok
    }

    fn try_finalize(
        self,
        round: Self::Round,
    ) -> Result<rounds::OnFinalize<Self, Self::NextState>, Self::Error> {
        if self.parties_verified.iter().all(|x| *x) {
            Ok(rounds::OnFinalize::Finished(KeyShare {
                rid: round.data.rid,
                public: round
                    .datas
                    .into_iter()
                    .map(|data| data.public)
                    .collect::<Vec<_>>(),
                secret: round.secret,
            }))
        } else {
            Ok(rounds::OnFinalize::NotFinished(self))
        }
    }
}

pub struct KeyShare {
    pub rid: Vec<u8>,
    pub public: Vec<Point>,
    pub secret: NonZeroScalar,
}

#[cfg(test)]
mod tests {

    use alloc::collections::BTreeMap;

    use crate::rounds::tests::step;

    use super::*;

    #[test]
    fn execute_keygen() {
        let parties = [PartyId(111), PartyId(222), PartyId(333)];

        let sid = Sid {
            parties: parties.clone().to_vec(),
            kappa: 256,
        };

        let r1 = BTreeMap::from([
            (parties[0].clone(), Round1::new(&sid, &parties[0])),
            (parties[1].clone(), Round1::new(&sid, &parties[1])),
            (parties[2].clone(), Round1::new(&sid, &parties[2])),
        ]);

        let r2 = step(r1).unwrap();
        let r3 = step(r2).unwrap();
        let shares = step(r3).unwrap();

        // Check that the sets of public keys are the same at each node

        let public_sets = shares
            .iter()
            .map(|(_id, s)| s.public.clone())
            .collect::<Vec<_>>();

        assert!(public_sets[1..].iter().all(|pk| pk == &public_sets[0]));

        // Check that the public keys correspond to the secret key shares
        let public_set = &public_sets[0];

        let public_from_secret = shares
            .iter()
            .map(|(_id, s)| &Point::GENERATOR * &s.secret)
            .collect::<Vec<_>>();

        assert!(public_set == &public_from_secret);
    }
}
