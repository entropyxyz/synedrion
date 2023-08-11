use alloc::boxed::Box;
use alloc::vec::Vec;

use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use super::common::{KeyShare, KeySharePublic, KeyShareSecret, PartyIdx};
use crate::curve::Point;
use crate::tools::sss::{interpolation_coeff, shamir_evaluation_points};
use crate::SchemeParams;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "KeyShareSecret<P>: Serialize,
        KeySharePublic<P>: Serialize"))]
#[serde(bound(deserialize = "KeyShareSecret<P>: for <'x> Deserialize<'x>,
        KeySharePublic<P>: for <'x> Deserialize<'x>"))]
pub struct ThresholdKeyShare<P: SchemeParams> {
    pub(crate) index: PartyIdx,
    pub(crate) threshold: u32, // TODO: make typed? Can it be `ShareIdx`?
    pub(crate) secret: KeyShareSecret<P>,
    pub(crate) public: Box<[KeySharePublic<P>]>,
}

impl<P: SchemeParams> ThresholdKeyShare<P> {
    pub(crate) fn verifying_key_as_point(&self) -> Point {
        let points = shamir_evaluation_points(self.num_parties());
        self.public[0..self.threshold as usize]
            .iter()
            .enumerate()
            .map(|(idx, p)| &p.x * &interpolation_coeff(&points[0..self.threshold as usize], idx))
            .sum()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO: need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
    }

    pub fn num_parties(&self) -> usize {
        // TODO: technically it is `num_shares`, but for now we are equating the two,
        // since we assume that one party has one share.
        self.public.len()
    }

    pub fn party_index(&self) -> PartyIdx {
        // TODO: technically it is the share index, but for now we are equating the two,
        // since we assume that one party has one share.
        self.index
    }

    /// Converts a t-of-n key share into a t-of-t key share
    /// (for the `t` parties supplied as `party_idxs`)
    /// that can be used in the presigning/signing protocols.
    pub fn to_key_share(&self, party_idxs: &[PartyIdx]) -> KeyShare<P> {
        debug_assert!(party_idxs.len() == self.threshold as usize);
        // TODO: assert that all indices are distinct
        let mapped_idx = party_idxs
            .iter()
            .position(|idx| idx == &self.index)
            .unwrap();

        let all_points = shamir_evaluation_points(self.num_parties());
        let points = party_idxs
            .iter()
            .map(|idx| all_points[idx.as_usize()])
            .collect::<Vec<_>>();

        // TODO: make the rescaling a method of KeyShareSecret?
        let secret = KeyShareSecret {
            secret: self.secret.secret * interpolation_coeff(&points, mapped_idx),
            paillier_sk: self.secret.paillier_sk.clone(),
            el_gamal_sk: self.secret.el_gamal_sk,
        };

        let public = party_idxs
            .iter()
            .enumerate()
            .map(|(mapped_idx, idx)| {
                let public = &self.public[idx.as_usize()];
                KeySharePublic {
                    x: &public.x * &interpolation_coeff(&points, mapped_idx),
                    el_gamal_pk: public.el_gamal_pk,
                    paillier_pk: public.paillier_pk.clone(),
                    rp_generator: public.rp_generator,
                    rp_power: public.rp_power,
                }
            })
            .collect();

        KeyShare {
            index: PartyIdx::from_usize(mapped_idx),
            secret,
            public,
        }
    }
}
