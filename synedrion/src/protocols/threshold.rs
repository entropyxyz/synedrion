use alloc::boxed::Box;
use alloc::vec::Vec;

use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use super::common::{KeyShare, PartyIdx, PublicAuxInfo, SecretAuxInfo};
use crate::curve::{Point, Scalar};
use crate::sigma::params::SchemeParams;
use crate::tools::sss::{interpolation_coeff, shamir_evaluation_points};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SecretAuxInfo<P>: Serialize,
        PublicAuxInfo<P>: Serialize"))]
#[serde(bound(deserialize = "SecretAuxInfo<P>: for <'x> Deserialize<'x>,
        PublicAuxInfo<P>: for <'x> Deserialize<'x>"))]
pub struct ThresholdKeyShare<P: SchemeParams> {
    pub(crate) index: PartyIdx,
    pub(crate) threshold: u32, // TODO: make typed? Can it be `ShareIdx`?
    pub(crate) secret_share: Scalar,
    pub(crate) public_shares: Box<[Point]>,
    pub(crate) secret_aux: SecretAuxInfo<P>,
    pub(crate) public_aux: Box<[PublicAuxInfo<P>]>,
}

impl<P: SchemeParams> ThresholdKeyShare<P> {
    pub(crate) fn verifying_key_as_point(&self) -> Point {
        let points = shamir_evaluation_points(self.num_parties());
        self.public_shares[0..self.threshold as usize]
            .iter()
            .enumerate()
            .map(|(idx, p)| p * &interpolation_coeff(&points[0..self.threshold as usize], idx))
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
        self.public_shares.len()
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
        let secret_share = self.secret_share * interpolation_coeff(&points, mapped_idx);
        let public_shares = party_idxs
            .iter()
            .enumerate()
            .map(|(mapped_idx, idx)| {
                &self.public_shares[idx.as_usize()] * &interpolation_coeff(&points, mapped_idx)
            })
            .collect();

        KeyShare {
            index: PartyIdx::from_usize(mapped_idx),
            secret_share,
            public_shares,
            secret_aux: self.secret_aux.clone(),
            public_aux: self.public_aux.clone(),
        }
    }
}
