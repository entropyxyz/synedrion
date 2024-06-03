use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::marker::PhantomData;

#[cfg(test)]
use alloc::vec::Vec;

use k256::ecdsa::VerifyingKey;
use rand_core::CryptoRngCore;

use crate::curve::{Point, Scalar};
use crate::rounds::PartyIdx;
use crate::tools::sss::{shamir_evaluation_points, shamir_join_points, shamir_split, ShareId};
use crate::SchemeParams;

#[cfg(test)]
use crate::{cggmp21::KeyShare, tools::sss::interpolation_coeff};

#[derive(Clone)]
pub struct ThresholdKeyShare<P: SchemeParams> {
    pub(crate) index: PartyIdx,
    pub(crate) threshold: u32,
    pub(crate) secret_share: Scalar,
    pub(crate) share_ids: BTreeMap<PartyIdx, ShareId>,
    pub(crate) public_shares: BTreeMap<PartyIdx, Point>,
    // TODO (#27): this won't be needed when Scalar/Point are a part of `P`
    pub(crate) phantom: PhantomData<P>,
}

impl<P: SchemeParams> ThresholdKeyShare<P> {
    pub fn share_index(&self) -> ShareId {
        self.share_ids[&self.index]
    }

    pub fn threshold(&self) -> usize {
        self.threshold as usize
    }

    pub fn secret(&self) -> Scalar {
        self.secret_share
    }

    pub fn new_centralized(
        rng: &mut impl CryptoRngCore,
        threshold: usize,
        num_parties: usize,
        signing_key: Option<&k256::ecdsa::SigningKey>,
    ) -> Box<[Self]> {
        debug_assert!(threshold <= num_parties); // TODO (#68): make the method fallible

        let secret = match signing_key {
            None => Scalar::random(rng),
            Some(sk) => Scalar::from(sk.as_nonzero_scalar()),
        };

        let share_ids = shamir_evaluation_points(num_parties);
        let secret_shares = shamir_split(rng, &secret, threshold, &share_ids);
        let public_shares = share_ids
            .iter()
            .enumerate()
            .map(|(idx, share_id)| {
                (
                    PartyIdx::from_usize(idx),
                    secret_shares[share_id].mul_by_generator(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let share_ids = share_ids
            .iter()
            .enumerate()
            .map(|(idx, share_id)| (PartyIdx::from_usize(idx), *share_id))
            .collect::<BTreeMap<_, _>>();

        (0..num_parties)
            .map(|idx| Self {
                index: PartyIdx::from_usize(idx),
                threshold: threshold as u32,
                secret_share: secret_shares[&share_ids[&PartyIdx::from_usize(idx)]],
                share_ids: share_ids.clone(),
                public_shares: public_shares.clone(),
                phantom: PhantomData,
            })
            .collect()
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point {
        shamir_join_points(
            self.share_ids
                .iter()
                .map(|(party_idx, share_id)| (share_id, &self.public_shares[party_idx]))
                .take(self.threshold as usize),
        )
    }

    /// Return the verifying key to which this set of shares corresponds.
    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO (#5): need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
    }

    /// Converts a t-of-n key share into a t-of-t key share
    /// (for the `t` share indices supplied as `share_ids`)
    /// that can be used in the presigning/signing protocols.
    #[cfg(test)]
    pub fn to_key_share(&self, party_idxs: &[PartyIdx]) -> KeyShare<P> {
        debug_assert!(party_idxs.len() == self.threshold as usize);
        debug_assert!(party_idxs.iter().any(|idx| idx == &self.index));
        // TODO (#68): assert that all indices are distinct

        let share_id = self.share_ids[&self.index];
        let share_ids = party_idxs
            .iter()
            .map(|idx| self.share_ids[idx])
            .collect::<Vec<_>>();

        let secret_share = self.secret_share * interpolation_coeff(&share_ids, &share_id);
        let public_shares = party_idxs
            .iter()
            .map(|party_idx| {
                self.public_shares[party_idx]
                    * interpolation_coeff(&share_ids, &self.share_ids[party_idx])
            })
            .collect();

        KeyShare {
            index: self.index,
            secret_share,
            public_shares,
            phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;

    use super::ThresholdKeyShare;
    use crate::curve::Scalar;
    use crate::rounds::PartyIdx;
    use crate::TestParams;

    #[test]
    fn threshold_key_share_centralized() {
        let sk = SigningKey::random(&mut OsRng);
        let shares = ThresholdKeyShare::<TestParams>::new_centralized(&mut OsRng, 2, 3, Some(&sk));

        assert_eq!(&shares[0].verifying_key(), sk.verifying_key());
        assert_eq!(&shares[1].verifying_key(), sk.verifying_key());
        assert_eq!(&shares[2].verifying_key(), sk.verifying_key());

        assert_eq!(&shares[0].verifying_key(), sk.verifying_key());

        let party_idxs = [PartyIdx::from_usize(2), PartyIdx::from_usize(0)];
        let nt_share0 = shares[0].to_key_share(&party_idxs);
        let nt_share1 = shares[2].to_key_share(&party_idxs);

        assert_eq!(
            nt_share0.secret_share + nt_share1.secret_share,
            Scalar::from(sk.as_nonzero_scalar())
        );
        assert_eq!(&nt_share0.verifying_key(), sk.verifying_key());
        assert_eq!(&nt_share1.verifying_key(), sk.verifying_key());
    }
}
