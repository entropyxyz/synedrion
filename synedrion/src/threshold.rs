use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::marker::PhantomData;

use k256::ecdsa::VerifyingKey;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::cggmp21::SchemeParams;
use crate::common::{make_aux_info, KeyShare, PublicAuxInfo, SecretAuxInfo};
use crate::curve::{Point, Scalar};
use crate::rounds::PartyIdx;
use crate::tools::sss::{
    interpolation_coeff, shamir_evaluation_points, shamir_join_points, shamir_split, ShareIdx,
};

#[derive(Clone)]
pub struct ThresholdKeyShareSeed<P: SchemeParams> {
    pub(crate) index: PartyIdx,
    pub(crate) threshold: u32,
    pub(crate) secret_share: Scalar,
    pub(crate) holders: BTreeMap<PartyIdx, ShareIdx>,
    pub(crate) public_shares: BTreeMap<PartyIdx, Point>,
    pub(crate) phantom: PhantomData<P>,
}

impl<P: SchemeParams> ThresholdKeyShareSeed<P> {
    pub fn share_index(&self) -> ShareIdx {
        self.holders[&self.index]
    }

    pub fn threshold(&self) -> usize {
        self.threshold as usize
    }

    pub fn secret(&self) -> Scalar {
        self.secret_share
    }

    #[allow(dead_code)]
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

        let share_idxs = shamir_evaluation_points(num_parties);
        let secret_shares = shamir_split(rng, &secret, threshold, &share_idxs);
        let public_shares = share_idxs
            .iter()
            .enumerate()
            .map(|(idx, share_idx)| {
                (
                    PartyIdx::from_usize(idx),
                    secret_shares[share_idx].mul_by_generator(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let holders = share_idxs
            .iter()
            .enumerate()
            .map(|(idx, share_idx)| (PartyIdx::from_usize(idx), *share_idx))
            .collect::<BTreeMap<_, _>>();

        (0..num_parties)
            .map(|idx| Self {
                index: PartyIdx::from_usize(idx),
                threshold: threshold as u32,
                secret_share: secret_shares[&share_idxs[idx]],
                holders: holders.clone(),
                public_shares: public_shares.clone(),
                phantom: PhantomData,
            })
            .collect()
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point {
        shamir_join_points(
            self.holders
                .iter()
                .map(|(party_idx, share_idx)| (share_idx, &self.public_shares[party_idx]))
                .take(self.threshold as usize),
        )
    }

    /// Return the verifying key to which this set of shares corresponds.
    #[allow(dead_code)]
    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO (#5): need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
    }
}

/// A threshold variant of the key share, where any `threshold` shares our of the total number
/// is enough to perform signing.
// TODO (#77): Debug can be derived automatically here if `secret_share` is wrapped in its own struct,
// or in a `SecretBox`-type wrapper.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SecretAuxInfo<P>: Serialize,
        PublicAuxInfo<P>: Serialize"))]
#[serde(bound(deserialize = "SecretAuxInfo<P>: for <'x> Deserialize<'x>,
        PublicAuxInfo<P>: for <'x> Deserialize<'x>"))]
pub struct ThresholdKeyShare<P: SchemeParams> {
    pub(crate) index: PartyIdx,
    pub(crate) threshold: u32,
    pub(crate) secret_share: Scalar,
    pub(crate) holders: BTreeMap<PartyIdx, ShareIdx>,
    pub(crate) public_shares: BTreeMap<PartyIdx, Point>,
    pub(crate) secret_aux: SecretAuxInfo<P>,
    pub(crate) public_aux: BTreeMap<PartyIdx, PublicAuxInfo<P>>,
}

impl<P: SchemeParams> ThresholdKeyShare<P> {
    /// Returns `num_parties` of random self-consistent key shares
    /// (which in a decentralized case would be the output of KeyGen + Auxiliary protocols).
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

        let share_idxs = shamir_evaluation_points(num_parties);
        let secret_shares = shamir_split(rng, &secret, threshold, &share_idxs);
        let public_shares = share_idxs
            .iter()
            .enumerate()
            .map(|(idx, share_idx)| {
                (
                    PartyIdx::from_usize(idx),
                    secret_shares[share_idx].mul_by_generator(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let holders = share_idxs
            .iter()
            .enumerate()
            .map(|(idx, share_idx)| (PartyIdx::from_usize(idx), *share_idx))
            .collect::<BTreeMap<_, _>>();

        let (secret_aux, public_aux) = make_aux_info(rng, num_parties);

        let public_aux = public_aux
            .into_vec()
            .into_iter()
            .enumerate()
            .map(|(idx, public)| (PartyIdx::from_usize(idx), public))
            .collect::<BTreeMap<_, _>>();

        secret_aux
            .into_vec()
            .into_iter()
            .enumerate()
            .map(|(idx, secret_aux)| ThresholdKeyShare {
                index: PartyIdx::from_usize(idx),
                threshold: threshold as u32,
                secret_share: secret_shares[&share_idxs[idx]],
                holders: holders.clone(),
                public_shares: public_shares.clone(),
                secret_aux,
                public_aux: public_aux.clone(),
            })
            .collect()
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point {
        shamir_join_points(
            self.holders
                .iter()
                .map(|(party_idx, share_idx)| (share_idx, &self.public_shares[party_idx]))
                .take(self.threshold as usize),
        )
    }

    /// Return the verifying key to which this set of shares corresponds.
    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO (#5): need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
    }

    /// Returns the index of this share's party.
    pub fn share_index(&self) -> ShareIdx {
        self.holders[&self.index]
    }

    /// Converts a t-of-n key share into a t-of-t key share
    /// (for the `t` share indices supplied as `share_idxs`)
    /// that can be used in the presigning/signing protocols.
    pub fn to_key_share(&self, party_idxs: &[PartyIdx]) -> KeyShare<P> {
        debug_assert!(party_idxs.len() == self.threshold as usize);
        debug_assert!(party_idxs
            .iter()
            .position(|idx| idx == &self.index)
            .is_some());
        // TODO (#68): assert that all indices are distinct

        let share_idx = self.holders[&self.index];
        let share_idxs = party_idxs
            .iter()
            .map(|idx| self.holders[idx])
            .collect::<Vec<_>>();

        let secret_share = self.secret_share * interpolation_coeff(&share_idxs, &share_idx);
        let public_shares = party_idxs
            .iter()
            .map(|party_idx| {
                self.public_shares[party_idx]
                    * interpolation_coeff(&share_idxs, &self.holders[party_idx])
            })
            .collect();

        let public_aux = party_idxs
            .iter()
            .map(|idx| self.public_aux[idx].clone())
            .collect();

        KeyShare {
            index: self.index,
            secret_share,
            public_shares,
            secret_aux: self.secret_aux.clone(),
            public_aux,
        }
    }
}

// A custom Debug impl that skips the secret values
impl<P: SchemeParams + core::fmt::Debug> core::fmt::Debug for ThresholdKeyShare<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            concat![
                "KeyShare {{",
                "index: {:?}, ",
                "threshold: {:?} ",
                "secret_share: <...>, ",
                "public_shares: {:?}, ",
                "secret_aux: {:?}, ",
                "public_aux: {:?} ",
                "}}"
            ],
            self.index, self.threshold, self.public_shares, self.secret_aux, self.public_aux
        )
    }
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;

    use super::ThresholdKeyShare;
    use crate::cggmp21::TestParams;
    use crate::curve::Scalar;
    use crate::rounds::PartyIdx;

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
