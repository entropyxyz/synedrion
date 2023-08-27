use alloc::boxed::Box;
use alloc::vec::Vec;

use k256::ecdsa::VerifyingKey;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::{make_aux_info, KeyShare, PartyIdx, PublicAuxInfo, SecretAuxInfo};
use crate::cggmp21::SchemeParams;
use crate::curve::{Point, Scalar};
use crate::tools::sss::{interpolation_coeff, shamir_evaluation_points, shamir_split};

/// A threshold variant of the key share, where any `threshold` shares our of the total number
/// is enough to perform signing.
// TODO: Debug can be derived automatically here if `secret_share` is wrapped in its own struct,
// or in a `SecretBox`-type wrapper.
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
    /// Returns `num_parties` of random self-consistent key shares
    /// (which in a decentralized case would be the output of KeyGen + Auxiliary protocols).
    pub fn new_centralized(
        rng: &mut impl CryptoRngCore,
        threshold: usize,
        num_parties: usize,
        signing_key: Option<&k256::ecdsa::SigningKey>,
    ) -> Box<[Self]> {
        debug_assert!(threshold <= num_parties);

        let secret = match signing_key {
            None => Scalar::random(rng),
            Some(sk) => Scalar::from(sk.as_nonzero_scalar()),
        };

        let secret_shares = shamir_split(
            rng,
            &secret,
            threshold,
            &shamir_evaluation_points(num_parties),
        );
        let public_shares = secret_shares
            .iter()
            .map(|s| s.mul_by_generator())
            .collect::<Box<_>>();

        let (secret_aux, public_aux) = make_aux_info(rng, num_parties);

        secret_aux
            .into_vec()
            .into_iter()
            .enumerate()
            .map(|(idx, secret_aux)| ThresholdKeyShare {
                index: PartyIdx::from_usize(idx),
                threshold: threshold as u32, // TODO: fallible conversion?
                secret_share: secret_shares[idx],
                public_shares: public_shares.clone(),
                secret_aux,
                public_aux: public_aux.clone(),
            })
            .collect()
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point {
        let points = shamir_evaluation_points(self.num_parties());
        self.public_shares[0..self.threshold as usize]
            .iter()
            .enumerate()
            .map(|(idx, p)| p * &interpolation_coeff(&points[0..self.threshold as usize], idx))
            .sum()
    }

    /// Return the verifying key to which this set of shares corresponds.
    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO: need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
    }

    /// Returns the number of parties in this set of shares.
    pub fn num_parties(&self) -> usize {
        // TODO: technically it is `num_shares`, but for now we are equating the two,
        // since we assume that one party has one share.
        self.public_shares.len()
    }

    /// Returns the index of this share's party.
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
    use crate::curve::Scalar;
    use crate::{PartyIdx, TestParams};

    #[test]
    fn threshold_key_share_centralized() {
        let sk = SigningKey::random(&mut OsRng);
        let shares = ThresholdKeyShare::<TestParams>::new_centralized(&mut OsRng, 2, 3, Some(&sk));
        assert_eq!(&shares[0].verifying_key(), sk.verifying_key());

        let nt_share0 = shares[0].to_key_share(&[PartyIdx::from_usize(2), PartyIdx::from_usize(0)]);
        let nt_share1 = shares[2].to_key_share(&[PartyIdx::from_usize(2), PartyIdx::from_usize(0)]);

        assert_eq!(&nt_share0.verifying_key(), sk.verifying_key());
        assert_eq!(&nt_share1.verifying_key(), sk.verifying_key());
        assert_eq!(
            nt_share0.secret_share + nt_share1.secret_share,
            Scalar::from(sk.as_nonzero_scalar())
        );
    }
}
