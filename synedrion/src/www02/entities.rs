use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};
use manul::session::LocalError;

use bip32::{DerivationPath, PrivateKey, PrivateKeyBytes, PublicKey};
use k256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    cggmp21::{KeyShare, SchemeParams},
    curve::{Point, Scalar},
    tools::{
        hashing::{Chain, FofHasher},
        sss::{interpolation_coeff, shamir_evaluation_points, shamir_join_points, shamir_split, ShareId},
        Secret,
    },
};

/// A threshold variant of the key share, where any `threshold` shares our of the total number
/// is enough to perform signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdKeyShare<P: SchemeParams, I: Ord> {
    // TODO (#5): make this private to ensure invariants are held
    // (mainly, that the verifying key is not an identity)
    pub(crate) owner: I,
    pub(crate) threshold: u32,
    pub(crate) secret_share: Secret<Scalar>,
    pub(crate) share_ids: BTreeMap<I, ShareId>,
    pub(crate) public_shares: BTreeMap<I, Point>,
    // TODO (#27): this won't be needed when Scalar/Point are a part of `P`
    pub(crate) phantom: PhantomData<P>,
}

impl<P: SchemeParams, I: Clone + Ord + PartialEq + Debug> ThresholdKeyShare<P, I> {
    /// Threshold share ID.
    pub fn share_id(&self) -> Result<&ShareId, LocalError> {
        self.share_ids.get(&self.owner).ok_or(LocalError::new(format!(
            "owner={:?} is missing in the share_ids",
            self.owner
        )))
    }

    /// The threshold.
    pub fn threshold(&self) -> usize {
        self.threshold as usize
    }

    /// Creates a set of threshold key shares for the given IDs.
    pub fn new_centralized(
        rng: &mut impl CryptoRngCore,
        ids: &BTreeSet<I>,
        threshold: usize,
        signing_key: Option<&SigningKey>,
    ) -> Result<BTreeMap<I, Self>, LocalError> {
        if threshold > ids.len() {
            return Err(LocalError::new(format!(
                "Invalid threshold ({threshold}). Must be smaller than {}",
                ids.len()
            )));
        }

        let secret = Secret::init_with(|| match signing_key {
            None => Scalar::random(rng),
            Some(sk) => Scalar::from(sk.as_nonzero_scalar()),
        });

        let share_ids = shamir_evaluation_points(ids.len());
        let secret_shares = shamir_split(rng, secret, threshold, &share_ids);
        let share_ids = ids.iter().cloned().zip(share_ids).collect::<BTreeMap<_, _>>();

        let public_shares = share_ids
            .iter()
            .map(|(id, share_id)| {
                let secret_share = secret_shares
                    .get(share_id)
                    .ok_or_else(|| LocalError::new("share_id={share_id:?} is missing in the secret shares"))?;
                Ok((id.clone(), secret_share.mul_by_generator()))
            })
            .collect::<Result<BTreeMap<_, _>, LocalError>>()?;

        ids.iter()
            .map(|id| {
                let share_id = share_ids
                    .get(id)
                    .ok_or_else(|| LocalError::new("id={id:?} is missing in the share_ids"))?;
                let secret_share = secret_shares
                    .get(share_id)
                    .ok_or_else(|| LocalError::new("share_id={share_id:?} is missing in the secret shares"))?
                    .clone();
                Ok((
                    id.clone(),
                    Self {
                        owner: id.clone(),
                        threshold: threshold as u32,
                        secret_share,
                        share_ids: share_ids.clone(),
                        public_shares: public_shares.clone(),
                        phantom: PhantomData,
                    },
                ))
            })
            .collect()
    }

    pub(crate) fn verifying_key_as_point(&self) -> Result<Point, LocalError> {
        Ok(shamir_join_points(
            &self
                .share_ids
                .iter()
                .map(|(party_idx, share_id)| {
                    let public_share = self.public_shares.get(party_idx).ok_or(LocalError::new(
                        "party_idx={party_idx:?} is missing in the public shares",
                    ))?;
                    Ok((*share_id, *public_share))
                })
                .take(self.threshold as usize)
                .collect::<Result<_, LocalError>>()?,
        ))
    }

    /// Return the verifying key to which this set of shares corresponds.
    pub fn verifying_key(&self) -> Result<VerifyingKey, LocalError> {
        self.verifying_key_as_point()?
            .to_verifying_key()
            .ok_or_else(|| LocalError::new("The combined verifying key is an identity"))
    }

    /// Converts a t-of-n key share into a t-of-t key share
    /// (for the `t` share indices supplied as `share_ids`)
    /// that can be used in the presigning/signing protocols.
    pub fn to_key_share(&self, ids: &BTreeSet<I>) -> Result<KeyShare<P, I>, LocalError> {
        debug_assert!(ids.len() == self.threshold as usize);
        debug_assert!(ids.iter().any(|id| id == &self.owner));

        let owner_share_id = self
            .share_ids
            .get(&self.owner)
            .ok_or_else(|| LocalError::new("id={id:?} is missing in the share_ids"))?;

        let share_ids = ids
            .iter()
            .map(|id| {
                let share_id = self
                    .share_ids
                    .get(id)
                    .ok_or_else(|| LocalError::new("id={id:?} is missing in the share_ids"))?;
                Ok((id.clone(), *share_id))
            })
            .collect::<Result<BTreeMap<_, _>, LocalError>>()?;

        let share_ids_set = share_ids.values().cloned().collect();
        let secret_share = self.secret_share.clone() * interpolation_coeff(&share_ids_set, owner_share_id);
        let public_shares = ids
            .iter()
            .map(|id| {
                let public_share = self
                    .public_shares
                    .get(id)
                    .ok_or_else(|| LocalError::new("id={id:?} is missing in the public shares"))?;
                let this_share_id = self
                    .share_ids
                    .get(id)
                    .ok_or_else(|| LocalError::new("id={id:?} is missing in the share_ids"))?;
                Ok((
                    id.clone(),
                    public_share * interpolation_coeff(&share_ids_set, this_share_id),
                ))
            })
            .collect::<Result<_, LocalError>>()?;

        KeyShare::new(self.owner.clone(), secret_share, public_shares)
    }

    /// Creates a t-of-t threshold keyshare that can be used in KeyResharing protocol.
    pub fn from_key_share(key_share: &KeyShare<P, I>) -> Self {
        let ids = key_share.all_parties();
        let num_parties: u64 = ids.len().try_into().expect("no more than 2^64-1 shares needed");
        let share_ids = ids
            .iter()
            .cloned()
            .zip((1..=num_parties).map(ShareId::new))
            .collect::<BTreeMap<_, _>>();

        let share_ids_set = share_ids.values().cloned().collect();
        let owner_share_id = share_ids
            .get(key_share.owner())
            .expect("Just created a ShareId for all parties");

        let secret_share = key_share.secret_share().clone()
            * interpolation_coeff(&share_ids_set, owner_share_id)
                .invert()
                .expect("the interpolation coefficient is a non-zero scalar");
        let public_shares = ids
            .iter()
            .map(|id| {
                let share_id = share_ids.get(id).expect("share_ids and ids have identical lengths");
                let public_share = key_share
                    .public_shares()
                    .get(id)
                    .expect("There is one public share (Point) for each party")
                    * interpolation_coeff(&share_ids_set, share_id)
                        .invert()
                        .expect("the interpolation coefficient is a non-zero scalar");
                (id.clone(), public_share)
            })
            .collect();

        Self {
            owner: key_share.owner().clone(),
            threshold: ids.len() as u32,
            share_ids,
            secret_share,
            public_shares,
            phantom: PhantomData,
        }
    }

    /// Deterministically derives a child share using BIP-32 standard.
    pub fn derive_bip32(&self, derivation_path: &DerivationPath) -> Result<Self, bip32::Error> {
        let pk = self.verifying_key().map_err(|_| bip32::Error::Crypto)?;
        let tweaks = derive_tweaks(pk, derivation_path)?;

        // Will fail here if secret share is zero
        let secret_share = self.secret_share.clone().to_signing_key().ok_or(bip32::Error::Crypto)?;
        let secret_share =
            apply_tweaks_private(secret_share, &tweaks).map(|signing_key| Scalar::from_signing_key(&signing_key))?;

        let public_shares = self
            .public_shares
            .clone()
            .into_iter()
            .map(|(id, point)|
                // Will fail here if the final or one of the intermediate points is an identity
                point.to_verifying_key().ok_or(bip32::Error::Crypto)
                    .and_then(|vkey| apply_tweaks_public(vkey, &tweaks))
                    .map(|vkey| (id, Point::from_verifying_key(&vkey))))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            owner: self.owner.clone(),
            threshold: self.threshold,
            share_ids: self.share_ids.clone(),
            secret_share,
            public_shares,
            phantom: PhantomData,
        })
    }
}

/// Used for deriving child keys from a parent type.
pub trait DeriveChildKey {
    /// Return a verifying key derived from the given type using the BIP-32 scheme.
    fn derive_verifying_key_bip32(&self, derivation_path: &DerivationPath) -> Result<VerifyingKey, bip32::Error>;
}

impl<P: SchemeParams, I: Clone + Ord + PartialEq + Debug> DeriveChildKey for ThresholdKeyShare<P, I> {
    fn derive_verifying_key_bip32(&self, derivation_path: &DerivationPath) -> Result<VerifyingKey, bip32::Error> {
        let public_key = self.verifying_key().map_err(|_| bip32::Error::Crypto)?;
        let tweaks = derive_tweaks(public_key, derivation_path)?;
        apply_tweaks_public(public_key, &tweaks)
    }
}

impl DeriveChildKey for VerifyingKey {
    fn derive_verifying_key_bip32(&self, derivation_path: &DerivationPath) -> Result<VerifyingKey, bip32::Error> {
        let tweaks = derive_tweaks(*self, derivation_path)?;
        apply_tweaks_public(*self, &tweaks)
    }
}

fn derive_tweaks(
    public_key: VerifyingKey,
    derivation_path: &DerivationPath,
) -> Result<Vec<PrivateKeyBytes>, bip32::Error> {
    let mut public_key = public_key;

    // Note: deriving the initial chain code from public information. Is this okay?
    let mut chain_code = FofHasher::new_with_dst(b"chain-code-derivation")
        .chain_bytes(&Point::from_verifying_key(&public_key).to_compressed_array())
        .finalize()
        .0;

    let mut tweaks = Vec::new();
    for child_number in derivation_path.iter() {
        let (tweak, new_chain_code) = public_key.derive_tweak(&chain_code, child_number)?;
        public_key = public_key.derive_child(tweak)?;
        tweaks.push(tweak);
        chain_code = new_chain_code;
    }

    Ok(tweaks)
}

fn apply_tweaks_public(public_key: VerifyingKey, tweaks: &[PrivateKeyBytes]) -> Result<VerifyingKey, bip32::Error> {
    let mut public_key = public_key;
    for tweak in tweaks {
        public_key = public_key.derive_child(*tweak)?;
    }
    Ok(public_key)
}

fn apply_tweaks_private(private_key: SigningKey, tweaks: &[PrivateKeyBytes]) -> Result<SigningKey, bip32::Error> {
    let mut private_key = private_key;
    for tweak in tweaks {
        private_key = private_key.derive_child(*tweak)?;
    }
    Ok(private_key)
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use k256::ecdsa::SigningKey;
    use manul::{
        dev::{TestSigner, TestVerifier},
        signature::Keypair,
    };
    use rand_core::OsRng;

    use super::ThresholdKeyShare;
    use crate::{cggmp21::TestParams, curve::Scalar};

    #[test]
    fn threshold_key_share_centralized() {
        let sk = SigningKey::random(&mut OsRng);

        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers.iter().map(|signer| signer.verifying_key()).collect::<Vec<_>>();
        let ids_set = ids.iter().cloned().collect::<BTreeSet<_>>();

        let shares =
            ThresholdKeyShare::<TestParams, TestVerifier>::new_centralized(&mut OsRng, &ids_set, 2, Some(&sk)).unwrap();

        let sk_verifying_key = sk.verifying_key();
        assert_eq!(&shares[&ids[0]].verifying_key().unwrap(), sk_verifying_key);
        assert_eq!(&shares[&ids[1]].verifying_key().unwrap(), sk_verifying_key);
        assert_eq!(&shares[&ids[2]].verifying_key().unwrap(), sk_verifying_key);

        assert_eq!(&shares[&ids[0]].verifying_key().unwrap(), sk_verifying_key);

        let ids_subset = BTreeSet::from([ids[2], ids[0]]);
        let nt_share0 = shares[&ids[0]].to_key_share(&ids_subset).unwrap();
        let nt_share1 = shares[&ids[2]].to_key_share(&ids_subset).unwrap();

        assert_eq!(
            nt_share0.secret_share().expose_secret() + nt_share1.secret_share().expose_secret(),
            Scalar::from(sk.as_nonzero_scalar())
        );
        assert_eq!(&nt_share0.verifying_key(), sk_verifying_key);
        assert_eq!(&nt_share1.verifying_key(), sk_verifying_key);
    }
}
