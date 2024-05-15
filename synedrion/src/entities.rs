use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::marker::PhantomData;

use k256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::common::{self, PublicAuxInfo, SecretAuxInfo};
use crate::curve::{Point, Scalar};
use crate::rounds::PartyIdx;
use crate::sessions::MappedResult;
use crate::threshold;
use crate::tools::sss::{interpolation_coeff, shamir_join_points, ShareIdx};
use crate::{
    InteractiveSigningResult, KeyGenResult, KeyInitResult, KeyRefreshResult, KeyResharingResult,
    SchemeParams,
};

fn map_iter<T, V: Clone + Ord>(
    elems: impl IntoIterator<Item = T>,
    verifiers: &[V],
) -> BTreeMap<V, T> {
    elems
        .into_iter()
        .enumerate()
        .map(|(idx, elem)| (verifiers[idx].clone(), elem))
        .collect()
}

/// The result of the KeyInit protocol.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyShareSeed<V: Ord> {
    pub(crate) owner: V,
    pub(crate) secret_share: Scalar,
    pub(crate) public_shares: BTreeMap<V, Point>,
}

impl<V: Ord + Clone> KeyShareSeed<V> {
    /// Creates a t-of-t threshold keyshare that can be used in KeyResharing protocol.
    pub fn to_threshold_key_share_seed<P: SchemeParams>(&self) -> ThresholdKeyShareSeed<P, V> {
        let num_parties = self.public_shares.len();
        let verifiers = self.public_shares.keys().cloned().collect::<Vec<_>>();
        let my_index = verifiers.iter().position(|v| v == &self.owner).unwrap();
        let share_idxs = (1..=num_parties).map(ShareIdx::new).collect::<Vec<_>>();
        let share_index = share_idxs[my_index];

        let secret_share = self.secret_share
            * interpolation_coeff(&share_idxs, &share_index)
                .invert()
                .unwrap();
        let public_shares = (0..num_parties)
            .map(|idx| {
                let share_idx = share_idxs[idx];
                let public_share = self.public_shares[&verifiers[idx]]
                    * interpolation_coeff(&share_idxs, &share_idx)
                        .invert()
                        .unwrap();
                (verifiers[idx].clone(), public_share)
            })
            .collect();

        let share_idxs = verifiers.iter().cloned().zip(share_idxs).collect();

        ThresholdKeyShareSeed {
            owner: self.owner.clone(),
            threshold: num_parties as u32,
            share_idxs,
            secret_share,
            public_shares,
            phantom: PhantomData,
        }
    }

    /// Creates a set of key shares corresponding to the given signing key,
    /// or to a random one if none is provided.
    pub fn new_centralized(
        rng: &mut impl CryptoRngCore,
        verifiers: &[V],
        signing_key: Option<&SigningKey>,
    ) -> Box<[Self]> {
        let secret = match signing_key {
            None => Scalar::random(rng),
            Some(sk) => Scalar::from(sk.as_nonzero_scalar()),
        };

        let secret_shares = secret.split(rng, verifiers.len());
        let public_shares = verifiers
            .iter()
            .zip(secret_shares.iter())
            .map(|(v, s)| (v.clone(), s.mul_by_generator()))
            .collect::<BTreeMap<_, _>>();

        secret_shares
            .into_iter()
            .enumerate()
            .map(|(idx, secret_share)| KeyShareSeed {
                owner: verifiers[idx].clone(),
                secret_share,
                public_shares: public_shares.clone(),
            })
            .collect()
    }
}

impl<V: Clone + Ord> MappedResult<V> for KeyInitResult {
    type MappedSuccess = KeyShareSeed<V>;
    fn map_success(inner: Self::Success, verifiers: &[V]) -> Self::MappedSuccess {
        KeyShareSeed {
            owner: verifiers[inner.index.as_usize()].clone(),
            secret_share: inner.secret_share,
            public_shares: map_iter(inner.public_shares.into_vec(), verifiers),
        }
    }
}

/// The result of the Auxiliary Info & Key Refresh protocol - the update to the key share.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
        V: Serialize,
        SecretAuxInfo<P>: Serialize,
        PublicAuxInfo<P>: Serialize"))]
#[serde(bound(deserialize = "
        V: for<'x> Deserialize<'x>,
        SecretAuxInfo<P>: for<'x> Deserialize<'x>,
        PublicAuxInfo<P>: for <'x> Deserialize<'x>"))]
pub struct KeyShareChange<P: SchemeParams, V: Ord> {
    pub(crate) secret_share_change: Scalar,
    pub(crate) public_share_changes: BTreeMap<V, Point>,
    pub(crate) secret_aux: SecretAuxInfo<P>,
    pub(crate) public_aux: BTreeMap<V, PublicAuxInfo<P>>,
}

impl<P: SchemeParams, V: Clone + Ord> MappedResult<V> for KeyRefreshResult<P> {
    type MappedSuccess = KeyShareChange<P, V>;
    fn map_success(inner: Self::Success, verifiers: &[V]) -> Self::MappedSuccess {
        KeyShareChange {
            secret_share_change: inner.secret_share_change,
            public_share_changes: map_iter(inner.public_share_changes.into_vec(), verifiers),
            secret_aux: inner.secret_aux,
            public_aux: map_iter(inner.public_aux.into_vec(), verifiers),
        }
    }
}

/// The full key share with auxiliary parameters.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
        V: Serialize,
        SecretAuxInfo<P>: Serialize,
        PublicAuxInfo<P>: Serialize"))]
#[serde(bound(deserialize = "
        V: for<'x> Deserialize<'x>,
        SecretAuxInfo<P>: for<'x> Deserialize<'x>,
        PublicAuxInfo<P>: for <'x> Deserialize<'x>"))]
pub struct KeyShare<P: SchemeParams, V: Ord> {
    pub(crate) owner: V,
    pub(crate) secret_share: Scalar,
    pub(crate) public_shares: BTreeMap<V, Point>,
    pub(crate) secret_aux: SecretAuxInfo<P>,
    pub(crate) public_aux: BTreeMap<V, PublicAuxInfo<P>>,
}

impl<P: SchemeParams, V: Clone + Ord> KeyShare<P, V> {
    /// The owner of this key share.
    pub fn owner(&self) -> &V {
        &self.owner
    }

    /// The number of parties in this key share.
    pub fn num_parties(&self) -> usize {
        self.public_shares.len()
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point {
        self.public_shares.values().sum()
    }

    /// Returns the verifying key to which this set of shares corresponds.
    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO (#5): need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
    }

    pub(crate) fn map_verifiers(&self, verifiers: &[V]) -> common::KeyShare<P> {
        let verifiers_to_idxs = verifiers
            .iter()
            .enumerate()
            .map(|(idx, v)| (v, PartyIdx::from_usize(idx)))
            .collect::<BTreeMap<_, _>>();
        let public_shares = verifiers.iter().map(|v| self.public_shares[v]).collect();
        let public_aux = verifiers
            .iter()
            .map(|v| self.public_aux[v].clone())
            .collect();
        common::KeyShare {
            index: verifiers_to_idxs[&self.owner],
            secret_share: self.secret_share,
            public_shares,
            secret_aux: self.secret_aux.clone(),
            public_aux,
        }
    }

    /// Creates a set of key shares corresponding to the given signing key,
    /// or a random one if none is provided.
    pub fn new_centralized(
        rng: &mut impl CryptoRngCore,
        verifiers: &[V],
        signing_key: Option<&SigningKey>,
    ) -> Box<[Self]> {
        let secret = match signing_key {
            None => Scalar::random(rng),
            Some(sk) => Scalar::from(sk.as_nonzero_scalar()),
        };

        let secret_shares = secret.split(rng, verifiers.len());
        let public_shares = verifiers
            .iter()
            .zip(secret_shares.iter())
            .map(|(v, s)| (v.clone(), s.mul_by_generator()))
            .collect::<BTreeMap<_, _>>();

        let (secret_aux, public_aux) = common::make_aux_info(rng, verifiers.len());
        let public_aux = verifiers
            .iter()
            .cloned()
            .zip(public_aux.into_vec())
            .collect::<BTreeMap<_, _>>();

        secret_shares
            .into_iter()
            .enumerate()
            .map(|(idx, secret_share)| KeyShare {
                owner: verifiers[idx].clone(),
                secret_share,
                public_shares: public_shares.clone(),
                secret_aux: secret_aux[idx].clone(),
                public_aux: public_aux.clone(),
            })
            .collect()
    }
}

impl<P: SchemeParams, V: Clone + Ord> MappedResult<V> for KeyGenResult<P> {
    type MappedSuccess = KeyShare<P, V>;
    fn map_success(inner: Self::Success, verifiers: &[V]) -> Self::MappedSuccess {
        KeyShare {
            owner: verifiers[inner.index.as_usize()].clone(),
            secret_share: inner.secret_share,
            public_shares: map_iter(inner.public_shares.into_vec(), verifiers),
            secret_aux: inner.secret_aux,
            public_aux: map_iter(inner.public_aux.into_vec(), verifiers),
        }
    }
}

impl<P: SchemeParams, V: Clone + Ord> MappedResult<V> for InteractiveSigningResult<P> {
    type MappedSuccess = Self::Success;
    fn map_success(inner: Self::Success, _verifiers: &[V]) -> Self::MappedSuccess {
        inner
    }
}

/// A threshold variant of the key share seed, where any `threshold` shares our of the total number
/// is enough to perform signing.
#[derive(Clone, Serialize, Deserialize)]
pub struct ThresholdKeyShareSeed<P: SchemeParams, V: Ord> {
    pub(crate) owner: V,
    pub(crate) threshold: u32,
    pub(crate) secret_share: Scalar,
    pub(crate) share_idxs: BTreeMap<V, ShareIdx>,
    pub(crate) public_shares: BTreeMap<V, Point>,
    pub(crate) phantom: PhantomData<P>,
}

impl<P: SchemeParams, V: Ord> ThresholdKeyShareSeed<P, V> {
    /// This key share's threshold.
    pub fn threshold(&self) -> usize {
        self.threshold as usize
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point {
        shamir_join_points(
            self.share_idxs
                .iter()
                .map(|(v, share_idx)| (share_idx, &self.public_shares[v]))
                .take(self.threshold as usize),
        )
    }

    /// Return the verifying key to which this set of shares corresponds.
    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO (#5): need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
    }

    pub(crate) fn map_verifiers(&self, verifiers: &[V]) -> threshold::ThresholdKeyShareSeed<P> {
        let verifiers_to_idxs = verifiers
            .iter()
            .enumerate()
            .map(|(idx, v)| (v, PartyIdx::from_usize(idx)))
            .collect::<BTreeMap<_, _>>();
        let holders = self
            .share_idxs
            .iter()
            .map(|(v, share_idx)| (verifiers_to_idxs[v], *share_idx))
            .collect();
        let public_shares = self
            .share_idxs
            .keys()
            .map(|v| (verifiers_to_idxs[v], self.public_shares[v]))
            .collect();
        threshold::ThresholdKeyShareSeed {
            index: verifiers_to_idxs[&self.owner],
            threshold: self.threshold,
            secret_share: self.secret_share,
            holders,
            public_shares,
            phantom: PhantomData,
        }
    }
}

impl<P: SchemeParams, V: Clone + Ord> MappedResult<V> for KeyResharingResult<P> {
    type MappedSuccess = Option<ThresholdKeyShareSeed<P, V>>;
    fn map_success(inner: Self::Success, verifiers: &[V]) -> Self::MappedSuccess {
        inner.map(|inner| {
            let share_idxs = inner
                .holders
                .iter()
                .map(|(idx, share_idx)| (verifiers[idx.as_usize()].clone(), *share_idx))
                .collect();
            let public_shares = inner
                .holders
                .keys()
                .map(|party_idx| {
                    (
                        verifiers[party_idx.as_usize()].clone(),
                        inner.public_shares[party_idx],
                    )
                })
                .collect();
            ThresholdKeyShareSeed {
                owner: verifiers[inner.index.as_usize()].clone(),
                threshold: inner.threshold,
                secret_share: inner.secret_share,
                share_idxs,
                public_shares,
                phantom: PhantomData,
            }
        })
    }
}

/// A threshold variant of the key share, where any `threshold` shares our of the total number
/// is enough to perform signing.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
        V: Serialize,
        SecretAuxInfo<P>: Serialize,
        PublicAuxInfo<P>: Serialize"))]
#[serde(bound(deserialize = "
        V: for<'x> Deserialize<'x>,
        SecretAuxInfo<P>: for<'x> Deserialize<'x>,
        PublicAuxInfo<P>: for <'x> Deserialize<'x>"))]
pub struct ThresholdKeyShare<P: SchemeParams, V: Ord> {
    pub(crate) owner: V,
    pub(crate) threshold: u32,
    pub(crate) secret_share: Scalar,
    pub(crate) share_idxs: BTreeMap<V, ShareIdx>,
    pub(crate) public_shares: BTreeMap<V, Point>,
    pub(crate) secret_aux: SecretAuxInfo<P>,
    pub(crate) public_aux: BTreeMap<V, PublicAuxInfo<P>>,
}

impl<P: SchemeParams, V: Clone + Ord> ThresholdKeyShare<P, V> {
    /// Creates a new key share from a seed and auxiliary data.
    pub fn new(seed: ThresholdKeyShareSeed<P, V>, change: KeyShareChange<P, V>) -> Self {
        let secret_share = seed.secret_share + change.secret_share_change;
        let public_shares = seed
            .public_shares
            .into_iter()
            .map(|(v, public_share)| (v.clone(), public_share + change.public_share_changes[&v]))
            .collect();

        Self {
            owner: seed.owner,
            threshold: seed.threshold,
            secret_share,
            public_shares,
            share_idxs: seed.share_idxs,
            secret_aux: change.secret_aux,
            public_aux: change.public_aux,
        }
    }

    /// Creates a non-threshold key share suitable for signing.
    pub fn to_key_share(&self, verifiers: &[V]) -> KeyShare<P, V> {
        debug_assert!(verifiers.len() == self.threshold as usize);
        debug_assert!(verifiers.iter().any(|v| v == &self.owner));
        // TODO (#68): assert that all indices are distinct

        let share_idx = self.share_idxs[&self.owner];
        let share_idxs = verifiers
            .iter()
            .map(|v| self.share_idxs[v])
            .collect::<Vec<_>>();

        let secret_share = self.secret_share * interpolation_coeff(&share_idxs, &share_idx);
        let public_shares = verifiers
            .iter()
            .map(|v| {
                (
                    v.clone(),
                    self.public_shares[v] * interpolation_coeff(&share_idxs, &self.share_idxs[v]),
                )
            })
            .collect();

        let public_aux = verifiers
            .iter()
            .map(|v| (v.clone(), self.public_aux[v].clone()))
            .collect();

        KeyShare {
            owner: self.owner.clone(),
            secret_share,
            public_shares,
            secret_aux: self.secret_aux.clone(),
            public_aux,
        }
    }
}
