use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::marker::PhantomData;

use k256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;

use crate::common;
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

#[derive(Clone)]
pub struct KeyShareSeed<V> {
    pub(crate) owner: V,
    pub(crate) secret_share: Scalar,
    pub(crate) public_shares: BTreeMap<V, Point>,
}

impl<V: Ord + Clone> KeyShareSeed<V> {
    pub fn to_threshold_key_share_seed<P: SchemeParams>(&self) -> ThresholdKeyShareSeed<P, V> {
        let num_parties = self.public_shares.len();
        let verifiers = self.public_shares.keys().collect::<Vec<_>>();
        let my_index = verifiers.iter().position(|v| v == &&self.owner).unwrap();
        let share_idxs = (1..=num_parties).map(ShareIdx::new).collect::<Vec<_>>();
        let share_index = share_idxs[my_index];

        let secret_share = self.secret_share
            * interpolation_coeff(&share_idxs, &share_index)
                .invert()
                .unwrap();
        let public_shares = (0..num_parties)
            .map(|idx| {
                let share_idx = share_idxs[idx];
                let public_share = self.public_shares[verifiers[idx]]
                    * interpolation_coeff(&share_idxs, &share_idx)
                        .invert()
                        .unwrap();
                ((*verifiers[idx]).clone(), (share_idx, public_share))
            })
            .collect();

        ThresholdKeyShareSeed {
            index: share_index,
            threshold: num_parties as u32,
            secret_share,
            public_shares,
            phantom: PhantomData,
        }
    }

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

pub struct KeyShareChange<P: SchemeParams, V> {
    pub(crate) secret_share_change: Scalar,
    pub(crate) public_share_changes: BTreeMap<V, Point>,
    pub(crate) secret_aux: common::SecretAuxInfo<P>,
    pub(crate) public_aux: BTreeMap<V, common::PublicAuxInfo<P>>,
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

#[derive(Clone)]
pub struct KeyShare<P: SchemeParams, V> {
    pub(crate) owner: V,
    pub(crate) secret_share: Scalar,
    pub(crate) public_shares: BTreeMap<V, Point>,
    pub(crate) secret_aux: common::SecretAuxInfo<P>,
    pub(crate) public_aux: BTreeMap<V, common::PublicAuxInfo<P>>,
}

impl<P: SchemeParams, V: Clone + Ord> KeyShare<P, V> {
    pub fn owner(&self) -> &V {
        &self.owner
    }

    pub fn num_parties(&self) -> usize {
        self.public_shares.len()
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point {
        self.public_shares.values().sum()
    }

    /// Return the verifying key to which this set of shares corresponds.
    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO (#5): need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
    }

    pub fn map_verifiers(&self, verifiers: &[V]) -> common::KeyShare<P> {
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

#[derive(Clone)]
pub struct ThresholdKeyShareSeed<P: SchemeParams, V> {
    pub(crate) index: ShareIdx,
    pub(crate) threshold: u32,
    pub(crate) secret_share: Scalar,
    pub(crate) public_shares: BTreeMap<V, (ShareIdx, Point)>,
    pub(crate) phantom: PhantomData<P>,
}

impl<P: SchemeParams, V: Ord> ThresholdKeyShareSeed<P, V> {
    pub fn threshold(&self) -> usize {
        self.threshold as usize
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point {
        shamir_join_points(
            self.public_shares
                .values()
                .map(|(k, v)| (k, v))
                .take(self.threshold as usize),
        )
    }

    /// Return the verifying key to which this set of shares corresponds.
    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO (#5): need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
    }

    pub fn map_verifiers(&self, verifiers: &[V]) -> threshold::ThresholdKeyShareSeed<P> {
        let verifiers_to_idxs = verifiers
            .iter()
            .enumerate()
            .map(|(idx, v)| (v, PartyIdx::from_usize(idx)))
            .collect::<BTreeMap<_, _>>();
        let holders = self
            .public_shares
            .iter()
            .map(|(v, (idx, _share))| (*idx, verifiers_to_idxs[v]))
            .collect();
        let public_shares = self.public_shares.values().cloned().collect();
        threshold::ThresholdKeyShareSeed {
            index: self.index,
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
            let public_shares = inner
                .holders
                .into_iter()
                .map(|(share_idx, party_idx)| {
                    (
                        verifiers[party_idx.as_usize()].clone(),
                        (share_idx, inner.public_shares[&share_idx]),
                    )
                })
                .collect();
            ThresholdKeyShareSeed {
                index: inner.index,
                threshold: inner.threshold,
                secret_share: inner.secret_share,
                public_shares,
                phantom: PhantomData,
            }
        })
    }
}
