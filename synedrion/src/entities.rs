use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::marker::PhantomData;

use k256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::cggmp21::{self, PublicAuxInfo, SecretAuxInfo};
use crate::curve::{Point, Scalar};
use crate::rounds::PartyIdx;
use crate::sessions::MappedResult;
use crate::tools::sss::{interpolation_coeff, shamir_join_points, ShareId};
use crate::www02;
use crate::{
    AuxGenResult, InteractiveSigningResult, KeyGenResult, KeyInitResult, KeyRefreshResult,
    KeyResharingResult, SchemeParams,
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
pub struct KeyShare<P: SchemeParams, V: Ord> {
    pub(crate) owner: V,
    pub(crate) secret_share: Scalar,
    pub(crate) public_shares: BTreeMap<V, Point>,
    pub(crate) phantom: PhantomData<P>,
}

impl<P: SchemeParams, V: Ord + Clone> KeyShare<P, V> {
    /// Creates a t-of-t threshold keyshare that can be used in KeyResharing protocol.
    pub fn to_threshold_key_share(&self) -> ThresholdKeyShare<P, V> {
        let num_parties = self.public_shares.len();
        let verifiers = self.public_shares.keys().cloned().collect::<Vec<_>>();
        let my_index = verifiers.iter().position(|v| v == &self.owner).unwrap();
        let share_ids = (1..=num_parties).map(ShareId::new).collect::<Vec<_>>();
        let share_index = share_ids[my_index];

        let secret_share = self.secret_share
            * interpolation_coeff(&share_ids, &share_index)
                .invert()
                .unwrap();
        let public_shares = (0..num_parties)
            .map(|idx| {
                let share_id = share_ids[idx];
                let public_share = self.public_shares[&verifiers[idx]]
                    * interpolation_coeff(&share_ids, &share_id).invert().unwrap();
                (verifiers[idx].clone(), public_share)
            })
            .collect();

        let share_ids = verifiers.iter().cloned().zip(share_ids).collect();

        ThresholdKeyShare {
            owner: self.owner.clone(),
            threshold: num_parties as u32,
            share_ids,
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
        let key_shares = cggmp21::KeyShare::<P>::new_centralized(rng, verifiers.len(), signing_key);
        let public_shares = verifiers
            .iter()
            .cloned()
            .zip(key_shares[0].public_shares.clone().into_vec())
            .collect::<BTreeMap<_, _>>();

        verifiers
            .iter()
            .cloned()
            .zip(key_shares.iter())
            .map(|(verifier, key_share)| KeyShare {
                owner: verifier,
                secret_share: key_share.secret_share,
                public_shares: public_shares.clone(),
                phantom: PhantomData,
            })
            .collect()
    }

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

    pub(crate) fn map_verifiers(&self, verifiers: &[V]) -> cggmp21::KeyShare<P> {
        let verifiers_to_idxs = verifiers
            .iter()
            .enumerate()
            .map(|(idx, v)| (v, PartyIdx::from_usize(idx)))
            .collect::<BTreeMap<_, _>>();
        let public_shares = verifiers.iter().map(|v| self.public_shares[v]).collect();
        cggmp21::KeyShare {
            index: verifiers_to_idxs[&self.owner],
            secret_share: self.secret_share,
            public_shares,
            phantom: PhantomData,
        }
    }
}

impl<P: SchemeParams, V: Clone + Ord> MappedResult<V> for KeyInitResult<P> {
    type MappedSuccess = KeyShare<P, V>;
    fn map_success(inner: Self::Success, verifiers: &[V]) -> Self::MappedSuccess {
        KeyShare {
            owner: verifiers[inner.index.as_usize()].clone(),
            secret_share: inner.secret_share,
            public_shares: map_iter(inner.public_shares.into_vec(), verifiers),
            phantom: PhantomData,
        }
    }
}

/// The result of the Auxiliary Info & Key Refresh protocol - the update to the key share.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyShareChange<P: SchemeParams, V: Ord> {
    pub(crate) owner: V,
    pub(crate) secret_share_change: Scalar,
    pub(crate) public_share_changes: BTreeMap<V, Point>,
    pub(crate) phantom: PhantomData<P>,
}

/// The result of the KeyInit protocol.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
        V: Serialize,
        SecretAuxInfo<P>: Serialize,
        PublicAuxInfo<P>: Serialize"))]
#[serde(bound(deserialize = "
        V: for<'x> Deserialize<'x>,
        SecretAuxInfo<P>: for<'x> Deserialize<'x>,
        PublicAuxInfo<P>: for <'x> Deserialize<'x>"))]
pub struct AuxInfo<P: SchemeParams, V: Ord> {
    pub(crate) owner: V,
    pub(crate) secret_aux: SecretAuxInfo<P>,
    pub(crate) public_aux: BTreeMap<V, PublicAuxInfo<P>>,
}

impl<P: SchemeParams, V: Ord + Clone> AuxInfo<P, V> {
    /// Creates a random set of auxiliary info.
    pub fn new_centralized(rng: &mut impl CryptoRngCore, verifiers: &[V]) -> Box<[Self]> {
        let aux_infos = cggmp21::AuxInfo::new_centralized(rng, verifiers.len());
        let public_aux = verifiers
            .iter()
            .cloned()
            .zip(aux_infos[0].public_aux.clone().into_vec())
            .collect::<BTreeMap<_, _>>();

        verifiers
            .iter()
            .cloned()
            .zip(aux_infos.iter())
            .map(|(verifier, aux_info)| AuxInfo {
                owner: verifier,
                secret_aux: aux_info.secret_aux.clone(),
                public_aux: public_aux.clone(),
            })
            .collect()
    }

    pub(crate) fn map_verifiers(&self, verifiers: &[V]) -> cggmp21::AuxInfo<P> {
        let verifiers_to_idxs = verifiers
            .iter()
            .enumerate()
            .map(|(idx, v)| (v, PartyIdx::from_usize(idx)))
            .collect::<BTreeMap<_, _>>();
        let public_aux = verifiers
            .iter()
            .map(|v| self.public_aux[v].clone())
            .collect();
        cggmp21::AuxInfo {
            index: verifiers_to_idxs[&self.owner],
            secret_aux: self.secret_aux.clone(),
            public_aux,
        }
    }
}

impl<P: SchemeParams, V: Clone + Ord> MappedResult<V> for KeyRefreshResult<P> {
    type MappedSuccess = (KeyShareChange<P, V>, AuxInfo<P, V>);
    fn map_success(inner: Self::Success, verifiers: &[V]) -> Self::MappedSuccess {
        let (key_share_change, aux_info) = inner;
        let mapped_key_share_change = KeyShareChange {
            owner: verifiers[key_share_change.index.as_usize()].clone(),
            secret_share_change: key_share_change.secret_share_change,
            public_share_changes: map_iter(
                key_share_change.public_share_changes.into_vec(),
                verifiers,
            ),
            phantom: PhantomData,
        };
        let mapped_aux_info = AuxInfo {
            owner: verifiers[aux_info.index.as_usize()].clone(),
            secret_aux: aux_info.secret_aux,
            public_aux: map_iter(aux_info.public_aux.into_vec(), verifiers),
        };
        (mapped_key_share_change, mapped_aux_info)
    }
}

impl<P: SchemeParams, V: Clone + Ord> MappedResult<V> for KeyGenResult<P> {
    type MappedSuccess = (KeyShare<P, V>, AuxInfo<P, V>);
    fn map_success(inner: Self::Success, verifiers: &[V]) -> Self::MappedSuccess {
        let (key_share, aux_info) = inner;
        let mapped_key_share = KeyShare {
            owner: verifiers[key_share.index.as_usize()].clone(),
            secret_share: key_share.secret_share,
            public_shares: map_iter(key_share.public_shares.into_vec(), verifiers),
            phantom: PhantomData,
        };
        let mapped_aux_info = AuxInfo {
            owner: verifiers[aux_info.index.as_usize()].clone(),
            secret_aux: aux_info.secret_aux,
            public_aux: map_iter(aux_info.public_aux.into_vec(), verifiers),
        };
        (mapped_key_share, mapped_aux_info)
    }
}

impl<P: SchemeParams, V: Clone + Ord> MappedResult<V> for AuxGenResult<P> {
    type MappedSuccess = AuxInfo<P, V>;
    fn map_success(inner: Self::Success, verifiers: &[V]) -> Self::MappedSuccess {
        AuxInfo {
            owner: verifiers[inner.index.as_usize()].clone(),
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

impl<P: SchemeParams, V: Clone + Ord> MappedResult<V> for KeyResharingResult<P> {
    type MappedSuccess = Option<ThresholdKeyShare<P, V>>;
    fn map_success(inner: Self::Success, verifiers: &[V]) -> Self::MappedSuccess {
        inner.map(|inner| {
            let share_ids = inner
                .share_ids
                .iter()
                .map(|(idx, share_id)| (verifiers[idx.as_usize()].clone(), *share_id))
                .collect();
            let public_shares = inner
                .share_ids
                .keys()
                .map(|party_idx| {
                    (
                        verifiers[party_idx.as_usize()].clone(),
                        inner.public_shares[party_idx],
                    )
                })
                .collect();
            ThresholdKeyShare {
                owner: verifiers[inner.index.as_usize()].clone(),
                threshold: inner.threshold,
                secret_share: inner.secret_share,
                share_ids,
                public_shares,
                phantom: PhantomData,
            }
        })
    }
}

/// A threshold variant of the key share, where any `threshold` shares our of the total number
/// is enough to perform signing.
#[derive(Clone, Serialize, Deserialize)]
pub struct ThresholdKeyShare<P: SchemeParams, V: Ord> {
    pub(crate) owner: V,
    pub(crate) threshold: u32,
    pub(crate) secret_share: Scalar,
    pub(crate) share_ids: BTreeMap<V, ShareId>,
    pub(crate) public_shares: BTreeMap<V, Point>,
    pub(crate) phantom: PhantomData<P>,
}

impl<P: SchemeParams, V: Clone + Ord> ThresholdKeyShare<P, V> {
    /// This key share's threshold.
    pub fn threshold(&self) -> usize {
        self.threshold as usize
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point {
        shamir_join_points(
            self.share_ids
                .iter()
                .map(|(v, share_id)| (share_id, &self.public_shares[v]))
                .take(self.threshold as usize),
        )
    }

    /// Return the verifying key to which this set of shares corresponds.
    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO (#5): need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
    }

    pub(crate) fn map_verifiers(&self, verifiers: &[V]) -> www02::ThresholdKeyShare<P> {
        let verifiers_to_idxs = verifiers
            .iter()
            .enumerate()
            .map(|(idx, v)| (v, PartyIdx::from_usize(idx)))
            .collect::<BTreeMap<_, _>>();
        let share_ids = self
            .share_ids
            .iter()
            .map(|(v, share_id)| (verifiers_to_idxs[v], *share_id))
            .collect();
        let public_shares = self
            .share_ids
            .keys()
            .map(|v| (verifiers_to_idxs[v], self.public_shares[v]))
            .collect();
        www02::ThresholdKeyShare {
            index: verifiers_to_idxs[&self.owner],
            threshold: self.threshold,
            secret_share: self.secret_share,
            share_ids,
            public_shares,
            phantom: PhantomData,
        }
    }

    /// Creates a non-threshold key share suitable for signing.
    pub fn to_key_share(&self, verifiers: &[V]) -> KeyShare<P, V> {
        debug_assert!(verifiers.len() == self.threshold as usize);
        debug_assert!(verifiers.iter().any(|v| v == &self.owner));
        // TODO (#68): assert that all indices are distinct

        let share_id = self.share_ids[&self.owner];
        let share_ids = verifiers
            .iter()
            .map(|v| self.share_ids[v])
            .collect::<Vec<_>>();

        let secret_share = self.secret_share * interpolation_coeff(&share_ids, &share_id);
        let public_shares = verifiers
            .iter()
            .map(|v| {
                (
                    v.clone(),
                    self.public_shares[v] * interpolation_coeff(&share_ids, &self.share_ids[v]),
                )
            })
            .collect();

        KeyShare {
            owner: self.owner.clone(),
            secret_share,
            public_shares,
            phantom: PhantomData,
        }
    }
}
