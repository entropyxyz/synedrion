use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    vec::Vec,
};
use core::fmt::Debug;
use manul::session::LocalError;

use ecdsa::VerifyingKey;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    cggmp21::SchemeParams,
    curve::{secret_split, Point, Scalar},
    paillier::{
        PublicKeyPaillier, PublicKeyPaillierWire, RPParams, RPParamsWire, SecretKeyPaillier, SecretKeyPaillierWire,
    },
    tools::Secret,
};

/// The result of the KeyInit protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "I: for<'x> Deserialize<'x>"))]
pub struct KeyShare<P, I>
where
    P: SchemeParams,
    I: Ord,
{
    owner: I,
    /// Secret key share of this node.
    secret: Secret<Scalar<P>>, // `x_i`
    public: PublicKeyShares<P, I>, // `X_j`
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "I: for<'x> Deserialize<'x>"))]
pub struct PublicKeyShares<P: SchemeParams, I: Ord>(BTreeMap<I, Point<P>>);

/// The result of the AuxGen protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    I: Serialize,
    SecretAuxInfo<P>: Serialize,
    PublicAuxInfos<P, I>: Serialize,
"))]
#[serde(bound(deserialize = "
    I: for<'x> Deserialize<'x>,
    SecretAuxInfo<P>: for<'x> Deserialize<'x>,
    PublicAuxInfos<P, I>: for<'x> Deserialize<'x>,
"))]
pub struct AuxInfo<P: SchemeParams, I: Ord> {
    pub(crate) owner: I,
    pub(crate) secret: SecretAuxInfo<P>,
    pub(crate) public: PublicAuxInfos<P, I>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "
    I: Serialize,
    PublicAuxInfo<P>: Serialize,
"))]
#[serde(bound(deserialize = "
    I: for<'x> Deserialize<'x>,
    PublicAuxInfo<P>: for<'x> Deserialize<'x>,
"))]
pub struct PublicAuxInfos<P: SchemeParams, I: Ord>(pub(crate) BTreeMap<I, PublicAuxInfo<P>>);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SecretKeyPaillierWire<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "SecretKeyPaillierWire<P::Paillier>: for <'x> Deserialize<'x>"))]
pub(crate) struct SecretAuxInfo<P: SchemeParams> {
    pub(crate) paillier_sk: SecretKeyPaillierWire<P::Paillier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicKeyPaillierWire<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "PublicKeyPaillierWire<P::Paillier>: for <'x> Deserialize<'x>"))]
pub(crate) struct PublicAuxInfo<P: SchemeParams> {
    /// The Paillier public key.
    pub(crate) paillier_pk: PublicKeyPaillierWire<P::Paillier>,
    /// The ring-Pedersen parameters.
    pub(crate) rp_params: RPParamsWire<P::Paillier>, // `s_i` and `t_i`
}

#[derive(Debug, Clone)]
pub(crate) struct AuxInfoPrecomputed<P: SchemeParams, I> {
    pub(crate) secret_aux: SecretAuxInfoPrecomputed<P>,
    pub(crate) public_aux: BTreeMap<I, PublicAuxInfoPrecomputed<P>>,
}

#[derive(Debug, Clone)]
pub(crate) struct SecretAuxInfoPrecomputed<P: SchemeParams> {
    pub(crate) paillier_sk: SecretKeyPaillier<P::Paillier>,
}

#[derive(Debug, Clone)]
pub(crate) struct PublicAuxInfoPrecomputed<P: SchemeParams> {
    pub(crate) paillier_pk: PublicKeyPaillier<P::Paillier>,
    pub(crate) rp_params: RPParams<P::Paillier>,
}

/// The result of the Auxiliary Info & Key Refresh protocol - the update to the key share.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "I: for<'x> Deserialize<'x>"))]
pub struct KeyShareChange<P: SchemeParams, I: Ord> {
    pub(crate) owner: I,
    /// The value to be added to the secret share.
    pub(crate) secret_share_change: Secret<Scalar<P>>, // `x_i^* - x_i == \sum_{j} x_j^i`
    /// The values to be added to the public shares of remote nodes.
    pub(crate) public_share_changes: BTreeMap<I, Point<P>>, // `X_k^* - X_k == \sum_j X_j^k`, for all nodes
}

impl<P: SchemeParams, I: Ord> PublicAuxInfos<P, I> {
    pub(crate) fn as_map(&self) -> &BTreeMap<I, PublicAuxInfo<P>> {
        &self.0
    }

    /// Returns a `PublicAuxInfos` object for the given subset of all parties.
    pub fn subset(self, parties: &BTreeSet<I>) -> Result<Self, LocalError> {
        let aux_infos = self
            .0
            .into_iter()
            .filter(|(id, _aux)| parties.contains(id))
            .collect::<BTreeMap<_, _>>();
        if aux_infos.len() != parties.len() {
            return Err(LocalError::new(
                "`parties` must be a subset of all the available Aux Infos",
            ));
        }

        Ok(Self(aux_infos))
    }
}

impl<P: SchemeParams, I: Clone + Ord + Debug> PublicKeyShares<P, I> {
    pub(crate) fn as_map(&self) -> &BTreeMap<I, Point<P>> {
        &self.0
    }
}

impl<P, I> KeyShare<P, I>
where
    P: SchemeParams,
    I: Ord + Debug + Clone,
{
    pub(crate) fn new(
        owner: I,
        secret: Secret<Scalar<P>>,
        public_shares: BTreeMap<I, Point<P>>,
    ) -> Result<Self, LocalError> {
        if public_shares.values().sum::<Point<P>>() == Point::identity() {
            return Err(LocalError::new("Secret key shares add up to zero"));
        }
        Ok(KeyShare {
            owner,
            secret,
            public: PublicKeyShares(public_shares),
        })
    }

    /// Updates a key share with a change obtained from KeyRefresh protocol.
    pub fn update(self, change: KeyShareChange<P, I>) -> Result<Self, LocalError> {
        if self.owner != change.owner {
            return Err(LocalError::new(format!(
                "Owning party mismatch. self.owner={:?}, change.owner={:?}",
                self.owner, change.owner
            )));
        }
        if self.public.0.len() != change.public_share_changes.len() {
            return Err(LocalError::new(format!(
                "Inconsistent number of public key shares in updated share set (expected {}, was {})",
                self.public.0.len(),
                change.public_share_changes.len()
            )));
        }

        let secret = self.secret + change.secret_share_change;
        let public_shares = self
            .public
            .0
            .iter()
            .map(|(id, public_share)| {
                Ok((
                    id.clone(),
                    *public_share
                        + *change
                            .public_share_changes
                            .get(id)
                            .ok_or_else(|| LocalError::new("id={id:?} is missing in public_share_changes"))?,
                ))
            })
            .collect::<Result<_, LocalError>>()?;

        Ok(Self {
            owner: self.owner,
            secret,
            public: PublicKeyShares(public_shares),
        })
    }

    /// Creates a set of random self-consistent key shares
    /// (which in a decentralized case would be the output of KeyInit protocol).
    pub fn new_centralized(
        rng: &mut impl CryptoRngCore,
        ids: &BTreeSet<I>,
        signing_key: Option<&ecdsa::SigningKey<P::Curve>>,
    ) -> BTreeMap<I, Self> {
        let secret = Secret::init_with(|| match signing_key {
            None => Scalar::random(rng),
            Some(sk) => Scalar::from(sk.as_nonzero_scalar()),
        });

        let secret_shares = secret_split(rng, secret, ids.len());
        let public_shares = ids
            .iter()
            .zip(secret_shares.iter())
            .map(|(id, secret_share)| (id.clone(), secret_share.mul_by_generator()))
            .collect::<BTreeMap<_, _>>();

        ids.iter()
            .zip(secret_shares)
            .map(|(id, secret_share)| {
                (
                    id.clone(),
                    KeyShare {
                        owner: id.clone(),
                        secret: secret_share,
                        public: PublicKeyShares(public_shares.clone()),
                    },
                )
            })
            .collect()
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point<P> {
        self.public.0.values().sum()
    }

    /// Return the verifying key to which this set of shares corresponds.
    pub fn verifying_key(&self) -> VerifyingKey<P::Curve> {
        // All the constructors ensure that the shares add up to a non-infinity point.
        self.verifying_key_as_point()
            .to_verifying_key()
            .expect("the public shares add up to a non-infinity point")
    }

    /// Returns the owner of this key share.
    pub fn owner(&self) -> &I {
        &self.owner
    }

    pub(crate) fn secret_share(&self) -> &Secret<Scalar<P>> {
        &self.secret
    }

    pub(crate) fn public(&self) -> &PublicKeyShares<P, I> {
        &self.public
    }

    pub(crate) fn public_shares(&self) -> &BTreeMap<I, Point<P>> {
        &self.public.0
    }

    /// Returns the set of parties holding other shares from the set.
    pub fn all_parties(&self) -> BTreeSet<I> {
        self.public.0.keys().cloned().collect()
    }
}

impl<P: SchemeParams, I: Ord + Clone> AuxInfo<P, I> {
    /// Returns the owner of this aux data.
    pub fn owner(&self) -> &I {
        &self.owner
    }

    pub(crate) fn public(&self) -> &PublicAuxInfos<P, I> {
        &self.public
    }

    /// Returns an `AuxInfo` object for the given subset of all parties.
    pub fn subset(self, parties: &BTreeSet<I>) -> Result<Self, LocalError> {
        if !parties.contains(&self.owner) {
            return Err(LocalError::new(
                "The subset of parties must include the owner of the secret Aux Info",
            ));
        }

        Ok(Self {
            owner: self.owner,
            secret: self.secret,
            public: self.public.subset(parties)?,
        })
    }

    /// Creates a set of random self-consistent auxiliary data.
    /// (which in a decentralized case would be the output of AuxGen protocol).
    pub fn new_centralized(rng: &mut impl CryptoRngCore, ids: &BTreeSet<I>) -> BTreeMap<I, Self> {
        let secret_aux = (0..ids.len())
            .map(|_| SecretAuxInfo {
                paillier_sk: SecretKeyPaillierWire::<P::Paillier>::random(rng),
            })
            .collect::<Vec<_>>();

        let public_aux = ids
            .iter()
            .zip(secret_aux.iter())
            .map(|(id, secret)| {
                (
                    id.clone(),
                    PublicAuxInfo {
                        paillier_pk: secret.paillier_sk.public_key(),
                        rp_params: RPParams::random(rng).to_wire(),
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();

        ids.iter()
            .zip(secret_aux)
            .map(|(id, secret_aux)| {
                (
                    id.clone(),
                    Self {
                        owner: id.clone(),
                        secret: secret_aux,
                        public: PublicAuxInfos(public_aux.clone()),
                    },
                )
            })
            .collect()
    }

    pub(crate) fn into_precomputed(self) -> AuxInfoPrecomputed<P, I> {
        AuxInfoPrecomputed {
            secret_aux: SecretAuxInfoPrecomputed {
                paillier_sk: self.secret.paillier_sk.clone().into_precomputed(),
            },
            public_aux: self
                .public
                .0
                .iter()
                .map(|(id, public_aux)| {
                    let paillier_pk = public_aux.paillier_pk.clone().into_precomputed();
                    (
                        id.clone(),
                        PublicAuxInfoPrecomputed {
                            paillier_pk: paillier_pk.clone(),
                            rp_params: public_aux.rp_params.to_precomputed(),
                        },
                    )
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use ecdsa::{SigningKey, VerifyingKey};
    use rand_core::OsRng;

    use super::KeyShare;
    use crate::{cggmp21::TestParams, SchemeParams};

    #[test]
    fn key_share_centralized() {
        let sk = SigningKey::random(&mut OsRng);

        let ids = (0..3)
            .map(|_| *SigningKey::random(&mut OsRng).verifying_key())
            .collect::<BTreeSet<_>>();

        let shares = KeyShare::<TestParams, VerifyingKey<<TestParams as SchemeParams>::Curve>>::new_centralized(
            &mut OsRng,
            &ids,
            Some(&sk),
        );
        assert!(shares
            .values()
            .all(|share| &share.verifying_key() == sk.verifying_key()));
    }
}
