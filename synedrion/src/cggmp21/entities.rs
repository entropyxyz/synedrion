use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};
use manul::session::LocalError;

use k256::ecdsa::VerifyingKey;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    cggmp21::SchemeParams,
    curve::{secret_split, Point, Scalar},
    paillier::{
        Ciphertext, PaillierParams, PublicKeyPaillier, PublicKeyPaillierWire, RPParams, RPParamsWire, Randomizer,
        SecretKeyPaillier, SecretKeyPaillierWire,
    },
    tools::Secret,
    uint::Signed,
};

/// The result of the KeyInit protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare<P, I: Ord> {
    pub(crate) owner: I,
    /// Secret key share of this node.
    pub(crate) secret_share: Secret<Scalar>, // `x_i`
    pub(crate) public_shares: BTreeMap<I, Point>, // `X_j`
    // TODO (#27): this won't be needed when Scalar/Point are a part of `P`
    pub(crate) phantom: PhantomData<P>,
}

/// The result of the AuxGen protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuxInfo<P: SchemeParams, I: Ord> {
    pub(crate) owner: I,
    pub(crate) secret_aux: SecretAuxInfo<P>,
    pub(crate) public_aux: BTreeMap<I, PublicAuxInfo<P>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SecretKeyPaillierWire<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "SecretKeyPaillierWire<P::Paillier>: for <'x> Deserialize<'x>"))]
pub(crate) struct SecretAuxInfo<P: SchemeParams> {
    pub(crate) paillier_sk: SecretKeyPaillierWire<P::Paillier>,
    pub(crate) el_gamal_sk: Secret<Scalar>, // `y_i`
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicKeyPaillierWire<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "PublicKeyPaillierWire<P::Paillier>: for <'x> Deserialize<'x>"))]
pub(crate) struct PublicAuxInfo<P: SchemeParams> {
    pub(crate) el_gamal_pk: Point, // `Y_i`
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
    #[allow(dead_code)] // TODO (#36): this will be needed for the 6-round presigning protocol.
    pub(crate) el_gamal_sk: Secret<Scalar>, // `y_i`
}

#[derive(Debug, Clone)]
pub(crate) struct PublicAuxInfoPrecomputed<P: SchemeParams> {
    #[allow(dead_code)] // TODO (#36): this will be needed for the 6-round presigning protocol.
    pub(crate) el_gamal_pk: Point,
    pub(crate) paillier_pk: PublicKeyPaillier<P::Paillier>,
    pub(crate) rp_params: RPParams<P::Paillier>,
}

/// The result of the Auxiliary Info & Key Refresh protocol - the update to the key share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShareChange<P: SchemeParams, I: Ord> {
    pub(crate) owner: I,
    /// The value to be added to the secret share.
    pub(crate) secret_share_change: Secret<Scalar>, // `x_i^* - x_i == \sum_{j} x_j^i`
    /// The values to be added to the public shares of remote nodes.
    pub(crate) public_share_changes: BTreeMap<I, Point>, // `X_k^* - X_k == \sum_j X_j^k`, for all nodes
    // TODO (#27): this won't be needed when Scalar/Point are a part of `P`
    pub(crate) phantom: PhantomData<P>,
}

/// The result of the Presigning protocol.
#[derive(Debug, Clone)]
pub(crate) struct PresigningData<P: SchemeParams, I> {
    pub(crate) nonce: Scalar, // x-coordinate of $R$
    /// An additive share of the ephemeral scalar.
    pub(crate) ephemeral_scalar_share: Secret<Scalar>, // $k_i$
    /// An additive share of `k * x` where `x` is the secret key.
    pub(crate) product_share: Secret<Scalar>,

    // Values generated during presigning,
    // kept in case we need to generate a proof of correctness.
    pub(crate) product_share_nonreduced: Secret<Signed<<P::Paillier as PaillierParams>::Uint>>,

    // $K_i$.
    pub(crate) cap_k: Ciphertext<P::Paillier>,

    // The values for $j$, $j != i$.
    pub(crate) values: BTreeMap<I, PresigningValues<P>>,
}

#[derive(Debug, Clone)]
pub(crate) struct PresigningValues<P: SchemeParams> {
    pub(crate) hat_beta: Secret<Signed<<P::Paillier as PaillierParams>::Uint>>,
    pub(crate) hat_r: Randomizer<P::Paillier>,
    pub(crate) hat_s: Randomizer<P::Paillier>,
    pub(crate) cap_k: Ciphertext<P::Paillier>,
    /// Received $\hat{D}_{i,j}$.
    pub(crate) hat_cap_d_received: Ciphertext<P::Paillier>,
    /// Sent $\hat{D}_{j,i}$.
    pub(crate) hat_cap_d: Ciphertext<P::Paillier>,
    pub(crate) hat_cap_f: Ciphertext<P::Paillier>,
}

impl<P: SchemeParams, I: Clone + Ord + PartialEq + Debug> KeyShare<P, I> {
    /// Updates a key share with a change obtained from KeyRefresh protocol.
    pub fn update(self, change: KeyShareChange<P, I>) -> Result<Self, LocalError> {
        if self.owner != change.owner {
            return Err(LocalError::new(format!(
                "Owning party mismatch. self.owner={:?}, change.owner={:?}",
                self.owner, change.owner
            )));
        }
        if self.public_shares.len() != change.public_share_changes.len() {
            return Err(LocalError::new(format!(
                "Inconsistent number of public key shares in updated share set (expected {}, was {})",
                self.public_shares.len(),
                change.public_share_changes.len()
            )));
        }

        let secret_share = self.secret_share + change.secret_share_change;
        let public_shares = self
            .public_shares
            .iter()
            .zip(change.public_share_changes)
            // TODO(dp): this should fail, I'm pretty sure, but doesn't (no test)
            // let obviously_wrong_value = change.public_share_changes.first_key_value().unwrap().0.clone();
            // .map(|(pub_share, changed_pub_share)| (obviously_wrong_value.clone(), pub_share.1 + &changed_pub_share.1))
            .map(|(pub_share, changed_pub_share)| (changed_pub_share.0, *pub_share.1 + changed_pub_share.1))
            .collect();

        Ok(Self {
            owner: self.owner,
            secret_share,
            public_shares,
            phantom: PhantomData,
        })
    }

    /// Creates a set of random self-consistent key shares
    /// (which in a decentralized case would be the output of KeyInit protocol).
    pub fn new_centralized(
        rng: &mut impl CryptoRngCore,
        ids: &BTreeSet<I>,
        signing_key: Option<&k256::ecdsa::SigningKey>,
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
                        secret_share,
                        public_shares: public_shares.clone(),
                        phantom: PhantomData,
                    },
                )
            })
            .collect()
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point {
        self.public_shares.values().sum()
    }

    /// Return the verifying key to which this set of shares corresponds.
    pub fn verifying_key(&self) -> Option<VerifyingKey> {
        // TODO (#5): need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key()
    }

    /// Returns the owner of this key share.
    pub fn owner(&self) -> &I {
        &self.owner
    }

    /// Returns the set of parties holding other shares from the set.
    pub fn all_parties(&self) -> BTreeSet<I> {
        self.public_shares.keys().cloned().collect()
    }
}

impl<P: SchemeParams, I: Ord + Clone> AuxInfo<P, I> {
    /// Returns the owner of this aux data.
    pub fn owner(&self) -> &I {
        &self.owner
    }

    /// Creates a set of random self-consistent auxiliary data.
    /// (which in a decentralized case would be the output of AuxGen protocol).
    pub fn new_centralized(rng: &mut impl CryptoRngCore, ids: &BTreeSet<I>) -> BTreeMap<I, Self> {
        let secret_aux = (0..ids.len())
            .map(|_| SecretAuxInfo {
                paillier_sk: SecretKeyPaillierWire::<P::Paillier>::random(rng),
                el_gamal_sk: Secret::init_with(|| Scalar::random(rng)),
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
                        el_gamal_pk: secret.el_gamal_sk.mul_by_generator(),
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
                        secret_aux,
                        public_aux: public_aux.clone(),
                    },
                )
            })
            .collect()
    }

    pub(crate) fn into_precomputed(self) -> AuxInfoPrecomputed<P, I> {
        AuxInfoPrecomputed {
            secret_aux: SecretAuxInfoPrecomputed {
                paillier_sk: self.secret_aux.paillier_sk.clone().into_precomputed(),
                el_gamal_sk: self.secret_aux.el_gamal_sk.clone(),
            },
            public_aux: self
                .public_aux
                .iter()
                .map(|(id, public_aux)| {
                    let paillier_pk = public_aux.paillier_pk.clone().into_precomputed();
                    (
                        id.clone(),
                        PublicAuxInfoPrecomputed {
                            el_gamal_pk: public_aux.el_gamal_pk,
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

    use k256::ecdsa::{SigningKey, VerifyingKey};
    use rand_core::OsRng;

    use super::KeyShare;
    use crate::cggmp21::TestParams;

    #[test]
    fn key_share_centralized() {
        let sk = SigningKey::random(&mut OsRng);

        let ids = (0..3)
            .map(|_| *SigningKey::random(&mut OsRng).verifying_key())
            .collect::<BTreeSet<_>>();

        let shares = KeyShare::<TestParams, VerifyingKey>::new_centralized(&mut OsRng, &ids, Some(&sk));
        assert!(shares
            .values()
            .all(|share| &share.verifying_key().unwrap() == sk.verifying_key()));
    }
}
