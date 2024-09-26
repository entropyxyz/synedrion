use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;

use k256::ecdsa::VerifyingKey;
use rand_core::CryptoRngCore;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use crate::cggmp21::SchemeParams;
use crate::curve::{Point, Scalar};
use crate::paillier::{
    CiphertextMod, PaillierParams, PublicKeyPaillier, PublicKeyPaillierPrecomputed, RPParams,
    RPParamsMod, Randomizer, SecretKeyPaillier, SecretKeyPaillierPrecomputed,
};
use crate::uint::Signed;

#[cfg(any(test, feature = "bench-internals"))]
use crate::paillier::RandomizerMod;

/// The result of the KeyInit protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare<P, I: Ord> {
    pub(crate) owner: I,
    /// Secret key share of this node.
    pub(crate) secret_share: SecretBox<Scalar>, // `x_i`
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
#[serde(bound(serialize = "SecretKeyPaillier<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "SecretKeyPaillier<P::Paillier>: for <'x> Deserialize<'x>"))]
pub(crate) struct SecretAuxInfo<P: SchemeParams> {
    pub(crate) paillier_sk: SecretKeyPaillier<P::Paillier>,
    pub(crate) el_gamal_sk: SecretBox<Scalar>, // `y_i`
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "PublicKeyPaillier<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "PublicKeyPaillier<P::Paillier>: for <'x> Deserialize<'x>"))]
pub(crate) struct PublicAuxInfo<P: SchemeParams> {
    pub(crate) el_gamal_pk: Point, // `Y_i`
    /// The Paillier public key.
    pub(crate) paillier_pk: PublicKeyPaillier<P::Paillier>,
    /// The ring-Pedersen parameters.
    pub(crate) rp_params: RPParams<P::Paillier>, // `s_i` and `t_i`
}

#[derive(Clone)]
pub(crate) struct AuxInfoPrecomputed<P: SchemeParams, I> {
    pub(crate) secret_aux: SecretAuxInfoPrecomputed<P>,
    pub(crate) public_aux: BTreeMap<I, PublicAuxInfoPrecomputed<P>>,
}

#[derive(Clone)]
pub(crate) struct SecretAuxInfoPrecomputed<P: SchemeParams> {
    pub(crate) paillier_sk: SecretKeyPaillierPrecomputed<P::Paillier>,
    #[allow(dead_code)] // TODO (#36): this will be needed for the 6-round presigning protocol.
    pub(crate) el_gamal_sk: SecretBox<Scalar>, // `y_i`
}

#[derive(Clone)]
pub(crate) struct PublicAuxInfoPrecomputed<P: SchemeParams> {
    #[allow(dead_code)] // TODO (#36): this will be needed for the 6-round presigning protocol.
    pub(crate) el_gamal_pk: Point,
    pub(crate) paillier_pk: PublicKeyPaillierPrecomputed<P::Paillier>,
    pub(crate) rp_params: RPParamsMod<P::Paillier>,
}

/// The result of the Auxiliary Info & Key Refresh protocol - the update to the key share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShareChange<P: SchemeParams, I: Ord> {
    pub(crate) owner: I,
    /// The value to be added to the secret share.
    pub(crate) secret_share_change: SecretBox<Scalar>, // `x_i^* - x_i == \sum_{j} x_j^i`
    /// The values to be added to the public shares of remote nodes.
    pub(crate) public_share_changes: BTreeMap<I, Point>, // `X_k^* - X_k == \sum_j X_j^k`, for all nodes
    // TODO (#27): this won't be needed when Scalar/Point are a part of `P`
    pub(crate) phantom: PhantomData<P>,
}

/// The result of the Presigning protocol.
#[derive(Debug, Clone)]
pub struct PresigningData<P: SchemeParams, I> {
    pub(crate) nonce: Scalar, // x-coordinate of $R$
    /// An additive share of the ephemeral scalar.
    pub(crate) ephemeral_scalar_share: SecretBox<Scalar>, // $k_i$
    /// An additive share of `k * x` where `x` is the secret key.
    pub(crate) product_share: SecretBox<Scalar>,

    // Values generated during presigning,
    // kept in case we need to generate a proof of correctness.
    pub(crate) product_share_nonreduced: Signed<<P::Paillier as PaillierParams>::Uint>,

    // $K_i$.
    pub(crate) cap_k: CiphertextMod<P::Paillier>,

    // The values for $j$, $j != i$.
    pub(crate) values: BTreeMap<I, PresigningValues<P>>,
}

#[derive(Debug, Clone)]
pub(crate) struct PresigningValues<P: SchemeParams> {
    pub(crate) hat_beta: SecretBox<Signed<<P::Paillier as PaillierParams>::Uint>>,
    pub(crate) hat_r: Randomizer<P::Paillier>,
    pub(crate) hat_s: Randomizer<P::Paillier>,
    pub(crate) cap_k: CiphertextMod<P::Paillier>,
    /// Received $\hat{D}_{i,j}$.
    pub(crate) hat_cap_d_received: CiphertextMod<P::Paillier>,
    /// Sent $\hat{D}_{j,i}$.
    pub(crate) hat_cap_d: CiphertextMod<P::Paillier>,
    pub(crate) hat_cap_f: CiphertextMod<P::Paillier>,
}

impl<P: SchemeParams, I: Clone + Ord + PartialEq + Debug> KeyShare<P, I> {
    /// Updates a key share with a change obtained from KeyRefresh protocol.
    pub(crate) fn update(self, change: KeyShareChange<P, I>) -> Self {
        // TODO (#68): check that party_idx is the same for both, and the number of parties is the same
        assert_eq!(self.owner, change.owner);

        let secret_share = SecretBox::new(Box::new(
            self.secret_share.expose_secret() + change.secret_share_change.expose_secret(),
        ));
        let public_shares = self
            .public_shares
            .iter()
            .map(|(id, public_share)| (id.clone(), public_share + &change.public_share_changes[id]))
            .collect();

        Self {
            owner: self.owner,
            secret_share,
            public_shares,
            phantom: PhantomData,
        }
    }

    /// Creates a set of random self-consistent key shares
    /// (which in a decentralized case would be the output of KeyInit protocol).
    pub fn new_centralized(
        rng: &mut impl CryptoRngCore,
        ids: &BTreeSet<I>,
        signing_key: Option<&k256::ecdsa::SigningKey>,
    ) -> BTreeMap<I, Self> {
        let secret = match signing_key {
            None => Scalar::random(rng),
            Some(sk) => Scalar::from(sk.as_nonzero_scalar()),
        };

        let secret_shares = secret.split(rng, ids.len());
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
                        secret_share: SecretBox::new(Box::new(secret_share)),
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
    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO (#5): need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
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
                paillier_sk: SecretKeyPaillier::<P::Paillier>::random(rng),
                el_gamal_sk: SecretBox::new(Box::new(Scalar::random(rng))),
            })
            .collect::<Vec<_>>();

        let public_aux = ids
            .iter()
            .zip(secret_aux.iter())
            .map(|(id, secret)| {
                let sk = secret.paillier_sk.to_precomputed();
                (
                    id.clone(),
                    PublicAuxInfo {
                        paillier_pk: sk.public_key().to_minimal(),
                        el_gamal_pk: secret.el_gamal_sk.expose_secret().mul_by_generator(),
                        rp_params: RPParamsMod::random(rng, &sk).retrieve(),
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

    pub(crate) fn to_precomputed(&self) -> AuxInfoPrecomputed<P, I> {
        AuxInfoPrecomputed {
            secret_aux: SecretAuxInfoPrecomputed {
                paillier_sk: self.secret_aux.paillier_sk.to_precomputed(),
                el_gamal_sk: self.secret_aux.el_gamal_sk.clone(),
            },
            public_aux: self
                .public_aux
                .iter()
                .map(|(id, public_aux)| {
                    let paillier_pk = public_aux.paillier_pk.to_precomputed();
                    (
                        id.clone(),
                        PublicAuxInfoPrecomputed {
                            el_gamal_pk: public_aux.el_gamal_pk,
                            paillier_pk: paillier_pk.clone(),
                            rp_params: public_aux.rp_params.to_mod(&paillier_pk),
                        },
                    )
                })
                .collect(),
        }
    }
}

impl<P, I> PresigningData<P, I>
where
    P: SchemeParams,
    I: Ord + Clone + PartialEq,
{
    /// Creates a consistent set of presigning data for testing purposes.
    #[cfg(any(test, feature = "bench-internals"))]
    pub(crate) fn new_centralized(
        rng: &mut impl CryptoRngCore,
        key_shares: &BTreeMap<I, KeyShare<P, I>>,
        aux_infos: &BTreeMap<I, AuxInfo<P, I>>,
    ) -> BTreeMap<I, Self> {
        let ids = key_shares.keys().cloned().collect::<BTreeSet<_>>();

        let ephemeral_scalar = Scalar::random(rng);
        let nonce = ephemeral_scalar
            .invert()
            .unwrap()
            .mul_by_generator()
            .x_coordinate();
        let ephemeral_scalar_shares = ephemeral_scalar.split(rng, key_shares.len());

        let ephemeral_scalar_shares = ids
            .iter()
            .zip(ephemeral_scalar_shares)
            .map(|(id, k)| (id.clone(), k))
            .collect::<BTreeMap<_, _>>();

        let public_keys = aux_infos
            .first_key_value()
            .unwrap()
            .1
            .public_aux
            .iter()
            .map(|(id, aux)| (id, aux.paillier_pk.to_precomputed()))
            .collect::<BTreeMap<_, _>>();

        let all_cap_k = ephemeral_scalar_shares
            .iter()
            .map(|(id, k)| {
                (
                    id.clone(),
                    CiphertextMod::new(rng, &public_keys[id], &P::uint_from_scalar(k)),
                )
            })
            .collect::<BTreeMap<_, _>>();

        let mut hat_betas = BTreeMap::new();
        let mut hat_ss = BTreeMap::new();
        let mut hat_cap_ds = BTreeMap::new();
        let mut hat_rs = BTreeMap::new();
        let mut hat_cap_fs = BTreeMap::new();

        for id_i in ids.iter() {
            let x_i = key_shares[id_i].secret_share.clone();
            let pk_i = &public_keys[id_i];

            for id_j in ids.iter().filter(|id| id != &id_i) {
                let hat_beta = Signed::random_bounded_bits(rng, P::LP_BOUND);
                let hat_s = RandomizerMod::random(rng, &public_keys[&id_j]).retrieve();
                let hat_r = RandomizerMod::random(rng, pk_i).retrieve();

                let hat_cap_d = &all_cap_k[id_j] * P::signed_from_scalar(x_i.expose_secret())
                    + CiphertextMod::new_with_randomizer_signed(
                        &public_keys[&id_j],
                        &-hat_beta,
                        &hat_s,
                    );
                let hat_cap_f = CiphertextMod::new_with_randomizer_signed(pk_i, &hat_beta, &hat_r);

                let id_ij = (id_i.clone(), id_j.clone());
                let id_ji = (id_j.clone(), id_i.clone());

                hat_betas.insert(id_ij.clone(), hat_beta);
                hat_ss.insert(id_ij.clone(), hat_s.clone());
                hat_rs.insert(id_ij.clone(), hat_r);

                hat_cap_ds.insert(id_ji.clone(), hat_cap_d);
                hat_cap_fs.insert(id_ji.clone(), hat_cap_f);
            }
        }

        let mut presigning = BTreeMap::new();

        for id_i in ids.iter() {
            let id_i = id_i.clone();

            let mut values = BTreeMap::new();

            for id_j in ids.iter().filter(|id| id != &&id_i) {
                let id_ij = (id_i.clone(), id_j.clone());
                let id_ji = (id_j.clone(), id_i.clone());

                values.insert(
                    id_j.clone(),
                    PresigningValues {
                        hat_beta: SecretBox::new(Box::new(hat_betas[&id_ij])),
                        hat_r: hat_rs[&id_ij].clone(),
                        hat_s: hat_ss[&id_ij].clone(),
                        hat_cap_d_received: hat_cap_ds[&id_ij].clone(),
                        hat_cap_d: hat_cap_ds[&id_ji].clone(),
                        hat_cap_f: hat_cap_fs[&id_ji].clone(),
                        cap_k: all_cap_k[id_j].clone(),
                    },
                );
            }

            let x_i = key_shares[&id_i].secret_share.clone();
            let k_i = ephemeral_scalar_shares[&id_i];

            let alpha_sum: Signed<_> = ids
                .iter()
                .filter(|id| id != &&id_i)
                .map(|id_j| {
                    P::signed_from_scalar(key_shares[id_j].secret_share.expose_secret())
                        * P::signed_from_scalar(&k_i)
                        - hat_betas[&(id_j.clone(), id_i.clone())]
                })
                .sum();

            let beta_sum: Signed<_> = ids
                .iter()
                .filter(|id| id != &&id_i)
                .map(|id_j| hat_betas[&(id_i.clone(), id_j.clone())])
                .sum();
            let product_share_nonreduced = P::signed_from_scalar(x_i.expose_secret())
                * P::signed_from_scalar(&k_i)
                + alpha_sum
                + beta_sum;

            presigning.insert(
                id_i.clone(),
                PresigningData {
                    nonce,
                    ephemeral_scalar_share: SecretBox::new(Box::new(k_i)),
                    product_share: SecretBox::new(Box::new(P::scalar_from_signed(
                        &product_share_nonreduced,
                    ))),
                    product_share_nonreduced,
                    cap_k: all_cap_k[&id_i].clone(),
                    values,
                },
            );
        }

        presigning
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

        let shares =
            KeyShare::<TestParams, VerifyingKey>::new_centralized(&mut OsRng, &ids, Some(&sk));
        assert!(shares
            .values()
            .all(|share| &share.verifying_key() == sk.verifying_key()));
    }
}
