use alloc::boxed::Box;

#[cfg(any(test, feature = "bench-internals"))]
use alloc::vec::Vec;

use k256::ecdsa::VerifyingKey;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::cggmp21::SchemeParams;
use crate::curve::{Point, Scalar};
use crate::paillier::{
    Ciphertext, PaillierParams, PublicKeyPaillier, PublicKeyPaillierPrecomputed, RPParams,
    RPParamsMod, Randomizer, SecretKeyPaillier, SecretKeyPaillierPrecomputed,
};
use crate::rounds::PartyIdx;
use crate::tools::collections::HoleVec;
use crate::uint::Signed;

#[cfg(any(test, feature = "bench-internals"))]
use crate::{
    paillier::RandomizerMod,
    tools::collections::{HoleRange, HoleVecAccum},
    uint::FromScalar,
};

/// The result of the KeyInit protocol.
// TODO (#77): Debug can be derived automatically here if `secret_share` is wrapped in its own struct,
// or in a `SecretBox`-type wrapper.
#[derive(Clone)]
pub struct KeyShareSeed {
    /// Secret key share of this node.
    pub(crate) secret_share: Scalar, // `x_i`
    /// Public key shares of all nodes (including this one).
    pub(crate) public_shares: Box<[Point]>, // `X_j`
}

/// The full key share with auxiliary parameters.
// TODO (#77): Debug can be derived automatically here if `secret_share` is wrapped in its own struct,
// or in a `SecretBox`-type wrapper.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SecretAuxInfo<P>: Serialize,
        PublicAuxInfo<P>: Serialize"))]
#[serde(bound(deserialize = "SecretAuxInfo<P>: for<'x> Deserialize<'x>,
        PublicAuxInfo<P>: for <'x> Deserialize<'x>"))]
pub struct KeyShare<P: SchemeParams> {
    pub(crate) index: PartyIdx,
    pub(crate) secret_share: Scalar,
    pub(crate) public_shares: Box<[Point]>,
    pub(crate) secret_aux: SecretAuxInfo<P>,
    pub(crate) public_aux: Box<[PublicAuxInfo<P>]>,
}

// TODO (#77): Debug can be derived automatically here if `el_gamal_sk` is wrapped in its own struct,
// or in a `SecretBox`-type wrapper.
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SecretKeyPaillier<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "SecretKeyPaillier<P::Paillier>: for <'x> Deserialize<'x>"))]
pub(crate) struct SecretAuxInfo<P: SchemeParams> {
    pub(crate) paillier_sk: SecretKeyPaillier<P::Paillier>,
    pub(crate) el_gamal_sk: Scalar, // `y_i`
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
pub(crate) struct KeySharePrecomputed<P: SchemeParams> {
    pub(crate) index: PartyIdx,
    pub(crate) secret_share: Scalar,
    pub(crate) public_shares: Box<[Point]>,
    pub(crate) secret_aux: SecretAuxInfoPrecomputed<P>,
    pub(crate) public_aux: Box<[PublicAuxInfoPrecomputed<P>]>,
}

#[derive(Clone)]
pub(crate) struct SecretAuxInfoPrecomputed<P: SchemeParams> {
    pub(crate) paillier_sk: SecretKeyPaillierPrecomputed<P::Paillier>,
    #[allow(dead_code)] // TODO (#36): this will be needed for the 6-round presigning protocol.
    pub(crate) el_gamal_sk: Scalar,
}

#[derive(Clone)]
pub(crate) struct PublicAuxInfoPrecomputed<P: SchemeParams> {
    #[allow(dead_code)] // TODO (#36): this will be needed for the 6-round presigning protocol.
    pub(crate) el_gamal_pk: Point,
    pub(crate) paillier_pk: PublicKeyPaillierPrecomputed<P::Paillier>,
    pub(crate) rp_params: RPParamsMod<P::Paillier>,
}

/// The result of the Auxiliary Info & Key Refresh protocol - the update to the key share.
#[derive(Debug, Clone)]
pub struct KeyShareChange<P: SchemeParams> {
    pub(crate) index: PartyIdx,
    /// The value to be added to the secret share.
    pub(crate) secret_share_change: Scalar, // `x_i^* - x_i == \sum_{j} x_j^i`
    /// The values to be added to the public shares of remote nodes.
    pub(crate) public_share_changes: Box<[Point]>, // `X_k^* - X_k == \sum_j X_j^k`, for all nodes
    pub(crate) secret_aux: SecretAuxInfo<P>,
    pub(crate) public_aux: Box<[PublicAuxInfo<P>]>,
}

/// The result of the Presigning protocol.
#[derive(Debug, Clone)]
pub struct PresigningData<P: SchemeParams> {
    // TODO (#79): can we store nonce as a scalar?
    pub(crate) nonce: Point, // `R`
    /// An additive share of the ephemeral scalar `k`.
    pub(crate) ephemeral_scalar_share: Scalar, // `k_i`
    /// An additive share of `k * x` where `x` is the secret key.
    pub(crate) product_share: Scalar,
    // Values generated during presigning,
    // kept in case we need to generate a proof of correctness.
    pub(crate) hat_beta: HoleVec<Signed<<P::Paillier as PaillierParams>::Uint>>,
    pub(crate) hat_r: HoleVec<Randomizer<P::Paillier>>,
    pub(crate) hat_s: HoleVec<Randomizer<P::Paillier>>,
    pub(crate) cap_k: Ciphertext<P::Paillier>,
    pub(crate) hat_cap_d: HoleVec<Ciphertext<P::Paillier>>,
    pub(crate) hat_cap_f: HoleVec<Ciphertext<P::Paillier>>,
}

impl<P: SchemeParams> KeyShare<P> {
    /// Creates a key share out of the seed (obtained from the KeyGen protocol)
    /// and the share change (obtained from the KeyRefresh+Auxiliary protocol).
    pub(crate) fn new(seed: KeyShareSeed, change: KeyShareChange<P>) -> Self {
        // TODO (#68): check that party_idx is the same for both, and the number of parties is the same
        let secret_share = seed.secret_share + change.secret_share_change;
        let public_shares = seed
            .public_shares
            .iter()
            .zip(change.public_share_changes.into_vec())
            .map(|(public_share, public_share_change)| public_share + &public_share_change)
            .collect();
        Self {
            index: change.index,
            secret_share,
            public_shares,
            secret_aux: change.secret_aux,
            public_aux: change.public_aux,
        }
    }

    /// Returns `num_parties` of random self-consistent key shares
    /// (which in a decentralized case would be the output of KeyGen + Auxiliary protocols).
    pub fn new_centralized(
        rng: &mut impl CryptoRngCore,
        num_parties: usize,
        signing_key: Option<&k256::ecdsa::SigningKey>,
    ) -> Box<[Self]> {
        let secret = match signing_key {
            None => Scalar::random(rng),
            Some(sk) => Scalar::from(sk.as_nonzero_scalar()),
        };

        let secret_shares = secret.split(rng, num_parties);
        let public_shares = secret_shares
            .iter()
            .map(|s| s.mul_by_generator())
            .collect::<Box<_>>();

        let (secret_aux, public_aux) = make_aux_info(rng, num_parties);

        secret_aux
            .into_vec()
            .into_iter()
            .enumerate()
            .map(|(idx, secret_aux)| KeyShare {
                index: PartyIdx::from_usize(idx),
                secret_share: secret_shares[idx],
                public_shares: public_shares.clone(),
                secret_aux,
                public_aux: public_aux.clone(),
            })
            .collect()
    }

    /// Return the updated key share using the share change
    /// obtained from the KeyRefresh+Auxiliary protocol).
    pub fn update(self, change: KeyShareChange<P>) -> Self {
        // TODO (#68): check that party_idx is the same for both, and the number of parties is the same
        let secret_share = self.secret_share + change.secret_share_change;
        let public_shares = self
            .public_shares
            .iter()
            .zip(change.public_share_changes.into_vec())
            .map(|(public_share, public_share_change)| public_share + &public_share_change)
            .collect();
        Self {
            index: change.index,
            secret_share,
            public_shares,
            secret_aux: change.secret_aux,
            public_aux: change.public_aux,
        }
    }

    pub(crate) fn to_precomputed(&self) -> KeySharePrecomputed<P> {
        KeySharePrecomputed {
            index: self.index,
            secret_share: self.secret_share,
            public_shares: self.public_shares.clone(),
            secret_aux: SecretAuxInfoPrecomputed {
                paillier_sk: self.secret_aux.paillier_sk.to_precomputed(),
                el_gamal_sk: self.secret_aux.el_gamal_sk,
            },
            public_aux: self
                .public_aux
                .iter()
                .map(|public_aux| {
                    let paillier_pk = public_aux.paillier_pk.to_precomputed();
                    PublicAuxInfoPrecomputed {
                        el_gamal_pk: public_aux.el_gamal_pk,
                        paillier_pk: paillier_pk.clone(),
                        rp_params: public_aux.rp_params.to_mod(&paillier_pk),
                    }
                })
                .collect(),
        }
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point {
        self.public_shares.iter().sum()
    }

    /// Return the verifying key to which this set of shares corresponds.
    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO (#5): need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
    }

    /// Returns the number of parties in this set of shares.
    pub fn num_parties(&self) -> usize {
        // TODO (#31): technically it is `num_shares`, but for now we are equating the two,
        // since we assume that one party has one share.
        self.public_shares.len()
    }

    /// Returns the index of this share's party.
    pub fn party_index(&self) -> usize {
        // TODO (#31): technically it is the share index, but for now we are equating the two,
        // since we assume that one party has one share.
        self.index.as_usize()
    }
}

impl<P: SchemeParams> KeySharePrecomputed<P> {
    /// Returns the number of parties in this set of shares.
    pub fn num_parties(&self) -> usize {
        // TODO (#31): technically it is `num_shares`, but for now we are equating the two,
        // since we assume that one party has one share.
        self.public_shares.len()
    }

    /// Returns the index of this share's party.
    pub fn party_index(&self) -> PartyIdx {
        // TODO (#31): technically it is the share index, but for now we are equating the two,
        // since we assume that one party has one share.
        self.index
    }

    pub(crate) fn verifying_key_as_point(&self) -> Point {
        self.public_shares.iter().sum()
    }
}

impl<P: SchemeParams> PresigningData<P> {
    /// Creates a consistent set of presigning data for testing purposes.
    #[cfg(any(test, feature = "bench-internals"))]
    pub(crate) fn new_centralized(
        rng: &mut impl CryptoRngCore,
        key_shares: &[KeyShare<P>],
    ) -> Box<[Self]> {
        let ephemeral_scalar = Scalar::random(rng);
        let nonce = &Point::GENERATOR * &ephemeral_scalar.invert().unwrap();
        let ephemeral_scalar_shares = ephemeral_scalar.split(rng, key_shares.len());
        let secret: Scalar = key_shares
            .iter()
            .map(|key_share| key_share.secret_share)
            .sum();
        let product_shares = (ephemeral_scalar * secret).split(rng, key_shares.len());

        let num_parties = key_shares.len();
        let public_keys = key_shares[0]
            .public_aux
            .iter()
            .map(|aux| aux.paillier_pk.to_precomputed())
            .collect::<Vec<_>>();

        let cap_k = ephemeral_scalar_shares
            .iter()
            .enumerate()
            .map(|(i, k)| {
                Ciphertext::new(
                    rng,
                    &public_keys[i],
                    &<<P as SchemeParams>::Paillier as PaillierParams>::Uint::from_scalar(k),
                )
            })
            .collect::<Vec<_>>();

        let mut presigning = Vec::new();

        for i in 0..key_shares.len() {
            let mut hat_beta_vec = HoleVecAccum::new(num_parties, i);
            let mut hat_r_vec = HoleVecAccum::new(num_parties, i);
            let mut hat_s_vec = HoleVecAccum::new(num_parties, i);
            let mut hat_cap_d_vec = HoleVecAccum::new(num_parties, i);
            let mut hat_cap_f_vec = HoleVecAccum::new(num_parties, i);

            let x = key_shares[i].secret_share;
            let k = ephemeral_scalar_shares[i];

            for j in HoleRange::new(num_parties, i) {
                let hat_beta = Signed::random_bounded_bits(rng, P::LP_BOUND);
                let hat_r = RandomizerMod::random(rng, &public_keys[i]).retrieve();
                let hat_s = RandomizerMod::random(rng, &public_keys[j]).retrieve();

                let hat_cap_d = cap_k[j]
                    .homomorphic_mul(&public_keys[j], &Signed::from_scalar(&x))
                    .homomorphic_add(
                        &public_keys[j],
                        &Ciphertext::new_with_randomizer_signed(
                            &public_keys[j],
                            &-hat_beta,
                            &hat_s,
                        ),
                    );
                let hat_cap_f =
                    Ciphertext::new_with_randomizer_signed(&public_keys[j], &hat_beta, &hat_r);

                hat_beta_vec.insert(j, hat_beta);
                hat_r_vec.insert(j, hat_r);
                hat_s_vec.insert(j, hat_s);
                hat_cap_d_vec.insert(j, hat_cap_d);
                hat_cap_f_vec.insert(j, hat_cap_f);
            }

            presigning.push(PresigningData {
                nonce,
                ephemeral_scalar_share: k,
                product_share: product_shares[i],
                hat_beta: hat_beta_vec.finalize().unwrap(),
                hat_r: hat_r_vec.finalize().unwrap(),
                hat_s: hat_s_vec.finalize().unwrap(),
                hat_cap_d: hat_cap_d_vec.finalize().unwrap(),
                hat_cap_f: hat_cap_f_vec.finalize().unwrap(),
                cap_k: cap_k[i].clone(),
            });
        }

        presigning.into()
    }
}

// A custom Debug impl that skips the secret value
impl core::fmt::Debug for KeyShareSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "KeySeed {{ secret_share: <...>, public_shares: {:?} }}",
            self.public_shares,
        )
    }
}

// A custom Debug impl that skips the secret value
impl<P: SchemeParams> core::fmt::Debug for SecretAuxInfo<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(f, "SecretAuxInfo {{ <...> }}",)
    }
}

// A custom Debug impl that skips the secret values
impl<P: SchemeParams + core::fmt::Debug> core::fmt::Debug for KeyShare<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            concat![
                "KeyShare {{",
                "index: {:?}, ",
                "secret_share: <...>, ",
                "public_shares: {:?}, ",
                "secret_aux: {:?}, ",
                "public_aux: {:?} ",
                "}}"
            ],
            self.index, self.public_shares, self.secret_aux, self.public_aux
        )
    }
}

impl<P: SchemeParams> core::fmt::Display for KeyShare<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "KeyShare(idx={}, vkey={})",
            self.index.as_usize(),
            hex::encode(self.verifying_key_as_point().to_compressed_array())
        )
    }
}

#[allow(clippy::type_complexity)]
pub(crate) fn make_aux_info<P: SchemeParams>(
    rng: &mut impl CryptoRngCore,
    num_parties: usize,
) -> (Box<[SecretAuxInfo<P>]>, Box<[PublicAuxInfo<P>]>) {
    let secret_aux = (0..num_parties)
        .map(|_| SecretAuxInfo {
            paillier_sk: SecretKeyPaillier::<P::Paillier>::random(rng),
            el_gamal_sk: Scalar::random(rng),
        })
        .collect::<Box<_>>();

    let public_aux = secret_aux
        .iter()
        .map(|secret| {
            let sk = secret.paillier_sk.to_precomputed();
            PublicAuxInfo {
                paillier_pk: sk.public_key().to_minimal(),
                el_gamal_pk: secret.el_gamal_sk.mul_by_generator(),
                rp_params: RPParamsMod::random(rng, &sk).retrieve(),
            }
        })
        .collect();

    (secret_aux, public_aux)
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::SigningKey;
    use rand_core::OsRng;

    use super::KeyShare;
    use crate::TestParams;

    #[test]
    fn key_share_centralized() {
        let sk = SigningKey::random(&mut OsRng);
        let shares = KeyShare::<TestParams>::new_centralized(&mut OsRng, 3, Some(&sk));
        assert_eq!(&shares[0].verifying_key(), sk.verifying_key());
    }
}
