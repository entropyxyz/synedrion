use alloc::boxed::Box;

use k256::ecdsa::VerifyingKey;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::cggmp21::SchemeParams;
use crate::curve::{Point, Scalar};
use crate::paillier::{
    PublicKeyPaillier, PublicKeyPaillierPrecomputed, RPParams, RPParamsMod, SecretKeyPaillier,
    SecretKeyPaillierPrecomputed,
};
use crate::tools::hashing::{Chain, Hashable};

/// A typed integer denoting the index of a party in the group.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PartyIdx(u32);

impl PartyIdx {
    /// Converts the party index to a regular integer.
    pub fn as_usize(self) -> usize {
        self.0.try_into().unwrap()
    }

    /// Wraps an integers into the party index.
    pub fn from_usize(val: usize) -> Self {
        Self(val.try_into().unwrap())
    }
}

impl Hashable for PartyIdx {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.0)
    }
}

/// The result of the Keygen protocol.
// TODO: Debug can be derived automatically here if `secret_share` is wrapped in its own struct,
// or in a `SecretBox`-type wrapper.
#[derive(Clone)]
pub struct KeyShareSeed {
    /// Secret key share of this node.
    pub(crate) secret_share: Scalar, // `x_i`
    /// Public key shares of all nodes (including this one).
    pub(crate) public_shares: Box<[Point]>, // `X_j`
}

/// The full key share with auxiliary parameters.
// TODO: Debug can be derived automatically here if `secret_share` is wrapped in its own struct,
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

// TODO: Debug can be derived automatically here if `el_gamal_sk` is wrapped in its own struct,
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
    /// Auxiliary public key and ring-Pedersen parameters (for ZK proofs).
    pub(crate) aux_paillier_pk: PublicKeyPaillier<P::Paillier>,
    pub(crate) aux_rp_params: RPParams<P::Paillier>,
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
    #[allow(dead_code)]
    pub(crate) el_gamal_sk: Scalar,
}

#[derive(Clone)]
pub(crate) struct PublicAuxInfoPrecomputed<P: SchemeParams> {
    #[allow(dead_code)]
    pub(crate) el_gamal_pk: Point,
    pub(crate) paillier_pk: PublicKeyPaillierPrecomputed<P::Paillier>,
    pub(crate) aux_rp_params: RPParamsMod<P::Paillier>,
    #[allow(dead_code)]
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
pub struct PresigningData {
    // CHECK: can we store nonce as a scalar?
    pub(crate) nonce: Point, // `R`
    /// An additive share of the ephemeral scalar `k`.
    pub(crate) ephemeral_scalar_share: Scalar, // `k_i`
    /// An additive share of `k * x` where `x` is the secret key.
    pub(crate) product_share: Scalar,
}

impl<P: SchemeParams> KeyShare<P> {
    /// Creates a key share out of the seed (obtained from the KeyGen protocol)
    /// and the share change (obtained from the KeyRefresh+Auxiliary protocol).
    pub fn new(seed: KeyShareSeed, change: KeyShareChange<P>) -> Self {
        // TODO: check that party_idx is the same for both, and the number of parties is the same
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
        // TODO: check that party_idx is the same for both, and the number of parties is the same
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
                    let aux_paillier_pk = public_aux.aux_paillier_pk.to_precomputed();
                    PublicAuxInfoPrecomputed {
                        el_gamal_pk: public_aux.el_gamal_pk,
                        paillier_pk: paillier_pk.clone(),
                        rp_params: public_aux.rp_params.to_mod(&paillier_pk),
                        aux_rp_params: public_aux.aux_rp_params.to_mod(&aux_paillier_pk),
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
}

impl<P: SchemeParams> KeySharePrecomputed<P> {
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
}

impl PresigningData {
    /// Creates a consistent set of presigning data for testing purposes.
    #[cfg(any(test, feature = "bench-internals"))]
    pub(crate) fn new_centralized<P: SchemeParams>(
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

        ephemeral_scalar_shares
            .into_iter()
            .zip(product_shares)
            .map(|(ephemeral_scalar_share, product_share)| PresigningData {
                nonce,
                ephemeral_scalar_share,
                product_share,
            })
            .collect()
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
            let aux_sk = SecretKeyPaillier::<P::Paillier>::random(rng).to_precomputed();
            PublicAuxInfo {
                paillier_pk: sk.public_key().to_minimal(),
                aux_paillier_pk: aux_sk.public_key().to_minimal(),
                aux_rp_params: RPParamsMod::random(rng, &aux_sk).retrieve(),
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
