use alloc::boxed::Box;

use rand_core::{CryptoRng, RngCore};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::paillier::{PaillierParams, PaillierTest, PublicKeyPaillier, SecretKeyPaillier};
use crate::tools::group::{Point, Scalar};
use crate::tools::hashing::{Chain, Hashable};

// TODO: this trait can include curve scalar/point types as well,
// but for now they are hardcoded to `k256`.
pub trait SchemeParams: Clone {
    const SECURITY_PARAMETER: usize;
    type Paillier: PaillierParams;
}

#[derive(Clone)]
pub struct TestSchemeParams;

impl SchemeParams for TestSchemeParams {
    const SECURITY_PARAMETER: usize = 10;
    type Paillier = PaillierTest;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionId([u8; 32]);

impl SessionId {
    pub fn random(rng: &mut (impl CryptoRng + RngCore)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl Hashable for SessionId {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain_constant_sized_bytes(&self.0)
    }
}

/// The result of the Keygen protocol.
#[derive(Clone)]
pub struct KeyShareSeed {
    /// Secret key share of this node.
    pub secret: Scalar, // `x`
    /// Public key shares of all nodes (including this one).
    pub public: Box<[Point]>, // `X`
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "SecretKeyPaillier<P::Paillier>: Serialize, KeySharePublic<P>: Serialize"
))]
#[serde(bound(
    deserialize = "for <'x> SecretKeyPaillier<P::Paillier>: Deserialize<'x>,
        for <'x> KeySharePublic<P>: Deserialize<'x>"
))]
pub struct KeyShare<P: SchemeParams> {
    pub secret: Scalar,
    pub sk: SecretKeyPaillier<P::Paillier>,
    pub(crate) y: Scalar, // TODO: a more descriptive name? Where is it even used?
    pub public: Box<[KeySharePublic<P>]>,
}

impl<P: SchemeParams> KeyShare<P> {
    pub(crate) fn verifying_key_as_point(&self) -> Point {
        self.public.iter().map(|p| p.x).sum()
    }

    pub fn verifying_key(&self) -> Option<VerifyingKey> {
        // TODO: can we unwrap here and get rid of Option?
        self.verifying_key_as_point().to_verifying_key()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct KeySharePublic<P: SchemeParams> {
    pub(crate) x: Point,
    pub(crate) y: Point, // TODO: a more descriptive name? Where is it even used?
    /// The Paillier public key.
    pub(crate) paillier_pk: PublicKeyPaillier<P::Paillier>,
    /// The ring-Pedersen generator.
    pub(crate) rp_generator: <P::Paillier as PaillierParams>::DoubleUint, // `t_i`
    /// The ring-Pedersen power (a number belonging to the group produced by the generator).
    pub(crate) rp_power: <P::Paillier as PaillierParams>::DoubleUint, // `s_i`
}

/// The result of the Auxiliary Info & Key Refresh protocol - the update to the key share.
#[derive(Clone)]
pub struct KeyShareChange<P: SchemeParams> {
    /// The value to be added to the secret share.
    pub(crate) secret: Scalar, // `x_i^* - x_i == \sum_{j} x_j^i`
    pub sk: SecretKeyPaillier<P::Paillier>,
    pub(crate) y: Scalar, // TODO: a more descriptive name? Where is it even used?
    pub(crate) public: Box<[KeyShareChangePublic<P>]>,
}

#[derive(Clone)]
pub struct KeyShareChangePublic<P: SchemeParams> {
    /// The value to be added to the public share of a remote node.
    pub(crate) x: Point, // `X_k^* - X_k == \sum_j X_j^k`, for all nodes
    pub(crate) y: Point, // TODO: a more descriptive name? Where is it even used?
    /// The Paillier public key.
    pub(crate) paillier_pk: PublicKeyPaillier<P::Paillier>,
    /// The ring-Pedersen generator.
    pub(crate) rp_generator: <P::Paillier as PaillierParams>::DoubleUint, // `t_i`
    /// The ring-Pedersen power (a number belonging to the group produced by the generator).
    pub(crate) rp_power: <P::Paillier as PaillierParams>::DoubleUint, // `s_i`
}

/// The result of the Presigning protocol.
#[derive(Clone)]
pub struct PresigningData {
    pub(crate) big_r: Point,
    pub(crate) k: Scalar,
    pub(crate) chi: Scalar,
}
