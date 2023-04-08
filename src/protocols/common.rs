use alloc::boxed::Box;

use serde::{Deserialize, Serialize};

use crate::paillier::{PaillierParams, PaillierTest, PublicKeyPaillier, SecretKeyPaillier};
use crate::tools::group::{NonZeroScalar, Point, Scalar};
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
    pub fn random() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
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
pub struct KeyShare {
    /// Secret key share of this node.
    pub secret: Scalar, // `x`
    /// Public key shares of all nodes (including this one).
    pub public: Box<[Point]>, // `X`
}

/// The secret part of the result of the Auxiliary Info & Key Refresh protocol.
pub struct AuxDataSecret<P: PaillierParams> {
    /// The value to be added to the secret share.
    pub(crate) share_change: Scalar, // `x_i^* - x_i == \sum_{j} x_j^i`
    pub(crate) y: NonZeroScalar, // TODO: a more descriptive name? Where is it even used?
    /// The Paillier secret key.
    pub(crate) paillier_sk: SecretKeyPaillier<P>,
}

/// The public part of the result of the Auxiliary Info & Key Refresh protocol.
pub struct AuxDataPublic<P: PaillierParams> {
    /// The value to be added to the public share of a remote node.
    pub(crate) share_change: Point, // `X_k^* - X_k == \sum_j X_j^k`
    pub(crate) y: Point, // TODO: a more descriptive name? Where is it even used?
    /// The Paillier public key.
    pub(crate) paillier_pk: PublicKeyPaillier<P>,
    /// The ring-Pedersen generator.
    pub(crate) rp_generator: P::DoubleUint, // `t_i`
    /// The ring-Pedersen power (a number belonging to the group produced by the generator).
    pub(crate) rp_power: P::DoubleUint, // `s_i`
}

/// The result of the Auxiliary Info & Key Refresh protocol.
pub struct AuxData<P: PaillierParams> {
    pub(crate) secret: AuxDataSecret<P>,
    pub(crate) public: Box<[AuxDataPublic<P>]>,
}
