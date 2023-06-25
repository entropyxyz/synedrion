use alloc::boxed::Box;

use k256::ecdsa::VerifyingKey;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::curve::{Point, Scalar};
use crate::paillier::{PaillierParams, PaillierTest, PublicKeyPaillier, SecretKeyPaillier};
use crate::tools::hashing::{Chain, Hashable};

// TODO: this trait can include curve scalar/point types as well,
// but for now they are hardcoded to `k256`.
pub trait SchemeParams: Clone + Send {
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
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
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

// TODO: should it be here? HoleVecs can just function with usizes I think.
// Maybe it's better moved to `protocols/common`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PartyIdx(u32);

impl PartyIdx {
    pub fn as_usize(self) -> usize {
        self.0.try_into().unwrap()
    }

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
#[derive(Clone)]
pub struct KeyShareSeed {
    /// Secret key share of this node.
    pub secret: Scalar, // `x`
    /// Public key shares of all nodes (including this one).
    pub public: Box<[Point]>, // `X`
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SecretKeyPaillier<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "SecretKeyPaillier<P::Paillier>: for<'x> Deserialize<'x>"))]
pub struct KeyShareSecret<P: SchemeParams> {
    pub(crate) secret: Scalar,
    pub(crate) sk: SecretKeyPaillier<P::Paillier>,
    pub(crate) y: Scalar, // TODO: a more descriptive name? Where is it even used?
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "KeyShareSecret<P>: Serialize,
        KeySharePublic<P>: Serialize"))]
#[serde(bound(deserialize = "KeyShareSecret<P>: for<'x> Deserialize<'x>,
        KeySharePublic<P>: for <'x> Deserialize<'x>"))]
pub struct KeyShare<P: SchemeParams> {
    pub(crate) index: PartyIdx,
    pub(crate) secret: KeyShareSecret<P>,
    pub(crate) public: Box<[KeySharePublic<P>]>,
}

impl<P: SchemeParams> KeyShare<P> {
    pub(crate) fn verifying_key_as_point(&self) -> Point {
        self.public.iter().map(|p| p.x).sum()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        // TODO: need to ensure on creation of the share that the verifying key actually exists
        // (that is, the sum of public keys does not evaluate to the infinity point)
        self.verifying_key_as_point().to_verifying_key().unwrap()
    }

    pub fn num_parties(&self) -> usize {
        // TODO: technically it is `num_shares`, but for now we are equating the two,
        // since we assume that one party has one share.
        self.public.len()
    }

    pub fn party_index(&self) -> PartyIdx {
        // TODO: technically it is the share index, but for now we are equating the two,
        // since we assume that one party has one share.
        self.index
    }
}

impl<P: SchemeParams> core::fmt::Debug for KeyShare<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        write!(
            f,
            "KeyShare(vkey={})",
            hex::encode(self.verifying_key_as_point().to_compressed_array())
        )
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "SecretKeyPaillier<P::Paillier>: Serialize"))]
#[serde(bound(deserialize = "SecretKeyPaillier<P::Paillier>: for <'x> Deserialize<'x>"))]
pub struct KeyShareChangeSecret<P: SchemeParams> {
    /// The value to be added to the secret share.
    #[allow(dead_code)] // TODO: to be used in KeyShare.apply(KeyShareChange)
    pub(crate) secret: Scalar, // `x_i^* - x_i == \sum_{j} x_j^i`
    pub sk: SecretKeyPaillier<P::Paillier>,
    #[allow(dead_code)] // TODO: to be used in KeyShare.apply(KeyShareChange)
    pub(crate) y: Scalar, // TODO: a more descriptive name? Where is it even used?
}

#[derive(Clone)]
pub struct KeyShareChangePublic<P: SchemeParams> {
    /// The value to be added to the public share of a remote node.
    #[allow(dead_code)] // TODO: to be used in KeyShare.apply(KeyShareChange)
    pub(crate) x: Point, // `X_k^* - X_k == \sum_j X_j^k`, for all nodes
    #[allow(dead_code)] // TODO: to be used in KeyShare.apply(KeyShareChange)
    pub(crate) y: Point, // TODO: a more descriptive name? Where is it even used?
    /// The Paillier public key.
    #[allow(dead_code)] // TODO: to be used in KeyShare.apply(KeyShareChange)
    pub(crate) paillier_pk: PublicKeyPaillier<P::Paillier>,
    /// The ring-Pedersen generator.
    #[allow(dead_code)] // TODO: to be used in KeyShare.apply(KeyShareChange)
    pub(crate) rp_generator: <P::Paillier as PaillierParams>::DoubleUint, // `t_i`
    /// The ring-Pedersen power (a number belonging to the group produced by the generator).
    #[allow(dead_code)] // TODO: to be used in KeyShare.apply(KeyShareChange)
    pub(crate) rp_power: <P::Paillier as PaillierParams>::DoubleUint, // `s_i`
}

/// The result of the Auxiliary Info & Key Refresh protocol - the update to the key share.
#[derive(Clone)]
pub struct KeyShareChange<P: SchemeParams> {
    #[allow(dead_code)] // TODO: to be used in KeyShare.apply(KeyShareChange)
    pub(crate) secret: KeyShareChangeSecret<P>,
    #[allow(dead_code)] // TODO: to be used in KeyShare.apply(KeyShareChange)
    pub(crate) public: Box<[KeyShareChangePublic<P>]>,
}

/// The result of the Presigning protocol.
#[derive(Clone)]
pub struct PresigningData {
    pub(crate) big_r: Point,
    pub(crate) k: Scalar,
    pub(crate) chi: Scalar,
}
