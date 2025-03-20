//! Parameters intended for testing, scaled down to small curve orders and integer sizes.

use crypto_bigint::{nlimbs, Uint};
use elliptic_curve::bigint::{self as bigintv05};
use serde::{Deserialize, Serialize};
use sha3::Shake256;
use tiny_curve::TinyCurve32;

#[cfg(feature = "bip32")]
use ::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::{PublicKey, SecretKey},
    tiny_curve::{PrivateKeyBip32, PublicKeyBip32},
};

use super::traits::SchemeParams;
use crate::paillier::PaillierParams;

#[cfg(feature = "bip32")]
use crate::curve::{PublicTweakable, SecretTweakable};

/// Paillier parameters **for testing purposes only**.
/// Security is weakened to allow for faster execution.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaillierTest;

impl PaillierParams for PaillierTest {
    const PRIME_BITS: u32 = 128;
    type HalfUint = Uint<{ nlimbs!(128) }>;
    type Uint = Uint<{ nlimbs!(256) }>;
    type WideUint = Uint<{ nlimbs!(512) }>;
}

static_assertions::const_assert!(PaillierTest::SELF_CONSISTENT);

/// Scheme parameters **for testing purposes only**.
/// Security is weakened to allow for faster execution.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct TestParams;

impl SchemeParams for TestParams {
    type Curve = TinyCurve32;
    // TODO: ReprUint is typenum::U192 because of RustCrypto stack internals, hence the U384 here,
    // but once that is solved, this can be a U128 (or even smaller).
    type WideCurveUint = bigintv05::U384;
    type Digest = Shake256;
    const SECURITY_BITS: usize = 16;
    type Paillier = PaillierTest;
    type ExtraWideUint = Uint<{ nlimbs!(640) }>;
}

static_assertions::const_assert!(TestParams::SELF_CONSISTENT);

#[cfg(feature = "bip32")]
impl PublicTweakable for VerifyingKey<<TestParams as SchemeParams>::Curve> {
    type Bip32Pk = PublicKeyBip32<<TestParams as SchemeParams>::Curve>;
    fn tweakable_pk(&self) -> Self::Bip32Pk {
        let pk: PublicKey<_> = self.into();
        let wrapped_pk: PublicKeyBip32<_> = pk.into();
        wrapped_pk
    }
    fn key_from_tweakable_pk(pk: &Self::Bip32Pk) -> Self {
        VerifyingKey::from(pk.as_ref())
    }
}

#[cfg(feature = "bip32")]
impl SecretTweakable for SigningKey<<TestParams as SchemeParams>::Curve> {
    type Bip32Sk = PrivateKeyBip32<<TestParams as SchemeParams>::Curve>;

    fn tweakable_sk(&self) -> Self::Bip32Sk {
        let sk: SecretKey<_> = self.into();
        let wrapped_sk: PrivateKeyBip32<_> = sk.into();
        wrapped_sk
    }

    fn key_from_tweakable_sk(sk: &Self::Bip32Sk) -> Self {
        SigningKey::from(sk.as_ref())
    }
}
