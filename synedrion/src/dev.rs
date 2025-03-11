//! Parameters intended for testing, scaled down to small curve orders and integer sizes.

use crypto_bigint::{modular::MontyForm, nlimbs, NonZero, U1024, U128, U256, U512};
use elliptic_curve::{
    bigint::{self as bigintv05},
    Curve,
};
use serde::{Deserialize, Serialize};
use tiny_curve::TinyCurve32;

#[cfg(feature = "bip32")]
use ::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::{PublicKey, SecretKey},
    tiny_curve::{PrivateKeyBip32, PublicKeyBip32},
};

use crate::{
    cggmp21::{convert_uint, upcast_uint, SchemeParams},
    paillier::PaillierParams,
};

#[cfg(feature = "bip32")]
use crate::curve::{PublicTweakable, SecretTweakable};

type U128Mod = MontyForm<{ nlimbs!(128) }>;
type U256Mod = MontyForm<{ nlimbs!(256) }>;
type U512Mod = MontyForm<{ nlimbs!(512) }>;

/// Paillier parameters **for testing purposes only**.
/// Security is weakened to allow for faster execution.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaillierTest;

impl PaillierParams for PaillierTest {
    const PRIME_BITS: u32 = 128;
    type HalfUint = U128;
    type HalfUintMod = U128Mod;
    type Uint = U256;
    type UintMod = U256Mod;
    type WideUint = U512;
    type WideUintMod = U512Mod;
    type ExtraWideUint = U1024;
}

/// Scheme parameters **for testing purposes only**.
/// Security is weakened to allow for faster execution.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub struct TestParams;

impl SchemeParams for TestParams {
    type Curve = TinyCurve32;
    // TODO: ReprUint is typenum::U192 because of RustCrypto stack internals, hence the U384 here,
    // but once that is solved, this can be a U128 (or even smaller).
    type WideCurveUint = bigintv05::U384;
    const SECURITY_BITS: usize = 16;
    const SECURITY_PARAMETER: usize = 32;
    const L_BOUND: u32 = 32;
    const EPS_BOUND: u32 = 64;
    const LP_BOUND: u32 = 160;
    type Paillier = PaillierTest;
    const CURVE_ORDER: NonZero<<Self::Paillier as PaillierParams>::Uint> =
        convert_uint(upcast_uint(Self::Curve::ORDER))
            .to_nz()
            .expect("Correct by construction");
    const CURVE_ORDER_WIDE: NonZero<<Self::Paillier as PaillierParams>::WideUint> =
        convert_uint(upcast_uint(Self::Curve::ORDER))
            .to_nz()
            .expect("Correct by construction");
}

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

#[cfg(test)]
mod tests {
    use super::{SchemeParams, TestParams};

    #[test]
    fn parameter_consistency() {
        assert!(TestParams::are_self_consistent());
    }
}
