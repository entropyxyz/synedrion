//! Scheme parametes for Secp256k1 curve (as implemented by [`k256']).

use core::fmt::Debug;

// We're depending on a pre-release `crypto-bigint` version,
// and `k256` depends on the released one.
// So as long as that is the case, `k256` `Uint` is separate
// from the one used throughout the crate.
use crypto_bigint::{modular::MontyForm, nlimbs, NonZero, Uint, U1024, U2048, U4096};
use elliptic_curve::{
    bigint::{self as bigintv05},
    Curve,
};
use serde::{Deserialize, Serialize};
use sha3::Shake256;

#[cfg(feature = "bip32")]
use ecdsa::{SigningKey, VerifyingKey};

use super::traits::{convert_uint, upcast_uint, SchemeParams};
use crate::paillier::PaillierParams;

#[cfg(feature = "bip32")]
use crate::curve::{PublicTweakable, SecretTweakable};

type U1024Mod = MontyForm<{ nlimbs!(1024) }>;
type U2048Mod = MontyForm<{ nlimbs!(2048) }>;
type U4096Mod = MontyForm<{ nlimbs!(4096) }>;

/// Paillier parameters corresponding to 112 bits of security.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaillierProduction112;

// Source of the values: Appendix C.1.
impl PaillierParams for PaillierProduction112 {
    const PRIME_BITS: u32 = 1024;
    type HalfUint = U1024;
    type HalfUintMod = U1024Mod;
    type Uint = U2048;
    type UintMod = U2048Mod;
    type WideUint = U4096;
    type WideUintMod = U4096Mod;
    type ExtraWideUint = Uint<{ nlimbs!(5120) }>;
}

/// Production strength parameters.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct ProductionParams112;

impl SchemeParams for ProductionParams112 {
    type Curve = k256::Secp256k1;
    type WideCurveUint = bigintv05::U512;
    type Digest = Shake256;
    const SECURITY_BITS: usize = 112;
    const SECURITY_PARAMETER: usize = 256;
    const L_BOUND: u32 = 256;
    const EPS_BOUND: u32 = Self::L_BOUND * 2;
    const LP_BOUND: u32 = Self::L_BOUND * 5;
    type Paillier = PaillierProduction112;
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
impl SecretTweakable for SigningKey<<ProductionParams112 as SchemeParams>::Curve> {
    type Bip32Sk = SigningKey<<ProductionParams112 as SchemeParams>::Curve>;

    fn tweakable_sk(&self) -> Self::Bip32Sk {
        self.clone()
    }

    fn key_from_tweakable_sk(sk: &Self::Bip32Sk) -> Self {
        sk.clone()
    }
}

#[cfg(feature = "bip32")]
impl PublicTweakable for VerifyingKey<<ProductionParams112 as SchemeParams>::Curve> {
    type Bip32Pk = VerifyingKey<<ProductionParams112 as SchemeParams>::Curve>;
    fn tweakable_pk(&self) -> Self::Bip32Pk {
        *self
    }
    fn key_from_tweakable_pk(pk: &Self::Bip32Pk) -> Self {
        *pk
    }
}

#[cfg(test)]
mod tests {
    use super::{ProductionParams112, SchemeParams};

    #[test]
    fn parameter_consistency() {
        assert!(ProductionParams112::are_self_consistent());
    }
}
