//! Scheme parametes for Secp256k1 curve (as implemented by [`k256']).

use core::fmt::Debug;

// We're depending on a pre-release `crypto-bigint` version,
// and `k256` depends on the released one.
// So as long as that is the case, `k256` `Uint` is separate
// from the one used throughout the crate.
use crypto_bigint::{nlimbs, Uint};
use elliptic_curve::bigint::{self as bigintv05};
use serde::{Deserialize, Serialize};
use sha3::Shake256;

#[cfg(feature = "bip32")]
use ecdsa::{SigningKey, VerifyingKey};

use super::traits::SchemeParams;
use crate::paillier::PaillierParams;

#[cfg(feature = "bip32")]
use crate::curve::{PublicTweakable, SecretTweakable};

/// Paillier parameters corresponding to 112 bits of security.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaillierProduction112;

// Source of the values: Appendix C.1.
impl PaillierParams for PaillierProduction112 {
    const PRIME_BITS: u32 = 1024;
    type HalfUint = Uint<{ nlimbs!(1024) }>;
    type Uint = Uint<{ nlimbs!(2048) }>;
    type WideUint = Uint<{ nlimbs!(4096) }>;
}

static_assertions::const_assert!(PaillierProduction112::SELF_CONSISTENT);

/// Paillier parameters corresponding to 128 bits of security.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaillierProduction128;

// Source of the values: Appendix C.1.
impl PaillierParams for PaillierProduction128 {
    const PRIME_BITS: u32 = 1536;
    type HalfUint = Uint<{ nlimbs!(1536) }>;
    type Uint = Uint<{ nlimbs!(3072) }>;
    type WideUint = Uint<{ nlimbs!(6144) }>;
}

static_assertions::const_assert!(PaillierProduction128::SELF_CONSISTENT);

/// Production strength parameters corresponding to 112 bits of security.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct ProductionParams112;

impl SchemeParams for ProductionParams112 {
    type Curve = k256::Secp256k1;
    type WideCurveUint = bigintv05::U512;
    type Digest = Shake256;
    const SECURITY_BITS: usize = 112;
    type Paillier = PaillierProduction112;
    type ExtraWideUint = Uint<{ nlimbs!(5120) }>;
}

static_assertions::const_assert!(ProductionParams112::SELF_CONSISTENT);

/// Production strength parameters corresponding to 128 bits of security.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct ProductionParams128;

impl SchemeParams for ProductionParams128 {
    type Curve = k256::Secp256k1;
    type WideCurveUint = bigintv05::U512;
    type Digest = Shake256;
    const SECURITY_BITS: usize = 128;
    type Paillier = PaillierProduction128;
    type ExtraWideUint = Uint<{ nlimbs!(7680) }>;
}

static_assertions::const_assert!(ProductionParams128::SELF_CONSISTENT);

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
