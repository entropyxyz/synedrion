use core::{fmt::Debug, ops::Add};

// We're depending on a pre-release `crypto-bigint` version,
// and `k256` depends on the released one.
// So as long as that is the case, `k256` `Uint` is separate
// from the one used throughout the crate.
use crypto_bigint::{NonZero, Uint, U1024, U128, U2048, U256, U4096, U512, U8192};
use digest::generic_array::ArrayLength;
use ecdsa::hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive};
use elliptic_curve::{
    bigint::{self as bigintv05, Concat, Uint as CurveUint},
    point::DecompressPoint,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve, CurveArithmetic, PrimeCurve, PrimeField,
};
use serde::{Deserialize, Serialize};

use tiny_curve::TinyCurve32;

use crate::{
    paillier::PaillierParams,
    tools::hashing::HashableType,
    uint::{U1024Mod, U128Mod, U2048Mod, U256Mod, U4096Mod, U512Mod},
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaillierTest;

#[allow(clippy::indexing_slicing)]
const fn upcast_uint<const N1: usize, const N2: usize>(value: CurveUint<N1>) -> CurveUint<N2> {
    assert!(N2 >= N1, "Upcast target must be bigger than the upcast candidate");
    let mut result_words = [0; N2];
    let mut i = 0;
    let words = value.as_words();
    while i < N1 {
        result_words[i] = words[i];
        i += 1;
    }
    CurveUint::from_words(result_words)
}

const fn convert_uint<const N: usize>(value: CurveUint<N>) -> Uint<N> {
    Uint::from_words(value.to_words())
}

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
    type ExtraWideUint = U8192;
}

/// Signing scheme parameters.
pub trait SchemeParams: 'static + Debug + Clone + Send + PartialEq + Eq + Send + Sync + Ord + Copy + Serialize
where
    <Self::Curve as CurveArithmetic>::ProjectivePoint: FromEncodedPoint<Self::Curve>,
    <Self::Curve as Curve>::FieldBytesSize: ModulusSize,
    <<Self as SchemeParams>::Curve as CurveArithmetic>::AffinePoint: ToEncodedPoint<Self::Curve>
        + FromEncodedPoint<Self::Curve>
        + DecompressPoint<Self::Curve>
        + VerifyPrimitive<Self::Curve>,
    <Self::Curve as CurveArithmetic>::Scalar: SignPrimitive<Self::Curve> + Ord,
    <<Self::Curve as Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
    <Self::Curve as Curve>::Uint: Concat<Output = Self::WideCurveUint>,
{
    /// The elliptic curve (of prime order) used.
    type Curve: CurveArithmetic + PrimeCurve + HashableType + DigestPrimitive;
    /// Double the curve Scalar-width integer type.
    type WideCurveUint: bigintv05::Integer + bigintv05::Split<Output = <Self::Curve as Curve>::Uint>;

    /// The number of bits of security provided by the scheme.
    const SECURITY_BITS: usize; // $m$ in the paper
    /// The order of the curve.
    const CURVE_ORDER: NonZero<<Self::Paillier as PaillierParams>::Uint>; // $q$
    /// The order of the curve as a wide integer.
    const CURVE_ORDER_WIDE: NonZero<<Self::Paillier as PaillierParams>::WideUint>;
    /// The scheme's statistical security parameter.
    const SECURITY_PARAMETER: usize; // $\kappa$ in the paper
    /// The bound for secret values.
    const L_BOUND: u32; // $\ell$, paper sets it to $\log2(q)$ (see Table 2)
    /// The error bound for secret masks.
    const LP_BOUND: u32; // $\ell^\prime$, in paper $= 5 \ell$ (see Table 2)
    /// The error bound for range checks (referred to in the paper as the slackness parameter).
    const EPS_BOUND: u32; // $\eps$, in paper $= 2 \ell$ (see Table 2)
    /// The parameters of the Paillier encryption.
    ///
    /// Note: `PaillierParams::Uint` must be able to contain the full range of `Scalar` values
    /// plus one bit (so that any curve scalar still represents a positive value
    /// when treated as a 2-complement signed integer).
    type Paillier: PaillierParams;

    /// Returns ``true`` if the parameters satisfy a set of inequalities
    /// required for them to be used for the CGGMP scheme.
    fn are_self_consistent() -> bool {
        // See Appendix C.1
        <<Self::Curve as CurveArithmetic>::Scalar as PrimeField>::NUM_BITS == Self::SECURITY_PARAMETER as u32
        && Self::L_BOUND >= Self::SECURITY_PARAMETER as u32
        && Self::EPS_BOUND >= Self::L_BOUND + Self::SECURITY_PARAMETER as u32
        && Self::LP_BOUND >= Self::L_BOUND * 3 + Self::EPS_BOUND
        && Self::Paillier::MODULUS_BITS >= Self::LP_BOUND + Self::EPS_BOUND
        // This one is not mentioned in C.1, but is required by $П^{fac}$ (Fig. 26)
        // (it says $\approx$, not $=$, but it is not clear how approximately this should hold,
        // so to be on the safe side we require equality).
        && Self::L_BOUND * 2 + Self::EPS_BOUND == Self::Paillier::PRIME_BITS
    }
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

/// Production strength parameters.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize, Ord, PartialOrd)]
pub struct ProductionParams112;

impl SchemeParams for ProductionParams112 {
    type Curve = k256::Secp256k1;
    type WideCurveUint = bigintv05::U512;
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

#[cfg(test)]
mod tests {
    use super::{
        bigintv05::{U256, U64},
        upcast_uint, ProductionParams112, SchemeParams, TestParams,
    };

    #[test]
    fn upcast_uint_results_in_a_bigger_type() {
        let n = U64::from_u8(10);
        let expected = U256::from_u8(10);
        let bigger_n: U256 = upcast_uint(n);

        assert_eq!(bigger_n, expected);
    }

    #[test]
    #[should_panic(expected = "Upcast target must be bigger than the upcast candidate")]
    fn upcast_uint_panics_in_test_if_actually_attempting_downcast() {
        let n256 = U256::from_u8(8);
        let _n: U64 = upcast_uint(n256);
    }

    #[test]
    fn upcast_uint_allows_casting_to_same_size() {
        let n256 = U256::from_u8(8);
        let n: U256 = upcast_uint(n256);
        assert_eq!(n, n256)
    }

    #[test]
    fn parameter_consistency() {
        assert!(ProductionParams112::are_self_consistent());
        assert!(TestParams::are_self_consistent());
    }
}
