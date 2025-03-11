use core::{fmt::Debug, ops::Add};

// We're depending on a pre-release `crypto-bigint` version,
// and `k256` depends on the released one.
// So as long as that is the case, `k256` `Uint` is separate
// from the one used throughout the crate.
use crypto_bigint::NonZero;
use digest::generic_array::ArrayLength;
use ecdsa::hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive};
use elliptic_curve::{
    bigint::{self as bigintv05, Concat, Split},
    point::DecompressPoint,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve, CurveArithmetic, PrimeCurve, PrimeField,
};
use serde::Serialize;

use crate::{paillier::PaillierParams, tools::hashing::HashableType};

#[cfg(any(test, feature = "k256", feature = "dev"))]
#[allow(clippy::indexing_slicing)]
pub(crate) const fn upcast_uint<const N1: usize, const N2: usize>(
    value: elliptic_curve::bigint::Uint<N1>,
) -> elliptic_curve::bigint::Uint<N2> {
    assert!(N2 >= N1, "Upcast target must be bigger than the upcast candidate");
    let mut result_words = [0; N2];
    let mut i = 0;
    let words = value.as_words();
    while i < N1 {
        result_words[i] = words[i];
        i += 1;
    }
    elliptic_curve::bigint::Uint::from_words(result_words)
}

#[cfg(any(test, feature = "k256", feature = "dev"))]
pub(crate) const fn convert_uint<const N: usize>(value: elliptic_curve::bigint::Uint<N>) -> crypto_bigint::Uint<N> {
    crypto_bigint::Uint::from_words(value.to_words())
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
    type WideCurveUint: bigintv05::Integer + Split<Output = <Self::Curve as Curve>::Uint>;

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

#[cfg(test)]
mod tests {
    use super::{
        bigintv05::{U256, U64},
        upcast_uint,
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
}
