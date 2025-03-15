use core::{fmt::Debug, ops::Add};

// We're depending on a pre-release `crypto-bigint` version,
// and `k256` depends on the released one.
// So as long as that is the case, `k256` `Uint` is separate
// from the one used throughout the crate.
use crypto_bigint::{subtle::ConditionallySelectable, Bounded, Integer, NonZero, PowBoundedExp, RandomMod};
use digest::{ExtendableOutput, Update};
use ecdsa::hazmat::{DigestPrimitive, SignPrimitive, VerifyPrimitive};
use elliptic_curve::{
    bigint::{self as bigintv05, Concat, Split},
    generic_array::ArrayLength,
    point::DecompressPoint,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    Curve, CurveArithmetic, PrimeCurve, PrimeField,
};
use serde::Serialize;
use zeroize::Zeroize;

use crate::{
    curve::chain_curve,
    paillier::{chain_paillier_params, PaillierParams},
    tools::hashing::Chain,
    uint::{BoxedEncoding, Extendable},
};

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
    type Curve: CurveArithmetic + PrimeCurve + DigestPrimitive;
    /// Double the curve Scalar-width integer type.
    type WideCurveUint: bigintv05::Integer + Split<Output = <Self::Curve as Curve>::Uint>;

    /// The hash that will be used for protocol's internal purposes.
    ///
    /// Note: the collision probability must be consistent with [`Self::SECURITY_BITS`].
    type Digest: Default + Update + ExtendableOutput;

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
    type Paillier: PaillierParams<
        WideUint: Extendable<Self::ExtraWideUint>,
        Uint: Integer<Monty: PowBoundedExp<Self::ExtraWideUint>>,
    >;

    /// An integer that fits the squared RSA modulus times a small factor.
    /// Used in some ZK proofs.
    type ExtraWideUint: Bounded + ConditionallySelectable + Integer + RandomMod + BoxedEncoding + Zeroize;

    /// Evaluates to ``true`` if the parameters satisfy a set of inequalities
    /// required for them to be used for the CGGMP scheme.
    const SELF_CONSISTENT: bool =
        // See Appendix C.1
        <Self::Curve as CurveArithmetic>::Scalar::NUM_BITS == Self::SECURITY_PARAMETER as u32
        && Self::L_BOUND >= Self::SECURITY_PARAMETER as u32
        && Self::EPS_BOUND >= Self::L_BOUND + Self::SECURITY_PARAMETER as u32
        && Self::LP_BOUND >= Self::L_BOUND * 3 + Self::EPS_BOUND
        && Self::Paillier::MODULUS_BITS >= Self::LP_BOUND + Self::EPS_BOUND
        // This one is not mentioned in C.1, but is required by $П^{fac}$ (Fig. 26)
        // (it says $\approx$, not $=$, but it is not clear how approximately this should hold,
        // so to be on the safe side we require equality).
        && Self::L_BOUND * 2 + Self::EPS_BOUND == Self::Paillier::PRIME_BITS
        // Make sure the calculations in `П^{fac}` fit into `ExtraWideUint`
        // In that proof, we are sampling a random in range `∈ ±2^(L + EPS) * N^2`
        // and adding a much smaller number to it, so the absolute value of the result is
        // `< 2^(L + EPS + MODULUS_BITS * 2)`.
        // Therefore `ExtraWideUint::BITS` must fit `L + EPS + MODULUS_BITS * 2` bits,
        // and we make it strictly greater to accommodate 1 bit for the sign.
        && Self::ExtraWideUint::BITS > Self::Paillier::MODULUS_BITS * 2 + Self::L_BOUND + Self::EPS_BOUND;
}

pub(crate) fn chain_scheme_params<P, C>(digest: C) -> C
where
    P: SchemeParams,
    C: Chain,
{
    let digest = chain_curve::<P::Curve, _>(digest);
    let digest = chain_paillier_params::<P::Paillier, _>(digest);
    digest
        .chain_bytes(&(P::SECURITY_BITS as u32).to_be_bytes())
        .chain_bytes(&(P::SECURITY_PARAMETER as u32).to_be_bytes())
        .chain_bytes(&P::L_BOUND.to_be_bytes())
        .chain_bytes(&P::LP_BOUND.to_be_bytes())
        .chain_bytes(&P::EPS_BOUND.to_be_bytes())
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
