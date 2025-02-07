use core::{fmt::Debug, ops::Add};

// We're depending on a pre-release `crypto-bigint` version,
// and `k256` depends on the released one.
// So as long as that is the case, `k256` `Uint` is separate
// from the one used throughout the crate.
use crypto_bigint::{NonZero, Uint, U1024, U2048, U4096, U512, U8192};
use digest::generic_array::ArrayLength;
use ecdsa::hazmat::SignPrimitive;
use serde::{Deserialize, Serialize};

use primeorder::{
    elliptic_curve::{
        ops::Reduce,
        sec1::{FromEncodedPoint, ModulusSize},
        Curve, CurveArithmetic, PrimeCurve,
    },
    PrimeCurveParams,
};
// TODO(dp): this should really be `elliptic_curve::Curve` and we shouldn't use the re-exported on from k256
use k256::elliptic_curve::bigint::Uint as K256Uint;
use tiny_curve::TinyCurve64;

use crate::{
    paillier::PaillierParams,
    tools::hashing::{Chain, HashableType},
    uint::{U1024Mod, U2048Mod, U4096Mod, U512Mod},
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaillierTest;

#[allow(clippy::indexing_slicing)]
const fn upcast_uint<const N1: usize, const N2: usize>(value: K256Uint<N1>) -> K256Uint<N2> {
    assert!(N2 >= N1, "Upcast target must be bigger than the upcast candidate");
    let mut result_words = [0; N2];
    let mut i = 0;
    let words = value.as_words();
    while i < N1 {
        result_words[i] = words[i];
        i += 1;
    }
    K256Uint::from_words(result_words)
}

const fn convert_uint<const N: usize>(value: K256Uint<N>) -> Uint<N> {
    Uint::from_words(value.to_words())
}

impl PaillierParams for PaillierTest {
    /*
    The prime size is chosen to be minimal for which the `TestSchemeParams` still work.
    In the presigning, we are effectively constructing a ciphertext of

        d = x * sum(j=1..P) y_i + sum(j=1..2*(P-1)) z_j

    where

        0 < x, y_i < q < 2^L, and
        -2^LP < z < 2^LP

    (`q` is the curve order, `L` and `LP` are constants in `TestSchemeParams`,
    `P` is the number of parties).
    This is `delta_i` or `chi_i`.

    During signing `chi_i` gets additionally multiplied by `r` (nonce, a scalar).

    We need the final result to be `-N/2 < d < N/2`
    (that is, it may be negative, and it cannot wrap around modulo N),
    so that it could fit in a Paillier ciphertext without wrapping around.
    This is needed for ZK proofs to work.

    `N` is a product of two primes of the size `PRIME_BITS`, so `N > 2^(2 * PRIME_BITS - 2)`.
    The upper bound on `log2(d * r)` is

        max(2 * L, LP + 2) + ceil(log2(CURVE_ORDER)) + ceil(log2(P))

    (note that in reality, due to numbers being random, the distribution will have a distinct peak,
    and the upper bound will have a low probability of being reached)

    Therefore we require

        max(2 * L, LP + 2) + ceil(log2(CURVE_ORDER)) + ceil(log2(P)) < 2 * PRIME_BITS - 2`

    For tests we assume `ceil(log2(P)) = 5` (we won't run tests with more than 32 nodes),
    and since in `TestSchemeParams` `L = LP = 256`, this leads to `PRIME_BITS >= 397`.

    For production it does not matter since 2*L, LP, and log2(CURVE_ORDER)
    are much smaller than 2*PRIME_BITS.
    */

    const PRIME_BITS: u32 = 397;
    type HalfUint = U512;
    type HalfUintMod = U512Mod;
    type Uint = U1024;
    type UintMod = U1024Mod;
    type WideUint = U2048;
    type WideUintMod = U2048Mod;
    type ExtraWideUint = U4096;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaillierProduction;

impl PaillierParams for PaillierProduction {
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
// TODO (#27): this trait can include curve scalar/point types as well,
// but for now they are hardcoded to `k256`.
pub trait SchemeParams: Debug + Clone + Send + PartialEq + Eq + Send + Sync + 'static
where
    // TODO(dp): This insanity all stems from the `FromEncodedPoint` bound. WTH?
    <Self::Curve as CurveArithmetic>::ProjectivePoint: FromEncodedPoint<Self::Curve>,
    <Self::Curve as Curve>::FieldBytesSize: ModulusSize,
    <<Self::Curve as Curve>::FieldBytesSize as ArrayLength<u8>>::ArrayType: Copy,
    <<Self::Curve as Curve>::FieldBytesSize as ModulusSize>::CompressedPointSize: Copy,
    <<<Self::Curve as Curve>::FieldBytesSize as ModulusSize>::CompressedPointSize as ArrayLength<u8>>::ArrayType: Copy,
    <<<Self::Curve as Curve>::FieldBytesSize as ModulusSize>::UncompressedPointSize as ArrayLength<u8>>::ArrayType:
        Copy,
    <Self::Curve as CurveArithmetic>::Scalar: Serialize
        + SignPrimitive<Self::Curve>
        + Ord
        + /* TODO(dp): Shouldn't be necessary to bound on Reduce */
        Reduce<<Self::Curve as Curve>::Uint>,
    for<'a> <Self::Curve as CurveArithmetic>::Scalar: Deserialize<'a>,
    <<Self::Curve as Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
{
    /// Elliptic curve of prime order used.
    type Curve: PrimeCurve
        + CurveArithmetic
        + HashableType
        +
        /*TODO(dp): k256 doesn't seem to implement this trait which is a bit of a problem. Is there a (good) reason for this? */
        PrimeCurveParams;
    /// The order of the curve.
    const CURVE_ORDER: NonZero<<Self::Paillier as PaillierParams>::Uint>; // $q$
    /// The order of the curve as a wide integer.
    const CURVE_ORDER_WIDE: NonZero<<Self::Paillier as PaillierParams>::WideUint>;
    /// The scheme's statistical security parameter.
    const SECURITY_PARAMETER: usize; // $\kappa$
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
}

impl<P: SchemeParams> HashableType for P {
    fn chain_type<C: Chain>(digest: C) -> C {
        digest.chain_type::<P::Curve>()
    }
}

/// Scheme parameters **for testing purposes only**.
/// Security is weakened to allow for faster execution.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestParams;

// Some requirements from range proofs etc:
// - $П_{enc}$, safe two's complement representation of $\alpha$ requires
//   `L_BOUND + EPS_BOUND + 1 < Uint::BITS - 1`
// - $П_{enc}$, safe two's complement representation of $z_1$ requires
//   `L_BOUND + max(EPS_BOUND, log2(q)) + 1 < Uint::BITS - 1`
//   (where `q` is the curve order)
// - Range checks will fail with the probability $q / 2^\eps$, so $\eps$ should be large enough.
// - P^{fac} assumes $N ~ 2^{4 \ell + 2 \eps}$
impl SchemeParams for TestParams {
    type Curve = TinyCurve64;
    const SECURITY_PARAMETER: usize = 10;
    const L_BOUND: u32 = 256;
    const LP_BOUND: u32 = 256;
    const EPS_BOUND: u32 = 320;
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
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionParams;

impl SchemeParams for ProductionParams {
    type Curve = k256::Secp256k1;
    const SECURITY_PARAMETER: usize = 80; // The value is given in Table 2 in the paper
    const L_BOUND: u32 = 256;
    const LP_BOUND: u32 = Self::L_BOUND * 5;
    const EPS_BOUND: u32 = Self::L_BOUND * 2;
    type Paillier = PaillierProduction;
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
    use primeorder::elliptic_curve::bigint::{U256, U64};

    use super::upcast_uint;

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
