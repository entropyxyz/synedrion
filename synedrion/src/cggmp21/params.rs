use core::fmt::Debug;

// We're depending on a pre-release `crypto-bigint` version,
// and `k256` depends on the released one.
// So as long as that is the case, `k256` `Uint` is separate
// from the one used throughout the crate.
use k256::elliptic_curve::bigint::Uint as K256Uint;
use serde::{Deserialize, Serialize};

use crate::{
    curve::{Curve, Scalar, ORDER},
    paillier::PaillierParams,
    tools::hashing::{Chain, HashableType},
    uint::{
        subtle::ConditionallySelectable, Bounded, Encoding, NonZero, Signed, U1024Mod, U2048Mod,
        U4096Mod, U512Mod, Uint, Zero, U1024, U2048, U4096, U512, U8192,
    },
};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaillierTest;

const fn upcast_uint<const N1: usize, const N2: usize>(value: K256Uint<N1>) -> K256Uint<N2> {
    assert!(
        N2 >= N1,
        "Upcast target must be bigger than the upcast candidate"
    );
    let mut result_words = [0; N2];
    let mut i = 0;
    while i < N1 {
        result_words[i] = value.as_words()[i];
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

    const PRIME_BITS: usize = 397;
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
    const PRIME_BITS: usize = 1024;
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
pub trait SchemeParams: Debug + Clone + Send + PartialEq + Eq + Send + Sync + 'static {
    /// The order of the curve.
    const CURVE_ORDER: NonZero<<Self::Paillier as PaillierParams>::Uint>; // $q$
    /// The order of the curve as a wide integer.
    const CURVE_ORDER_WIDE: NonZero<<Self::Paillier as PaillierParams>::WideUint>;
    /// The scheme's statistical security parameter.
    const SECURITY_PARAMETER: usize; // $\kappa$
    /// The bound for secret values.
    const L_BOUND: usize; // $\ell$, paper sets it to $\log2(q)$ (see Table 2)
    /// The error bound for secret masks.
    const LP_BOUND: usize; // $\ell^\prime$, in paper $= 5 \ell$ (see Table 2)
    /// The error bound for range checks (referred to in the paper as the slackness parameter).
    const EPS_BOUND: usize; // $\eps$, in paper $= 2 \ell$ (see Table 2)
    /// The parameters of the Paillier encryption.
    type Paillier: PaillierParams;

    /// Converts a curve scalar to the associated integer type.
    fn uint_from_scalar(value: &Scalar) -> <Self::Paillier as PaillierParams>::Uint {
        let scalar_bytes = value.to_bytes();
        let mut repr = <Self::Paillier as PaillierParams>::Uint::zero().to_be_bytes();

        let uint_len = repr.as_ref().len();
        let scalar_len = scalar_bytes.len();

        debug_assert!(uint_len >= scalar_len);
        repr.as_mut()[uint_len - scalar_len..].copy_from_slice(&scalar_bytes);
        <Self::Paillier as PaillierParams>::Uint::from_be_bytes(repr)
    }

    /// Converts a curve scalar to the associated integer type, wrapped in `Bounded`.
    fn bounded_from_scalar(
        value: &Scalar,
    ) -> Option<Bounded<<Self::Paillier as PaillierParams>::Uint>> {
        Bounded::new(Self::uint_from_scalar(value), ORDER.bits_vartime() as u32)
    }

    /// Converts a curve scalar to the associated integer type, wrapped in `Signed`.
    /// Returns `None` if:
    /// - the bound provided by [`ORDER_BITS`] is invalid for the associated integer type from [`PaillierParams`];
    /// - the scalar value encodes a negative value
    fn signed_from_scalar(
        value: &Scalar,
    ) -> Option<Signed<<Self::Paillier as PaillierParams>::Uint>> {
        Self::bounded_from_scalar(value).and_then(Bounded::into_signed)
    }

    /// Converts an integer to the associated curve scalar type.
    fn scalar_from_uint(value: &<Self::Paillier as PaillierParams>::Uint) -> Scalar {
        let r = *value % Self::CURVE_ORDER;

        let repr = r.to_be_bytes();
        let uint_len = repr.as_ref().len();
        let scalar_len = Scalar::repr_len();

        // Can unwrap here since the value is within the Scalar range
        Scalar::try_from_bytes(&repr.as_ref()[uint_len - scalar_len..]).unwrap()
    }

    /// Converts a `Signed`-wrapped integer to the associated curve scalar type.
    fn scalar_from_signed(value: &Signed<<Self::Paillier as PaillierParams>::Uint>) -> Scalar {
        let abs_value = Self::scalar_from_uint(&value.abs());
        Scalar::conditional_select(&abs_value, &-abs_value, value.is_negative())
    }

    /// Converts a wide integer to the associated curve scalar type.
    fn scalar_from_wide_uint(value: &<Self::Paillier as PaillierParams>::WideUint) -> Scalar {
        let r = *value % Self::CURVE_ORDER_WIDE;

        let repr = r.to_be_bytes();
        let uint_len = repr.as_ref().len();
        let scalar_len = Scalar::repr_len();

        // Can unwrap here since the value is within the Scalar range
        Scalar::try_from_bytes(&repr.as_ref()[uint_len - scalar_len..]).unwrap()
    }

    /// Converts a `Signed`-wrapped wide integer to the associated curve scalar type.
    fn scalar_from_wide_signed(
        value: &Signed<<Self::Paillier as PaillierParams>::WideUint>,
    ) -> Scalar {
        let abs_value = Self::scalar_from_wide_uint(&value.abs());
        Scalar::conditional_select(&abs_value, &-abs_value, value.is_negative())
    }
}

impl<P: SchemeParams> HashableType for P {
    fn chain_type<C: Chain>(digest: C) -> C {
        digest.chain_type::<Curve>()
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
    const SECURITY_PARAMETER: usize = 10;
    const L_BOUND: usize = 256;
    const LP_BOUND: usize = 256;
    const EPS_BOUND: usize = 320;
    type Paillier = PaillierTest;
    const CURVE_ORDER: NonZero<<Self::Paillier as PaillierParams>::Uint> =
        convert_uint(upcast_uint(ORDER))
            .to_nz()
            .expect("Correct by construction");
    const CURVE_ORDER_WIDE: NonZero<<Self::Paillier as PaillierParams>::WideUint> =
        convert_uint(upcast_uint(ORDER))
            .to_nz()
            .expect("Correct by construction");
}

/// Production strength parameters.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionParams;

impl SchemeParams for ProductionParams {
    const SECURITY_PARAMETER: usize = 80; // The value is given in Table 2 in the paper
    const L_BOUND: usize = 256;
    const LP_BOUND: usize = Self::L_BOUND * 5;
    const EPS_BOUND: usize = Self::L_BOUND * 2;
    type Paillier = PaillierProduction;
    const CURVE_ORDER: NonZero<<Self::Paillier as PaillierParams>::Uint> =
        convert_uint(upcast_uint(ORDER))
            .to_nz()
            .expect("Correct by construction");
    const CURVE_ORDER_WIDE: NonZero<<Self::Paillier as PaillierParams>::WideUint> =
        convert_uint(upcast_uint(ORDER))
            .to_nz()
            .expect("Correct by construction");
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::bigint::{U256, U64};

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
