use crate::curve::ORDER;
use crate::paillier::PaillierParams;
use crate::uint::{
    upcast_uint, U1024Mod, U2048Mod, U4096Mod, U512Mod, U1024, U2048, U4096, U512, U8192,
};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PaillierTest;

impl PaillierParams for PaillierTest {
    // We need 257-bit primes because we need MODULUS_BITS to accommodate all the possible
    // values of curve scalar squared, which is 512 bits.

    /*
    The prime size is chosen to be minimal for which the `TestSchemeParams` still work.
    In the presigning, we are effectively constructing a ciphertext of
        d = x * sum(j=1..P) y_i + sum(j=1..2*(P-1)) z_j
    where
        0 < x, y_i < q < 2^L, and
        -2^LP < z < 2^LP
    (`q` is the curve order, `L` and `LP` are constants in `TestSchemeParams`,
    `P` is the number of parties).
    This is `delta_i`, an additive share of the product of two secret values.

    We need the final result to be `-N/2 < d < N/2`
    (that is, it may be negative, and it cannot wrap around modulo N).

    `N` is a product of two primes of the size `PRIME_BITS`, so `N > 2^(2 * PRIME_BITS - 2)`.
    The upper bound on `log2(d)` is
        max(2 * L, LP + 2) + ceil(log2(P))

    Note in reality, due to numbers being random, the distribution will have a distinct peak,
    and the upper bound will have a low probability of being reached.

    Therefore we require `max(2 * L, LP + 2) + ceil(log2(P)) < 2 * PRIME_BITS - 2`.
    For tests we assume `ceil(log2(P)) = 5` (we won't run tests with more than 32 nodes),
    and since in `TestSchemeParams` `L = LP = 256`, this leads to `PRIME_BITS >= L + 4`.

    For production it does not matter since both 2*L and LP are much smaller than 2*PRIME_BITS.

    TODO: add an assertion for `SchemeParams` checking that?
    */

    const PRIME_BITS: usize = 260;
    type HalfUint = U512;
    type HalfUintMod = U512Mod;
    type Uint = U1024;
    type UintMod = U1024Mod;
    type WideUint = U2048;
    type WideUintMod = U2048Mod;
    type ExtraWideUint = U4096;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
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
// TODO: additional requirements from range proofs etc:
// - $П_{enc}$, safe two's complement representation of $\alpha$ requires
//   `L_BOUND + EPS_BOUND + 1 < Uint::BITS - 1`
// - $П_{enc}$, safe two's complement representation of $z_1$ requires
//   `L_BOUND + max(EPS_BOUND, log2(q)) + 1 < Uint::BITS - 1`
//   (where `q` is the curve order)
// - Range checks will fail with the probability $q / 2^\eps$, so $\eps$ should be large enough.
// - P^{fac} assumes $N ~ 2^{4 \ell + 2 \eps}$
pub trait SchemeParams: Clone + Send + PartialEq + Eq + core::fmt::Debug + 'static {
    /// The order of the curve.
    const CURVE_ORDER: <Self::Paillier as PaillierParams>::Uint; // $q$
    /// The sheme's statistical security parameter.
    const SECURITY_PARAMETER: usize; // $\kappa$
                                     // TODO: better names for the bounds?
                                     // See Table 2 in the paper for the respective values of these parameters.
    /// The bound for secret values.
    const L_BOUND: usize; // $\ell$, paper sets it to $\log2(q)$
    /// The error bound for secret masks.
    const LP_BOUND: usize; // $\ell^\prime$, in paper $= 5 \ell$
    /// The error bound for range checks.
    const EPS_BOUND: usize; // $\eps$, in paper $= 2 \ell$
    /// The parameters of the Paillier encryption.
    type Paillier: PaillierParams;
}

/// Scheme parameters **for testing purposes only**.
/// Security is weakened to allow for faster execution.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TestParams;

impl SchemeParams for TestParams {
    const SECURITY_PARAMETER: usize = 10;
    const L_BOUND: usize = 256;
    const LP_BOUND: usize = 256;
    const EPS_BOUND: usize = 320;
    type Paillier = PaillierTest;
    const CURVE_ORDER: <Self::Paillier as PaillierParams>::Uint = upcast_uint(ORDER);
}

/// Production strength parameters.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ProductionParams;

impl SchemeParams for ProductionParams {
    const SECURITY_PARAMETER: usize = 80;
    const L_BOUND: usize = 256;
    const LP_BOUND: usize = Self::L_BOUND * 5;
    const EPS_BOUND: usize = Self::L_BOUND * 2;
    type Paillier = PaillierProduction;
    const CURVE_ORDER: <Self::Paillier as PaillierParams>::Uint = upcast_uint(ORDER);
}
