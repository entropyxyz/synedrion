use crate::curve::ORDER;
use crate::paillier::{PaillierParams, PaillierProduction, PaillierTest};
use crate::uint::upcast_uint;

/// Signing scheme parameters.
// TODO (#27): this trait can include curve scalar/point types as well,
// but for now they are hardcoded to `k256`.
// TODO: additional requirements from range proofs etc:
// - $П_{enc}$, safe two's complement representation of $\alpha$ requires
//   `L_BOUND + EPS_BOUND + 1 < DoubleUint::BITS - 1`
// - $П_{enc}$, safe two's complement representation of $z_1$ requires
//   `L_BOUND + max(EPS_BOUND, log2(q)) + 1 < DoubleUint::BITS - 1`
//   (where `q` is the curve order)
// - Range checks will fail with the probability $q / 2^\eps$, so $\eps$ should be large enough.
// - P^{fac} assumes $N ~ 2^{4 \ell + 2 \eps}$
pub trait SchemeParams: Clone + Send {
    /// The order of the curve.
    const CURVE_ORDER: <Self::Paillier as PaillierParams>::DoubleUint; // $q$
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
#[derive(Debug, Copy, Clone)]
pub struct TestParams;

impl SchemeParams for TestParams {
    const SECURITY_PARAMETER: usize = 10;
    const L_BOUND: usize = 256;
    const LP_BOUND: usize = 256;
    const EPS_BOUND: usize = 320;
    type Paillier = PaillierTest;
    const CURVE_ORDER: <Self::Paillier as PaillierParams>::DoubleUint = upcast_uint(ORDER);
}

/// Production strength parameters.
#[derive(Debug, Copy, Clone)]
pub struct ProductionParams;

impl SchemeParams for ProductionParams {
    const SECURITY_PARAMETER: usize = 80;
    const L_BOUND: usize = 256;
    const LP_BOUND: usize = Self::L_BOUND * 5;
    const EPS_BOUND: usize = Self::L_BOUND * 2;
    type Paillier = PaillierProduction;
    const CURVE_ORDER: <Self::Paillier as PaillierParams>::DoubleUint = upcast_uint(ORDER);
}
