use crate::curve::ORDER;
use crate::paillier::{uint::upcast_uint, PaillierParams, PaillierTest};

// TODO (#27): this trait can include curve scalar/point types as well,
// but for now they are hardcoded to `k256`.
pub trait SchemeParams: Clone + Send {
    const SECURITY_PARAMETER: usize; // `\kappa`
                                     // TODO: better names for the bounds
    const L_BOUND: usize; // `\ell`
    const LP_BOUND: usize; // `\ell^\prime`
    const EPS_BOUND: usize; // `\eps`
    type Paillier: PaillierParams;
    const CURVE_ORDER: <Self::Paillier as PaillierParams>::DoubleUint;
}

#[derive(Clone)]
pub struct TestSchemeParams;

// TODO: additional requirements from range proofs etc:
// - $П_{enc}$, safe two's complement representation of $\alpha$ requires
//   `L_BOUND + EPS_BOUND + 1 < DoubleUint::BITS - 1`
// - $П_{enc}$, safe two's complement representation of $z_1$ requires
//   `L_BOUND + max(EPS_BOUND, log2(q)) + 1 < DoubleUint::BITS - 1`
//   (where `q` is the curve order)
impl SchemeParams for TestSchemeParams {
    const SECURITY_PARAMETER: usize = 10;
    const L_BOUND: usize = 256;
    const LP_BOUND: usize = 256;
    const EPS_BOUND: usize = 320;
    type Paillier = PaillierTest;
    const CURVE_ORDER: <Self::Paillier as PaillierParams>::DoubleUint = upcast_uint(ORDER);
}
