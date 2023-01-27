use core::ops::Mul;

use crypto_bigint::{modular::runtime_mod::DynResidue, nlimbs, AddMod, Pow, U128, U64};

use super::uint::Uint;

pub trait PaillierParams {
    type PrimeUint: Uint;
    type FieldElement: Uint
        + From<(Self::PrimeUint, Self::PrimeUint)>
        + AddMod<Self::FieldElement, Output = Self::FieldElement>;
    type GroupElement: Clone
        + PartialEq
        + Eq
        + Pow<Self::FieldElement>
        + for<'a> Mul<&'a Self::GroupElement, Output = Self::GroupElement>;

    fn mul_to_field_elem(lhs: &Self::PrimeUint, rhs: &Self::PrimeUint) -> Self::FieldElement {
        let (hi, lo) = lhs.mul_wide(rhs);
        (lo, hi).into()
    }
}

pub struct PaillierTest;

impl PaillierParams for PaillierTest {
    type PrimeUint = U64;
    type FieldElement = U128;
    type GroupElement = DynResidue<{ nlimbs!(128) }>;
}
