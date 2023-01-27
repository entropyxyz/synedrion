use core::ops::Mul;

use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    nlimbs, AddMod, Pow, U128, U64,
};

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

    fn field_elem_to_group_elem(
        x: &Self::FieldElement,
        modulus: &Self::FieldElement,
    ) -> Self::GroupElement;
}

pub struct PaillierTest;

impl PaillierParams for PaillierTest {
    type PrimeUint = U64;
    type FieldElement = U128;
    type GroupElement = DynResidue<{ nlimbs!(128) }>;

    fn field_elem_to_group_elem(
        x: &Self::FieldElement,
        modulus: &Self::FieldElement,
    ) -> Self::GroupElement {
        let params = DynResidueParams::new(&modulus);
        DynResidue::new(&x, params)
    }
}
