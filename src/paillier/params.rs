use core::ops::Mul;

use crypto_bigint::subtle::CtOption;
use crypto_bigint::{
    modular::{
        runtime_mod::{DynResidue, DynResidueParams},
        Retrieve,
    },
    nlimbs, AddMod, Encoding, Invert, NonZero, Pow, U128, U64,
};

use super::uint::Uint;
use crate::tools::hashing::{HashEncoding, HashInto};
use crate::tools::jacobi::JacobiSymbolTrait;

pub trait PaillierParams: PartialEq + Eq {
    type PrimeUint: Uint + core::ops::Shr<usize, Output = Self::PrimeUint> + core::fmt::Display;
    type PrimeUintMod: Pow<Self::PrimeUint>
        + PartialEq
        + Eq
        + Copy
        + Retrieve<Output = Self::PrimeUint>
        + core::ops::Neg<Output = Self::PrimeUintMod>
        + core::ops::Mul<Self::PrimeUintMod, Output = Self::PrimeUintMod>;
    type FieldElement: Uint
        + From<(Self::PrimeUint, Self::PrimeUint)>
        + Into<(Self::PrimeUint, Self::PrimeUint)>
        + AddMod<Self::FieldElement, Output = Self::FieldElement>
        + JacobiSymbolTrait
        + Encoding
        + HashInto
        + core::fmt::Display
        + core::ops::Rem<NonZero<Self::FieldElement>>;
    type GroupElement: Clone
        + Copy
        + PartialEq
        + Eq
        + HashEncoding
        + core::ops::Neg<Output = Self::GroupElement>
        + core::ops::Add<Self::GroupElement, Output = Self::GroupElement>
        + Invert<Output = CtOption<Self::GroupElement>>
        + core::fmt::Debug
        + Pow<Self::FieldElement>
        + Retrieve<Output = Self::FieldElement>
        + for<'a> Mul<&'a Self::GroupElement, Output = Self::GroupElement>;

    fn mul_to_field_elem(lhs: &Self::PrimeUint, rhs: &Self::PrimeUint) -> Self::FieldElement {
        let (hi, lo) = lhs.mul_wide(rhs);
        (lo, hi).into()
    }

    fn field_elem_to_group_elem(
        x: &Self::FieldElement,
        modulus: &Self::FieldElement,
    ) -> Self::GroupElement;

    fn puint_to_puint_mod(x: &Self::PrimeUint, modulus: &Self::PrimeUint) -> Self::PrimeUintMod;
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct PaillierTest;

impl PaillierParams for PaillierTest {
    type PrimeUint = U64;
    type PrimeUintMod = DynResidue<{ nlimbs!(64) }>;
    type FieldElement = U128;
    type GroupElement = DynResidue<{ nlimbs!(128) }>;

    fn field_elem_to_group_elem(
        x: &Self::FieldElement,
        modulus: &Self::FieldElement,
    ) -> Self::GroupElement {
        let params = DynResidueParams::new(modulus);
        DynResidue::new(x, params)
    }

    fn puint_to_puint_mod(x: &Self::PrimeUint, modulus: &Self::PrimeUint) -> Self::PrimeUintMod {
        let params = DynResidueParams::new(modulus);
        DynResidue::new(x, params)
    }
}
