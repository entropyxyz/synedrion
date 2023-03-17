use serde::{Deserialize, Serialize};

use super::uint::{HasWide, U128Mod, U64Mod, UintLike, UintModLike, U128, U64};
use crate::tools::hashing::Hashable;

pub trait PaillierParams: PartialEq + Eq + Clone + core::fmt::Debug {
    type SingleUint: UintLike + HasWide<Wide = Self::DoubleUint>;
    type SingleUintMod: UintModLike<RawUint = Self::SingleUint>;
    type DoubleUint: UintLike + Serialize + for<'de> Deserialize<'de>;
    type DoubleUintMod: Hashable + UintModLike<RawUint = Self::DoubleUint>;
    //type QuadUint: Uint;

    /*
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
        + Hashable
        + core::fmt::Display
        + core::ops::Rem<NonZero<Self::FieldElement>>;
    type GroupElement: Clone
        + Copy
        + PartialEq
        + Eq
        + Hashable
        + core::ops::Neg<Output = Self::GroupElement>
        + core::ops::Add<Self::GroupElement, Output = Self::GroupElement>
        + Invert<Output = CtOption<Self::GroupElement>>
        + core::fmt::Debug
        + Pow<Self::FieldElement>
        + Retrieve<Output = Self::FieldElement>
        + for<'a> Mul<&'a Self::GroupElement, Output = Self::GroupElement>;
    */

    /*
    fn mul_to_field_elem(lhs: &Self::PrimeUint, rhs: &Self::PrimeUint) -> Self::FieldElement {
        lhs.mul_wide(rhs).into()
    }

    fn field_elem_to_group_elem(
        x: &Self::FieldElement,
        modulus: &Self::FieldElement,
    ) -> Self::GroupElement;

    fn puint_to_puint_mod(x: &Self::PrimeUint, modulus: &Self::PrimeUint) -> Self::PrimeUintMod;
    */
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PaillierTest;

impl PaillierParams for PaillierTest {
    type SingleUint = U64;
    type SingleUintMod = U64Mod;
    type DoubleUint = U128;
    type DoubleUintMod = U128Mod;

    /*
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
    */
}
