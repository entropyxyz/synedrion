use core::ops::{BitAnd, BitXor, Not};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    subtle::{Choice, ConstantTimeEq, CtOption},
    Bounded, CheckedAdd, CheckedMul, NonZero, UintLike,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Signed<T: UintLike>(T);

impl<T: UintLike> Signed<T> {
    pub fn is_negative(&self) -> Choice {
        self.0.bit(<T as Bounded>::BITS - 1)
    }

    pub fn abs(&self) -> T {
        T::conditional_select(&self.0, &self.0.neg(), self.is_negative())
    }

    pub fn new_positive(value: T) -> CtOption<Self> {
        let result = Self(value);
        let is_negative = result.is_negative();
        CtOption::new(result, is_negative.not())
    }

    pub fn extract_mod(&self, modulus: &NonZero<T>) -> T {
        if self.is_negative().into() {
            (self.0.neg() % *modulus).neg_mod(modulus)
        } else {
            self.0 % *modulus
        }
    }

    /// Returns a two's complement representation of a random value in range [-bound, bound]
    pub fn random_bounded(rng: &mut impl CryptoRngCore, bound: &NonZero<T>) -> Self {
        debug_assert!(bound.as_ref() <= &(T::MAX >> 1));
        // Will not overflow because of the assertion above
        let positive_bound = (*bound.as_ref() << 1).checked_add(&T::ONE).unwrap();
        let positive_result = T::random_mod(rng, &NonZero::new(positive_bound).unwrap());
        Self(positive_result.wrapping_sub(bound.as_ref()))
    }

    /// Returns a two's complement representation of a random value in range
    /// [-2^bound_bits, 2^bound_bits]
    pub fn random_bounded_bits(rng: &mut impl CryptoRngCore, bound_bits: usize) -> Self {
        debug_assert!(bound_bits < <T as Bounded>::BITS - 1);
        let bound = NonZero::new(T::ONE << (bound_bits + 1)).unwrap();
        Self::random_bounded(rng, &bound)
    }

    pub fn in_range_bits(&self, bound_bits: usize) -> bool {
        let bound = T::ONE << (bound_bits + 1);
        self.0 <= bound || self.0.neg() <= bound
    }
}

impl<T: UintLike> CheckedAdd for Signed<T> {
    type Output = Self;
    fn checked_add(&self, rhs: Self) -> CtOption<Self> {
        let result = Self(self.0.wrapping_add(&rhs.0));
        let lhs_neg = self.is_negative();
        let rhs_neg = rhs.is_negative();
        let res_neg = result.is_negative();

        // Cannot get overflow from adding values of different signs,
        // and if for two values of the same sign the sign of the result remains the same
        // it means there was no overflow.
        CtOption::new(
            result,
            lhs_neg
                .ct_eq(&rhs_neg)
                .bitand(lhs_neg.ct_ne(&res_neg))
                .not(),
        )
    }
}

impl<T: UintLike> CheckedMul for Signed<T> {
    type Output = Self;
    fn checked_mul(&self, rhs: Self) -> CtOption<Self> {
        let lhs_neg = self.is_negative();
        let rhs_neg = rhs.is_negative();
        let lhs = T::conditional_select(&self.0, &self.0.neg(), lhs_neg);
        let rhs = T::conditional_select(&rhs.0, &rhs.0.neg(), rhs_neg);
        let result = lhs.checked_mul(&rhs);
        let result_neg = lhs_neg.bitxor(rhs_neg);
        result.and_then(|val| {
            let out_of_range: Choice = val.bit(<T as Bounded>::BITS - 1);
            let signed_val = T::conditional_select(&val, &val.neg(), result_neg);
            CtOption::new(Self(signed_val), out_of_range.not())
        })
    }
}
