use core::ops::{Add, Mul, Neg, Not, Sub};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, CtOption},
    CheckedAdd, CheckedMul, HasWide, Integer, NonZero, UintLike,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Signed<T: UintLike>(T);

impl<T: UintLike> Signed<T> {
    pub fn is_negative(&self) -> Choice {
        self.0.bit(<T as Integer>::BITS - 1)
    }

    pub fn abs(&self) -> T {
        T::conditional_select(&self.0, &self.0.neg(), self.is_negative())
    }

    fn new(abs_value: T, is_negative: Choice) -> CtOption<Self> {
        Self::new_positive(abs_value).map(|x| {
            let mut x = x;
            x.conditional_negate(is_negative);
            x
        })
    }

    pub fn new_positive(value: T) -> CtOption<Self> {
        let result = Self(value);
        let is_negative = result.is_negative();
        CtOption::new(result, is_negative.not())
    }

    pub fn extract_mod(&self, modulus: &NonZero<T>) -> T {
        let reduced = self.abs() % *modulus;
        if self.is_negative().into() {
            modulus.as_ref().wrapping_sub(&reduced)
        } else {
            reduced
        }
    }

    pub fn extract_mod_half<S>(&self, modulus: &NonZero<S>) -> S
    where
        S: UintLike + HasWide<Wide = T> + Clone + core::fmt::Debug,
    {
        let m: S = *modulus.as_ref();
        let wide_reduced = self.abs() % NonZero::new(m.into_wide()).unwrap();
        let reduced = S::try_from_wide(wide_reduced).unwrap();

        if self.is_negative().into() {
            modulus.as_ref().wrapping_sub(&reduced)
        } else {
            reduced
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
        debug_assert!(bound_bits < <T as Integer>::BITS - 1);
        let bound = NonZero::new(T::ONE << bound_bits).unwrap();
        Self::random_bounded(rng, &bound)
    }

    pub fn in_range_bits(&self, bound_bits: usize) -> bool {
        let bound = T::ONE << (bound_bits + 1);
        self.abs() <= bound
    }
}

impl<T: UintLike> Default for Signed<T> {
    fn default() -> Self {
        Self(T::default())
    }
}

impl<T: UintLike> ConditionallySelectable for Signed<T> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(T::conditional_select(&a.0, &b.0, choice))
    }
}

impl<T: UintLike> Neg for Signed<T> {
    type Output = Signed<T>;
    fn neg(self) -> Self::Output {
        Signed(self.0.neg())
    }
}

impl<'a, T: UintLike> Neg for &'a Signed<T> {
    type Output = Signed<T>;
    fn neg(self) -> Self::Output {
        Signed(self.0.neg())
    }
}

impl<T: UintLike + HasWide> Signed<T> {
    pub fn random_bounded_bits_scaled(
        rng: &mut impl CryptoRngCore,
        bound_bits: usize,
        scale: &NonZero<T>,
    ) -> Signed<T::Wide> {
        // TODO: adjust the size check to include the scale
        debug_assert!(bound_bits < <T as Integer>::BITS - 1);
        let bound = NonZero::new(T::ONE << bound_bits).unwrap();
        let positive_bound = (*bound.as_ref() << 1).checked_add(&T::ONE).unwrap();
        let positive_result = T::random_mod(rng, &NonZero::new(positive_bound).unwrap());

        let scaled_positive_result = positive_result.mul_wide(scale.as_ref());
        // TODO: use vartime shift left
        let scaled_bound = scale.as_ref().into_wide() << bound_bits;

        /*extern crate std;
        std::println!("bound = {:?}", bound);
        std::println!("positive_bound = {:?}", positive_bound);
        std::println!("positive_result = {:?}", positive_result);
        std::println!("scaled_positive_result = {:?}", scaled_positive_result);
        std::println!("scaled_bound = {:?}", scaled_bound);
        std::println!("result = {:?}", scaled_positive_result.wrapping_sub(&scaled_bound));*/

        Signed(scaled_positive_result.wrapping_sub(&scaled_bound))
    }

    pub fn into_wide(self) -> Signed<T::Wide> {
        let abs_result = self.abs().into_wide();
        Signed::new(abs_result, self.is_negative()).unwrap()
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
            !(lhs_neg.ct_eq(&rhs_neg) & !lhs_neg.ct_eq(&res_neg)),
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
        let result_neg = lhs_neg ^ rhs_neg;
        result.and_then(|val| {
            let out_of_range: Choice = val.bit(<T as Integer>::BITS - 1);
            let signed_val = T::conditional_select(&val, &val.neg(), result_neg);
            CtOption::new(Self(signed_val), out_of_range.not())
        })
    }
}

impl<T: UintLike> Add<Signed<T>> for Signed<T> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(rhs).unwrap()
    }
}

impl<T: UintLike> Sub<Signed<T>> for Signed<T> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_add(-rhs).unwrap()
    }
}

impl<T: UintLike> Mul<Signed<T>> for Signed<T> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        self.checked_mul(rhs).unwrap()
    }
}
