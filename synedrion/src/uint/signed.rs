use alloc::{boxed::Box, string::String};
use core::ops::{Add, Mul, Neg, Sub};
use digest::XofReader;
use rand_core::CryptoRngCore;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};

use super::{
    bounded::PackedBounded,
    subtle::{
        Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess,
        CtOption,
    },
    Bounded, CheckedAdd, HasWide, Integer, NonZero, RandomMod, UintLike, UintModLike,
};

/// A packed representation for serializing Signed objects.
/// Usually they have the bound much lower than the full size of the integer,
/// so this way we avoid serializing a bunch of zeros.
#[derive(Serialize, Deserialize)]
struct PackedSigned {
    is_negative: bool,
    abs_value: PackedBounded,
}

impl<T: UintLike> From<Signed<T>> for PackedSigned {
    fn from(val: Signed<T>) -> Self {
        Self {
            is_negative: val.is_negative().into(),
            abs_value: PackedBounded::from(val.abs_bounded()),
        }
    }
}

impl<T: UintLike> TryFrom<PackedSigned> for Signed<T> {
    type Error = String;
    fn try_from(val: PackedSigned) -> Result<Self, Self::Error> {
        let abs_value = Bounded::try_from(val.abs_value)?;
        Self::new_from_abs(
            *abs_value.as_ref(),
            abs_value.bound(),
            Choice::from(val.is_negative as u8),
        )
        .ok_or_else(|| "Invalid values for the signed integer".into())
    }
}

/// A wrapper over unsigned integers that treats two's complement numbers as negative.
// In principle, Bounded could be separate from Signed, but we only use it internally,
// and pretty much every time we need a bounded value, it's also signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PackedSigned", into = "PackedSigned")]
pub struct Signed<T: UintLike> {
    /// bound on the bit size of the absolute value
    bound: u32,
    value: T,
}

impl<T: UintLike> Signed<T> {
    pub fn bound(&self) -> u32 {
        self.bound
    }

    // Asserts that the value lies in the interval `[-2^bound, 2^bound]`.
    // Panics if it is not the case.
    pub fn assert_bound(self, bound: usize) {
        assert!(self.abs() <= T::ONE.shl_vartime(bound));
    }

    // Asserts that the value has bound less or equal to `bound`
    // (or, in other words, the value lies in the interval `(-(2^bound-1), 2^bound-1)`).
    // Returns the value with the bound set to `bound`.
    pub fn assert_bit_bound_usize(self, bound: usize) -> Option<Self> {
        if self.abs().bits_vartime() <= bound {
            Some(Self {
                value: self.value,
                bound: bound as u32,
            })
        } else {
            None
        }
    }

    pub fn bound_usize(&self) -> usize {
        // Extracted into a method to localize the conversion
        self.bound as usize
    }

    pub fn is_negative(&self) -> Choice {
        Choice::from(self.value.bit_vartime(<T as Integer>::BITS - 1) as u8)
    }

    pub fn abs(&self) -> T {
        T::conditional_select(&self.value, &self.value.neg(), self.is_negative())
    }

    pub fn abs_bounded(&self) -> Bounded<T> {
        // Can unwrap here since the maximum bound on the positive Bounded
        // is always greater than the maximum bound on Signed
        Bounded::new(self.abs(), self.bound).unwrap()
    }

    /// Creates a signed value from an unsigned one,
    /// treating it as if the sign is encoded in the MSB.
    pub fn new_from_unsigned(value: T, bound: u32) -> Option<Self> {
        let result = Self { value, bound };
        if bound >= <T as Integer>::BITS as u32 || result.abs().bits() as u32 > bound {
            return None;
        }
        Some(result)
    }

    /// Creates a signed value from an unsigned one,
    /// treating it as if it is the absolute value.
    fn new_from_abs(abs_value: T, bound: u32, is_negative: Choice) -> Option<Self> {
        Self::new_positive(abs_value, bound).map(|x| {
            let mut x = x;
            x.conditional_negate(is_negative);
            x
        })
    }

    /// Creates a signed value from an unsigned one,
    /// assuming that it encodes a positive value.
    pub fn new_positive(value: T, bound: u32) -> Option<Self> {
        // Reserving one bit as the sign bit
        if bound >= <T as Integer>::BITS as u32 || value.bits() as u32 > bound {
            return None;
        }
        let result = Self { value, bound };
        if result.is_negative().into() {
            return None;
        }
        Some(result)
    }

    /// Returns a random value in the whole available range,
    /// that is `[-(2^(BITS-1)-1), 2^(BITS-1)-1]`.
    #[cfg(test)]
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        loop {
            let value = T::random(rng);
            if value != T::ONE << (T::BITS - 1) {
                return Self::new_from_unsigned(value, (T::BITS - 1) as u32).unwrap();
            }
        }
    }

    /// Returns a random value in range `[-bound, bound]`.
    ///
    /// Note: variable time in bit size of `bound`.
    pub fn random_bounded(rng: &mut impl CryptoRngCore, bound: &NonZero<T>) -> Self {
        let bound_bits = bound.as_ref().bits_vartime();
        assert!(bound_bits < <T as Integer>::BITS);
        // Will not overflow because of the assertion above
        let positive_bound = bound.as_ref().shl_vartime(1).checked_add(&T::ONE).unwrap();
        let positive_result = T::random_mod(rng, &NonZero::new(positive_bound).unwrap());
        // Will not panic because of the assertion above
        Self::new_from_unsigned(
            positive_result.wrapping_sub(bound.as_ref()),
            bound_bits as u32,
        )
        .unwrap()
    }

    /// Returns a value in range `[-bound, bound]` derived from an extendable-output hash.
    ///
    /// This method should be used for deriving non-interactive challenges,
    /// since it is guaranteed to produce the same results on 32- and 64-bit platforms.
    ///
    /// Note: variable time in bit size of `bound`.
    pub fn from_xof_reader_bounded(rng: &mut impl XofReader, bound: &NonZero<T>) -> Self {
        let bound_bits = bound.as_ref().bits_vartime();
        assert!(bound_bits < <T as Integer>::BITS);
        // Will not overflow because of the assertion above
        let positive_bound = bound.as_ref().shl_vartime(1).checked_add(&T::ONE).unwrap();
        let positive_result = T::from_xof(rng, &NonZero::new(positive_bound).unwrap());
        // Will not panic because of the assertion above
        Self::new_from_unsigned(
            positive_result.wrapping_sub(bound.as_ref()),
            bound_bits as u32,
        )
        .unwrap()
    }

    /// Returns a random value in range `[-2^bound_bits, 2^bound_bits]`.
    ///
    /// Note: variable time in `bound_bits`.
    pub fn random_bounded_bits(rng: &mut impl CryptoRngCore, bound_bits: usize) -> Self {
        assert!(bound_bits < <T as Integer>::BITS - 1);
        let bound = NonZero::new(T::ONE << bound_bits).unwrap();
        Self::random_bounded(rng, &bound)
    }

    /// Returns `true` if the value is within `[-2^bound_bits, 2^bound_bits]`.
    pub fn in_range_bits(&self, bound_bits: usize) -> bool {
        self.abs() <= T::ONE << bound_bits
    }

    pub fn to_mod(self, precomputed: &<T::ModUint as UintModLike>::Precomputed) -> T::ModUint {
        let abs_mod = self.abs().to_mod(precomputed);
        T::ModUint::conditional_select(&abs_mod, &-abs_mod, self.is_negative())
    }

    pub fn secret_box(self) -> SecretBox<Signed<T>> {
        Box::new(self).into()
    }

    fn checked_add(&self, rhs: &Self) -> CtOption<Self> {
        let bound = core::cmp::max(self.bound, rhs.bound) + 1;
        let in_range = bound.ct_lt(&(<T as Integer>::BITS as u32));

        let result = Self {
            bound,
            value: self.value.wrapping_add(&rhs.value),
        };
        let lhs_neg = self.is_negative();
        let rhs_neg = rhs.is_negative();
        let res_neg = result.is_negative();

        // Cannot get overflow from adding values of different signs,
        // and if for two values of the same sign the sign of the result remains the same
        // it means there was no overflow.
        CtOption::new(
            result,
            !(lhs_neg.ct_eq(&rhs_neg) & !lhs_neg.ct_eq(&res_neg)) & in_range,
        )
    }

    fn checked_mul(&self, rhs: &Self) -> CtOption<Self> {
        let bound = self.bound + rhs.bound;
        let in_range = bound.ct_lt(&(<T as Integer>::BITS as u32));

        let lhs_neg = self.is_negative();
        let rhs_neg = rhs.is_negative();
        let lhs = T::conditional_select(&self.value, &self.value.neg(), lhs_neg);
        let rhs = T::conditional_select(&rhs.value, &rhs.value.neg(), rhs_neg);
        let result = lhs.checked_mul(&rhs);
        let result_neg = lhs_neg ^ rhs_neg;
        result.and_then(|val| {
            let value = T::conditional_select(&val, &val.neg(), result_neg);
            CtOption::new(Self { bound, value }, in_range)
        })
    }
}

impl<T: UintLike> Default for Signed<T> {
    fn default() -> Self {
        Self {
            bound: 0,
            value: T::default(),
        }
    }
}

impl<T: UintLike> zeroize::DefaultIsZeroes for Signed<T> {}

impl<T: UintLike> secrecy::CloneableSecret for Signed<T> {}

impl<T: UintLike> From<Signed<T>> for SecretBox<Signed<T>> {
    fn from(value: Signed<T>) -> Self {
        value.secret_box()
    }
}

impl<T: UintLike> From<&Signed<T>> for SecretBox<Signed<T>> {
    fn from(value: &Signed<T>) -> Self {
        value.secret_box()
    }
}

impl<T: UintLike> ConditionallySelectable for Signed<T> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            bound: u32::conditional_select(&a.bound, &b.bound, choice),
            value: T::conditional_select(&a.value, &b.value, choice),
        }
    }
}

impl<T: UintLike> Neg for Signed<T> {
    type Output = Signed<T>;
    fn neg(self) -> Self::Output {
        Signed {
            bound: self.bound,
            value: self.value.neg(),
        }
    }
}

impl<'a, T: UintLike> Neg for &'a Signed<T> {
    type Output = Signed<T>;
    fn neg(self) -> Self::Output {
        Signed {
            bound: self.bound,
            value: self.value.neg(),
        }
    }
}

impl<T: UintLike + HasWide> Signed<T> {
    /// Returns a random value in range `[-2^bound_bits * scale, 2^bound_bits * scale]`.
    ///
    /// Note: variable time in `bound_bits` and bit size of `scale`.
    pub fn random_bounded_bits_scaled(
        rng: &mut impl CryptoRngCore,
        bound_bits: usize,
        scale: &Bounded<T>,
    ) -> Signed<T::Wide> {
        assert!(bound_bits < <T as Integer>::BITS - 1);
        let scaled_bound = scale.as_ref().into_wide().shl_vartime(bound_bits);

        // Sampling in range [0, 2^bound_bits * scale * 2 + 1) and translating to the desired range.
        let positive_bound = scaled_bound
            .shl_vartime(1)
            .checked_add(&T::Wide::ONE)
            .unwrap();
        let positive_result = T::Wide::random_mod(rng, &NonZero::new(positive_bound).unwrap());
        let result = positive_result.wrapping_sub(&scaled_bound);

        Signed {
            bound: bound_bits as u32 + scale.bound(),
            value: result,
        }
    }

    pub fn into_wide(self) -> Signed<T::Wide> {
        let abs_result = self.abs().into_wide();
        Signed::new_from_abs(abs_result, self.bound(), self.is_negative()).unwrap()
    }

    pub fn mul_wide(&self, rhs: &Self) -> Signed<T::Wide> {
        let abs_result = self.abs().mul_wide(&rhs.abs());
        Signed::new_from_abs(
            abs_result,
            self.bound() + rhs.bound(),
            self.is_negative() ^ rhs.is_negative(),
        )
        .unwrap()
    }
}

impl<T: UintLike + HasWide> Signed<T>
where
    T::Wide: HasWide,
{
    /// Returns a random value in range `[-2^bound_bits * scale, 2^bound_bits * scale]`.
    ///
    /// Note: variable time in `bound_bits` and `scale`.
    pub fn random_bounded_bits_scaled_wide(
        rng: &mut impl CryptoRngCore,
        bound_bits: usize,
        scale: &Bounded<T::Wide>,
    ) -> Signed<<T::Wide as HasWide>::Wide> {
        assert!(bound_bits < <T as Integer>::BITS - 1);
        let scaled_bound = scale.as_ref().into_wide().shl_vartime(bound_bits);

        // Sampling in range [0, 2^bound_bits * scale * 2 + 1) and translating to the desired range.
        let positive_bound = scaled_bound
            .shl_vartime(1)
            .checked_add(&<T::Wide as HasWide>::Wide::ONE)
            .unwrap();
        let positive_result =
            <T::Wide as HasWide>::Wide::random_mod(rng, &NonZero::new(positive_bound).unwrap());
        let result = positive_result.wrapping_sub(&scaled_bound);

        Signed {
            bound: bound_bits as u32 + scale.bound(),
            value: result,
        }
    }
}

impl<T: UintLike> Add<Signed<T>> for Signed<T> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(&rhs).unwrap()
    }
}

impl<T: UintLike> Add<&Signed<T>> for Signed<T> {
    type Output = Self;
    fn add(self, rhs: &Self) -> Self::Output {
        self.checked_add(rhs).unwrap()
    }
}

impl<T: UintLike> Sub<Signed<T>> for Signed<T> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_add(&-rhs).unwrap()
    }
}

impl<T: UintLike> Sub<&Signed<T>> for Signed<T> {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self::Output {
        self.checked_add(&-rhs).unwrap()
    }
}

impl<T: UintLike> Mul<Signed<T>> for Signed<T> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        self.checked_mul(&rhs).unwrap()
    }
}

impl<T: UintLike> Mul<&Signed<T>> for Signed<T> {
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self::Output {
        self.checked_mul(rhs).unwrap()
    }
}

impl<T: UintLike> core::iter::Sum for Signed<T> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x.checked_add(&y).unwrap())
            .unwrap_or(Self::default())
    }
}

impl<'a, T: UintLike> core::iter::Sum<&'a Self> for Signed<T> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}
