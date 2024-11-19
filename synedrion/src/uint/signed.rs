use alloc::{boxed::Box, string::String};
use core::ops::{Add, Mul, Neg, Sub};

use digest::XofReader;
use rand_core::CryptoRngCore;
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::{
    bounded::PackedBounded,
    subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess, CtOption},
    Bounded, CheckedAdd, CheckedSub, Encoding, HasWide, Integer, NonZero, RandomMod, ShlVartime, WrappingSub,
};
use crate::tools::hashing::uint_from_xof;

/// A packed representation for serializing Signed objects.
/// Usually they have the bound much lower than the full size of the integer,
/// so this way we avoid serializing a bunch of zeros.
#[derive(Serialize, Deserialize)]
struct PackedSigned {
    is_negative: bool,
    abs_value: PackedBounded,
}

impl<T> From<Signed<T>> for PackedSigned
where
    T: Integer + Encoding + crypto_bigint::Bounded + ConditionallySelectable,
{
    fn from(val: Signed<T>) -> Self {
        Self {
            is_negative: val.is_negative().into(),
            abs_value: PackedBounded::from(val.abs_bounded()),
        }
    }
}

impl<T> TryFrom<PackedSigned> for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded + ConditionallySelectable,
{
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
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(
    try_from = "PackedSigned",
    into = "PackedSigned",
    bound = "T: Integer + Encoding + crypto_bigint::Bounded + ConditionallySelectable"
)]
pub struct Signed<T> {
    /// bound on the bit size of the absolute value
    bound: u32,
    value: T,
}

impl<T> Signed<T>
where
    T: crypto_bigint::Bounded + Integer,
{
    /// Note: when adding two [`Signed`], the bound on the result is equal to the biggest bound of
    /// the two operands plus 1.
    fn checked_add(&self, rhs: &Self) -> CtOption<Self> {
        let bound = core::cmp::max(self.bound, rhs.bound) + 1;
        let in_range = bound.ct_lt(&T::BITS);

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
        CtOption::new(result, !(lhs_neg.ct_eq(&rhs_neg) & !lhs_neg.ct_eq(&res_neg)) & in_range)
    }

    /// Checks if a [`Signed`] is negative by checking the MSB: if it's `1` then the [`Signed`] is
    /// negative; if it's `0` it's positive. Returns a [`Choice`].
    pub fn is_negative(&self) -> Choice {
        Choice::from(self.value.bit_vartime(T::BITS - 1) as u8)
    }

    pub fn bound(&self) -> u32 {
        self.bound
    }

    pub fn bound_usize(&self) -> usize {
        // Extracted into a method to localize the conversion
        self.bound as usize
    }

    /// Creates a signed value from an unsigned one,
    /// assuming that it encodes a positive value.
    pub fn new_positive(value: T, bound: u32) -> Option<Self> {
        // Reserving one bit as the sign bit (MSB)
        if bound >= T::BITS || value.bits() > bound {
            return None;
        }
        let result = Self { value, bound };
        if result.is_negative().into() {
            return None;
        }
        Some(result)
    }
}

impl<T> Signed<T>
where
    T: ConditionallySelectable + crypto_bigint::Bounded + Encoding + Integer,
{
    /// Constant-time checked multiplication. The product must fit in a `T`; use [`Signed::mul_wide`] if widening is desired.
    /// Note: when multiplying two [`Signed`], the bound on the result is equal to the sum of the bounds of the operands.
    fn checked_mul(&self, rhs: &Self) -> CtOption<Self> {
        let bound = self.bound + rhs.bound;
        let in_range = bound.ct_lt(&T::BITS);

        let lhs_neg = self.is_negative();
        let rhs_neg = rhs.is_negative();
        let lhs = T::conditional_select(&self.value, &T::zero().wrapping_sub(&self.value), lhs_neg);
        let rhs = T::conditional_select(&rhs.value, &T::zero().wrapping_sub(&rhs.value), rhs_neg);
        let result = lhs.checked_mul(&rhs);
        result.and_then(|val| {
            let result_neg = lhs_neg ^ rhs_neg;
            let val_neg = T::zero().wrapping_sub(&val);
            let value = T::conditional_select(&val, &val_neg, result_neg);
            CtOption::new(Self { bound, value }, in_range)
        })
    }

    /// Performs the unary - operation.
    pub fn neg(&self) -> Self {
        Self {
            value: T::zero().wrapping_sub(&self.value),
            bound: self.bound,
        }
    }

    /// Computes the absolute value of [`self`]
    pub fn abs(&self) -> T {
        T::conditional_select(&self.value, &self.neg().value, self.is_negative())
    }

    // Asserts that the value lies in the interval `[-2^bound, 2^bound]`.
    // Panics if it is not the case.
    pub fn assert_bound(self, bound: usize) {
        assert!(
            T::one()
                .overflowing_shl_vartime(bound as u32)
                .map(|b| self.abs() <= b)
                .expect("Out of bounds"),
            "Out of bounds"
        );
    }

    /// Creates a [`Bounded`] from the absolute value of `self`.
    pub fn abs_bounded(&self) -> Bounded<T> {
        // Can unwrap here since the maximum bound on the positive Bounded
        // is always greater than the maximum bound on Signed
        Bounded::new(self.abs(), self.bound)
            .expect("Max bound for a positive Bounded is always greater than max bound for a Signed; qed")
    }

    /// Creates a signed value from an unsigned one,
    /// treating it as if the sign is encoded in the MSB.
    pub fn new_from_unsigned(value: T, bound: u32) -> Option<Self> {
        let result = Self { value, bound };
        if bound >= T::BITS || result.abs().bits() > bound {
            return None;
        }
        Some(result)
    }

    /// Creates a signed value from an unsigned one, treating it as if it is the absolute value.
    /// Returns `None` if `abs_value` is actually negative or if the bounds are invalid.
    fn new_from_abs(abs_value: T, bound: u32, is_negative: Choice) -> Option<Self> {
        Self::new_positive(abs_value, bound).map(|x| {
            let mut x = x;
            x.conditional_negate(is_negative);
            x
        })
    }

    // Asserts that the value has bound less or equal to `bound`
    // (or, in other words, the value lies in the interval `(-(2^bound-1), 2^bound-1)`).
    // Returns the value with the bound set to `bound`.
    pub fn assert_bit_bound_usize(self, bound: usize) -> Option<Self> {
        if self.abs().bits_vartime() <= bound as u32 {
            Some(Self {
                value: self.value,
                bound: bound as u32,
            })
        } else {
            None
        }
    }
    /// Returns `true` if the value is within `[-2^bound_bits, 2^bound_bits]`.
    pub fn in_range_bits(&self, bound_bits: usize) -> bool {
        self.abs() <= T::one() << bound_bits
    }

    /// Returns a value in range `[-bound, bound]` derived from an extendable-output hash.
    ///
    /// This method should be used for deriving non-interactive challenges,
    /// since it is guaranteed to produce the same results on 32- and 64-bit platforms.
    ///
    /// Note: variable time in bit size of `bound`.
    pub fn from_xof_reader_bounded(rng: &mut impl XofReader, bound: &NonZero<T>) -> Self {
        let bound_bits = bound.as_ref().bits_vartime();
        assert!(bound_bits < <T as crypto_bigint::Bounded>::BITS);
        // Will not overflow because of the assertion above
        let positive_bound = bound
            .as_ref()
            .overflowing_shl_vartime(1)
            .expect("Just asserted that bound is smaller than precision; qed")
            .checked_add(&T::one())
            .expect("does not overflow since we're adding 1 to an even number");
        let positive_result = uint_from_xof(
            rng,
            &NonZero::new(positive_bound).expect("Guaranteed to be greater than zero because we added 1"),
        );
        Self::new_from_unsigned(positive_result.wrapping_sub(bound.as_ref()), bound_bits)
            .expect("Guaranteed to be Some because we checked the bounds just above")
    }
}

impl<T> Signed<T>
where
    T: ConditionallySelectable + crypto_bigint::Bounded + Encoding + Integer + RandomMod,
{
    // Returns a random value in range `[-bound, bound]`.
    //
    // Note: variable time in bit size of `bound`.
    fn random_bounded(rng: &mut impl CryptoRngCore, bound: &NonZero<T>) -> Self {
        let bound_bits = bound.as_ref().bits_vartime();
        assert!(
            bound_bits < T::BITS,
            "Out of bounds: bound_bits was {} but must be smaller than {}",
            bound_bits,
            T::BITS - 1
        );
        // Will not overflow because of the assertion above
        let positive_bound = bound
            .as_ref()
            .overflowing_shl_vartime(1)
            .expect("Just asserted that bound is smaller than precision; qed")
            .checked_add(&T::one())
            .expect("Checked bounds above");
        let positive_result = T::random_mod(
            rng,
            &NonZero::new(positive_bound).expect("the bound is non-zero by construction"),
        );
        // Will not panic because of the assertion above
        Self::new_from_unsigned(positive_result.wrapping_sub(bound.as_ref()), bound_bits)
            .expect("bounded by `bound_bits` by construction")
    }

    /// Returns a random value in range `[-2^bound_bits, 2^bound_bits]`.
    ///
    /// Note: variable time in `bound_bits`.
    pub fn random_bounded_bits(rng: &mut impl CryptoRngCore, bound_bits: usize) -> Self {
        assert!(
            bound_bits < (T::BITS - 1) as usize,
            "Out of bounds: bound_bits was {} but must be smaller than {}",
            bound_bits,
            T::BITS - 1
        );

        let bound = NonZero::new(T::one() << bound_bits).expect("Checked bound_bits just above; qed");
        Self::random_bounded(rng, &bound)
    }
}

impl<T: Integer> Default for Signed<T> {
    fn default() -> Self {
        Self {
            bound: 0,
            value: T::default(),
        }
    }
}

impl<T> Zeroize for Signed<T>
where
    T: Integer + Zeroize,
{
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl<T> secrecy::CloneableSecret for Signed<T> where T: Clone + Integer + Zeroize {}

impl<T> From<Signed<T>> for SecretBox<Signed<T>>
where
    T: Integer + Zeroize,
{
    fn from(value: Signed<T>) -> Self {
        Box::new(value).into()
    }
}

impl<T> From<&Signed<T>> for SecretBox<Signed<T>>
where
    T: Integer + Zeroize,
{
    fn from(value: &Signed<T>) -> Self {
        SecretBox::new(Box::new(value.clone()))
    }
}

impl<T> ConditionallySelectable for Signed<T>
where
    T: Integer + ConditionallySelectable,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            bound: u32::conditional_select(&a.bound, &b.bound, choice),
            value: T::conditional_select(&a.value, &b.value, choice),
        }
    }
}

impl<T> Neg for Signed<T>
where
    T: Integer + crypto_bigint::Bounded + ConditionallySelectable + Encoding,
{
    type Output = Self;
    fn neg(self) -> Self::Output {
        Signed::neg(&self)
    }
}

impl<T> Neg for &Signed<T>
where
    T: Integer + crypto_bigint::Bounded + ConditionallySelectable + Encoding,
{
    type Output = Signed<T>;
    fn neg(self) -> Self::Output {
        Signed::neg(self)
    }
}

impl<T> Signed<T>
where
    T: crypto_bigint::Bounded + HasWide + Integer,
    <T as HasWide>::Wide: RandomMod,
{
    /// Returns a random value in range `[-2^bound_bits * scale, 2^bound_bits * scale]`.
    ///
    /// Note: variable time in `bound_bits` and bit size of `scale`.
    pub fn random_bounded_bits_scaled(
        rng: &mut impl CryptoRngCore,
        bound_bits: usize,
        scale: &Bounded<T>,
    ) -> Signed<T::Wide> {
        let bound_bits = u32::try_from(bound_bits).expect("Assumed to fit in a u32; caller beware");
        assert!(
            bound_bits < T::BITS - 1,
            "Out of bounds: bound_bits was {} but must be smaller than {}",
            bound_bits,
            T::BITS - 1
        );
        let scaled_bound: <T as HasWide>::Wide = scale
            .clone()
            .into_wide()
            .as_ref()
            .overflowing_shl_vartime(bound_bits)
            .expect("Just asserted that bound bits is smaller than T's bit precision");

        // Sampling in range [0, 2^bound_bits * scale * 2 + 1) and translating to the desired range.
        let positive_bound = scaled_bound
            .overflowing_shl_vartime(1)
            .expect(concat![
                "`scaled_bound` is double the size of a T; we asserted that the `bound_bits` ",
                "will not cause overflow in T ⇒ it's safe to left-shift 1 step ",
                "(aka multiply by 2)."
            ])
            .checked_add(&T::Wide::one())
            .expect(concat![
                "`scaled_bound` is double the size of a T; we asserted that the `bound_bits` ",
                "will not cause overflow in T ⇒ it's safe to add 1."
            ]);
        let positive_result = T::Wide::random_mod(
            rng,
            &NonZero::new(positive_bound)
                .expect("Input guaranteed to be positive and it's non-zero because we added 1"),
        );
        let result = positive_result.wrapping_sub(&scaled_bound);

        Signed {
            bound: bound_bits + scale.bound(),
            value: result,
        }
    }
}

impl<T> Signed<T>
where
    T: ConditionallySelectable + crypto_bigint::Bounded + HasWide + Encoding + Integer,
    T::Wide: ConditionallySelectable + crypto_bigint::Bounded,
{
    /// Returns a [`Signed`] with the same value, but twice the bit-width.
    /// Consumes `self`, but under the hood this method clones.
    pub fn into_wide(self) -> Signed<T::Wide> {
        let abs_result = self.abs().into_wide();
        Signed::new_from_abs(abs_result, self.bound(), self.is_negative())
            .expect("the value fit the bound before, and the bound won't overflow for `WideUint`")
    }

    /// Multiplies two [`Signed`] and returns a new [`Signed`] of twice the bit-width
    pub fn mul_wide(&self, rhs: &Self) -> Signed<T::Wide> {
        let abs_value = self.abs().mul_wide(&rhs.abs());
        Signed::new_from_abs(
            abs_value,
            self.bound() + rhs.bound(),
            self.is_negative() ^ rhs.is_negative(),
        )
        .expect("The call to new_positive cannot fail when the input is the absolute value ")
    }
}

impl<T> Signed<T>
where
    T: crypto_bigint::Bounded + HasWide + Integer,
    T::Wide: ConditionallySelectable + crypto_bigint::Bounded + HasWide,
{
    /// Returns a random value in range `[-2^bound_bits * scale, 2^bound_bits * scale]`.
    ///
    /// Note: variable time in `bound_bits` and `scale`.
    pub fn random_bounded_bits_scaled_wide(
        rng: &mut impl CryptoRngCore,
        bound_bits: usize,
        scale: &Bounded<T::Wide>,
    ) -> Signed<<T::Wide as HasWide>::Wide> {
        let bound_bits = u32::try_from(bound_bits).expect("Assumed to fit in a u32; caller beware");
        assert!(
            bound_bits < T::BITS - 1,
            "Out of bounds: bound_bits was {} but must be smaller than {}",
            bound_bits,
            T::BITS - 1
        );
        let scaled_bound = scale
            .as_ref()
            .into_wide()
            .overflowing_shl_vartime(bound_bits)
            .expect("Just asserted that bound_bits is smaller than bit precision of T");

        // Sampling in range [0, 2^bound_bits * scale * 2 + 1) and translating to the desired range.
        let positive_bound = scaled_bound
            .overflowing_shl_vartime(1)
            .expect(concat![
                "`scaled_bound` is double the size of a T::Wide; we asserted that the `bound_bits` ",
                "will not cause overflow in T::Wide ⇒ it's safe to left-shift 1 step ",
                "(aka multiply by 2)."
            ])
            .checked_add(&<T::Wide as HasWide>::Wide::one())
            .expect(concat![
                "`scaled_bound` is double the size of a T::Wide; we asserted that the `bound_bits` ",
                "will not cause overflow in T::Wide ⇒ it's safe to add 1."
            ]);
        let positive_result = <T::Wide as HasWide>::Wide::random_mod(
            rng,
            &NonZero::new(positive_bound)
                .expect("Input guaranteed to be positive and it's non-zero because we added 1"),
        );
        let result = positive_result.wrapping_sub(&scaled_bound);

        Signed {
            bound: bound_bits + scale.bound(),
            value: result,
        }
    }
}

impl<T> Add<Signed<T>> for Signed<T>
where
    T: Integer + crypto_bigint::Bounded,
{
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(&rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<T> Add<&Signed<T>> for Signed<T>
where
    T: Integer + crypto_bigint::Bounded,
{
    type Output = Self;
    fn add(self, rhs: &Self) -> Self::Output {
        self.checked_add(rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<T> CheckedSub<Signed<T>> for Signed<T>
where
    T: crypto_bigint::Bounded + ConditionallySelectable + Integer,
{
    /// Performs subtraction that returns `None` instead of wrapping around on underflow.
    /// The bound of the result is the bound of `self` (lhs).
    fn checked_sub(&self, rhs: &Signed<T>) -> CtOption<Self> {
        self.value.checked_sub(&rhs.value).and_then(|v| {
            let signed = Signed::new_positive(v, self.bound);
            if let Some(signed) = signed {
                CtOption::new(signed, 1u8.into())
            } else {
                CtOption::new(Signed::default(), 0u8.into())
            }
        })
    }
}

impl<T> Sub<Signed<T>> for Signed<T>
where
    T: crypto_bigint::Bounded + ConditionallySelectable + Encoding + Integer,
{
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_add(&-rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<T> Sub<&Signed<T>> for Signed<T>
where
    T: crypto_bigint::Bounded + ConditionallySelectable + Encoding + Integer,
{
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self::Output {
        self.checked_add(&-rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<T> Mul<Signed<T>> for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded + ConditionallySelectable,
{
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        self.checked_mul(&rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<T> Mul<&Signed<T>> for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded + ConditionallySelectable,
{
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self::Output {
        self.checked_mul(rhs)
            .expect("does not overflow by the construction of the arguments")
    }
}

impl<T> core::iter::Sum for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x.checked_add(&y).unwrap())
            .unwrap_or(Self::default())
    }
}

impl<'a, T> core::iter::Sum<&'a Self> for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded,
{
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}

impl<T> PartialOrd for Signed<T>
where
    T: ConditionallySelectable + crypto_bigint::Bounded + Encoding + Integer + PartialOrd,
{
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        // The bounds of the two numbers do not come into play, only the signs and absolute values
        if bool::from(self.is_negative()) {
            if bool::from(other.is_negative()) {
                // both are negative, flip comparison
                other.abs().partial_cmp(&self.abs())
            } else {
                // self is neg, other is not => other is bigger
                Some(core::cmp::Ordering::Less)
            }
        } else if bool::from(other.is_negative()) {
            // self is positive, other is not => self is bigger
            Some(core::cmp::Ordering::Greater)
        } else {
            // both are positive, use abs value
            self.abs().partial_cmp(&other.abs())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Neg;

    use crypto_bigint::{CheckedSub, U128};
    use rand::SeedableRng;
    use rand_chacha::{self, ChaCha8Rng};

    use super::Signed;
    use crate::uint::U1024;
    const SEED: u64 = 123;

    #[test]
    fn partial_ord_pos_vs_pos() {
        let bound = 34;
        let p1 = Signed::new_from_unsigned(U128::from_u64(10), bound).unwrap();
        let p2 = Signed::new_from_unsigned(U128::from_u64(12), bound).unwrap();

        assert!(p1 < p2);
        assert_eq!(p1, Signed::new_from_unsigned(U128::from_u64(10), bound).unwrap());
    }

    #[test]
    fn partial_ord_neg_vs_neg() {
        let bound = 114;
        let n1 = Signed::new_from_unsigned(U128::from_u64(10), bound).unwrap().neg();
        let n2 = Signed::new_from_unsigned(U128::from_u64(12), bound).unwrap().neg();

        assert!(n2 < n1);
        assert_eq!(
            n1 + Signed::new_from_unsigned(U128::from_u64(10), bound).unwrap(),
            Signed::new_from_unsigned(U128::ZERO, bound + 1).unwrap()
        );
    }

    #[test]
    fn partial_ord_pos_vs_neg() {
        let bound = 65;
        let p = Signed::new_from_unsigned(U128::from_u64(10), bound).unwrap();
        let n = Signed::new_from_unsigned(U128::from_u64(12), bound).unwrap().neg();
        assert!(n < p);
    }

    #[test]
    fn partial_ord_neg_vs_pos() {
        let bound = 93;
        let n = Signed::new_from_unsigned(U128::from_u64(10), bound).unwrap().neg();
        let p = Signed::new_from_unsigned(U128::from_u64(12), bound).unwrap();
        assert!(n < p);
    }

    #[test]
    fn partial_ord_different_bounds() {
        let s1 = Signed::new_from_unsigned(U128::from_u8(5), 10).unwrap();
        let s2 = Signed::new_from_unsigned(U128::from_u8(3), 106).unwrap();
        let s3 = Signed::new_from_unsigned(U128::from_u8(30), 127).unwrap();
        let s4 = Signed::new_from_unsigned(U128::from_u8(30), 47).unwrap();

        assert!(s2 < s1);
        assert!(s2 < s3);
        assert_ne!(s3, s4); // different bounds compare differently
        assert_eq!(s3.abs(), s4.abs());
    }

    #[test]
    fn adding_signed_numbers_increases_the_bound() {
        let s1 = Signed::new_from_unsigned(U128::from_u8(5), 13).unwrap();
        let s2 = Signed::new_from_unsigned(U128::from_u8(3), 10).unwrap();
        // The sum has a bound that is equal to the biggest bound of the operands + 1
        assert_eq!((s1 + s2).bound(), 14);
    }

    #[test]
    #[should_panic]
    fn adding_signed_numbers_with_max_bounds_panics() {
        let s1 = Signed::new_from_unsigned(U128::from_u8(5), 127).unwrap();
        let s2 = Signed::new_from_unsigned(U128::from_u8(3), 127).unwrap();

        let _ = s1 + s2;
    }

    #[test]
    fn checked_mul_sums_bounds() {
        let s1 = Signed::new_from_unsigned(U128::from_u8(5), 27).unwrap();
        let s2 = Signed::new_from_unsigned(U128::from_u8(3), 17).unwrap();
        let mul = s1.checked_mul(&s2).unwrap();

        assert_eq!(mul.bound(), 44);
    }

    #[test]
    fn checked_mul_fails_when_sum_of_bounds_is_too_large() {
        let s1 = Signed::new_from_unsigned(U128::from_u8(5), 127).unwrap();
        let s2 = Signed::new_from_unsigned(U128::from_u8(3), 17).unwrap();
        let mul = s1.checked_mul(&s2);

        assert!(bool::from(mul.is_none()));
    }

    #[test]
    fn mul_wide_sums_bounds() {
        let s1 = Signed::new_from_unsigned(U1024::MAX >> 1, 1023).unwrap();
        let mul = s1.mul_wide(&s1);
        assert_eq!(mul.bound(), 2046);

        let s2 = Signed::new_from_unsigned(U1024::from_u8(8), 4).unwrap();
        let mul = s1.mul_wide(&s2);
        assert_eq!(mul.bound(), 1027);
    }

    #[test]
    fn checked_mul_handles_sign() {
        let n = Signed::new_from_unsigned(U128::from_u8(5), 27).unwrap().neg();
        let p = Signed::new_from_unsigned(U128::from_u8(3), 17).unwrap();
        let neg_pos = n.checked_mul(&p).unwrap();
        let pos_neg = p.checked_mul(&n).unwrap();
        let pos_pos = p.checked_mul(&p).unwrap();
        let neg_neg = n.checked_mul(&n).unwrap();
        // negative * positive ⇒ negative
        assert!(bool::from(neg_pos.is_negative()));
        // positive * negative ⇒ negative
        assert!(bool::from(pos_neg.is_negative()));
        // positive * positive ⇒ positive
        assert!(!bool::from(pos_pos.is_negative()));
        // negative * negative ⇒ positive
        assert!(!bool::from(neg_neg.is_negative()));
    }

    #[test]
    fn random_bounded_bits_is_sane() {
        let mut rng = ChaCha8Rng::seed_from_u64(SEED);
        for bound_bits in 1..U1024::BITS - 1 {
            let signed: Signed<U1024> = Signed::random_bounded_bits(&mut rng, bound_bits as usize);
            assert!(signed.abs() < U1024::MAX >> (U1024::BITS - 1 - bound_bits));
            signed.assert_bound(bound_bits as usize);
        }
    }

    #[test]
    fn signed_with_low_bounds() {
        // a 2 bit bound means numbers must be smaller or equal to 3
        let bound = 2;
        let value = U1024::from_u8(3);
        let signed = Signed::new_from_unsigned(value, bound).unwrap();
        assert!(signed.abs() < U1024::MAX >> (U1024::BITS - 1 - bound));
        signed.assert_bound(bound as usize);
        // 4 is too big
        let value = U1024::from_u8(4);
        let signed = Signed::new_from_unsigned(value, bound);
        assert!(signed.is_none());

        // a 1 bit bound means numbers must be smaller or equal to 1
        let bound = 1;
        let value = U1024::from_u8(1);
        let signed = Signed::new_from_unsigned(value, bound).unwrap();
        assert!(signed.abs() < U1024::MAX >> (U1024::BITS - 1 - bound));
        signed.assert_bound(bound as usize);
        // 2 is too big
        let value = U1024::from_u8(2);
        let signed = Signed::new_from_unsigned(value, bound);
        assert!(signed.is_none());

        // a 0 bit bound means only 0 is a valid value
        let bound = 0;
        let value = U1024::from_u8(0);
        let signed = Signed::new_from_unsigned(value, bound).unwrap();
        assert!(signed.abs() < U1024::MAX >> (U1024::BITS - 1 - bound));
        signed.assert_bound(bound as usize);
        // 1 is too big
        let value = U1024::from_u8(1);
        let signed = Signed::new_from_unsigned(value, bound);
        assert!(signed.is_none());
    }

    #[test]
    fn neg_u128() {
        let n = Signed::new_from_unsigned(U128::from_be_hex("fffffffffffffffffffffffffffffff0"), 127).unwrap();
        let neg_n = Signed::new_from_unsigned(U128::from_be_hex("00000000000000000000000000000010"), 127).unwrap();
        assert!(bool::from(n.is_negative()));
        assert!(!bool::from(neg_n.is_negative()));
        assert_eq!(n.neg(), neg_n);
        assert_eq!(n.neg().neg(), n);
    }

    #[test]
    #[should_panic(expected = "does not overflow by the construction of the arguments")]
    fn sub_panics_on_underflow() {
        // Biggest/smallest Signed<U128> is |2^127|:
        use crypto_bigint::U128;
        let max_uint = U128::from_u128(u128::MAX >> 1);
        let one_signed = Signed::new_from_abs(U128::ONE, U128::BITS - 1, 0u8.into()).unwrap();
        let min_signed = Signed::new_from_abs(max_uint, U128::BITS - 1, 1u8.into()).expect("|2^127| is a valid Signed");
        let _ = min_signed - one_signed;
    }
    #[test]
    #[should_panic(expected = "does not overflow by the construction of the arguments")]
    fn sub_panics_on_underflow_1024() {
        // Biggest/smallest Signed<U1024> is |2^1023|:
        let max_uint = U1024::MAX >> 1;
        let one_signed = Signed::new_from_abs(U1024::ONE, U1024::BITS - 1, 0u8.into()).unwrap();
        let min_signed =
            Signed::new_from_abs(max_uint, U1024::BITS - 1, 1u8.into()).expect("|2^1023| is a valid Signed");
        let _ = min_signed - one_signed;
    }

    #[test]
    fn checked_sub_handles_underflow() {
        // Biggest/smallest Signed<U1024> is |2^1023|
        let max_uint = U1024::MAX >> 1;
        let one_signed = Signed::new_from_abs(U1024::ONE, U1024::BITS - 1, 0u8.into()).unwrap();
        let min_signed =
            Signed::new_from_abs(max_uint, U1024::BITS - 1, 1u8.into()).expect("|2^1023| is a valid Signed");

        let result = min_signed.checked_sub(&one_signed);
        assert!(bool::from(result.is_none()))
    }
}
