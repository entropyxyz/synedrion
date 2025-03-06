use core::ops::{Add, Mul, Neg, Sub};

use crypto_bigint::{
    rand_core::CryptoRngCore,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess, CtOption},
    zeroize::Zeroize,
    BitOps, Bounded, CheckedAdd, CheckedMul, CheckedSub, Integer, NonZero, RandomMod, ShlVartime, WrappingAdd,
    WrappingMul, WrappingNeg, WrappingSub,
};

use super::{HasWide, PublicSigned, SecretUnsigned};
use crate::tools::Secret;

/// A wrapper over secret unsigned integers that treats two's complement numbers as negative.
#[derive(Debug, Clone)]
pub(crate) struct SecretSigned<T: Zeroize> {
    /// Bound on the bit size of the absolute value (that is, `abs(value) < 2^bound`).
    bound: u32,
    value: Secret<T>,
}

impl<T> SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    /// A constructor for internal use where we already checked the bound.
    /// Creates a [`SignedSecret`] from an unsigned value, treating it as if it encodes the sign as two's complement.
    ///
    /// Extracting in a method to make the intent clear.
    fn new_from_unsigned_unchecked(value: Secret<T>, bound: u32) -> Self {
        Self { value, bound }
    }

    /// Creates a signed value from an unsigned one, assuming that it encodes a positive value
    /// treated as two's complement.
    ///
    /// Panics if it is not the case.
    pub fn new_positive(value: Secret<T>, bound: u32) -> Option<Self> {
        // Reserving one bit as the sign bit (MSB)
        if bound >= T::BITS || value.expose_secret().bits() > bound {
            return None;
        }
        let result = Self::new_from_unsigned_unchecked(value, bound);
        if result.is_negative().into() {
            return None;
        }
        Some(result)
    }

    pub fn zero() -> Self {
        Self {
            value: Secret::init_with(|| T::zero()),
            bound: 0,
        }
    }

    /// Returns a truthy `Choice` if this number is negative.
    pub fn is_negative(&self) -> Choice {
        // Check the MSB, `1` indicates that it is negative.
        Choice::from(self.value.expose_secret().bit_vartime(T::BITS - 1) as u8)
    }

    pub fn bound(&self) -> u32 {
        self.bound
    }

    pub fn to_public(&self) -> PublicSigned<T> {
        PublicSigned::new_from_unsigned(self.value.expose_secret().clone(), self.bound).expect("the bound is valid")
    }

    /// Performs the unary `-` operation.
    pub fn neg(&self) -> Self {
        Self {
            value: self.value.wrapping_neg(),
            bound: self.bound,
        }
    }
}

impl<T> SecretSigned<T>
where
    T: ConditionallySelectable + Zeroize + Integer + Bounded,
{
    pub fn abs_value(&self) -> Secret<T> {
        Secret::<T>::conditional_select(&self.value, &self.value.wrapping_neg(), self.is_negative())
    }

    /// Computes the absolute value of [`self`]
    pub fn abs(&self) -> SecretUnsigned<T> {
        SecretUnsigned::new(
            Secret::<T>::conditional_select(&self.value, &self.value.wrapping_neg(), self.is_negative()),
            self.bound,
        )
        .expect("the absolute value is within the same bound")
    }

    /// Creates a [`SignedSecret`] from an unsigned value, treating it as if it encodes the sign as two's complement.
    ///
    /// Returns `None` if the requested bound is too large, or if `abs(value)` is actually larger than the bound.
    pub fn new_from_unsigned(value: Secret<T>, bound: u32) -> Option<Self> {
        let is_negative = Choice::from(value.expose_secret().bit_vartime(T::BITS - 1) as u8);
        let abs = Secret::<T>::conditional_select(&value, &value.wrapping_neg(), is_negative);
        // Reserving one bit as the sign bit (MSB)
        if bound >= T::BITS || abs.expose_secret().bits() > bound {
            return None;
        }
        Some(Self::new_from_unsigned_unchecked(value, bound))
    }

    /// Creates a [`SignedSecret`] from an unsigned value, treating it as if it is the absolute value.
    /// If `is_negative` is truthy, crates a negative [`SignedSecret`] with the given absolute value.
    ///
    /// Returns `None` if the bound is too large, or if `abs_value` is actually larger than the bound.
    fn new_from_abs(abs_value: Secret<T>, bound: u32, is_negative: Choice) -> Option<Self> {
        Self::new_from_unsigned(
            Secret::<T>::conditional_select(&abs_value, &abs_value.wrapping_neg(), is_negative),
            bound,
        )
    }

    /// Creates a [`SignedSecret`] from an unsigned value in range `[0, modulus)`,
    /// treating the values greater than `modulus / 2` as negative ones (modulo `modulus`).
    /// `modulus_bound` is the bit bound for the modulus; the bound of the result will be set to `modulus_bound - 1`
    /// (since it is the bound for the absolute value).
    ///
    /// Returns `None` if the bound is too large, or if `abs(value)` is greater or equal to `2^bound`.
    pub fn new_modulo(positive_value: Secret<T>, modulus: &NonZero<T>, modulus_bound: u32) -> Option<Self> {
        // We are taking a `bound` explicitly and not deriving it from the `modulus`
        // because we want it to be the same across different runs, and the RSA modulus, being a product of two randoms,
        // can have varying size (e.g. for two random 1024 bit primes it can be 2046-2048 bits long).
        // TODO (#183): after this issue is fixed, this comment needs to be amended
        // (but we will probably still need the explicit `modulus_bound`).

        let half_modulus = modulus.as_ref().wrapping_shr_vartime(1);
        let is_negative = positive_value.expose_secret().ct_gt(&half_modulus);
        // Can't define a `Sub<Secret>` for `Uint`, so have to re-wrap manually.
        let negative_value = Secret::init_with(|| *modulus.as_ref() - positive_value.expose_secret()).wrapping_neg();
        let value = Secret::<T>::conditional_select(&positive_value, &negative_value, is_negative);
        Self::new_from_unsigned(value, modulus_bound - 1)
    }

    /// Asserts that the value is within the interval the paper denotes as $±2^exp$.
    /// Panics if it is not the case.
    ///
    /// That is, the value must be within $[-2^{exp-1}+1, 2^{exp-1}]$
    /// (See Section 3, Groups & Fields).
    ///
    /// Variable time w.r.t. `exp`.
    pub fn assert_exponent_range(&self, exp: u32) {
        let abs = self.abs();

        // Check if $abs(self) ∈ [0, 2^{exp-1}-1]$, that is $self ∈ [-2^{exp-1}+1, 2^{exp-1}-1]$.
        let mask = T::one().wrapping_neg().wrapping_shl_vartime(exp - 1);
        let masked = &abs & mask;
        let in_bound = masked.is_zero();

        // Have to check for the high end of the range too
        let is_high_end = abs.expose_secret().ct_eq(&(T::one() << (exp - 1))) & !self.is_negative();
        assert!(bool::from(in_bound | is_high_end), "out of bounds $±2^{exp}$",)
    }
}

impl<T> SecretSigned<T>
where
    T: ConditionallySelectable + Zeroize + Bounded + HasWide,
    T::Wide: ConditionallySelectable + Zeroize + Bounded,
{
    /// Returns a [`SecretSigned`] with the same value, but twice the bit-width.
    pub fn to_wide(&self) -> SecretSigned<T::Wide> {
        let abs_result = self.abs_value().to_wide();
        SecretSigned::new_from_abs(abs_result, self.bound(), self.is_negative())
            .expect("the value fit the bound before, and the bound won't overflow for `T::Wide`")
    }

    /// Multiplies two numbers and returns a new [`SecretSigned`] of twice the bit-width.
    pub fn mul_wide_public(&self, rhs: &PublicSigned<T>) -> SecretSigned<T::Wide> {
        let abs_value = Secret::init_with(|| self.abs_value().expose_secret().mul_wide(&rhs.abs()));
        SecretSigned::new_from_abs(
            abs_value,
            self.bound() + rhs.bound(),
            self.is_negative() ^ Choice::from(rhs.is_negative() as u8),
        )
        .expect("the new bound is valid since the sum of the constituent bounds fits in a `T::Wide`")
    }

    /// Multiplies two numbers and returns a new [`SecretSigned`] of twice the bit-width.
    pub fn mul_wide(&self, rhs: &SecretSigned<T>) -> SecretSigned<T::Wide> {
        let abs_value = Secret::init_with(|| {
            self.abs_value()
                .expose_secret()
                .mul_wide(rhs.abs_value().expose_secret())
        });
        SecretSigned::new_from_abs(
            abs_value,
            self.bound() + rhs.bound(),
            self.is_negative() ^ rhs.is_negative(),
        )
        .expect("the new bound is valid since the sum of the constituent bounds fits in a `T::Wide`")
    }
}

impl<T> CheckedAdd<SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    fn checked_add(&self, rhs: &SecretSigned<T>) -> CtOption<Self> {
        let bound = core::cmp::max(self.bound, rhs.bound);
        let in_bounds = bound.ct_lt(&T::BITS);

        let self_sign = self.is_negative();
        let rhs_sign = rhs.is_negative();

        let sum = self.value.wrapping_add(&rhs.value);
        let sum_sign = Choice::from(sum.expose_secret().bit_vartime(T::BITS - 1) as u8);

        // When the sign of the sum is different from the signs of the operands we have an overflow.
        let flipped_sign = self_sign.ct_eq(&rhs_sign) & self_sign.ct_ne(&sum_sign);
        // When the sum wraps around to the negative side, we need to check if it is the case of `-0`.
        let mut minus_zero = T::zero();
        minus_zero.set_bit_vartime(T::BITS - 1, true);
        let did_wrap = Choice::from((sum.expose_secret() == &minus_zero) as u8);
        let in_range = in_bounds & !flipped_sign & !did_wrap;

        let result = Self { bound, value: sum };
        CtOption::new(result, in_range)
    }
}

impl<T> CheckedAdd<PublicSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    fn checked_add(&self, rhs: &PublicSigned<T>) -> CtOption<Self> {
        // TODO(dp): Need to remove this +1 increment too?
        let bound = core::cmp::max(self.bound, rhs.bound()) + 1;
        let in_range = bound.ct_lt(&T::BITS);
        let result = Self {
            bound,
            value: Secret::init_with(|| self.value.expose_secret().wrapping_add(rhs.value())),
        };
        CtOption::new(result, in_range)
    }
}

impl<T> CheckedSub<SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    fn checked_sub(&self, rhs: &SecretSigned<T>) -> CtOption<Self> {
        // TODO(dp): Need to remove this +1 increment too?
        let bound = core::cmp::max(self.bound, rhs.bound()) + 1;
        let in_range = bound.ct_lt(&T::BITS);
        let result = Self {
            bound,
            value: self.value.wrapping_sub(&rhs.value),
        };
        CtOption::new(result, in_range)
    }
}

impl<T> CheckedMul<SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    fn checked_mul(&self, rhs: &SecretSigned<T>) -> CtOption<Self> {
        let bound = self.bound + rhs.bound;
        let in_range = bound.ct_lt(&T::BITS);
        let result = Self {
            bound,
            value: self.value.wrapping_mul(&rhs.value),
        };
        CtOption::new(result, in_range)
    }
}

impl<T> CheckedMul<PublicSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    fn checked_mul(&self, rhs: &PublicSigned<T>) -> CtOption<Self> {
        let bound = self.bound + rhs.bound();
        let in_range = bound.ct_lt(&T::BITS);
        let result = Self {
            bound,
            value: Secret::init_with(|| self.value.expose_secret().wrapping_mul(rhs.value())),
        };
        CtOption::new(result, in_range)
    }
}

impl<T> SecretSigned<T>
where
    T: Zeroize + Integer + Bounded + RandomMod,
{
    /// Returns a random value in range $±2^{exp}$ as defined by the paper, that is
    /// sampling from $[-2^{exp-1}+1, 2^{exp-1}]$ (See Section 3, Groups & Fields).
    ///
    /// Note: variable time in `exp`.
    pub fn random_in_exponent_range(rng: &mut impl CryptoRngCore, exp: u32) -> Self {
        assert!(exp > 0, "`exp` must be greater than zero");
        assert!(
            exp < T::BITS,
            "Out of bounds: `exp` was {exp} but must be smaller or equal to {}",
            T::BITS
        );

        // Sampling in range `[0, 2^exp)` and translating to the desired range by subtracting `2^{exp-1}-1`.
        let positive_bound = NonZero::new(
            T::one()
                .overflowing_shl_vartime(exp)
                .expect("does not overflow because of the assertions above"),
        )
        .expect("non-zero as long as `exp` doesn't overflow, which was checked above");
        let shift = T::one()
            .overflowing_shl_vartime(exp - 1)
            .expect("does not overflow because of the assertions above")
            .checked_sub(&T::one())
            .expect("does not overflow because of the assertions above");
        let positive_result = Secret::init_with(|| T::random_mod(rng, &positive_bound));
        Self::new_from_unsigned_unchecked(
            Secret::init_with(|| positive_result.expose_secret().wrapping_sub(&shift)),
            exp,
        )
    }
}

impl<T> SecretSigned<T>
where
    T: Zeroize + Integer + Bounded + HasWide,
    T::Wide: Zeroize + Bounded + RandomMod,
{
    /// Returns a random value in range $±2^{exp} scale$ as defined by the paper, that is
    /// sampling from $[-scale (2^{exp-1}+1), scale 2^{exp-1}]$ (See Section 3, Groups & Fields).
    ///
    /// Note: variable time in `exp` and bit size of `scale`.
    pub fn random_in_exponent_range_scaled(rng: &mut impl CryptoRngCore, exp: u32, scale: &T) -> SecretSigned<T::Wide> {
        assert!(exp > 0, "`exp` must be greater than zero");
        assert!(
            exp < T::BITS,
            "Out of bounds: `exp` was {exp} but must be smaller than {}",
            T::BITS
        );

        // Sampling in range `[0, scale * 2^exp)` and translating to the desired range
        // by subtracting `scale * 2^{exp-1}-1`.
        let positive_bound = NonZero::new(
            scale
                .to_wide()
                .overflowing_shl_vartime(exp)
                .expect("`2^exp` fits into `T`, so the result fits into `T::Wide`"),
        )
        .expect("non-zero as long as `exp` doesn't overflow, which was checked above");
        let shift = scale
            .to_wide()
            .overflowing_shl_vartime(exp - 1)
            .expect("`2^exp` fits into `T`, so the result fits into `T::Wide`")
            .checked_sub(&T::Wide::one())
            .expect("does not overflow because of the assertions above");

        let positive_result = Secret::init_with(|| T::Wide::random_mod(rng, &positive_bound));
        let value = Secret::init_with(|| positive_result.expose_secret().wrapping_sub(&shift));

        SecretSigned::new_from_unsigned_unchecked(value, exp + scale.bits_vartime())
    }
}

impl<T> SecretSigned<T>
where
    T: Zeroize + Integer + Bounded + HasWide,
    T::Wide: Zeroize + HasWide,
    <T::Wide as HasWide>::Wide: Zeroize + Bounded,
{
    /// Returns a random value in range $±2^{exp} scale$ as defined by the paper, that is
    /// sampling from $[-scale (2^{exp-1}+1), scale 2^{exp-1}]$ (See Section 3, Groups & Fields).
    ///
    /// Note: variable time in `exp` and bit size of `scale`.
    pub fn random_in_exponent_range_scaled_wide(
        rng: &mut impl CryptoRngCore,
        exp: u32,
        scale: &T::Wide,
    ) -> SecretSigned<<T::Wide as HasWide>::Wide> {
        assert!(exp > 0, "`exp` must be greater than zero");
        assert!(
            exp < T::BITS,
            "Out of bounds: `exp` was {exp} but must be smaller than {}",
            T::BITS
        );

        // Sampling in range `[0, scale * 2^exp)` and translating to the desired range
        // by subtracting `scale * 2^{exp-1}-1`.
        let positive_bound = NonZero::new(
            scale
                .to_wide()
                .overflowing_shl_vartime(exp)
                .expect("`2^exp` fits into `T`, so the result fits into `T::Wide::Wide`"),
        )
        .expect("non-zero as long as `exp` doesn't overflow, which was checked above");
        let shift = scale
            .to_wide()
            .overflowing_shl_vartime(exp - 1)
            .expect("`2^exp` fits into `T`, so the result fits into `T::Wide::Wide`")
            .checked_sub(&<T::Wide as HasWide>::Wide::one())
            .expect("does not overflow because of the assertions above");

        let positive_result = Secret::init_with(|| <T::Wide as HasWide>::Wide::random_mod(rng, &positive_bound));
        let value = Secret::init_with(|| positive_result.expose_secret().wrapping_sub(&shift));

        SecretSigned::new_from_unsigned_unchecked(value, exp + scale.bits_vartime())
    }
}

impl<T> Neg for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = Self;
    fn neg(self) -> Self::Output {
        SecretSigned::neg(&self)
    }
}

impl<T> Neg for &SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = SecretSigned<T>;
    fn neg(self) -> Self::Output {
        SecretSigned::neg(self)
    }
}

impl<T> Add<SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        self.checked_add(&rhs)
            .expect("Add<SecretSigned<T>>: the caller ensured the bounds will not overflow")
    }
}

impl<T> Add<&SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = Self;
    fn add(self, rhs: &SecretSigned<T>) -> Self::Output {
        self.checked_add(rhs)
            .expect("Add<&SecretSigned<T>>: the caller ensured the bounds will not overflow")
    }
}

impl<T> Sub<SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self.checked_sub(&rhs)
            .expect("Sub<SecretSigned<T>>: the caller ensured the bounds will not overflow")
    }
}

impl<T> Mul<SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        self.checked_mul(&rhs)
            .expect("Mul<SecretSigned<T>>: the caller ensured the bounds will not overflow")
    }
}

impl<T> Mul<&SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self::Output {
        self.checked_mul(rhs)
            .expect("Mul<&SecretSigned<T>>: the caller ensured the bounds will not overflow")
    }
}

impl<T> Add<PublicSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = SecretSigned<T>;

    fn add(self, rhs: PublicSigned<T>) -> Self::Output {
        self.checked_add(&rhs)
            .expect("Add<PublicSigned<T>>: the caller ensured the bounds will not overflow")
    }
}

impl<T> Mul<PublicSigned<T>> for &SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = SecretSigned<T>;

    fn mul(self, rhs: PublicSigned<T>) -> Self::Output {
        self.checked_mul(&rhs)
            .expect("Mul<PublicSigned<T>>: the caller ensured the bounds will not overflow")
    }
}

impl<T> Mul<PublicSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = SecretSigned<T>;

    fn mul(self, rhs: PublicSigned<T>) -> Self::Output {
        self.checked_mul(&rhs)
            .expect("Mul<PublicSigned<T>>: the caller ensured the bounds will not overflow")
    }
}

impl<'b, T> core::iter::Sum<&'b SecretSigned<T>> for SecretSigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    fn sum<I: Iterator<Item = &'b SecretSigned<T>>>(iter: I) -> Self {
        iter.fold(Self::zero(), |accum, x| accum + x)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Neg;

    use crypto_bigint::{
        subtle::{Choice, ConditionallySelectable},
        Bounded, CheckedAdd, CheckedMul, CheckedSub, Integer, U1024, U128,
    };
    use rand::SeedableRng;
    use rand_chacha::{self, ChaCha8Rng};
    use zeroize::Zeroize;

    use super::SecretSigned;
    use crate::{tools::Secret, uint::PublicSigned};

    const SEED: u64 = 123;

    fn test_new_from_abs<T>(abs_value: T, bound: u32, is_negative: bool) -> Option<SecretSigned<T>>
    where
        T: Zeroize + ConditionallySelectable + Integer + Bounded,
    {
        SecretSigned::new_from_abs(Secret::init_with(|| abs_value), bound, Choice::from(is_negative as u8))
    }

    fn test_new_from_unsigned<T>(abs_value: T, bound: u32) -> Option<SecretSigned<T>>
    where
        T: Zeroize + ConditionallySelectable + Integer + Bounded,
    {
        SecretSigned::new_from_unsigned(Secret::init_with(|| abs_value), bound)
    }

    #[test]
    fn adding_signed_numbers_uses_the_biggest_bound() {
        let s1 = test_new_from_unsigned(U128::from_u8(5), 13).unwrap();
        let s2 = test_new_from_unsigned(U128::from_u8(3), 10).unwrap();
        assert_eq!((s1 + s2).bound(), 13);
    }

    #[test]
    fn adding_signed_numbers_with_max_bounds_works() {
        let s1 = test_new_from_unsigned(U128::from_u8(5), 127).unwrap();
        let s2 = test_new_from_unsigned(U128::from_u8(3), 127).unwrap();

        assert_eq!((s1 + s2).bound(), 127);
    }

    #[test_log::test]
    fn adding_signed_numbers_with_max_bounds() {
        // pos + pos, no overflow
        let s1 = test_new_from_unsigned(U128::from_u8(5), 127).unwrap();
        let s2 = test_new_from_unsigned(U128::from_u8(3), 127).unwrap();
        let result = s1 + s2;
        assert_eq!(result.value.expose_secret(), &U128::from_u8(8));

        // pos + neg, no overflow
        let five = test_new_from_unsigned(U128::from_u8(5), 127).unwrap();
        let minus_3 = test_new_from_abs(U128::from_u8(3), 127, true).unwrap();
        let result = five + minus_3;
        assert_eq!(result.value.expose_secret(), &U128::from_u8(2));

        // pos + pos, overflow
        let max_pos = test_new_from_unsigned(U128::MAX >> 1, 127).unwrap();
        let one = test_new_from_unsigned(U128::from_u8(1), 127).unwrap();
        assert!(
            bool::from(max_pos.checked_add(&one).is_none()),
            "maximum positive plus one overflows"
        );

        // neg + neg, no overflow
        let minus_5 = test_new_from_abs(U128::from_u8(5), 127, true).unwrap();
        let minus_3 = test_new_from_abs(U128::from_u8(3), 127, true).unwrap();
        let result = minus_5 + minus_3;
        assert_eq!(
            result.value.expose_secret(),
            &U128::from_u8(8).wrapping_neg(),
            "|-5 + -3| = 8"
        );
        assert!(bool::from(result.is_negative()), "The result is negative");

        // neg + neg, overflow
        let max_neg = test_new_from_abs(U128::MAX >> 1, 127, true).unwrap(); // b11111111
        let minus_1 = test_new_from_abs(U128::from_u8(1), 127, true).unwrap(); // b10000001
        assert!(
            bool::from(max_neg.checked_add(&minus_1).is_none()),
            "Smallest signed minus 1 overflows"
        );

        // 1 + -1 = 0
        let one = test_new_from_unsigned(U128::from_u8(1), 127).unwrap();
        let minus_one = test_new_from_abs(U128::from_u8(1), 127, true).unwrap();
        let result = one + minus_one;
        assert_eq!(result.value.expose_secret(), &U128::ZERO, "1 + -1 = 0");

        // -1 + 1 = 0
        let minus_one = test_new_from_abs(U128::from_u8(1), 127, true).unwrap();
        let one = test_new_from_unsigned(U128::from_u8(1), 127).unwrap();
        let result = minus_one + one;
        assert_eq!(result.value.expose_secret(), &U128::ZERO, "-1 + 1 = 0");
    }

    #[test]
    fn checked_mul_sums_bounds() {
        let s1 = test_new_from_unsigned(U128::from_u8(5), 27).unwrap();
        let s2 = test_new_from_unsigned(U128::from_u8(3), 17).unwrap();
        let mul = s1.checked_mul(&s2).unwrap();

        assert_eq!(mul.bound(), 44);
    }

    #[test]
    fn checked_mul_fails_when_sum_of_bounds_is_too_large() {
        let s1 = test_new_from_unsigned(U128::from_u8(5), 127).unwrap();
        let s2 = test_new_from_unsigned(U128::from_u8(3), 17).unwrap();
        let mul = s1.checked_mul(&s2);

        assert!(bool::from(mul.is_none()));
    }

    #[test]
    fn mul_wide_sums_bounds() {
        let s = test_new_from_unsigned(U1024::MAX >> 1, 1023).unwrap();
        let s1 = PublicSigned::new_from_unsigned(U1024::MAX >> 1, 1023).unwrap();
        let mul = s.mul_wide_public(&s1);
        assert_eq!(mul.bound(), 2046);

        let s2 = PublicSigned::new_from_unsigned(U1024::from_u8(8), 4).unwrap();
        let mul = s.mul_wide_public(&s2);
        assert_eq!(mul.bound(), 1027);
    }

    #[test]
    fn checked_mul_handles_sign() {
        let n = test_new_from_unsigned(U128::from_u8(5), 27).unwrap().neg();
        let p = test_new_from_unsigned(U128::from_u8(3), 17).unwrap();
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
        for exp in [1, 2, 3, U1024::BITS - 1] {
            let signed: SecretSigned<U1024> = SecretSigned::random_in_exponent_range(&mut rng, exp);
            let value = *signed.abs().expose_secret();
            let bound = U1024::ONE << (exp - 1);
            assert!(value < bound || (value == bound && (!signed.is_negative()).into()));
        }
    }

    #[test]
    fn exponent_range() {
        // If the exponential bound is 3, in the paper definition $∈ ±2^3$ is $∈ [-3, 4]$.

        // 3 is fine
        let signed = test_new_from_unsigned(U1024::from_u8(3), 2).unwrap();
        signed.assert_exponent_range(3);

        // -3 is fine
        signed.neg().assert_exponent_range(3);

        // 4 is fine
        let signed = test_new_from_unsigned(U1024::from_u8(4), 3).unwrap();
        signed.assert_exponent_range(3);
    }

    #[test]
    #[should_panic(expected = "out of bounds $±2^3$")]
    fn exponent_bound_panics() {
        // -4 is out of $∈ ±2^3$ range
        let signed = test_new_from_unsigned(U1024::from_u8(4), 3).unwrap();
        signed.neg().assert_exponent_range(3);
    }

    #[test]
    fn signed_with_low_bounds() {
        // a 2 bit bound means numbers must be smaller or equal to 3
        let bound = 2;
        let value = U1024::from_u8(3);
        let signed = test_new_from_unsigned(value, bound).unwrap();
        assert!(*signed.abs().expose_secret() < U1024::MAX >> (U1024::BITS - 1 - bound));
        // 4 is too big
        let value = U1024::from_u8(4);
        let signed = test_new_from_unsigned(value, bound);
        assert!(signed.is_none());

        // a 1 bit bound means numbers must be smaller or equal to 1
        let bound = 1;
        let value = U1024::from_u8(1);
        let signed = test_new_from_unsigned(value, bound).unwrap();
        assert!(*signed.abs().expose_secret() < U1024::MAX >> (U1024::BITS - 1 - bound));

        // 2 is too big
        let value = U1024::from_u8(2);
        let signed = test_new_from_unsigned(value, bound);
        assert!(signed.is_none());

        // a 0 bit bound means only 0 is a valid value
        let bound = 0;
        let value = U1024::from_u8(0);
        let signed = test_new_from_unsigned(value, bound).unwrap();
        assert!(*signed.abs().expose_secret() < U1024::MAX >> (U1024::BITS - 1 - bound));

        // 1 is too big
        let value = U1024::from_u8(1);
        let signed = test_new_from_unsigned(value, bound);
        assert!(signed.is_none());
    }

    #[test]
    fn signed_with_high_bounds() {
        // Bound is too big
        let bound = 128;
        let value = U128::ONE << 10;
        let signed = test_new_from_unsigned(value, bound);
        assert!(signed.is_none(), "No 128 bit unsigned should fit in a 128-bit signed");

        let bound = 127;
        let signed = test_new_from_unsigned(value, bound);
        assert!(signed.is_some(), "2^10 should fit in a 128-bit signed");

        let bound = 127;
        // The last bit will be interpreted as the sign, so will become a negative number.
        let value = U128::MAX;
        let signed = test_new_from_unsigned(value, bound);
        assert!(signed.is_some());
        assert!(bool::from(signed.unwrap().is_negative()));

        let bound = 127;
        let value = U128::MAX >> 1;
        let signed = test_new_from_unsigned(value, bound);
        assert!(signed.is_some(), "A 127-bit unsigned should fit in a 128-bit signed");
    }

    #[test]
    fn neg_u128() {
        let n = test_new_from_unsigned(U128::from_be_hex("fffffffffffffffffffffffffffffff0"), 127).unwrap();
        let neg_n = test_new_from_unsigned(U128::from_be_hex("00000000000000000000000000000010"), 127).unwrap();
        assert!(bool::from(n.is_negative()));
        assert!(!bool::from(neg_n.is_negative()));
        assert_eq!(n.clone().neg().to_public(), neg_n.to_public());
        assert_eq!(n.clone().neg().neg().to_public(), n.to_public());
    }

    #[test_log::test]
    #[should_panic(expected = "Add<SecretSigned<T>>: the caller ensured the bounds will not overflow")]
    fn add_panics_on_overflow() {
        let max_int = U128::from_u128(u128::MAX >> 1);
        let one_signed = test_new_from_abs(U128::ONE, U128::BITS - 1, false).unwrap();
        let max_signed = test_new_from_abs(max_int, U128::BITS - 1, false).expect("|2^127| is a valid SecretSigned");
        let _ = max_signed + one_signed;
    }

    #[test]
    #[should_panic(expected = "Sub<SecretSigned<T>>: the caller ensured the bounds will not overflow")]
    fn sub_panics_on_underflow() {
        // Biggest/smallest SecretSigned<U128> is |2^127|:
        let max_int = U128::from_u128(u128::MAX >> 1);
        let one_signed = test_new_from_abs(U128::ONE, U128::BITS - 1, false).unwrap();
        let min_signed = test_new_from_abs(max_int, U128::BITS - 1, true).expect("|2^127| is a valid SecretSigned");
        let _ = min_signed - one_signed;
    }

    #[test]
    #[should_panic(expected = "Sub<SecretSigned<T>>: the caller ensured the bounds will not overflow")]
    fn sub_panics_on_underflow_1024() {
        // Biggest/smallest SecretSigned<U1024> is |2^1023|:
        let max_int = U1024::MAX >> 1;
        let one_signed = test_new_from_abs(U1024::ONE, U1024::BITS - 1, false).unwrap();
        let min_signed = test_new_from_abs(max_int, U1024::BITS - 1, true).expect("|2^1023| is a valid SecretSigned");
        let _ = min_signed - one_signed;
    }

    #[test]
    fn checked_sub_handles_underflow() {
        // Biggest/smallest SecretSigned<U1024> is |2^1023|
        let max_uint = U1024::MAX >> 1;
        let one_signed = test_new_from_abs(U1024::ONE, U1024::BITS - 1, false).unwrap();
        let min_signed = test_new_from_abs(max_uint, U1024::BITS - 1, true).expect("|2^1023| is a valid SecretSigned");

        let result = min_signed.checked_sub(&one_signed);
        assert!(bool::from(result.is_none()))
    }
}
