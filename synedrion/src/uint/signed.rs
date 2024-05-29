use alloc::string::String;
use core::ops::{Add, Mul, Neg, Sub};
#[cfg(test)]
use crypto_bigint::Random;
// TODO: re-export these too and put them in the `super::` section
use crypto_bigint::{ShlVartime, WrappingSub};
use digest::XofReader;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    bounded::PackedBounded,
    subtle::{
        Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess,
        CtOption,
    },
    Bounded, CheckedAdd, Encoding, HasWide, Integer, NonZero, RandomMod,
};

use crate::tools::hashing::{Chain, Hashable};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

impl<T> Hashable for Signed<T>
where
    T: Hashable + Integer + Encoding + crypto_bigint::Bounded,
{
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.bound).chain(&self.value)
    }
}

impl<T> Signed<T>
where
    T: Integer + crypto_bigint::Bounded,
{
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
        CtOption::new(
            result,
            !(lhs_neg.ct_eq(&rhs_neg) & !lhs_neg.ct_eq(&res_neg)) & in_range,
        )
    }

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
        // Reserving one bit as the sign bit
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
    T: Integer + crypto_bigint::Bounded + ConditionallySelectable + Encoding,
    T::Monty: ConditionallySelectable,
{
    // TODO: Remove these notes
    // DynResidue is now MontyForm
    // DynResidueParams is now MontyParams
    // UintLike for Uint<L> impl had an assoc type ModUint = DynResidue<L>;
    // In the new code, the Integer for Uint<L> impl has an assoc type Monty that impls trait  Monty
    // TODO: ask reviewers to check this very carefully – not at all sure this is doing the same as before.
    pub fn to_mod(
        self,
        precomputed: <<T as Integer>::Monty as crypto_bigint::Monty>::Params,
    ) -> T::Monty {
        let abs_mod = <<T as Integer>::Monty as crypto_bigint::Monty>::new(self.abs(), precomputed);
        T::Monty::conditional_select(&abs_mod, &-abs_mod, self.is_negative())
    }
}

// Medium amount of bounds
impl<T> Signed<T>
where
    T: Integer + crypto_bigint::Bounded + ConditionallySelectable + Encoding,
{
    fn checked_mul(&self, rhs: &Self) -> CtOption<Self> {
        let bound = self.bound + rhs.bound;
        let in_range = bound.ct_lt(&T::BITS);

        let lhs_neg = self.is_negative();
        let rhs_neg = rhs.is_negative();
        let lhs = T::conditional_select(&self.value, &T::zero().wrapping_sub(&self.value), lhs_neg);
        let rhs = T::conditional_select(&rhs.value, &T::zero().wrapping_sub(&rhs.value), rhs_neg);
        let result = lhs.checked_mul(&rhs);
        let result_neg = lhs_neg ^ rhs_neg;
        result.and_then(|val| {
            let val_neg = T::zero().wrapping_sub(&val);
            let value = T::conditional_select(&val, &val_neg, result_neg);
            CtOption::new(Self { bound, value }, in_range)
        })
    }

    // TODO: Hmm, not sure this helps at all. Or if it's actually correct.
    pub fn neg(&self) -> Self {
        Self {
            value: T::zero().wrapping_sub(&self.value),
            bound: self.bound,
        }
    }

    pub fn abs(&self) -> T {
        // TODO: not sure this is ok, copied from the old impl of `neg()`.
        let neg = T::zero().wrapping_sub(&self.value);
        T::conditional_select(&self.value, &neg, self.is_negative())
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

    pub fn abs_bounded(&self) -> Bounded<T> {
        // Can unwrap here since the maximum bound on the positive Bounded
        // is always greater than the maximum bound on Signed
        Bounded::new(self.abs(), self.bound).expect(
            "Bound for a positive Bounded is always greater than max bound for a Signed; qed",
        )
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

    /// Creates a signed value from an unsigned one,
    /// treating it as if it is the absolute value.
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
}

#[cfg(test)]
impl<T> Signed<T>
where
    T: Integer + crypto_bigint::Bounded + Encoding + ConditionallySelectable + Random,
{
    /// Returns a random value in the whole available range,
    /// that is `[-(2^(BITS-1)-1), 2^(BITS-1)-1]`.
    #[cfg(test)]
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        loop {
            let value = T::random(rng);
            if value != T::one() << (T::BITS - 1) {
                return Self::new_from_unsigned(value, T::BITS - 1).unwrap();
            }
        }
    }
}

impl<T> Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded + ConditionallySelectable + RandomMod,
{
    /// Returns a random value in range `[-bound, bound]`.
    ///
    /// Note: variable time in bit size of `bound`.
    pub fn random_bounded(rng: &mut impl CryptoRngCore, bound: &NonZero<T>) -> Self {
        let bound_bits = bound.as_ref().bits_vartime();
        assert!(bound_bits < <T as crypto_bigint::Bounded>::BITS);
        // Will not overflow because of the assertion above
        let positive_bound = bound
            .as_ref()
            .overflowing_shl_vartime(1)
            .expect("Just asserted that bound is smaller than precision; qed")
            .checked_add(&T::one())
            .unwrap();
        let positive_result = T::random_mod(rng, &NonZero::new(positive_bound).unwrap());
        // Will not panic because of the assertion above
        Self::new_from_unsigned(positive_result.wrapping_sub(bound.as_ref()), bound_bits).unwrap()
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
            .unwrap();
        let positive_result = from_xof(
            rng,
            &NonZero::new(positive_bound)
                .expect("Guaranteed to be greater than zero because we added 1"),
        );
        Self::new_from_unsigned(positive_result.wrapping_sub(bound.as_ref()), bound_bits)
            .expect("Guaranteed to be Some because we checked the bounds just above")
    }

    /// Returns a random value in range `[-2^bound_bits, 2^bound_bits]`.
    ///
    /// Note: variable time in `bound_bits`.
    pub fn random_bounded_bits(rng: &mut impl CryptoRngCore, bound_bits: usize) -> Self {
        assert!(bound_bits < <T as crypto_bigint::Bounded>::BITS as usize - 1);
        let bound =
            NonZero::new(T::one() << bound_bits).expect("Checked bound_bits just above; qed");
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

impl<T> ConditionallyNegatable for Signed<T>
where
    T: Integer + ConditionallySelectable,
{
    #[inline]
    fn conditional_negate(&mut self, choice: Choice) {
        let self_neg: Signed<T> = Signed {
            bound: self.bound,
            value: T::zero().wrapping_sub(&self.value),
        };

        self.conditional_assign(&self_neg, choice);
    }
}

impl<T> Signed<T>
where
    T: Integer + crypto_bigint::Bounded + HasWide,
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
        assert!((bound_bits as u32) < T::BITS - 1);
        let scaled_bound = scale
            .as_ref()
            .clone()
            .into_wide()
            .overflowing_shl_vartime(bound_bits as u32)
            .expect("Just asserted that bound bits is smaller than T's bit precision");

        // Sampling in range [0, 2^bound_bits * scale * 2 + 1) and translating to the desired range.
        let positive_bound = scaled_bound
            .overflowing_shl_vartime(1)
            .expect("TODO: justify this properly")
            .checked_add(&T::Wide::one())
            .expect("TODO: justify this properly");
        let positive_result = T::Wide::random_mod(rng, &NonZero::new(positive_bound).unwrap());
        let result = positive_result.wrapping_sub(&scaled_bound);

        Signed {
            bound: bound_bits as u32 + scale.bound(),
            value: result,
        }
    }
}

impl<T> Signed<T>
where
    T: Integer + HasWide + crypto_bigint::Bounded + Encoding + ConditionallySelectable,
    T::Wide: HasWide + crypto_bigint::Bounded + ConditionallySelectable, //+ ShlVartime,
    <T::Wide as HasWide>::Wide: RandomMod + WrappingSub,
{
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
    /// Returns a random value in range `[-2^bound_bits * scale, 2^bound_bits * scale]`.
    ///
    /// Note: variable time in `bound_bits` and `scale`.
    pub fn random_bounded_bits_scaled_wide(
        rng: &mut impl CryptoRngCore,
        bound_bits: u32, // TODO: was usize; check what BITS was before and decide if we should cast in the code or change the fn signature
        scale: &Bounded<T::Wide>,
    ) -> Signed<<T::Wide as HasWide>::Wide> {
        assert!(bound_bits < <T as crypto_bigint::Bounded>::BITS - 1);
        let scaled_bound = scale
            .as_ref()
            .into_wide()
            .overflowing_shl_vartime(bound_bits)
            .expect("Just asserted that bound_bits is smaller than bit precision of T");

        // Sampling in range [0, 2^bound_bits * scale * 2 + 1) and translating to the desired range.
        let positive_bound = scaled_bound
            .overflowing_shl_vartime(1)
            .expect("TODO: justify this properly")
            .checked_add(&<T::Wide as HasWide>::Wide::one())
            .unwrap();
        let positive_result =
            <T::Wide as HasWide>::Wide::random_mod(rng, &NonZero::new(positive_bound).unwrap());
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
        self.checked_add(&rhs).unwrap()
    }
}

impl<T> Add<&Signed<T>> for Signed<T>
where
    T: Integer + crypto_bigint::Bounded,
{
    type Output = Self;
    fn add(self, rhs: &Self) -> Self::Output {
        self.checked_add(rhs).unwrap()
    }
}

impl<T> Sub<Signed<T>> for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded,
{
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        // TODO: this feels sketchy - double check
        let rhs_neg = Self {
            bound: rhs.bound,
            value: T::zero().wrapping_sub(&rhs.value),
        };
        self.checked_add(&rhs_neg).unwrap()
    }
}

impl<T> Sub<&Signed<T>> for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded,
{
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self::Output {
        // TODO: this feels sketchy - double check
        let rhs_neg = Self {
            bound: rhs.bound,
            value: T::zero().wrapping_sub(&rhs.value),
        };
        self.checked_add(&rhs_neg).unwrap()
    }
}

impl<T> Mul<Signed<T>> for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded + ConditionallySelectable,
{
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        self.checked_mul(&rhs).unwrap()
    }
}

impl<T> Mul<&Signed<T>> for Signed<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded + ConditionallySelectable,
{
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self::Output {
        self.checked_mul(rhs).unwrap()
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

// Build a `T` integer from an extendable Reader function
fn from_xof<T>(reader: &mut impl XofReader, modulus: &NonZero<T>) -> T
where
    T: Integer + Encoding,
{
    let backend_modulus = modulus.as_ref();

    let n_bits = backend_modulus.bits_vartime();
    let n_bytes = (n_bits + 7) / 8; // ceiling division by 8

    // If the number of bits is not a multiple of 8,
    // use a mask to zeroize the high bits in the gererated random bytestring,
    // so that we don't have to reject too much.
    let mask = if n_bits & 7 != 0 {
        (1 << (n_bits & 7)) - 1
    } else {
        u8::MAX
    };

    let mut bytes = T::zero().to_le_bytes();
    loop {
        reader.read(&mut (bytes.as_mut()[0..n_bytes as usize]));
        bytes.as_mut()[n_bytes as usize - 1] &= mask;
        let n = T::from_le_bytes(bytes);

        if n.ct_lt(backend_modulus).into() {
            return n;
        }
    }
}
