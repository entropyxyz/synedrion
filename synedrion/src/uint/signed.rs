use core::fmt;
use core::marker::PhantomData;
use core::ops::{Add, Mul, Neg, Not, Sub};

use rand_core::CryptoRngCore;
use serde::{
    de, de::Error, ser::SerializeTupleStruct, Deserialize, Deserializer, Serialize, Serializer,
};

use super::{
    subtle::{Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq, CtOption},
    CheckedAdd, CheckedMul, FromScalar, HasWide, Integer, NonZero, UintLike,
};
use crate::curve::{Scalar, ORDER};

/// A wrapper over unsigned integers that treats two's complement numbers as negative.
// In principle, Bounded could be separate from Signed, but we only use it internally,
// and pretty much every time we need a bounded value, it's also signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signed<T: UintLike> {
    /// bound on the bit size of the absolute value
    bound: u32,
    value: T,
}

impl<'de, T: UintLike + Deserialize<'de>> Deserialize<'de> for Signed<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SignedVisitor<T: UintLike>(PhantomData<T>);

        impl<'de, T: UintLike + Deserialize<'de>> de::Visitor<'de> for SignedVisitor<T> {
            type Value = Signed<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a tuple struct Signed")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Signed<T>, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let bound: u32 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let value: T = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                Signed::new_from_unsigned(value, bound)
                    .ok_or_else(|| A::Error::custom("The integer is over the declared bound"))
            }
        }

        deserializer.deserialize_tuple_struct("Signed", 2, SignedVisitor::<T>(PhantomData))
    }
}

impl<T: UintLike + Serialize> Serialize for Signed<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // TODO: save just the `bound` bytes? That will save some bandwidth.
        let mut ts = serializer.serialize_tuple_struct("Signed", 2)?;
        ts.serialize_field(&self.bound)?;
        ts.serialize_field(&self.value)?;
        ts.end()
    }
}

impl<T: UintLike> Signed<T> {
    pub fn bound(&self) -> usize {
        self.bound as usize
    }

    pub fn is_negative(&self) -> Choice {
        Choice::from(self.value.bit_vartime(<T as Integer>::BITS - 1) as u8)
    }

    pub fn abs(&self) -> T {
        T::conditional_select(&self.value, &self.value.neg(), self.is_negative())
    }

    /// Creates a signed value from an unsigned one,
    /// treating it as if the sign is encoded in the MSB.
    pub fn new_from_unsigned(value: T, bound: u32) -> Option<Self> {
        let result = Self { value, bound };
        if bound >= <T as Integer>::BITS as u32 || result.abs().bits_vartime() as u32 > bound {
            return None;
        }
        Some(result)
    }

    /// Creates a signed value from an unsigned one,
    /// treating it as if it is the absolute value.
    fn new_from_abs(abs_value: T, bound: usize, is_negative: Choice) -> Option<Self> {
        Self::new_positive(abs_value, bound).map(|x| {
            let mut x = x;
            x.conditional_negate(is_negative);
            x
        })
    }

    /// Creates a signed value from an unsigned one,
    /// assuming that it encodes a positive value.
    pub fn new_positive(value: T, bound: usize) -> Option<Self> {
        // Reserving one bit as the sign bit
        if bound >= <T as Integer>::BITS || value.bits_vartime() > bound {
            return None;
        }
        let result = Self {
            value,
            bound: bound as u32,
        };
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
        let positive_bound = (*bound.as_ref() << 1).checked_add(&T::ONE).unwrap();
        let positive_result = T::random_mod(rng, &NonZero::new(positive_bound).unwrap());
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
        let bound = T::ONE << (bound_bits + 1);
        self.abs() <= bound
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
        scale: &NonZero<T>,
    ) -> Signed<T::Wide> {
        assert!(bound_bits < <T as Integer>::BITS - 1);
        let bound = T::ONE.shl_vartime(bound_bits);
        let positive_bound = bound.shl_vartime(1).checked_add(&T::ONE).unwrap();
        let positive_result = T::random_mod(rng, &NonZero::new(positive_bound).unwrap());

        let scaled_positive_result = positive_result.mul_wide(scale.as_ref());
        let scaled_bound = scale.as_ref().into_wide().shl_vartime(bound_bits);

        Signed {
            bound: (bound_bits + scale.bits_vartime()) as u32,
            value: scaled_positive_result.wrapping_sub(&scaled_bound),
        }
    }

    pub fn into_wide(self) -> Signed<T::Wide> {
        let abs_result = self.abs().into_wide();
        Signed::new_from_abs(abs_result, self.bound(), self.is_negative()).unwrap()
    }
}

impl<T: UintLike + HasWide> Signed<T>
where
    <T as HasWide>::Wide: HasWide,
{
    /// Returns a random value in range `[-2^bound_bits * scale, 2^bound_bits * scale]`.
    ///
    /// Note: variable time in `bound_bits` and `scale`.
    pub fn random_bounded_bits_scaled_wide(
        rng: &mut impl CryptoRngCore,
        bound_bits: usize,
        scale: &NonZero<<T as HasWide>::Wide>,
    ) -> Signed<<<T as HasWide>::Wide as HasWide>::Wide> {
        assert!(bound_bits < <T as Integer>::BITS - 1);
        let bound = T::ONE.shl_vartime(bound_bits);
        let positive_bound = bound.shl_vartime(1).checked_add(&T::ONE).unwrap();
        let positive_result = T::random_mod(rng, &NonZero::new(positive_bound).unwrap());

        let positive_result = positive_result.into_wide();

        let scaled_positive_result = positive_result.mul_wide(scale);
        let scaled_bound = scale.as_ref().into_wide().shl_vartime(bound_bits);

        Signed {
            bound: (bound_bits + scale.bits_vartime()) as u32,
            value: scaled_positive_result.wrapping_sub(&scaled_bound),
        }
    }
}

impl<T: UintLike + FromScalar> FromScalar for Signed<T> {
    fn from_scalar(value: &Scalar) -> Self {
        const ORDER_BITS: usize = ORDER.bits_vartime();
        Signed::new_positive(T::from_scalar(value), ORDER_BITS).unwrap()
    }
    fn to_scalar(&self) -> Scalar {
        let abs_value = self.abs().to_scalar();
        Scalar::conditional_select(&abs_value, &-abs_value, self.is_negative())
    }
}

impl<T: UintLike> CheckedAdd for Signed<T> {
    type Output = Self;
    fn checked_add(&self, rhs: Self) -> CtOption<Self> {
        let bound = core::cmp::max(self.bound, rhs.bound) + 1;
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
            !(lhs_neg.ct_eq(&rhs_neg) & !lhs_neg.ct_eq(&res_neg)),
        )
    }
}

impl<T: UintLike> CheckedMul for Signed<T> {
    type Output = Self;
    fn checked_mul(&self, rhs: Self) -> CtOption<Self> {
        let bound = self.bound + rhs.bound;
        let lhs_neg = self.is_negative();
        let rhs_neg = rhs.is_negative();
        let lhs = T::conditional_select(&self.value, &self.value.neg(), lhs_neg);
        let rhs = T::conditional_select(&rhs.value, &rhs.value.neg(), rhs_neg);
        let result = lhs.checked_mul(&rhs);
        let result_neg = lhs_neg ^ rhs_neg;
        result.and_then(|val| {
            let out_of_range = Choice::from((bound as usize >= <T as Integer>::BITS - 1) as u8);
            let signed_val = T::conditional_select(&val, &val.neg(), result_neg);
            CtOption::new(
                Self {
                    bound,
                    value: signed_val,
                },
                out_of_range.not(),
            )
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

impl<T: UintLike> core::iter::Sum for Signed<T> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|x, y| x.checked_add(y).unwrap())
            .unwrap_or(Self::default())
    }
}

impl<'a, T: UintLike> core::iter::Sum<&'a Self> for Signed<T> {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.cloned().sum()
    }
}
