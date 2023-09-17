use core::fmt;
use core::marker::PhantomData;

use serde::{
    de, de::Error, ser::SerializeTupleStruct, Deserialize, Deserializer, Serialize, Serializer,
};

use super::{
    subtle::{Choice, ConditionallySelectable, CtOption},
    CheckedAdd, CheckedMul, FromScalar, HasWide, NonZero, Signed, UintLike,
};
use crate::curve::{Scalar, ORDER};
use crate::tools::hashing::{Chain, Hashable};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounded<T: UintLike> {
    /// bound on the bit size of the value
    bound: u32,
    value: T,
}

impl<T: UintLike> Hashable for Bounded<T> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.bound).chain(&self.value)
    }
}

impl<'de, T: UintLike + Deserialize<'de>> Deserialize<'de> for Bounded<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedVisitor<T: UintLike>(PhantomData<T>);

        impl<'de, T: UintLike + Deserialize<'de>> de::Visitor<'de> for BoundedVisitor<T> {
            type Value = Bounded<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a tuple struct Bounded")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Bounded<T>, A::Error>
            where
                A: de::SeqAccess<'de>,
            {
                let bound: u32 = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let value: T = seq
                    .next_element()?
                    .ok_or_else(|| de::Error::invalid_length(1, &self))?;

                Bounded::new(value, bound)
                    .ok_or_else(|| A::Error::custom("The integer is over the declared bound"))
            }
        }

        deserializer.deserialize_tuple_struct("Bounded", 2, BoundedVisitor::<T>(PhantomData))
    }
}

impl<T: UintLike + Serialize> Serialize for Bounded<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // TODO: save just the `bound` bytes? That will save some bandwidth.
        let mut ts = serializer.serialize_tuple_struct("Bounded", 2)?;
        ts.serialize_field(&self.bound)?;
        ts.serialize_field(&self.value)?;
        ts.end()
    }
}

impl<T: UintLike> Bounded<T> {
    pub fn bound(&self) -> u32 {
        self.bound
    }

    pub fn bound_usize(&self) -> usize {
        // Extracted into a method to localize the conversion
        self.bound as usize
    }

    pub fn new(value: T, bound: u32) -> Option<Self> {
        if bound > T::BITS as u32 || value.bits_vartime() as u32 > bound {
            return None;
        }
        Some(Self { value, bound })
    }

    pub fn add_mod(&self, rhs: &Self, modulus: &NonZero<T>) -> Self {
        // Note: assuming that the bit size of the modulus is not secret
        // (although the modulus itself might be)
        Self {
            value: self.value.add_mod(&rhs.value, modulus),
            bound: modulus.bits_vartime() as u32,
        }
    }

    pub fn into_signed(self) -> Option<Signed<T>> {
        Signed::new_positive(self.value, self.bound)
    }
}

impl<T: UintLike> AsRef<T> for Bounded<T> {
    fn as_ref(&self) -> &T {
        &self.value
    }
}

impl<T: UintLike + HasWide> Bounded<T> {
    pub fn into_wide(self) -> Bounded<T::Wide> {
        Bounded {
            value: self.value.into_wide(),
            bound: self.bound,
        }
    }
}

impl<T: UintLike + FromScalar> FromScalar for Bounded<T> {
    fn from_scalar(value: &Scalar) -> Self {
        const ORDER_BITS: usize = ORDER.bits_vartime();
        Bounded::new(T::from_scalar(value), ORDER_BITS as u32).unwrap()
    }
    fn to_scalar(&self) -> Scalar {
        self.value.to_scalar()
    }
}

impl<T: UintLike> CheckedAdd for Bounded<T> {
    type Output = Self;
    fn checked_add(&self, rhs: Self) -> CtOption<Self> {
        let bound = core::cmp::max(self.bound, rhs.bound) + 1;
        let result = Self {
            bound,
            value: self.value.wrapping_add(&rhs.value),
        };
        CtOption::new(result, Choice::from((bound <= T::BITS as u32) as u8))
    }
}

impl<T: UintLike> CheckedMul for Bounded<T> {
    type Output = Self;
    fn checked_mul(&self, rhs: Self) -> CtOption<Self> {
        let bound = self.bound + rhs.bound;
        let result = Self {
            bound,
            value: self.value.wrapping_mul(&rhs.value),
        };
        CtOption::new(result, Choice::from((bound <= T::BITS as u32) as u8))
    }
}

impl<T: UintLike> ConditionallySelectable for Bounded<T> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            bound: u32::conditional_select(&a.bound, &b.bound, choice),
            value: T::conditional_select(&a.value, &b.value, choice),
        }
    }
}
