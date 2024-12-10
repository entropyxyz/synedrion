use alloc::{boxed::Box, format, string::String};
use core::ops::{Add, Mul, Neg, Sub};

use digest::XofReader;
use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Hex, SliceLike};
use zeroize::Zeroize;

use super::{Encoding, HasWide, Integer, NonZero};
use crate::tools::hashing::uint_from_xof;

/// A packed representation for serializing Signed objects.
/// Usually they have the bound much lower than the full size of the integer,
/// so this way we avoid serializing a bunch of zeros.
#[derive(Serialize, Deserialize)]
struct PackedSigned {
    bound: u32,
    is_negative: bool,
    #[serde(with = "SliceLike::<Hex>")]
    abs_bytes: Box<[u8]>,
}

impl<T> From<PublicSigned<T>> for PackedSigned
where
    T: Integer + Encoding + crypto_bigint::Bounded,
{
    fn from(val: PublicSigned<T>) -> Self {
        let repr = val.abs().to_be_bytes();
        let bound_bytes = (val.bound + 7) / 8;
        let slice = &repr.as_ref()[(repr.as_ref().len() - bound_bytes as usize)..];
        Self {
            bound: val.bound,
            is_negative: val.is_negative(),
            abs_bytes: slice.into(),
        }
    }
}

impl<T> TryFrom<PackedSigned> for PublicSigned<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded,
{
    type Error = String;
    fn try_from(val: PackedSigned) -> Result<Self, Self::Error> {
        let mut repr = T::zero().to_be_bytes();
        let bytes_len: usize = val.abs_bytes.len();
        let repr_len: usize = repr.as_ref().len();

        if repr_len < bytes_len {
            return Err(format!(
                "The bytestring of length {} does not fit the expected integer size {}",
                bytes_len, repr_len
            ));
        }

        repr.as_mut()[(repr_len - bytes_len)..].copy_from_slice(&val.abs_bytes);
        let abs_value = T::from_be_bytes(repr);

        Self::new_from_abs(abs_value, val.bound, val.is_negative)
            .ok_or_else(|| "Invalid values for the signed integer".into())
    }
}

/// A wrapper over unsigned integers that treats two's complement numbers as negative.
// In principle, Bounded could be separate from Signed, but we only use it internally,
// and pretty much every time we need a bounded value, it's also signed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Zeroize)]
#[serde(
    try_from = "PackedSigned",
    into = "PackedSigned",
    bound = "T: Integer + Encoding + crypto_bigint::Bounded"
)]
pub(crate) struct PublicSigned<T> {
    /// bound on the bit size of the absolute value
    pub(crate) bound: u32,
    pub(crate) value: T,
}

impl<T> From<Signed<T>> for PublicSigned<T> {
    fn from(source: Signed<T>) -> Self {
        Self {
            value: source.value,
            bound: source.bound,
        }
    }
}

impl<T> PublicSigned<T>
where
    T: Integer + crypto_bigint::Bounded,
{
    fn new_from_abs(abs_value: T, bound: u32, is_negative: bool) -> Option<Self> {
        if bound >= T::BITS || abs_value.bits_vartime() > bound {
            return None;
        }

        let value = if is_negative {
            abs_value.wrapping_neg()
        } else {
            abs_value
        };

        Some(Self { value, bound })
    }

    pub fn new_positive(value: T, bound: u32) -> Option<Self> {
        Self::new_from_abs(value, bound, false)
    }

    pub fn new_from_unsigned(value: T, bound: u32) -> Option<Self> {
        let result = Self { value, bound };
        if bound >= T::BITS || result.abs().bits_vartime() > bound {
            return None;
        }
        Some(result)
    }

    pub fn is_negative(&self) -> bool {
        self.value.bit_vartime(T::BITS - 1)
    }

    pub fn abs(&self) -> T {
        if self.is_negative() {
            self.neg().value
        } else {
            self.value.clone()
        }
    }

    pub fn bound(&self) -> u32 {
        self.bound
    }

    /// Returns `true` if the value is within `[-2^bound_bits, 2^bound_bits]`.
    pub fn in_range_bits(&self, bound_bits: u32) -> bool {
        self.abs() <= T::one() << bound_bits
    }

    fn checked_sub(&self, rhs: &Self) -> Option<Self> {
        let bound = core::cmp::max(self.bound, rhs.bound) + 1;
        if bound < T::BITS {
            Some(Self {
                bound,
                value: self.value.wrapping_sub(&rhs.value),
            })
        } else {
            None
        }
    }

    /// Constant-time checked multiplication. The product must fit in a `T`; use [`Signed::mul_wide`] if widening is desired.
    /// Note: when multiplying two [`Signed`], the bound on the result is equal to the sum of the bounds of the operands.
    fn checked_mul(&self, rhs: &Self) -> Option<Self> {
        let bound = self.bound + rhs.bound;
        if bound < T::BITS {
            Some(Self {
                bound,
                value: self.value.wrapping_mul(&rhs.value),
            })
        } else {
            None
        }
    }

    /// Performs the unary - operation.
    pub fn neg(&self) -> Self {
        Self {
            value: T::zero().wrapping_sub(&self.value),
            bound: self.bound,
        }
    }
}

impl<T> PublicSigned<T>
where
    T: Integer + crypto_bigint::Bounded + Encoding,
{
    /// Returns a value in range `[-bound, bound]` derived from an extendable-output hash.
    ///
    /// This method should be used for deriving non-interactive challenges,
    /// since it is guaranteed to produce the same results on 32- and 64-bit platforms.
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

impl<T> PublicSigned<T>
where
    T: crypto_bigint::Bounded + HasWide + Encoding + Integer,
    T::Wide: crypto_bigint::Bounded,
{
    /// Returns a [`PublicSigned`] with the same value, but twice the bit-width.
    pub fn to_wide(&self) -> PublicSigned<T::Wide> {
        let abs_result = self.abs().to_wide();
        PublicSigned::new_from_abs(abs_result, self.bound, self.is_negative())
            .expect("the value fit the bound before, and the bound won't overflow for `WideUint`")
    }
}

use super::Signed;
use crate::tools::Secret;

impl<T> Neg for PublicSigned<T>
where
    T: Integer + crypto_bigint::Bounded,
{
    type Output = PublicSigned<T>;

    fn neg(self) -> Self::Output {
        PublicSigned::neg(&self)
    }
}

impl<T> Neg for &PublicSigned<T>
where
    T: Integer + crypto_bigint::Bounded,
{
    type Output = PublicSigned<T>;

    fn neg(self) -> Self::Output {
        PublicSigned::neg(self)
    }
}

impl<T> Sub<PublicSigned<T>> for PublicSigned<T>
where
    T: Integer + crypto_bigint::Bounded,
{
    type Output = PublicSigned<T>;

    fn sub(self, rhs: PublicSigned<T>) -> Self::Output {
        self.checked_sub(&rhs)
            .expect("the calling code ensured the bound is not overflown")
    }
}

impl<T> Mul<PublicSigned<T>> for PublicSigned<T>
where
    T: Integer + crypto_bigint::Bounded,
{
    type Output = PublicSigned<T>;

    fn mul(self, rhs: PublicSigned<T>) -> Self::Output {
        self.checked_mul(&rhs)
            .expect("the calling code ensured the bound is not overflown")
    }
}

impl<T> Add<PublicSigned<T>> for Secret<Signed<T>>
where
    T: Integer + crypto_bigint::Bounded + Zeroize,
{
    type Output = Secret<Signed<T>>;

    fn add(self, rhs: PublicSigned<T>) -> Self::Output {
        Secret::init_with(|| self.expose_secret().add_public(&rhs))
    }
}

impl<T> Mul<PublicSigned<T>> for &Secret<Signed<T>>
where
    T: Integer + crypto_bigint::Bounded + Zeroize,
{
    type Output = Secret<Signed<T>>;

    fn mul(self, rhs: PublicSigned<T>) -> Self::Output {
        Secret::init_with(|| self.expose_secret().mul_by_public(&rhs))
    }
}

impl<T> Mul<PublicSigned<T>> for Secret<Signed<T>>
where
    T: Integer + crypto_bigint::Bounded + Zeroize,
{
    type Output = Secret<Signed<T>>;

    fn mul(self, rhs: PublicSigned<T>) -> Self::Output {
        Secret::init_with(|| self.expose_secret().mul_by_public(&rhs))
    }
}
