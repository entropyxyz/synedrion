use alloc::{boxed::Box, format, string::String};
use core::ops::Neg;

use crypto_bigint::{Bounded, Encoding, Integer};
use digest::XofReader;
use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Hex, SliceLike};

use super::{FromXofReader, HasWide};

/// A packed representation for serializing Signed objects.
/// Usually they have the bound set much lower than the full size of the integer,
/// so this way we avoid serializing a bunch of zeros.
#[derive(Serialize, Deserialize)]
struct PackedSigned {
    /// Bound on the bit size of the absolute value (that is, `abs(value) < 2^bound`).
    bound: u32,
    is_negative: bool,
    #[serde(with = "SliceLike::<Hex>")]
    abs_bytes: Box<[u8]>,
}

impl<T> From<PublicSigned<T>> for PackedSigned
where
    T: Integer + Encoding + Bounded,
{
    fn from(val: PublicSigned<T>) -> Self {
        let repr = val.abs().to_be_bytes();
        let bound_bytes = (val.bound + 7) / 8;
        let slice = repr
            .as_ref()
            .get((repr.as_ref().len() - bound_bytes as usize)..)
            .expect("val has a valid bound that was checked when it was created");
        Self {
            bound: val.bound,
            is_negative: val.is_negative(),
            abs_bytes: slice.into(),
        }
    }
}

impl<T> TryFrom<PackedSigned> for PublicSigned<T>
where
    T: Integer + Encoding + Bounded,
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

        repr.as_mut()
            .get_mut((repr_len - bytes_len)..)
            .expect("Just checked that val's data all fit in a T")
            .copy_from_slice(&val.abs_bytes);
        let abs_value = T::from_be_bytes(repr);

        Self::new_from_abs(abs_value, val.bound, val.is_negative)
            .ok_or_else(|| "Invalid values for the signed integer".into())
    }
}

/// A wrapper over bounded unsigned integers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    try_from = "PackedSigned",
    into = "PackedSigned",
    bound = "T: Integer + Encoding + Bounded"
)]
pub(crate) struct PublicSigned<T> {
    /// bound on the bit size of the absolute value
    bound: u32,
    value: T,
}

impl<T> PublicSigned<T>
where
    T: Integer + Bounded,
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

    /// Creates a new [`PublicSigned`] from an integer that is assumed to be positive
    /// (that is, has its MSB set to 0).
    /// Returns `None` if the bound is invalid.
    pub fn new_positive(value: T, bound: u32) -> Option<Self> {
        Self::new_from_abs(value, bound, false)
    }

    /// Creates a new [`PublicSigned`] from an integer that will be treated as a negative number in two's complement
    /// if its MSB is set to 1.
    /// Returns `None` if the bound is invalid.
    pub fn new_from_unsigned(value: T, bound: u32) -> Option<Self> {
        let result = Self { value, bound };
        if bound >= T::BITS || result.abs().bits_vartime() > bound {
            return None;
        }
        Some(result)
    }

    pub fn one() -> Self {
        Self {
            value: T::one(),
            bound: 1,
        }
    }

    pub fn zero() -> Self {
        Self {
            value: T::zero(),
            bound: 0,
        }
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

    pub fn value(&self) -> &T {
        &self.value
    }

    /// Returns `true` if the value is within the interval the paper denotes as $±2^exp$.
    ///
    /// That is, the value must be within $[-2^{exp-1}+1, 2^{exp-1}]$
    /// (See Section 3, Groups & Fields).
    pub fn is_in_exponent_range(&self, exp: u32) -> bool {
        let abs = self.abs();
        let in_bound = abs.bits_vartime() < exp;
        // Have to check for the high end of the range too
        let is_high_end = (abs == T::one() << (exp - 1)) && !self.is_negative();
        in_bound || is_high_end
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
    T: Integer + Bounded + Encoding,
{
    /// Returns a value in range `±2^{exp}` derived from an extendable-output hash.
    ///
    /// Note that in the paper's definitions, `±2^{exp}` is equivalent to `[-2^(x-1)+1, 2^(x-1)]`
    /// (see Section 3, Groups & Fields).
    pub fn from_xof_reader_in_exponent_range(reader: &mut impl XofReader, exp: u32) -> Self {
        assert!(exp > 0, "`exp` must be greater than zero");
        assert!(
            exp < T::BITS,
            "Out of bounds: `exp` was {exp} but must be smaller or equal to {}",
            T::BITS
        );

        let positive_result = T::from_xof_reader(reader, exp);
        let shift = T::one()
            .overflowing_shl_vartime(exp - 1)
            .expect("checked that `exp` is smaller than `T::BITS`")
            .checked_sub(&T::one())
            .expect("does not overflow because of the assertions above");
        Self::new_from_unsigned(positive_result.wrapping_sub(&shift), exp)
            .expect("Guaranteed to be Some because we checked the bounds just above")
    }
}

impl<T> PublicSigned<T>
where
    T: Bounded + HasWide + Encoding + Integer,
    T::Wide: Bounded,
{
    /// Returns a [`PublicSigned`] with the same value, but twice the bit-width.
    pub fn to_wide(&self) -> PublicSigned<T::Wide> {
        let abs_result = self.abs().to_wide();
        PublicSigned::new_from_abs(abs_result, self.bound, self.is_negative())
            .expect("the value fit the bound before, and the bound won't overflow for `WideUint`")
    }
}

impl<T> Neg for PublicSigned<T>
where
    T: Integer + Bounded,
{
    type Output = PublicSigned<T>;

    fn neg(self) -> Self::Output {
        PublicSigned::neg(&self)
    }
}
