use alloc::{boxed::Box, format, string::String};

use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Hex, SliceLike};
use zeroize::Zeroize;

use super::{
    subtle::{Choice, ConditionallySelectable, ConstantTimeLess, CtOption},
    CheckedMul, Encoding, HasWide, Integer, NonZero, Signed,
};

/// A packed representation for serializing Bounded objects.
/// Usually they have the bound much lower than the full size of the integer,
/// so this way we avoid serializing a bunch of zeros.
#[derive(Serialize, Deserialize)]
pub(crate) struct PackedBounded {
    bound: u32,
    #[serde(with = "SliceLike::<Hex>")]
    bytes: Box<[u8]>,
}

impl<T> From<Bounded<T>> for PackedBounded
where
    T: Integer + Encoding + crypto_bigint::Bounded,
{
    fn from(val: Bounded<T>) -> Self {
        let repr = val.as_ref().to_be_bytes();
        let bound_bytes = (val.bound() + 7) / 8;
        let slice = repr
            .as_ref()
            .get((repr.as_ref().len() - bound_bytes as usize)..)
            .expect("val has a valid bound that was checked when it was created");
        Self {
            bound: val.bound(),
            bytes: slice.into(),
        }
    }
}

impl<T> TryFrom<PackedBounded> for Bounded<T>
where
    T: Integer + Encoding + crypto_bigint::Bounded,
{
    type Error = String;
    fn try_from(val: PackedBounded) -> Result<Self, Self::Error> {
        let mut repr = T::zero().to_be_bytes();
        let bytes_len: usize = val.bytes.len();
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
            .copy_from_slice(&val.bytes);
        let abs_value = T::from_be_bytes(repr);

        Self::new(abs_value, val.bound).ok_or_else(|| "Invalid values for the signed integer".into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, Zeroize)]
#[serde(
    try_from = "PackedBounded",
    into = "PackedBounded",
    bound = "T: Integer + Encoding + crypto_bigint::Bounded"
)]
pub(crate) struct Bounded<T> {
    /// bound on the bit size of the value
    bound: u32,
    value: T,
}

impl<T> Bounded<T>
where
    T: Integer + crypto_bigint::Bounded,
{
    pub fn bound(&self) -> u32 {
        self.bound
    }

    /// Creates a new [`Bounded`] wrapper around `T`, restricted to `bound`.
    ///
    /// Returns `None` if the bound is invalid, i.e.:
    /// - The bound is bigger than a `T` can represent.
    /// - The value of `T` is too big to be bounded by the provided bound.
    pub fn new(value: T, bound: u32) -> Option<Self> {
        if bound > T::BITS || value.bits() > bound {
            return None;
        }
        Some(Self { value, bound })
    }

    pub fn add_mod(&self, rhs: &Self, modulus: &NonZero<T>) -> Self {
        // Note: assuming that the bit size of the modulus is not secret
        // (although the modulus itself might be)
        Self {
            value: self.value.add_mod(&rhs.value, modulus),
            bound: modulus.bits_vartime(),
        }
    }

    pub fn into_signed(self) -> Option<Signed<T>> {
        Signed::new_positive(self.value, self.bound)
    }
}

impl<T> AsRef<T> for Bounded<T> {
    fn as_ref(&self) -> &T {
        &self.value
    }
}

impl<T> Bounded<T>
where
    T: HasWide,
{
    pub fn to_wide(&self) -> Bounded<T::Wide> {
        Bounded {
            value: self.value.to_wide(),
            bound: self.bound,
        }
    }

    pub fn mul_wide(&self, rhs: &Self) -> Bounded<T::Wide> {
        let result = self.value.mul_wide(&rhs.value);
        Bounded {
            value: result,
            bound: self.bound + rhs.bound,
        }
    }
}

impl<T> CheckedMul for Bounded<T>
where
    T: Integer + crypto_bigint::Bounded,
{
    fn checked_mul(&self, rhs: &Self) -> CtOption<Self> {
        let bound = self.bound + rhs.bound;
        let in_range = bound.ct_lt(&<T as crypto_bigint::Bounded>::BITS);

        let result = Self {
            bound,
            value: self.value.wrapping_mul(&rhs.value),
        };
        CtOption::new(result, in_range)
    }
}

impl<T> ConditionallySelectable for Bounded<T>
where
    T: ConditionallySelectable,
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            bound: u32::conditional_select(&a.bound, &b.bound, choice),
            value: T::conditional_select(&a.value, &b.value, choice),
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto_bigint::{CheckedMul, U1024, U128, U2048};

    use super::Bounded;

    #[test]
    fn checked_mul_fails_when_operands_have_max_bounds() {
        let bound = 88;
        let b1 = Bounded::new(U128::from_u8(10), bound).unwrap();
        let b2 = Bounded::new(U128::from_u8(10), bound).unwrap();
        let b3 = b1.checked_mul(&b2);

        // Bounds are summed up, so 88 + 88 = 176 ==> OoB
        assert!(bool::from(b3.is_none()));

        let b4 = Bounded::new(U128::from_u8(10), 20).unwrap();
        let b5 = b1.checked_mul(&b4);
        // This is fine, because 88 + 20 < MAX BOUND (127)
        assert!(bool::from(b5.is_some()));
        assert_eq!(b5.unwrap(), Bounded::new(U128::from_u8(100), 108).unwrap());
    }

    #[test]
    fn mul_wide_sums_the_bounds_of_the_operands() {
        let bound = 678;
        let b1 = Bounded::new(U1024::from_u8(10), bound).unwrap();
        let b2 = Bounded::new(U1024::from_u8(10), bound).unwrap();
        let b3 = b1.mul_wide(&b2);

        // Bounds are summed up, so 678 + 678 = 1356
        assert_eq!(b3.bound(), 1356);
        assert_eq!(b3, Bounded::new(U2048::from_u8(100), 1356).unwrap());
    }
}
