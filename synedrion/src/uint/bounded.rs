use zeroize::Zeroize;

use super::{HasWide, Integer, NonZero, Signed};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Zeroize)]
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
}
