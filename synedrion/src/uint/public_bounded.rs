use crypto_bigint::Bounded;

use super::{HasWide, Integer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct PublicBounded<T> {
    /// bound on the bit size of the value
    bound: u32,
    value: T,
}

impl<T> PublicBounded<T>
where
    T: Integer + Bounded,
{
    pub fn bound(&self) -> u32 {
        self.bound
    }

    /// Creates a new [`PublicBounded`] wrapper around `T`, restricted to `bound`.
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
}

impl<T> AsRef<T> for PublicBounded<T> {
    fn as_ref(&self) -> &T {
        &self.value
    }
}

impl<T> PublicBounded<T>
where
    T: HasWide,
{
    pub fn to_wide(&self) -> PublicBounded<T::Wide> {
        PublicBounded {
            value: self.value.to_wide(),
            bound: self.bound,
        }
    }
}
