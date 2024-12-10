use crypto_bigint::{Bounded, Integer, NonZero};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{HasWide, Signed};
use crate::tools::Secret;

/// A bounded integer with sensitive data.
#[derive(Debug, Clone, PartialEq, Eq, Default, ZeroizeOnDrop)]
pub(crate) struct SecretBounded<T: Zeroize> {
    /// bound on the bit size of the value
    bound: u32,
    value: T,
}

impl<T> SecretBounded<T>
where
    T: Zeroize + Integer + Bounded,
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

    pub fn add_mod(&self, rhs: &Self, modulus: &Secret<NonZero<T>>) -> Self {
        // Note: assuming that the bit size of the modulus is not secret
        // (although the modulus itself might be)
        Self {
            value: self.value.add_mod(&rhs.value, modulus.expose_secret()),
            bound: modulus.expose_secret().bits_vartime(),
        }
    }

    pub fn to_signed(&self) -> Option<Secret<Signed<T>>> {
        Secret::maybe_init_with(|| Signed::new_positive(self.value.clone(), self.bound))
    }

    pub fn expose_secret(&self) -> &T {
        &self.value
    }
}

impl<T> SecretBounded<T>
where
    T: Zeroize + HasWide,
    T::Wide: Zeroize,
{
    pub fn to_wide(&self) -> SecretBounded<T::Wide> {
        SecretBounded {
            value: self.value.to_wide(),
            bound: self.bound,
        }
    }
}
