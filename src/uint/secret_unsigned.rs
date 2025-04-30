use core::ops::BitAnd;

use crypto_bigint::{subtle::Choice, Bounded, Integer, Monty, NonZero};
use zeroize::Zeroize;

use super::Extendable;
use crate::tools::Secret;

/// A bounded unsigned integer with sensitive data.
#[derive(Debug, Clone)]
pub(crate) struct SecretUnsigned<T: Zeroize> {
    /// Bound on the bit size of the value (that is, `value < 2^bound`).
    bound: u32,
    value: Secret<T>,
}

impl<T> SecretUnsigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    pub fn is_zero(&self) -> Choice {
        self.value.expose_secret().is_zero()
    }

    pub fn bound(&self) -> u32 {
        self.bound
    }

    /// Creates a new [`Bounded`] wrapper around `T`, restricted to `bound`.
    ///
    /// Returns `None` if the bound is invalid, i.e.:
    /// - The bound is bigger than a `T` can represent.
    /// - The value of `T` is too big to be bounded by the provided bound.
    pub fn new(value: Secret<T>, bound: u32) -> Option<Self> {
        if bound > T::BITS || value.expose_secret().bits() > bound {
            return None;
        }
        Some(Self { value, bound })
    }

    pub fn add_mod(&self, rhs: &Self, modulus: &Secret<NonZero<T>>) -> Self {
        Self {
            value: Secret::init_with(|| {
                self.value
                    .expose_secret()
                    .add_mod(rhs.value.expose_secret(), modulus.expose_secret())
            }),
            bound: modulus.expose_secret().bits(),
        }
    }

    pub fn expose_secret(&self) -> &T {
        self.value.expose_secret()
    }
}

impl<T> BitAnd<T> for &SecretUnsigned<T>
where
    T: Zeroize + Integer + Bounded,
{
    type Output = SecretUnsigned<T>;
    fn bitand(self, rhs: T) -> Self::Output {
        SecretUnsigned {
            value: Secret::init_with(|| self.value.expose_secret().clone() & rhs),
            bound: self.bound,
        }
    }
}

impl<T> SecretUnsigned<T>
where
    T: Zeroize + Integer<Monty: Zeroize> + Bounded,
{
    pub fn to_montgomery(&self, params: &<T::Monty as Monty>::Params) -> Secret<T::Monty> {
        Secret::init_with(|| <T::Monty as Monty>::new(self.expose_secret().clone(), params.clone()))
    }
}

impl<T> SecretUnsigned<T>
where
    T: Zeroize + Clone,
{
    pub fn to_wide<W>(&self) -> SecretUnsigned<W>
    where
        T: Extendable<W>,
        W: Zeroize + Clone,
    {
        SecretUnsigned {
            value: self.value.to_wide(),
            bound: self.bound,
        }
    }
}
