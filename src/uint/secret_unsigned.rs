use core::ops::BitAnd;

use crypto_bigint::{
    subtle::{Choice, CtOption},
    Bounded, Integer, Monty, NonZero,
};
use zeroize::Zeroize;

use super::HasWide;
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

    /// Creates a new [`SecretUnsigned`] wrapper around `T`, restricted to `bound`.
    ///
    /// Returns `None` if the bound is invalid, i.e.:
    /// - The bound is bigger than a `T` can represent.
    /// - The value of `T` is too big to be bounded by the provided bound.
    pub fn new(value: Secret<T>, bound: u32) -> CtOption<Self> {
        let in_bound =
            Choice::from((bound <= T::BITS) as u8).bitand(Choice::from((value.expose_secret().bits() <= bound) as u8));
        CtOption::new(Self { value, bound }, in_bound)
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
    T: Zeroize + Clone + HasWide,
    T::Wide: Zeroize,
{
    pub fn to_wide(&self) -> SecretUnsigned<T::Wide> {
        SecretUnsigned {
            value: self.value.to_wide(),
            bound: self.bound,
        }
    }
}
