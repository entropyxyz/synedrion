use core::{
    fmt::Debug,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, RemAssign, Sub, SubAssign},
};

use crypto_bigint::{
    modular::Retrieve,
    subtle::{Choice, ConditionallyNegatable, ConditionallySelectable},
    Encoding, Integer, Monty, NonZero,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::{
    curve::{Point, Scalar},
    uint::{Bounded, Exponentiable, HasWide, Signed},
};

/// A helper wrapper for managing secret values.
///
/// On top of `secrecy::SecretBox` functionality, it provides:
/// - Safe `Clone` implementation (without needing to impl `CloneableSecret`)
/// - Safe `Debug` implementation
/// - Safe serialization/deserialization (down to `serde` API; what happens there we cannot control)
pub(crate) struct Secret<T: Zeroize>(SecretBox<T>);

impl<T: Zeroize> Secret<T> {
    pub fn expose_secret(&self) -> &T {
        self.0.expose_secret()
    }

    pub fn expose_secret_mut(&mut self) -> &mut T {
        self.0.expose_secret_mut()
    }
}

impl<T: Zeroize + Clone> Secret<T> {
    pub fn init_with(ctr: impl FnOnce() -> T) -> Self {
        Self(SecretBox::init_with(ctr))
    }

    pub fn try_init_with<E>(ctr: impl FnOnce() -> Result<T, E>) -> Result<Self, E> {
        Ok(Self(SecretBox::try_init_with(ctr)?))
    }

    pub fn maybe_init_with(ctr: impl FnOnce() -> Option<T>) -> Option<Self> {
        Self::try_init_with(|| ctr().ok_or(())).ok()
    }
}

impl<T: Zeroize + Clone + Default> Default for Secret<T> {
    fn default() -> Self {
        Self::init_with(|| T::default())
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self::init_with(|| self.0.expose_secret().clone())
    }
}

impl<T: Zeroize + Serialize> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.expose_secret().serialize(serializer)
    }
}

impl<'de, T: Zeroize + Clone + Deserialize<'de>> Deserialize<'de> for Secret<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self(SecretBox::try_init_with(|| T::deserialize(deserializer))?))
    }
}

impl<T: Zeroize> Debug for Secret<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret<{}>(...)", core::any::type_name::<T>())
    }
}

impl<T> Secret<T>
where
    T: Zeroize + Clone + HasWide,
    T::Wide: Zeroize,
{
    pub fn to_wide(&self) -> Secret<<T as HasWide>::Wide> {
        Secret::init_with(|| self.expose_secret().to_wide())
    }

    pub fn mul_wide(&self, rhs: &T) -> Secret<T::Wide> {
        Secret::init_with(|| self.expose_secret().mul_wide(rhs))
    }
}

impl<T> Secret<Signed<T>>
where
    T: Zeroize + Clone + Encoding + Integer + HasWide + ConditionallySelectable + crypto_bigint::Bounded,
    T::Wide: ConditionallySelectable + crypto_bigint::Bounded + Zeroize,
{
    pub fn to_wide(&self) -> Secret<Signed<<T as HasWide>::Wide>> {
        Secret::init_with(|| self.expose_secret().to_wide())
    }

    pub fn mul_wide(&self, rhs: &Signed<T>) -> Secret<Signed<T::Wide>> {
        Secret::init_with(|| self.expose_secret().mul_wide(rhs))
    }
}

impl<T> Secret<Bounded<T>>
where
    T: Zeroize + Clone + Encoding + Integer + HasWide + crypto_bigint::Bounded,
    T::Wide: crypto_bigint::Bounded + Zeroize,
{
    pub fn to_wide(&self) -> Secret<Bounded<<T as HasWide>::Wide>> {
        Secret::init_with(|| self.expose_secret().to_wide())
    }

    pub fn to_signed(&self) -> Option<Secret<Signed<T>>> {
        Secret::maybe_init_with(|| self.expose_secret().clone().into_signed())
    }
}

// Addition

impl<'a, T: Zeroize + AddAssign<&'a T>> AddAssign<&'a T> for Secret<T> {
    fn add_assign(&mut self, other: &'a T) {
        self.expose_secret_mut().add_assign(other);
    }
}

impl<'a, T: Zeroize + AddAssign<&'a T>> AddAssign<&'a Secret<T>> for Secret<T> {
    fn add_assign(&mut self, other: &'a Secret<T>) {
        self.add_assign(other.expose_secret());
    }
}

impl<'a, T: Zeroize + AddAssign<&'a T>> Add<&'a T> for Secret<T> {
    type Output = Secret<T>;

    fn add(mut self, other: &'a T) -> Self::Output {
        self += other;
        self
    }
}

impl<T: Zeroize + for<'a> AddAssign<&'a T>> Add<Secret<T>> for Secret<T> {
    type Output = Secret<T>;

    fn add(mut self, other: Secret<T>) -> Self::Output {
        self += &other;
        self
    }
}

impl<'a, T: Zeroize + AddAssign<&'a T>> Add<&'a Secret<T>> for Secret<T> {
    type Output = Secret<T>;

    fn add(mut self, other: &'a Secret<T>) -> Self::Output {
        self += other.expose_secret();
        self
    }
}

impl<T: Zeroize + for<'a> AddAssign<&'a T>> Add<Secret<T>> for &Secret<T> {
    type Output = Secret<T>;

    fn add(self, other: Secret<T>) -> Self::Output {
        let mut result = other;
        result += self;
        result
    }
}

// Negation

impl<T: Zeroize + Clone + Neg<Output = T>> Neg for &Secret<T> {
    type Output = Secret<T>;
    fn neg(self) -> Self::Output {
        Secret::init_with(|| self.expose_secret().clone().neg())
    }
}

// Subtraction

impl<'a, T: Zeroize + SubAssign<&'a T>> SubAssign<&'a T> for Secret<T> {
    fn sub_assign(&mut self, other: &'a T) {
        self.expose_secret_mut().sub_assign(other);
    }
}

impl<'a, T: Zeroize + SubAssign<&'a T>> SubAssign<&'a Secret<T>> for Secret<T> {
    fn sub_assign(&mut self, other: &'a Secret<T>) {
        self.sub_assign(other.expose_secret());
    }
}

impl<'a, T: Zeroize + SubAssign<&'a T>> Sub<&'a T> for Secret<T> {
    type Output = Secret<T>;

    fn sub(mut self, other: &'a T) -> Self::Output {
        self -= other;
        self
    }
}

impl<T: Zeroize + for<'a> SubAssign<&'a T>> Sub<Secret<T>> for Secret<T> {
    type Output = Secret<T>;

    fn sub(mut self, other: Secret<T>) -> Self::Output {
        self -= &other;
        self
    }
}

// Multiplication

impl<'a, T: Zeroize + MulAssign<&'a T>> MulAssign<&'a T> for Secret<T> {
    fn mul_assign(&mut self, other: &'a T) {
        self.expose_secret_mut().mul_assign(other)
    }
}

impl<'a, T: Zeroize + MulAssign<&'a T>> MulAssign<&'a Secret<T>> for Secret<T> {
    fn mul_assign(&mut self, other: &'a Secret<T>) {
        self.mul_assign(other.expose_secret())
    }
}

impl<'a, T: Zeroize + MulAssign<&'a T>> Mul<&'a T> for Secret<T> {
    type Output = Secret<T>;

    fn mul(mut self, other: &'a T) -> Self::Output {
        self *= other;
        self
    }
}

impl<T: Zeroize + Clone + for<'a> MulAssign<&'a T>> Mul<T> for Secret<T> {
    type Output = Secret<T>;

    fn mul(mut self, other: T) -> Self::Output {
        self *= &other;
        self
    }
}

impl<T: Zeroize + Clone + for<'a> MulAssign<&'a T>> Mul<T> for &Secret<T> {
    type Output = Secret<T>;

    fn mul(self, other: T) -> Self::Output {
        let mut result: Secret<T> = self.clone();
        result *= &other;
        result
    }
}

impl<T: Zeroize + for<'a> MulAssign<&'a T>> Mul<Secret<T>> for Secret<T> {
    type Output = Secret<T>;

    fn mul(mut self, other: Secret<T>) -> Self::Output {
        self *= &other;
        self
    }
}

impl<'a, T: Zeroize + MulAssign<&'a T>> Mul<&'a Secret<T>> for Secret<T> {
    type Output = Secret<T>;

    fn mul(mut self, other: &'a Secret<T>) -> Self::Output {
        self *= other.expose_secret();
        self
    }
}

// Division

impl<'a, T: Zeroize + DivAssign<&'a NonZero<T>>> DivAssign<&'a NonZero<T>> for Secret<T> {
    fn div_assign(&mut self, other: &'a NonZero<T>) {
        self.expose_secret_mut().div_assign(other)
    }
}

impl<T: Zeroize + for<'a> DivAssign<&'a NonZero<T>>> Div<NonZero<T>> for Secret<T> {
    type Output = Secret<T>;

    fn div(mut self, other: NonZero<T>) -> Self::Output {
        self /= &other;
        self
    }
}

// Remainder

impl<'a, T: Zeroize + Clone + RemAssign<&'a NonZero<T>>> RemAssign<&'a NonZero<T>> for Secret<T> {
    fn rem_assign(&mut self, other: &'a NonZero<T>) {
        self.expose_secret_mut().rem_assign(other)
    }
}

impl<'a, T: Zeroize + Clone + RemAssign<&'a NonZero<T>>> Rem<&'a NonZero<T>> for &Secret<T> {
    type Output = Secret<T>;

    fn rem(self, other: &'a NonZero<T>) -> Self::Output {
        let mut result = self.clone();
        result %= other;
        result
    }
}

// Summation

impl<T: Zeroize + Clone + for<'a> AddAssign<&'a T> + Default> core::iter::Sum for Secret<T> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Add::add).unwrap_or(Secret::<T>::default())
    }
}

impl<'b, T: Zeroize + Clone + for<'a> AddAssign<&'a T> + Default> core::iter::Sum<&'b Secret<T>> for Secret<T> {
    fn sum<I: Iterator<Item = &'b Secret<T>>>(iter: I) -> Self {
        iter.fold(Secret::<T>::default(), |accum, x| accum + x)
    }
}

impl Secret<Scalar> {
    pub fn mul_by_generator(&self) -> Point {
        self.expose_secret().mul_by_generator()
    }

    pub fn invert(&self) -> Option<Secret<Scalar>> {
        Secret::maybe_init_with(|| Option::from(self.expose_secret().invert()))
    }
}

impl Mul<Secret<Scalar>> for Point {
    type Output = Point;
    fn mul(self, scalar: Secret<Scalar>) -> Self::Output {
        self * scalar.expose_secret()
    }
}

impl Mul<&Secret<Scalar>> for Point {
    type Output = Point;
    fn mul(self, scalar: &Secret<Scalar>) -> Self::Output {
        self * scalar.expose_secret()
    }
}

impl Mul<Secret<Scalar>> for &Point {
    type Output = Point;
    fn mul(self, scalar: Secret<Scalar>) -> Self::Output {
        self * scalar.expose_secret()
    }
}

impl<T: Zeroize + Retrieve<Output: Zeroize + Clone>> Retrieve for Secret<T> {
    type Output = Secret<T::Output>;
    fn retrieve(&self) -> Self::Output {
        Secret::init_with(|| self.expose_secret().retrieve())
    }
}

impl<T: Zeroize> Secret<T> {
    pub fn pow_bounded<V>(&self, exponent: &Bounded<V>) -> Self
    where
        T: Exponentiable<V>,
        V: Integer + crypto_bigint::Bounded + Encoding + ConditionallySelectable,
    {
        // TODO: do we need to implement our own windowed exponentiation to hide the secret?
        Secret::init_with(|| self.expose_secret().pow_bounded(exponent))
    }

    pub fn pow_signed_vartime<V>(&self, exponent: &Signed<V>) -> Self
    where
        T: Exponentiable<V>,
        V: Integer + crypto_bigint::Bounded + Encoding + ConditionallySelectable,
    {
        // TODO: do we need to implement our own windowed exponentiation to hide the secret?
        // The exponent will be put in a stack array when it's decomposed with a small radix
        // for windowed exponentiation. So if it's secret, it's going to leave traces on the stack.
        // With the multiplication, for example, there's less danger since Uints implement *Assign traits which we use,
        // so theoretically anything secret will be overwritten.
        Secret::init_with(|| self.expose_secret().pow_signed_vartime(exponent))
    }
}

impl<T: Zeroize + Integer<Monty: Zeroize>> Secret<T> {
    pub fn to_montgomery(&self, params: &<T::Monty as Monty>::Params) -> Secret<T::Monty> {
        // `self` has to be cloned and passed by value, which means it may be retained on the stack.
        // Can't help it with the current `Monty::new()` signature.
        Secret::init_with(|| <T::Monty as Monty>::new(self.expose_secret().clone(), params.clone()))
    }
}

// Can't implement `ConditionallySelectable` itself since it is bounded on `Copy`.
impl<T: Zeroize + ConditionallySelectable> Secret<T> {
    pub fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Secret::init_with(|| T::conditional_select(a.expose_secret(), b.expose_secret(), choice))
    }
}

impl<T: Zeroize + ConditionallyNegatable> ConditionallyNegatable for Secret<T> {
    fn conditional_negate(&mut self, choice: Choice) {
        self.0.expose_secret_mut().conditional_negate(choice)
    }
}
