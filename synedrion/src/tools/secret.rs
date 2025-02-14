use core::{
    fmt::Debug,
    ops::{Add, AddAssign, Div, DivAssign, Mul, Neg, Rem, RemAssign, Sub},
};

use crypto_bigint::{
    modular::Retrieve,
    subtle::{Choice, ConditionallyNegatable, ConditionallySelectable},
    ConstantTimeSelect, Integer, Monty, NonZero, WrappingAdd, WrappingMul, WrappingNeg, WrappingSub,
};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::{
    curve::{Point, Scalar},
    uint::{Exponentiable, HasWide},
    SchemeParams,
};

/// A helper wrapper for managing secret values.
///
/// On top of `secrecy::SecretBox` functionality, it provides:
/// - Safe `Clone` implementation (without needing to impl `CloneableSecret`)
/// - Safe `Debug` implementation
/// - Safe serialization/deserialization (down to `serde` API; what happens there we cannot control)
pub(crate) struct Secret<T: Zeroize>(SecretBox<T>);

impl<T> Secret<T>
where
    T: Zeroize,
{
    pub fn expose_secret(&self) -> &T {
        self.0.expose_secret()
    }

    pub fn expose_secret_mut(&mut self) -> &mut T {
        self.0.expose_secret_mut()
    }
}

impl<T> Secret<T>
where
    T: Zeroize + Clone,
{
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

impl<T> Clone for Secret<T>
where
    T: Zeroize + Clone,
{
    fn clone(&self) -> Self {
        Self::init_with(|| self.0.expose_secret().clone())
    }

    fn clone_from(&mut self, source: &Self) {
        *self = source.clone()
    }
}

impl<T> Serialize for Secret<T>
where
    T: Zeroize + Serialize,
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.expose_secret().serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for Secret<T>
where
    T: Zeroize + Clone + Deserialize<'de>,
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::try_init_with(|| T::deserialize(deserializer))?)
    }
}

impl<T> Debug for Secret<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Secret<{}>(...)", core::any::type_name::<T>())
    }
}

impl<T> Neg for &Secret<T>
where
    T: Zeroize + Clone + Neg<Output = T>,
{
    type Output = Secret<T>;
    fn neg(self) -> Self::Output {
        Secret::init_with(|| self.expose_secret().clone().neg())
    }
}

impl<T> WrappingNeg for Secret<T>
where
    T: Zeroize + Clone + WrappingNeg,
{
    fn wrapping_neg(&self) -> Self {
        Secret::init_with(|| self.expose_secret().wrapping_neg())
    }
}

impl<T> WrappingAdd for Secret<T>
where
    T: Zeroize + Clone + WrappingAdd + for<'a> Add<&'a T, Output = T>,
{
    fn wrapping_add(&self, rhs: &Self) -> Self {
        Secret::init_with(|| self.expose_secret().wrapping_add(rhs.expose_secret()))
    }
}

impl<T> WrappingSub for Secret<T>
where
    T: Zeroize + Clone + WrappingSub + for<'a> Sub<&'a T, Output = T>,
{
    fn wrapping_sub(&self, rhs: &Self) -> Self {
        Secret::init_with(|| self.expose_secret().wrapping_sub(rhs.expose_secret()))
    }
}

impl<T> WrappingMul for Secret<T>
where
    T: Zeroize + Clone + WrappingMul + for<'a> Mul<&'a T, Output = T>,
{
    fn wrapping_mul(&self, rhs: &Self) -> Self {
        Secret::init_with(|| self.expose_secret().wrapping_mul(rhs.expose_secret()))
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
}

// Addition

impl<T> AddAssign<Secret<T>> for Secret<T>
where
    T: Zeroize + Clone + for<'a> Add<&'a T, Output = T>,
{
    fn add_assign(&mut self, rhs: Secret<T>) {
        // Can be done without reallocation when Integer is bound on AddAssign.
        // See https://github.com/RustCrypto/crypto-bigint/pull/716
        *self = &*self + &rhs
    }
}

impl<'a, T> Add<&'a T> for &Secret<T>
where
    T: Zeroize + Clone + Add<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn add(self, rhs: &'a T) -> Self::Output {
        Secret::init_with(|| self.expose_secret().clone() + rhs)
    }
}

impl<'a, T> Add<&'a T> for Secret<T>
where
    T: Zeroize + Clone + Add<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn add(self, rhs: &'a T) -> Self::Output {
        &self + rhs
    }
}

impl<T> Add<Secret<T>> for Secret<T>
where
    T: Zeroize + Clone + for<'a> Add<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn add(self, rhs: Secret<T>) -> Self::Output {
        &self + rhs.expose_secret()
    }
}

impl<'a, T> Add<&'a Secret<T>> for Secret<T>
where
    T: Zeroize + Clone + Add<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn add(self, rhs: &'a Secret<T>) -> Self::Output {
        &self + rhs.expose_secret()
    }
}

impl<T> Add<Secret<T>> for &Secret<T>
where
    T: Zeroize + Clone + for<'a> Add<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn add(self, rhs: Secret<T>) -> Self::Output {
        self + rhs.expose_secret()
    }
}

impl<'a, T> Add<&'a Secret<T>> for &Secret<T>
where
    T: Zeroize + Clone + Add<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn add(self, rhs: &'a Secret<T>) -> Self::Output {
        self + rhs.expose_secret()
    }
}

// Subtraction

impl<'a, T> Sub<&'a T> for &Secret<T>
where
    T: Zeroize + Clone + Sub<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn sub(self, rhs: &'a T) -> Self::Output {
        Secret::init_with(|| self.expose_secret().clone() - rhs)
    }
}

impl<'a, T> Sub<&'a T> for Secret<T>
where
    T: Zeroize + Clone + Sub<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn sub(self, rhs: &'a T) -> Self::Output {
        &self - rhs
    }
}

impl<T> Sub<Secret<T>> for Secret<T>
where
    T: Zeroize + Clone + for<'a> Sub<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn sub(self, rhs: Secret<T>) -> Self::Output {
        &self - rhs.expose_secret()
    }
}

// Multiplication

impl<'a, T> Mul<&'a T> for &Secret<T>
where
    T: Zeroize + Clone + Mul<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn mul(self, rhs: &'a T) -> Self::Output {
        Secret::init_with(|| self.expose_secret().clone() * rhs)
    }
}

impl<T> Mul<T> for &Secret<T>
where
    T: Zeroize + Clone + for<'a> Mul<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn mul(self, rhs: T) -> Self::Output {
        Secret::init_with(|| self.expose_secret().clone() * &rhs)
    }
}

impl<'a, T> Mul<&'a T> for Secret<T>
where
    T: Zeroize + Clone + Mul<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn mul(self, rhs: &'a T) -> Self::Output {
        &self * rhs
    }
}

impl<T> Mul<T> for Secret<T>
where
    T: Zeroize + Clone + for<'a> Mul<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn mul(self, rhs: T) -> Self::Output {
        &self * &rhs
    }
}

impl<T> Mul<Secret<T>> for Secret<T>
where
    T: Zeroize + Clone + for<'a> Mul<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn mul(self, rhs: Secret<T>) -> Self::Output {
        &self * rhs.expose_secret()
    }
}

impl<'a, T> Mul<&'a Secret<T>> for Secret<T>
where
    T: Zeroize + Clone + Mul<&'a T, Output = T>,
{
    type Output = Secret<T>;
    fn mul(self, rhs: &'a Secret<T>) -> Self::Output {
        &self * rhs.expose_secret()
    }
}

impl<'a, T: Zeroize + Clone + Mul<&'a T, Output = T>> Mul<&'a Secret<T>> for &Secret<T> {
    type Output = Secret<T>;
    fn mul(self, rhs: &'a Secret<T>) -> Self::Output {
        self * rhs.expose_secret()
    }
}

// Division

impl<'a, T> DivAssign<&'a NonZero<T>> for Secret<T>
where
    T: Zeroize + DivAssign<&'a NonZero<T>>,
{
    fn div_assign(&mut self, rhs: &'a NonZero<T>) {
        self.expose_secret_mut().div_assign(rhs)
    }
}

impl<T> Div<NonZero<T>> for Secret<T>
where
    T: Zeroize + for<'a> DivAssign<&'a NonZero<T>>,
{
    type Output = Secret<T>;

    fn div(mut self, rhs: NonZero<T>) -> Self::Output {
        self /= &rhs;
        self
    }
}

// Remainder

impl<'a, T> RemAssign<&'a NonZero<T>> for Secret<T>
where
    T: Zeroize + Clone + RemAssign<&'a NonZero<T>>,
{
    fn rem_assign(&mut self, rhs: &'a NonZero<T>) {
        self.expose_secret_mut().rem_assign(rhs)
    }
}

impl<'a, T> Rem<&'a NonZero<T>> for &Secret<T>
where
    T: Zeroize + Clone + RemAssign<&'a NonZero<T>>,
{
    type Output = Secret<T>;

    fn rem(self, rhs: &'a NonZero<T>) -> Self::Output {
        let mut result = self.clone();
        result %= rhs;
        result
    }
}

impl<T> Retrieve for Secret<T>
where
    T: Zeroize + Retrieve<Output: Zeroize + Clone>,
{
    type Output = Secret<T::Output>;
    fn retrieve(&self) -> Self::Output {
        Secret::init_with(|| self.expose_secret().retrieve())
    }
}

impl<T> Secret<T>
where
    T: Zeroize + Clone,
{
    pub fn pow<V>(&self, exponent: &V) -> Self
    where
        T: Exponentiable<V>,
    {
        // TODO: do we need to implement our own windowed exponentiation to hide the secret?
        // The exponent will be put in a stack array when it's decomposed with a small radix
        // for windowed exponentiation. So if it's secret, it's going to leave traces on the stack.
        // With the multiplication, for example, there's less danger since Uints implement *Assign traits which we use,
        // so theoretically anything secret will be overwritten.
        Secret::init_with(|| self.expose_secret().pow(exponent))
    }
}

impl<T> Secret<T>
where
    T: Zeroize + Integer<Monty: Zeroize>,
{
    pub fn to_montgomery(&self, params: &<T::Monty as Monty>::Params) -> Secret<T::Monty> {
        // `self` has to be cloned and passed by value, which means it may be retained on the stack.
        // Can't help it with the current `Monty::new()` signature.
        // TODO (#162): `params` is cloned here and can remain on the stack.
        Secret::init_with(|| <T::Monty as Monty>::new(self.expose_secret().clone(), params.clone()))
    }
}

// TODO(dp): Decide whether we should keep this impl or ditch it given we have ConstantTimeSelect
// Can't implement `ConditionallySelectable` itself since it is bounded on `Copy`.
impl<T> Secret<T>
where
    T: Zeroize + ConditionallySelectable,
{
    pub fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Secret::init_with(|| T::conditional_select(a.expose_secret(), b.expose_secret(), choice))
    }
}

impl<T> ConstantTimeSelect for Secret<T>
where
    T: ConstantTimeSelect + Zeroize,
{
    fn ct_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Secret::init_with(|| T::ct_select(a.expose_secret(), b.expose_secret(), choice))
    }
}

impl<T> ConditionallyNegatable for Secret<T>
where
    T: Zeroize + ConditionallyNegatable,
{
    fn conditional_negate(&mut self, choice: Choice) {
        self.0.expose_secret_mut().conditional_negate(choice)
    }
}

// Scalar-specific impls

impl<P> core::iter::Sum<Secret<Scalar<P>>> for Secret<Scalar<P>>
where
    P: SchemeParams,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(Add::add).unwrap_or(Secret::init_with(|| Scalar::ZERO))
    }
}

impl<'a, P> core::iter::Sum<&'a Secret<Scalar<P>>> for Secret<Scalar<P>>
where
    P: SchemeParams,
{
    fn sum<I: Iterator<Item = &'a Secret<Scalar<P>>>>(iter: I) -> Self {
        iter.fold(Secret::init_with(|| Scalar::ZERO), |accum, x| accum + x)
    }
}

impl<P> Secret<Scalar<P>>
where
    P: SchemeParams,
{
    pub fn mul_by_generator(&self) -> Point<P> {
        self.expose_secret().mul_by_generator()
    }
}

impl<P> Mul<Secret<Scalar<P>>> for Point<P>
where
    P: SchemeParams,
{
    type Output = Point<P>;
    fn mul(self, scalar: Secret<Scalar<P>>) -> Self::Output {
        self * scalar.expose_secret()
    }
}

impl<P> Mul<&Secret<Scalar<P>>> for Point<P>
where
    P: SchemeParams,
{
    type Output = Point<P>;
    fn mul(self, scalar: &Secret<Scalar<P>>) -> Self::Output {
        self * scalar.expose_secret()
    }
}

impl<P> Mul<Secret<Scalar<P>>> for &Point<P>
where
    P: SchemeParams,
{
    type Output = Point<P>;
    fn mul(self, scalar: Secret<Scalar<P>>) -> Self::Output {
        self * scalar.expose_secret()
    }
}

impl<P> Mul<&Secret<Scalar<P>>> for &Point<P>
where
    P: SchemeParams,
{
    type Output = Point<P>;
    fn mul(self, scalar: &Secret<Scalar<P>>) -> Self::Output {
        self * scalar.expose_secret()
    }
}
