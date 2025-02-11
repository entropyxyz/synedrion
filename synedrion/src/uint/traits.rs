use crypto_bigint::{
    modular::MontyForm,
    subtle::{ConditionallySelectable, CtOption},
    Bounded, ConcatMixed, Encoding, Gcd, Integer, Invert, Limb, Monty, PowBoundedExp, RandomMod, SplitMixed,
    WideningMul, Zero, U1024, U2048, U4096, U512, U8192,
};
use zeroize::Zeroize;

use crate::uint::{PublicSigned, SecretSigned, SecretUnsigned};

pub trait IsInvertible {
    /// Returns `true` if `self` is invertible modulo `modulus`.
    fn is_invertible(&self, modulus: &Self) -> bool;
}

impl<T> IsInvertible for T
where
    T: Integer + Gcd<Output = Self>,
{
    fn is_invertible(&self, modulus: &Self) -> bool {
        // There are technically two ways to check for that, one via `gcd()`,
        // and the other by trying `invert()` on the Montgomery form and checking if it succeeds.
        // For U1024, there is currently no detectable difference, since they're using the same algorithm underneath,
        // and conversion to Montgomery takes negligible time (the actual inversion/gcd is ~1000x slower).
        //
        // So we just pick one method, and isolate it in this function.
        self.gcd(modulus) == Self::one()
    }
}

pub trait ToMontgomery: Integer {
    fn to_montgomery(self, params: &<Self::Monty as Monty>::Params) -> Self::Monty {
        <Self::Monty as Monty>::new(self, params.clone())
    }
}

impl<T> ToMontgomery for T where T: Integer {}

/// Exponentiation to the power of bounded integers.
///
/// Constant-time for secret exponents, although not constant-time wrt the bound.
///
/// Assumes that the result exists, panics otherwise (e.g., when trying to raise 0 to a negative power).
// We cannot use the `crypto_bigint::Pow` trait since we cannot implement it for the foreign types
// (namely, `crypto_bigint::modular::MontyForm`).
pub trait Exponentiable<Exponent> {
    fn pow(&self, exp: &Exponent) -> Self;
}

impl<T, V> Exponentiable<SecretSigned<V>> for T
where
    T: ConditionallySelectable + PowBoundedExp<V> + Invert<Output = CtOption<T>>,
    V: ConditionallySelectable + Zeroize + Integer + Bounded,
{
    fn pow(&self, exp: &SecretSigned<V>) -> Self {
        let abs_exp = exp.abs();
        let abs_result = self.pow_bounded_exp(abs_exp.expose_secret(), exp.bound());
        let inv_result = abs_result.invert().expect("`self` is assumed to be invertible");
        Self::conditional_select(&abs_result, &inv_result, exp.is_negative())
    }
}

impl<T, V> Exponentiable<SecretUnsigned<V>> for T
where
    T: PowBoundedExp<V> + Invert<Output = CtOption<T>>,
    V: ConditionallySelectable + Zeroize + Integer + Bounded,
{
    fn pow(&self, exp: &SecretUnsigned<V>) -> Self {
        self.pow_bounded_exp(exp.expose_secret(), exp.bound())
    }
}

impl<T, V> Exponentiable<PublicSigned<V>> for T
where
    T: PowBoundedExp<V> + Invert<Output = CtOption<T>>,
    V: Integer + Bounded,
{
    fn pow(&self, exp: &PublicSigned<V>) -> Self {
        let abs_exp = exp.abs();
        let abs_result = self.pow_bounded_exp(&abs_exp, exp.bound());
        if exp.is_negative() {
            abs_result.invert().expect("`self` is assumed invertible")
        } else {
            abs_result
        }
    }
}

pub trait HasWide:
    Sized + Zero + Integer + for<'a> WideningMul<&'a Self, Output = Self::Wide> + ConcatMixed<MixedOutput = Self::Wide>
{
    type Wide: Integer + Encoding + RandomMod + SplitMixed<Self, Self>;

    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.widening_mul(other)
    }

    /// Converts `self` to a new `Wide` uint, setting the higher half to `0`s.
    fn to_wide(&self) -> Self::Wide {
        // Note that this minimizes the presense of `self` on the stack (to the extent we can ensure it),
        // in case it is secret.
        Self::concat_mixed(self, &Self::zero())
    }

    /// Splits a `Wide` in two halves and returns the halves (`Self` sized) in a
    /// tuple (lower half first).
    fn from_wide(value: &Self::Wide) -> (Self, Self) {
        value.split_mixed()
    }

    /// Tries to convert a `Wide` into a `Self` sized uint. Splits a `Wide`
    /// value in two halves and returns the lower half if the high half is zero.
    /// Otherwise returns `None`.
    fn try_from_wide(value: &Self::Wide) -> Option<Self> {
        let (lo, hi) = Self::from_wide(value);
        if hi.is_zero().into() {
            return Some(lo);
        }
        None
    }
}

impl HasWide for U512 {
    type Wide = U1024;
}

impl HasWide for U1024 {
    type Wide = U2048;
}

impl HasWide for U2048 {
    type Wide = U4096;
}

impl HasWide for U4096 {
    type Wide = U8192;
}

// TODO(dp): Suggest crypto-bigint update nlimbs! macro.
pub type U512Mod = MontyForm<{ 512u32.div_ceil(Limb::BITS) as usize }>;
pub type U1024Mod = MontyForm<{ 1024u32.div_ceil(Limb::BITS) as usize }>;
pub type U2048Mod = MontyForm<{ 2048u32.div_ceil(Limb::BITS) as usize }>;
pub type U4096Mod = MontyForm<{ 4096u32.div_ceil(Limb::BITS) as usize }>;
