use crypto_bigint::{
    modular::MontyForm,
    nlimbs,
    subtle::{ConditionallySelectable, CtOption},
    Bounded, ConcatMixed, Encoding, Gcd, Integer, Invert, Monty, PowBoundedExp, RandomMod, SplitMixed, WideningMul,
    Zero, U1024, U2048, U4096, U512, U8192,
};
use digest::XofReader;
use zeroize::Zeroize;

use crate::uint::{PublicSigned, SecretSigned, SecretUnsigned};

pub trait FromXofReader {
    /// Returns an integer derived deterministically from an extensible output hash,
    /// with the bit size limited to `n_bits`.
    ///
    /// Panics if `n_bits` exceeds the capacity of the integer type.
    fn from_xof_reader(reader: &mut impl XofReader, n_bits: u32) -> Self;
}

impl<T> FromXofReader for T
where
    T: Integer + Bounded + Encoding,
{
    fn from_xof_reader(reader: &mut impl XofReader, n_bits: u32) -> Self {
        assert!(n_bits <= Self::BITS);
        let n_bytes = n_bits.div_ceil(8) as usize;

        // If the number of bits is not a multiple of 8, use a mask to zeroize the high bits in the
        // gererated random bytestring, so that we don't have to reject too much.
        let mask = if n_bits & 7 != 0 {
            (1 << (n_bits & 7)) - 1
        } else {
            u8::MAX
        };

        let mut bytes = Self::zero().to_le_bytes();
        let buf = bytes
            .as_mut()
            .get_mut(0..n_bytes)
            .expect("`n_bytes` does not exceed `Self::BYTES` (following from the assertion for `n_bits`)");
        reader.read(buf);
        bytes.as_mut().last_mut().map(|byte| {
            *byte &= mask;
            Some(byte)
        });
        Self::from_le_bytes(bytes)
    }
}

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

pub type U512Mod = MontyForm<{ nlimbs!(512) }>;
pub type U1024Mod = MontyForm<{ nlimbs!(1024) }>;
pub type U2048Mod = MontyForm<{ nlimbs!(2048) }>;
pub type U4096Mod = MontyForm<{ nlimbs!(4096) }>;
