use crypto_bigint::{
    modular::MontyForm, subtle::ConditionallySelectable, Bounded, ConcatMixed, Encoding, Integer, Invert, Limb, Pow,
    PowBoundedExp, RandomMod, SplitMixed, WideningMul, Zero, U1024, U2048, U4096, U512, U8192,
};
use zeroize::Zeroize;

use crate::uint::{PublicSigned, SecretSigned, SecretUnsigned};

pub trait ToMontgomery: Integer {
    fn to_montgomery(
        self,
        params: &<<Self as Integer>::Monty as crypto_bigint::Monty>::Params,
    ) -> <Self as Integer>::Monty {
        <<Self as Integer>::Monty as crypto_bigint::Monty>::new(self, params.clone())
    }
}

macro_rules! impl_pow {
    ($uintmod:ident) => {
        /// Exponentiation to the power of secret signed integers.
        ///
        /// Constant-time for secret exponents, although not constant-time wrt the bound.
        ///
        /// Assumes that the result exists, panics otherwise (e.g., when trying to raise 0 to a negative power).
        impl<V> Pow<SecretSigned<V>> for $uintmod
        where
            Self: PowBoundedExp<V>,
            V: ConditionallySelectable + Zeroize + Integer + Bounded,
        {
            fn pow(&self, exp: &SecretSigned<V>) -> Self {
                let abs_exp = exp.abs();
                let abs_result =
                    <Self as PowBoundedExp<V>>::pow_bounded_exp(self, abs_exp.expose_secret(), exp.bound());
                let inv_result = abs_result.invert().expect("`self` is assumed to be invertible");
                Self::conditional_select(&abs_result, &inv_result, exp.is_negative())
            }
        }

        /// Exponentiation to the power of secret unsigned integers.
        ///
        /// Constant-time for secret exponents, although not constant-time wrt the bound.
        impl<V> Pow<SecretUnsigned<V>> for $uintmod
        where
            Self: PowBoundedExp<V>,
            V: Zeroize + Integer + Bounded,
        {
            fn pow(&self, exp: &SecretUnsigned<V>) -> Self {
                <Self as PowBoundedExp<V>>::pow_bounded_exp(self, exp.expose_secret(), exp.bound())
            }
        }

        /// Exponentiation to the power of public signed integers.
        impl<V> Pow<PublicSigned<V>> for $uintmod
        where
            Self: PowBoundedExp<V>,
            V: Integer + Bounded,
        {
            fn pow(&self, exp: &PublicSigned<V>) -> Self {
                let abs_exp = exp.abs();
                let abs_result = <Self as PowBoundedExp<V>>::pow_bounded_exp(self, &abs_exp, exp.bound());
                if exp.is_negative() {
                    abs_result.invert().expect("`self` is assumed invertible")
                } else {
                    abs_result
                }
            }
        }

    };
    ([ $($uintmod:ident), + ]) => {
        $(
            impl_pow!($uintmod);
        )+
    };
}
impl_pow!([U1024Mod, U2048Mod, U4096Mod]);

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

impl ToMontgomery for U512 {}
impl ToMontgomery for U1024 {}
impl ToMontgomery for U2048 {}
impl ToMontgomery for U4096 {}
impl ToMontgomery for U8192 {}
