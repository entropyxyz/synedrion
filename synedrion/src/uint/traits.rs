use crypto_bigint::{
    modular::MontyForm,
    subtle::{ConditionallySelectable, CtOption},
    Encoding, Integer, Invert, Limb, PowBoundedExp, RandomMod, Square, Uint, Zero, U1024, U2048, U4096, U512, U8192,
};

use crate::uint::{Bounded, Signed};

pub trait ToMontgomery: Integer {
    fn to_montgomery(
        self,
        params: &<<Self as Integer>::Monty as crypto_bigint::Monty>::Params,
    ) -> <Self as Integer>::Monty {
        <<Self as Integer>::Monty as crypto_bigint::Monty>::new(self, params.clone())
    }
}

/// Exponentiation functions for generic integers (in our case used for integers in Montgomery form
/// with `Signed` exponents).
pub trait Exponentiable<T>:
    PowBoundedExp<T> + Invert<Output = CtOption<Self>> + ConditionallySelectable + Square + core::ops::Mul<Output = Self>
where
    T: Integer + crypto_bigint::Bounded + Encoding + ConditionallySelectable,
{
    fn pow_bounded(&self, exponent: &Bounded<T>) -> Self {
        self.pow_bounded_exp(exponent.as_ref(), exponent.bound())
    }

    /// Constant-time exponentiation of an integer in Montgomery form by a signed exponent.
    ///
    /// #Panics
    ///
    /// Panics if `self` is not invertible.
    fn pow_signed(&self, exponent: &Signed<T>) -> Self {
        let abs_exponent = exponent.abs();
        let abs_result = self.pow_bounded_exp(&abs_exponent, exponent.bound());
        let inv_result = abs_result.invert().expect("`self` is assumed to be invertible");
        Self::conditional_select(&abs_result, &inv_result, exponent.is_negative())
    }

    /// Constant-time exponentiation of an integer in Montgomery form by a "wide" and signed exponent.
    ///
    /// #Panics
    ///
    /// Panics if `self` is not invertible.
    fn pow_signed_wide(&self, exp: &Signed<<T as HasWide>::Wide>) -> Self
    where
        T: HasWide,
        <T as HasWide>::Wide: crypto_bigint::Bounded + ConditionallySelectable,
    {
        let exp_abs = exp.abs();
        let abs = self.pow_wide(&exp_abs, exp.bound());
        let inv = abs.invert().expect("self is assumed to be invertible");
        Self::conditional_select(&abs, &inv, exp.is_negative())
    }

    fn pow_wide(self, exp: &<T as HasWide>::Wide, bound: u32) -> Self
    where
        T: HasWide,
    {
        let bits = <T as crypto_bigint::Bounded>::BITS;
        let bound = bound % (2 * bits + 1);

        let (lo, hi) = <T as HasWide>::from_wide(exp);
        let lo_res = self.pow_bounded_exp(&lo, core::cmp::min(bits, bound));

        // TODO (#34): this may be faster if we could get access to Uint's pow_bounded_exp() that takes
        // exponents of any size - it keeps the self^(2^k) already.
        if bound > bits {
            let mut hi_res = self.pow_bounded_exp(&hi, bound - bits);
            for _ in 0..bits {
                hi_res = hi_res.square()
            }
            hi_res * lo_res
        } else {
            lo_res
        }
    }

    /// Constant-time exponentiation of an integer in Montgomery form by an "extra wide" and signed exponent.
    ///
    /// #Panics
    ///
    /// Panics if `self` is not invertible.
    fn pow_signed_extra_wide(&self, exp: &Signed<<<T as HasWide>::Wide as HasWide>::Wide>) -> Self
    where
        T: HasWide,
        <T as HasWide>::Wide: crypto_bigint::Bounded + ConditionallySelectable + HasWide,
        <<T as HasWide>::Wide as HasWide>::Wide: crypto_bigint::Bounded + ConditionallySelectable,
    {
        let bits = <<T as HasWide>::Wide as crypto_bigint::Bounded>::BITS;
        let bound = exp.bound();

        let abs_exponent = exp.abs();
        let (wlo, whi) = <T as HasWide>::Wide::from_wide(&abs_exponent);

        let lo_res = self.pow_wide(&wlo, core::cmp::min(bits, bound));

        let abs_result = if bound > bits {
            let mut hi_res = self.pow_wide(&whi, bound - bits);
            for _ in 0..bits {
                hi_res = hi_res.square();
            }
            hi_res * lo_res
        } else {
            lo_res
        };

        let inv_result = abs_result.invert().expect("`self` is assumed invertible");
        Self::conditional_select(&abs_result, &inv_result, exp.is_negative())
    }

    /// Variable-time exponentiation of an integer in Montgomery form by a signed exponent.
    ///
    /// #Panics
    ///
    /// Panics if `self` is not invertible.
    fn pow_signed_vartime(self, exp: &Signed<T>) -> Self {
        let abs_exp = exp.abs();
        let abs_result = self.pow_bounded_exp(&abs_exp, exp.bound());
        if exp.is_negative().into() {
            abs_result.invert().expect("`self` is assumed invertible")
        } else {
            abs_result
        }
    }

    /// Variable-time exponentiation of an integer in Montgomery form by a "wide" and signed exponent.
    ///
    /// #Panics
    ///
    /// Panics if `self` is not invertible.
    fn pow_signed_wide_vartime(&self, exp: &Signed<<T as HasWide>::Wide>) -> Self
    where
        T: HasWide,
        <T as HasWide>::Wide: crypto_bigint::Bounded + ConditionallySelectable,
    {
        let exp_abs = exp.abs();
        let abs_result = self.pow_wide(&exp_abs, exp.bound());
        if exp.is_negative().into() {
            abs_result.invert().expect("`self` is assumed invertible")
        } else {
            abs_result
        }
    }
}

pub trait HasWide: Sized + Zero {
    type Wide: Integer + Encoding + RandomMod;
    fn mul_wide(&self, other: &Self) -> Self::Wide;
    fn square_wide(&self) -> Self::Wide;

    /// Converts `self` to a new `Wide` uint, setting the higher half to `0`s.
    /// Consumes `self`.
    fn to_wide(&self) -> Self::Wide;

    /// Splits a `Wide` in two halves and returns the halves (`Self` sized) in a
    /// tuple (lower half first).
    ///
    /// *Note*: The behaviour of this method has changed in v0.2. Previously,
    /// the order of the halves was `(hi, lo)` but after v0.2 the order is `(lo,
    /// hi)`.
    fn from_wide(value: &Self::Wide) -> (Self, Self);

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
    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.widening_mul(other)
    }
    fn square_wide(&self) -> Self::Wide {
        self.square_wide().into()
    }
    fn to_wide(&self) -> Self::Wide {
        Uint::concat_mixed(self, &Self::ZERO)
    }
    fn from_wide(value: &Self::Wide) -> (Self, Self) {
        value.split_mixed()
    }
}

impl HasWide for U1024 {
    type Wide = U2048;
    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.widening_mul(other)
    }
    fn square_wide(&self) -> Self::Wide {
        self.square_wide().into()
    }
    fn to_wide(&self) -> Self::Wide {
        Uint::concat_mixed(self, &Self::ZERO)
    }
    fn from_wide(value: &Self::Wide) -> (Self, Self) {
        value.split_mixed()
    }
}

impl HasWide for U2048 {
    type Wide = U4096;
    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.widening_mul(other)
    }
    fn square_wide(&self) -> Self::Wide {
        self.square_wide().into()
    }
    fn to_wide(&self) -> Self::Wide {
        Uint::concat_mixed(self, &Self::ZERO)
    }
    fn from_wide(value: &Self::Wide) -> (Self, Self) {
        value.split_mixed()
    }
}

impl HasWide for U4096 {
    type Wide = U8192;
    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.widening_mul(other)
    }
    fn square_wide(&self) -> Self::Wide {
        self.square_wide().into()
    }
    fn to_wide(&self) -> Self::Wide {
        Uint::concat_mixed(self, &Self::ZERO)
    }
    fn from_wide(value: &Self::Wide) -> (Self, Self) {
        value.split_mixed()
    }
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

impl Exponentiable<U512> for U512Mod {}
impl Exponentiable<U1024> for U1024Mod {}
impl Exponentiable<U2048> for U2048Mod {}
impl Exponentiable<U4096> for U4096Mod {}
