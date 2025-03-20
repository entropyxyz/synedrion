use alloc::{boxed::Box, format, string::String, vec};

use crypto_bigint::{
    subtle::{ConditionallySelectable, CtOption},
    Bounded, Encoding, Gcd, Integer, Invert, Limb, Monty, PowBoundedExp, Uint,
};
use digest::XofReader;
use zeroize::Zeroize;

use crate::uint::{PublicSigned, SecretSigned, SecretUnsigned};

pub(crate) trait FromXofReader {
    /// Returns an integer derived deterministically from an extensible output hash,
    /// with the bit size limited to `n_bits`.
    ///
    /// Panics if `n_bits` exceeds the capacity of the integer type.
    fn from_xof_reader(reader: &mut impl XofReader, n_bits: u32) -> Self;
}

impl<T> FromXofReader for T
where
    T: Integer + Bounded + BoxedEncoding,
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

        let mut bytes = vec![0u8; T::BYTES];
        let buf = AsMut::<[u8]>::as_mut(&mut bytes)
            .get_mut(T::BYTES - n_bytes..)
            .expect("`n_bytes` does not exceed `T::BYTES` (following from the assertion for `n_bits`)");
        reader.read(buf);
        buf.first_mut().map(|byte| {
            *byte &= mask;
            Some(byte)
        });
        Self::try_from_be_bytes(&bytes).expect("`bytes` lenth is equal to `T::BYTES`")
    }
}

pub(crate) trait IsInvertible {
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

pub(crate) trait ToMontgomery: Integer {
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
pub(crate) trait Exponentiable<Exponent> {
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

/// Exposes a way to widen `Self` to `Wide`.
pub trait Extendable<Wide: Sized>: Sized {
    fn to_wide(&self) -> Wide;
    fn try_from_wide(value: &Wide) -> Option<Self>;
}

impl<const L: usize, const W: usize> Extendable<Uint<W>> for Uint<L> {
    fn to_wide(&self) -> Uint<W> {
        const {
            if W < L {
                panic!("Inconsistent widths in `Extendable::to_wide()`");
            }
        }

        // TODO: can potentially expose a secret `self` if the compiler decides to copy it.
        let mut result = Uint::<W>::ZERO;
        result.as_limbs_mut()[0..L].copy_from_slice(self.as_limbs());
        result
    }

    fn try_from_wide(value: &Uint<W>) -> Option<Self> {
        const {
            if W < L {
                panic!("Inconsistent widths in `Extendable::try_from_wide()`");
            }
        }

        if value.bits_vartime() > Uint::<L>::BITS {
            return None;
        }

        // TODO: can potentially expose a secret `value` if the compiler decides to copy it.
        let mut lo = Uint::<L>::ZERO;
        lo.as_limbs_mut().copy_from_slice(&value.as_limbs()[0..L]);
        Some(lo)
    }
}

/// Exposes a way to multiply `Self` by `Hi` obtaining a `Wide` result.
pub trait MulWide<Hi, Wide: Sized>: Sized {
    fn mul_wide(&self, rhs: &Hi) -> Wide;
}

impl<const L: usize, const R: usize, const W: usize> MulWide<Uint<R>, Uint<W>> for Uint<L> {
    fn mul_wide(&self, rhs: &Uint<R>) -> Uint<W> {
        const {
            if W != L + R {
                panic!("Inconsistent widths in `MulWide::mul_wide()`");
            }
        }

        // TODO: can potentially expose a secret `self` or `rhs`.
        let (lo, hi) = self.split_mul(rhs);
        let mut result = Uint::<W>::ZERO;
        result.as_limbs_mut()[0..L].copy_from_slice(lo.as_limbs());
        result.as_limbs_mut()[L..W].copy_from_slice(hi.as_limbs());
        result
    }
}

pub trait BoxedEncoding: Sized {
    fn to_be_bytes(&self) -> Box<[u8]>;
    fn try_from_be_bytes(bytes: &[u8]) -> Result<Self, String>;
}

impl<const L: usize> BoxedEncoding for Uint<L> {
    fn to_be_bytes(&self) -> Box<[u8]> {
        let mut result = vec![0u8; Self::BYTES];
        // SAFETY:
        // - `rchunks_mut` will not panic as long as `Self::BYTES` is a multiple of `Limb::BYTES`
        // - `copy_from_slice` will not panic as long as `Limb::to_be_bytes()` returns an array of size `Limb::BYTES`
        for (limb, chunk) in self.as_limbs().iter().zip(result.rchunks_exact_mut(Limb::BYTES)) {
            chunk.copy_from_slice(&limb.to_be_bytes());
        }
        result.into()
    }

    fn try_from_be_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != Self::BYTES {
            return Err(format!(
                "Invalid slice length: {}, expected {}",
                bytes.len(),
                Self::BYTES
            ));
        }
        Ok(Self::from_be_slice(bytes))
    }
}
