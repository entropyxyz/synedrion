use core::ops::{Add, Mul, Neg, Sub};

use crypto_bigint::{
    modular::{
        runtime_mod::{DynResidue, DynResidueParams},
        Retrieve,
    },
    nlimbs,
    subtle::{self, Choice, ConstantTimeLess, CtOption},
    Encoding, Integer, Invert, NonZero, PowBoundedExp, Random, RandomMod, Uint, Zero, U1024, U2048,
    U4096, U512, U8192,
};
use crypto_primes::RandomPrimeWithRng;
use digest::XofReader;

use super::{bounded::Bounded, signed::Signed};
use crate::tools::hashing::{Chain, Hashable};

pub(crate) const fn upcast_uint<const N1: usize, const N2: usize>(value: Uint<N1>) -> Uint<N2> {
    debug_assert!(N2 >= N1);
    let mut result_words = [0; N2];
    let mut i = 0;
    while i < N1 {
        result_words[i] = value.as_words()[i];
        i += 1;
    }
    Uint::from_words(result_words)
}

pub trait UintLike:
    Integer
    + Encoding
    + Hashable
    + RandomPrimeWithRng
    + RandomMod
    + Random
    + subtle::ConditionallySelectable
{
    type ModUint: UintModLike<RawUint = Self>;
    fn from_xof(reader: &mut impl XofReader, modulus: &NonZero<Self>) -> Self;
    fn add_mod(&self, rhs: &Self, modulus: &NonZero<Self>) -> Self;
    fn sub_mod(&self, rhs: &Self, modulus: &NonZero<Self>) -> Self;
    fn trailing_zeros(&self) -> usize;
    fn inv_mod(&self, modulus: &Self) -> CtOption<Self>;
    fn wrapping_sub(&self, other: &Self) -> Self;
    fn wrapping_mul(&self, other: &Self) -> Self;
    fn wrapping_add(&self, other: &Self) -> Self;
    fn bits(&self) -> usize;
    fn bits_vartime(&self) -> usize;
    fn bit(&self, index: usize) -> Choice;
    fn bit_vartime(&self, index: usize) -> bool;
    fn neg(&self) -> Self;
    fn neg_mod(&self, modulus: &Self) -> Self;
    fn shl_vartime(&self, shift: usize) -> Self;
    fn shr_vartime(&self, shift: usize) -> Self;
    fn to_mod(&self, precomputed: &<Self::ModUint as UintModLike>::Precomputed) -> Self::ModUint {
        Self::ModUint::new(self, precomputed)
    }
}

pub trait HasWide: Sized + Zero {
    type Wide: UintLike;
    fn mul_wide(&self, other: &Self) -> Self::Wide;
    fn square_wide(&self) -> Self::Wide;
    fn into_wide(self) -> Self::Wide;
    fn from_wide(value: Self::Wide) -> (Self, Self);
    fn try_from_wide(value: Self::Wide) -> Option<Self> {
        let (hi, lo) = Self::from_wide(value);
        if hi.is_zero().into() {
            return Some(lo);
        }
        None
    }
}

impl<const L: usize> UintLike for Uint<L>
where
    Uint<L>: Encoding,
{
    type ModUint = DynResidue<L>;

    fn from_xof(reader: &mut impl XofReader, modulus: &NonZero<Self>) -> Self {
        let backend_modulus = modulus.as_ref();

        let n_bits = backend_modulus.bits_vartime();
        let n_bytes = (n_bits + 7) / 8; // ceiling division by 8

        // If the number of bits is not a multiple of 8,
        // use a mask to zeroize the high bits in the gererated random bytestring,
        // so that we don't have to reject too much.
        let mask = if n_bits & 7 != 0 {
            (1 << (n_bits & 7)) - 1
        } else {
            u8::MAX
        };

        let mut bytes = Uint::<L>::ZERO.to_le_bytes();

        loop {
            reader.read(&mut (bytes.as_mut()[0..n_bytes]));
            bytes.as_mut()[n_bytes - 1] &= mask;
            let n = Uint::<L>::from_le_bytes(bytes);

            if n.ct_lt(backend_modulus).into() {
                return n;
            }
        }
    }

    fn add_mod(&self, rhs: &Self, modulus: &NonZero<Self>) -> Self {
        self.add_mod(rhs, modulus)
    }

    fn sub_mod(&self, rhs: &Self, modulus: &NonZero<Self>) -> Self {
        self.sub_mod(rhs, modulus)
    }

    fn trailing_zeros(&self) -> usize {
        (*self).trailing_zeros()
    }

    fn inv_mod(&self, modulus: &Self) -> CtOption<Self> {
        let (res, choice) = self.inv_mod(modulus);
        CtOption::new(res, choice.into())
    }

    fn wrapping_sub(&self, other: &Self) -> Self {
        self.wrapping_sub(other)
    }

    fn wrapping_mul(&self, other: &Self) -> Self {
        self.wrapping_mul(other)
    }

    fn wrapping_add(&self, other: &Self) -> Self {
        self.wrapping_add(other)
    }

    fn bits(&self) -> usize {
        self.bits()
    }

    fn bits_vartime(&self) -> usize {
        self.bits_vartime()
    }

    fn bit(&self, index: usize) -> Choice {
        self.bit(index).into()
    }

    fn bit_vartime(&self, index: usize) -> bool {
        self.bit_vartime(index)
    }

    fn neg(&self) -> Self {
        Self::ZERO.wrapping_sub(self)
    }

    fn neg_mod(&self, modulus: &Self) -> Self {
        self.neg_mod(modulus)
    }

    fn shl_vartime(&self, shift: usize) -> Self {
        self.shl_vartime(shift)
    }

    fn shr_vartime(&self, shift: usize) -> Self {
        self.shr_vartime(shift)
    }
}

impl<const L: usize> Hashable for Uint<L>
where
    Uint<L>: Encoding,
{
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain_constant_sized_bytes(&self.to_be_bytes())
    }
}

/// Integers in an efficient representation for modulo operations.
pub trait UintModLike:
    PowBoundedExp<Self::RawUint>
    + Send
    + Sync
    + core::fmt::Debug
    + Add<Output = Self>
    + Neg<Output = Self>
    + Copy
    + Clone
    + PartialEq
    + Eq
    + Retrieve<Output = Self::RawUint>
    + Invert<Output = CtOption<Self>>
    + Mul<Output = Self>
    + Sub<Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
    + subtle::ConditionallyNegatable
    + subtle::ConditionallySelectable
{
    /// The corresponding regular integer type.
    type RawUint: UintLike<ModUint = Self>;

    /// Precomputed data for converting a regular integer to the modulo representation.
    type Precomputed: Clone + Copy + core::fmt::Debug + PartialEq + Eq + Send + Sync;

    fn new_precomputed(modulus: &NonZero<Self::RawUint>) -> Self::Precomputed;
    fn new(value: &Self::RawUint, precomputed: &Self::Precomputed) -> Self;
    fn one(precomputed: &Self::Precomputed) -> Self;

    fn pow_signed_vartime(&self, exponent: &Signed<Self::RawUint>) -> Self {
        let abs_exponent = exponent.abs();
        let abs_result = self.pow_bounded_exp(&abs_exponent, exponent.bound_usize());
        if exponent.is_negative().into() {
            abs_result.invert().unwrap()
        } else {
            abs_result
        }
    }

    fn pow_signed(&self, exponent: &Signed<Self::RawUint>) -> Self {
        let abs_exponent = exponent.abs();
        let abs_result = self.pow_bounded_exp(&abs_exponent, exponent.bound_usize());
        let inv_result = abs_result.invert().unwrap();
        Self::conditional_select(&abs_result, &inv_result, exponent.is_negative())
    }

    fn pow_bounded(&self, exponent: &Bounded<Self::RawUint>) -> Self {
        self.pow_bounded_exp(exponent.as_ref(), exponent.bound_usize())
    }
    fn pow_signed_wide(&self, exponent: &Signed<<Self::RawUint as HasWide>::Wide>) -> Self
    where
        Self::RawUint: HasWide,
    {
        let abs_exponent = exponent.abs();
        let abs_result = self.pow_wide(&abs_exponent, exponent.bound_usize());
        let inv_result = abs_result.invert().unwrap();
        Self::conditional_select(&abs_result, &inv_result, exponent.is_negative())
    }

    fn pow_wide(&self, exponent: &<Self::RawUint as HasWide>::Wide, bound: usize) -> Self
    where
        Self::RawUint: HasWide,
    {
        let bits = <Self::RawUint as Integer>::BITS;
        let bound = bound % (2 * bits + 1);

        let (hi, lo) = Self::RawUint::from_wide(*exponent);
        let lo_res = self.pow_bounded_exp(&lo, core::cmp::min(bits, bound));

        // TODO (#34): this may be faster if we could get access to Uint's pow_bounded_exp() that takes
        // exponents of any size - it keeps the self^(2^k) already.
        if bound > bits {
            self.pow_bounded_exp(&hi, bound - bits).pow_2k(bits) * lo_res
        } else {
            lo_res
        }
    }

    fn pow_signed_extra_wide(
        &self,
        exponent: &Signed<<<Self::RawUint as HasWide>::Wide as HasWide>::Wide>,
    ) -> Self
    where
        Self::RawUint: HasWide,
        <Self::RawUint as HasWide>::Wide: HasWide,
    {
        let bits = <<Self::RawUint as HasWide>::Wide as Integer>::BITS;
        let bound = exponent.bound_usize();

        let abs_exponent = exponent.abs();
        let (whi, wlo) = <Self::RawUint as HasWide>::Wide::from_wide(abs_exponent);

        let lo_res = self.pow_wide(&wlo, core::cmp::min(bits, bound));

        let abs_result = if bound > bits {
            self.pow_wide(&whi, bound - bits).pow_2k(bits) * lo_res
        } else {
            lo_res
        };

        let inv_result = abs_result.invert().unwrap();
        Self::conditional_select(&abs_result, &inv_result, exponent.is_negative())
    }

    /// Calculates `self^{2^k}`
    fn pow_2k(&self, k: usize) -> Self {
        let mut result = *self;
        for _ in 0..k {
            result = result.square();
        }
        result
    }
    fn square(&self) -> Self;
}

impl<const L: usize> UintModLike for DynResidue<L>
where
    Uint<L>: Encoding,
{
    type RawUint = Uint<L>;
    type Precomputed = DynResidueParams<L>;

    fn new_precomputed(modulus: &NonZero<Self::RawUint>) -> Self::Precomputed {
        DynResidueParams::<L>::new(modulus)
    }
    fn new(value: &Self::RawUint, precomputed: &Self::Precomputed) -> Self {
        Self::new(value, *precomputed)
    }
    fn one(precomputed: &Self::Precomputed) -> Self {
        Self::one(*precomputed)
    }
    fn square(&self) -> Self {
        self.square()
    }
}

impl HasWide for U512 {
    type Wide = U1024;
    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.mul_wide(other).into()
    }
    fn square_wide(&self) -> Self::Wide {
        self.square_wide().into()
    }
    fn into_wide(self) -> Self::Wide {
        (self, Self::ZERO).into()
    }
    fn from_wide(value: Self::Wide) -> (Self, Self) {
        value.into()
    }
}

impl HasWide for U1024 {
    type Wide = U2048;
    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.mul_wide(other).into()
    }
    fn square_wide(&self) -> Self::Wide {
        self.square_wide().into()
    }
    fn into_wide(self) -> Self::Wide {
        (self, Self::ZERO).into()
    }
    fn from_wide(value: Self::Wide) -> (Self, Self) {
        value.into()
    }
}

impl HasWide for U2048 {
    type Wide = U4096;
    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.mul_wide(other).into()
    }
    fn square_wide(&self) -> Self::Wide {
        self.square_wide().into()
    }
    fn into_wide(self) -> Self::Wide {
        (self, Self::ZERO).into()
    }
    fn from_wide(value: Self::Wide) -> (Self, Self) {
        value.into()
    }
}

impl HasWide for U4096 {
    type Wide = U8192;
    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.mul_wide(other).into()
    }
    fn square_wide(&self) -> Self::Wide {
        self.square_wide().into()
    }
    fn into_wide(self) -> Self::Wide {
        (self, Self::ZERO).into()
    }
    fn from_wide(value: Self::Wide) -> (Self, Self) {
        value.into()
    }
}

pub type U512Mod = DynResidue<{ nlimbs!(512) }>;
pub type U1024Mod = DynResidue<{ nlimbs!(1024) }>;
pub type U2048Mod = DynResidue<{ nlimbs!(2048) }>;
pub type U4096Mod = DynResidue<{ nlimbs!(4096) }>;
