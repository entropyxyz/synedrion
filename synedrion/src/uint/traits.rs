use core::ops::{Add, Mul, Neg, Rem, Sub};

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

use super::{bounded::Bounded, jacobi::JacobiSymbolTrait, signed::Signed};
use crate::curve::Scalar;
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

// TODO: currently in Rust bounds on `&Self` are not propagated,
// so we can't say "an UintLike x, y support &x + &y" -
// we would have to specify this bound at every place it is used (and it is a long one).
// We can specify the bound saying "an UintLike x, y support x + &y" though,
// which means that we will have to either clone or copy `x`.
// Copying `x` when the underlying operations really support taking it by reference
// involves a slight overhead, but it's better than monstrous trait bounds everywhere.

pub trait UintLike:
    Integer
    + JacobiSymbolTrait
    + Hashable
    + RandomPrimeWithRng
    + RandomMod
    + Random
    + subtle::ConditionallySelectable
{
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
    fn from_xof(reader: &mut impl XofReader, modulus: &NonZero<Self>) -> Self {
        let backend_modulus = modulus.as_ref();

        let n_bits = backend_modulus.bits_vartime();
        let n_bytes = (n_bits + 7) / 8; // ceiling division by 8

        let mut bytes = Uint::<L>::ZERO.to_le_bytes();

        loop {
            reader.read(&mut (bytes.as_mut()[0..n_bytes]));
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
    type RawUint: UintLike;

    /// Precomputed data for converting a regular integer to the modulo representation.
    type Precomputed: Clone + Copy + core::fmt::Debug + PartialEq + Eq + Send;

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

fn pow_wide<T>(base: &T, exponent: &<T::RawUint as HasWide>::Wide, bound: usize) -> T
where
    T: UintModLike,
    T::RawUint: HasWide,
{
    let bits = <T::RawUint as Integer>::BITS;
    let bound = bound % (2 * bits + 1);

    let (hi, lo) = T::RawUint::from_wide(*exponent);
    let lo_res = base.pow_bounded_exp(&lo, core::cmp::min(bits, bound));

    // TODO: this may be faster if we could get access to Uint's pow_bounded_exp() that takes
    // exponents of any size - it keeps the base^(2^k) already.
    if bound > bits {
        base.pow_bounded_exp(&hi, bound - bits).pow_2k(bits) * lo_res
    } else {
        lo_res
    }
}

// TODO: can it be made a method in UintModLike?
pub(crate) fn pow_signed_wide<T>(base: &T, exponent: &Signed<<T::RawUint as HasWide>::Wide>) -> T
where
    T: UintModLike,
    T::RawUint: HasWide,
{
    let abs_exponent = exponent.abs();
    let abs_result = pow_wide(base, &abs_exponent, exponent.bound_usize());
    let inv_result = abs_result.invert().unwrap();
    T::conditional_select(&abs_result, &inv_result, exponent.is_negative())
}

pub(crate) fn pow_signed_extra_wide<T>(
    base: &T,
    exponent: &Signed<<<T::RawUint as HasWide>::Wide as HasWide>::Wide>,
) -> T
where
    T: UintModLike,
    T::RawUint: HasWide,
    <T::RawUint as HasWide>::Wide: HasWide,
{
    let bits = <<T::RawUint as HasWide>::Wide as Integer>::BITS;
    let bound = exponent.bound_usize();

    let abs_exponent = exponent.abs();
    let (whi, wlo) = <T::RawUint as HasWide>::Wide::from_wide(abs_exponent);

    let lo_res = pow_wide(base, &wlo, core::cmp::min(bits, bound));

    let abs_result = if bound > bits {
        pow_wide(base, &whi, bound - bits).pow_2k(bits) * lo_res
    } else {
        lo_res
    };

    let inv_result = abs_result.invert().unwrap();
    T::conditional_select(&abs_result, &inv_result, exponent.is_negative())
}

impl<const L: usize> Hashable for DynResidue<L>
where
    Uint<L>: Encoding,
{
    fn chain<C: Chain>(&self, digest: C) -> C {
        // TODO: I don't think we really need `retrieve()` here,
        // but `DynResidue` objects are not serializable at the moment.
        digest.chain(&self.retrieve())
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

// TODO: use regular From?
pub trait FromScalar {
    fn from_scalar(value: &Scalar) -> Self;
    fn to_scalar(&self) -> Scalar;
}

// TODO: can we generalize it? Or put it in a macro?
impl FromScalar for U1024 {
    fn from_scalar(value: &Scalar) -> Self {
        // TODO: can we cast Scalar to Uint and use to_words()?
        let scalar_bytes = value.to_be_bytes();
        let mut repr = Self::ZERO.to_be_bytes();

        let uint_len = repr.as_ref().len();
        let scalar_len = scalar_bytes.len();

        debug_assert!(uint_len >= scalar_len);
        repr.as_mut()[uint_len - scalar_len..].copy_from_slice(&scalar_bytes);
        Self::from_be_bytes(repr)
    }

    fn to_scalar(&self) -> Scalar {
        // TODO: better as a method of Signed?
        // TODO: can be precomputed
        let p = NonZero::new(Self::from_scalar(&-Scalar::ONE).wrapping_add(&Self::ONE)).unwrap();
        let mut r = self.rem(&p);

        // Treating the values over Self::MAX / 2 as negative ones.
        if self.bit(Self::BITS - 1).into() {
            // TODO: can be precomputed
            let n_mod_p = Self::MAX.rem(&p).add_mod(&Self::ONE, &p);
            r = r.add_mod(&n_mod_p, &p);
        }

        let repr = r.to_be_bytes();
        let scalar_len = Scalar::repr_len();

        // Can unwrap here since the value is within the Scalar range
        Scalar::try_from_be_bytes(&repr[repr.len() - scalar_len..]).unwrap()
    }
}

// TODO: can we generalize it? Or put it in a macro?
impl FromScalar for U2048 {
    fn from_scalar(value: &Scalar) -> Self {
        // TODO: can we cast Scalar to Uint and use to_words()?
        let scalar_bytes = value.to_be_bytes();
        let mut repr = Self::ZERO.to_be_bytes();

        let uint_len = repr.as_ref().len();
        let scalar_len = scalar_bytes.len();

        debug_assert!(uint_len >= scalar_len);
        repr.as_mut()[uint_len - scalar_len..].copy_from_slice(&scalar_bytes);
        Self::from_be_bytes(repr)
    }

    fn to_scalar(&self) -> Scalar {
        // TODO: better as a method of Signed?
        // TODO: can be precomputed
        let p = NonZero::new(Self::from_scalar(&-Scalar::ONE).wrapping_add(&Self::ONE)).unwrap();
        let mut r = self.rem(&p);

        // Treating the values over Self::MAX / 2 as negative ones.
        if self.bit(Self::BITS - 1).into() {
            // TODO: can be precomputed
            let n_mod_p = Self::MAX.rem(&p).add_mod(&Self::ONE, &p);
            r = r.add_mod(&n_mod_p, &p);
        }

        let repr = r.to_be_bytes();
        let scalar_len = Scalar::repr_len();

        // Can unwrap here since the value is within the Scalar range
        Scalar::try_from_be_bytes(&repr[repr.len() - scalar_len..]).unwrap()
    }
}

pub type U512Mod = DynResidue<{ nlimbs!(512) }>;
pub type U1024Mod = DynResidue<{ nlimbs!(1024) }>;
pub type U2048Mod = DynResidue<{ nlimbs!(2048) }>;
pub type U4096Mod = DynResidue<{ nlimbs!(4096) }>;
