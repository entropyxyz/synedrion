use core::ops::{Add, Mul, Neg, Rem, Sub};

use crypto_bigint::{
    modular::{
        runtime_mod::{DynResidue, DynResidueParams},
        Retrieve,
    },
    nlimbs,
    subtle::{Choice, ConstantTimeLess, CtOption},
    Encoding, Integer, Invert, Limb, NonZero, Pow, RandomMod, Uint, Word, Zero, U1024, U1280,
    U2048, U320, U4096, U640,
};
use crypto_primes::RandomPrimeWithRng;
use digest::XofReader;

use super::jacobi::JacobiSymbolTrait;
use super::signed::Signed;
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
    Integer + JacobiSymbolTrait + Hashable + RandomPrimeWithRng + RandomMod
{
    // TODO: do we really need this? Or can we just use a simple RNG and `random_mod()`?
    fn hash_into_mod(reader: &mut impl XofReader, modulus: &NonZero<Self>) -> Self;
    fn add_mod(&self, rhs: &Self, modulus: &NonZero<Self>) -> Self;
    fn sub_mod(&self, rhs: &Self, modulus: &NonZero<Self>) -> Self;
    fn trailing_zeros(&self) -> usize;
    fn inv_odd_mod(&self, modulus: &Self) -> CtOption<Self>;
    fn inv_mod2k(&self, k: usize) -> Self;
    fn wrapping_sub(&self, other: &Self) -> Self;
    fn wrapping_mul(&self, other: &Self) -> Self;
    fn wrapping_add(&self, other: &Self) -> Self;
    fn bits(&self) -> usize;
    fn bit(&self, index: usize) -> Choice;
    fn neg(&self) -> Self;
    fn neg_mod(&self, modulus: &Self) -> Self;
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

impl<const L: usize> UintLike for Uint<L> {
    fn hash_into_mod(reader: &mut impl XofReader, modulus: &NonZero<Self>) -> Self {
        // TODO: The algorithm taken from `impl RandomMod for crypto_bigint::Uint<L>`.
        // Consider if this functionality can be added to `crypto_bigint`.
        let mut n = Uint::<L>::ZERO;
        let backend_modulus = modulus.as_ref();

        let n_bits = backend_modulus.bits_vartime();
        let n_limbs = (n_bits + Limb::BITS - 1) / Limb::BITS;
        let mask = Limb::MAX >> (Limb::BITS * n_limbs - n_bits);

        let mut limb_bytes = [0u8; Limb::BYTES];

        loop {
            for i in 0..n_limbs {
                reader.read(&mut limb_bytes);
                n.as_limbs_mut()[i] = Limb(Word::from_be_bytes(limb_bytes));
            }
            n.as_limbs_mut()[n_limbs - 1] = n.as_limbs()[n_limbs - 1] & mask;

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

    fn inv_odd_mod(&self, modulus: &Self) -> CtOption<Self> {
        let (res, choice) = self.inv_odd_mod(modulus);
        CtOption::new(res, choice.into())
    }

    fn inv_mod2k(&self, k: usize) -> Self {
        self.inv_mod2k(k)
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
        (*self).bits()
    }

    fn bit(&self, index: usize) -> Choice {
        (*self).bit(index).into()
    }

    fn neg(&self) -> Self {
        Self::ZERO.wrapping_sub(self)
    }

    fn neg_mod(&self, modulus: &Self) -> Self {
        self.neg_mod(modulus)
    }
}

// TODO: can it be made a method in UintModLike?
pub(crate) fn pow_wide_signed<T>(base: &T, exponent: &Signed<<T::RawUint as HasWide>::Wide>) -> T
where
    T: UintModLike,
    T::RawUint: HasWide,
    <T::RawUint as HasWide>::Wide: UintLike,
{
    let abs_exponent = exponent.abs();
    let (hi, lo) = T::RawUint::from_wide(abs_exponent);

    // TODO: replace with the regular `pow()` when crypto-biging 0.5.3 is released,
    // since it will be able to work with arbitrary-sized exponents.
    let mut abs_result = base.pow(&hi);
    for _ in 0..<T::RawUint as Integer>::BITS {
        abs_result = abs_result * abs_result;
    }
    abs_result = abs_result * base.pow(&lo);
    let inv_result = abs_result.invert().unwrap();

    // TODO: this should be constant-time, but ConditionallySelectable for DynResidue
    // is only supported since crypto-bigint 0.5.3 (unreleased).
    // Use `conditionally_select()` when available.
    if exponent.is_negative().into() {
        inv_result
    } else {
        abs_result
    }
}

impl<const L: usize> Hashable for Uint<L> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        // NOTE: This relies on the fact that `as_words()` returns words
        // starting from the least significant one.
        // So when we hash them like that it is equivalent to hashing the whole thing
        // in the big endian bytes representation.
        // We don't need the length into the digest since it is fixed.
        // TODO: This may be replaced with `to_be_bytes()` call when we have it;
        // right now `Encoding::to_be_bytes()` is only implemented for specific
        // `crypto_bigint::Uint<L>`, but there is no generic implementation.
        let mut digest = digest;
        for word in self.as_words().iter().rev() {
            digest = digest.chain_constant_sized_bytes(&word.to_be_bytes());
        }
        digest
    }
}

pub trait UintModLike:
    Pow<Self::RawUint>
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
{
    type RawUint: UintLike;
    fn new(value: &Self::RawUint, modulus: &NonZero<Self::RawUint>) -> Self;
    fn one(modulus: &NonZero<Self::RawUint>) -> Self;
    fn pow_signed(&self, exponent: &Signed<Self::RawUint>) -> Self {
        let abs_exponent = exponent.abs();
        let abs_result = self.pow(&abs_exponent);
        let inv_result = abs_result.invert().unwrap();

        // TODO: this should be constant-time, but ConditionallySelectable for DynResidue
        // is only supported since crypto-bigint 0.5.3 (unreleased).
        // Use `conditionally_select()` when available.
        if exponent.is_negative().into() {
            inv_result
        } else {
            abs_result
        }
    }
}

// TODO: use regular From?
pub trait FromScalar {
    fn from_scalar(value: &Scalar) -> Self;
    fn to_scalar(&self) -> Scalar;
}

impl<const L: usize> UintModLike for DynResidue<L> {
    type RawUint = Uint<L>;
    fn new(value: &Self::RawUint, modulus: &NonZero<Self::RawUint>) -> Self {
        Self::new(value, DynResidueParams::<L>::new(modulus))
    }
    fn one(modulus: &NonZero<Self::RawUint>) -> Self {
        Self::one(DynResidueParams::<L>::new(modulus))
    }
}

impl<const L: usize> Hashable for DynResidue<L> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        // TODO: I don't think we really need `retrieve()` here,
        // but `DynResidue` objects are not serializable at the moment.
        digest.chain(&self.retrieve())
    }
}

impl HasWide for U320 {
    type Wide = U640;
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

impl HasWide for U640 {
    type Wide = U1280;
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

// TODO: can we generalize it? Or put it in a macro?
impl FromScalar for U640 {
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
        // TODO: is this necessary?
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
        // TODO: is this necessary?
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

pub type U320Mod = DynResidue<{ nlimbs!(320) }>;
pub type U640Mod = DynResidue<{ nlimbs!(640) }>;
pub type U1280Mod = DynResidue<{ nlimbs!(1280) }>;

pub type U1024Mod = DynResidue<{ nlimbs!(1024) }>;
pub type U2048Mod = DynResidue<{ nlimbs!(2048) }>;
pub type U4096Mod = DynResidue<{ nlimbs!(4096) }>;
