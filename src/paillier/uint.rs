use core::ops::{Add, BitAnd, Mul, Neg, Rem, Shl, Shr, Sub};

use digest::XofReader;
use rand_core::{CryptoRng, RngCore};

use crypto_bigint::subtle::{ConstantTimeLess, CtOption};
use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    nlimbs, CtChoice, Encoding, Limb, Uint, Word,
};
use crypto_bigint::{Bounded, PowBoundedExp};

use crate::tools::hashing::{Chain, HashInto, Hashable};
use crate::tools::jacobi::{JacobiSymbol, JacobiSymbolTrait};

pub use crypto_bigint::{
    modular::Retrieve, CheckedAdd, CheckedMul, CheckedSub, Integer, Invert, NonZero, Pow,
    RandomMod, Zero, U128, U64,
};
pub use crypto_primes::RandomPrimeWithRng;

// Alternatively, we could just make `UintLike` a marker trait for a combination of `crypto_bigint`
// traits and use `crypto_bigint::Uint` directly.
// A newtype is used for several reasons:
// - we can implement foreign traits for it (most notably, `Serialize`/`Deserialize` and
//   arithmetic traits)
// - we don't have to import `crypto_bigint` traits everywhere -
//   now they are contained in this module.

// TODO: currently in Rust bounds on `&Self` are not propagated,
// so we can't say "an UintLike x, y support &x + &y" -
// we would have to specify this bound at every place it is used (and it is a long one).
// We can specify the bound saying "an UintLike x, y support x + &y" though,
// which means that we will have to either clone or copy `x`.
// Copying `x` when the underlying operations really support taking it by reference
// involves a slight overhead, but it's better than monstrous trait bounds everywhere.
pub trait UintLike:
    Sized
    + Integer
    + JacobiSymbolTrait
    + core::fmt::Debug
    + Clone
    + Copy
    + Bounded
    + Hashable
    + Shr<usize, Output = Self>
    + Shl<usize, Output = Self>
    + BitAnd<Output = Self>
    + Zero
    + PartialEq
    + Eq
    + RandomPrimeWithRng
    + RandomMod
    + for<'a> CheckedAdd<&'a Self>
    + for<'a> CheckedSub<&'a Self>
    + for<'a> CheckedMul<&'a Self>
    + Rem<NonZero<Self>, Output = Self>
{
    // TODO: do we really need this? Or can we just use a simple RNG and `random_mod()`?
    fn hash_into_mod(reader: &mut impl XofReader, modulus: &NonZero<Self>) -> Self;
    fn add_mod(&self, rhs: &Self, modulus: &NonZero<Self>) -> Self;
    fn trailing_zeros(&self) -> usize;
    fn inv_odd_mod(&self, modulus: &Self) -> CtOption<Self>;
    fn inv_mod2k(&self, k: usize) -> Self;
    fn safe_prime_with_rng(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        <Self as RandomPrimeWithRng>::safe_prime_with_rng(rng, <Self as Integer>::BITS)
    }
    fn wrapping_sub(&self, other: &Self) -> Self;
    fn wrapping_mul(&self, other: &Self) -> Self;
    fn bits(&self) -> usize;
}

pub trait HasWide: Sized {
    type Wide;
    fn mul_wide(&self, other: &Self) -> Self::Wide;
    fn into_wide(self) -> Self::Wide;
    fn try_from_wide(value: Self::Wide) -> Option<Self>;
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

            if n.ct_lt(&backend_modulus).into() {
                return n;
            }
        }
    }

    fn add_mod(&self, rhs: &Self, modulus: &NonZero<Self>) -> Self {
        self.add_mod(rhs, modulus)
    }

    fn trailing_zeros(&self) -> usize {
        (*self).trailing_zeros()
    }

    fn inv_odd_mod(&self, modulus: &Self) -> CtOption<Self> {
        let (res, choice) = self.inv_odd_mod(&modulus);
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

    fn bits(&self) -> usize {
        (*self).bits()
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
    + for<'a> Mul<&'a Self, Output = Self>
{
    type RawUint: UintLike;
    fn new(value: &Self::RawUint, modulus: &NonZero<Self::RawUint>) -> Self;
}

impl<const L: usize> UintModLike for DynResidue<L> {
    type RawUint = Uint<L>;
    fn new(value: &Self::RawUint, modulus: &NonZero<Self::RawUint>) -> Self {
        Self::new(value, DynResidueParams::<L>::new(modulus))
    }
}

impl<const L: usize> Hashable for DynResidue<L> {
    fn chain<C: Chain>(&self, digest: C) -> C {
        // TODO: I don't think we really need `retrieve()` here,
        // but `DynResidue` objects are not serializable at the moment.
        digest.chain(&self.retrieve())
    }
}

impl HasWide for U64 {
    type Wide = U128;
    fn mul_wide(&self, other: &Self) -> Self::Wide {
        self.mul_wide(other).into()
    }
    fn into_wide(self) -> Self::Wide {
        (self, Self::ZERO).into()
    }
    fn try_from_wide(value: Self::Wide) -> Option<Self> {
        let (hi, lo): (Self, Self) = value.into();
        if hi.is_zero().into() {
            return Some(lo);
        }
        None
    }
}

pub type U64Mod = DynResidue<{ nlimbs!(64) }>;
pub type U128Mod = DynResidue<{ nlimbs!(128) }>;
