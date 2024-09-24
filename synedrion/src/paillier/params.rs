use crypto_bigint::{
    modular::Retrieve,
    subtle::{ConditionallyNegatable, ConditionallySelectable, CtOption},
    Bounded, Encoding, Integer, InvMod, Invert, Monty, RandomMod,
};
use crypto_primes::RandomPrimeWithRng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{
    tools::hashing::Hashable,
    uint::{Exponentiable, HasWide, ToMontgomery},
};

#[cfg(test)]
use crate::uint::{U1024Mod, U2048Mod, U512Mod, U1024, U2048, U4096, U512};

pub trait PaillierParams: core::fmt::Debug + PartialEq + Eq + Clone + Send + Sync {
    /// The size of one of the pair of RSA primes.
    const PRIME_BITS: usize;
    /// The size of the RSA modulus (a product of two primes).
    const MODULUS_BITS: usize = Self::PRIME_BITS * 2;
    /// An integer that fits a single RSA prime.
    type HalfUint: Integer<Monty = Self::HalfUintMod>
        + Bounded
        + RandomMod
        + RandomPrimeWithRng
        + Serialize
        + for<'de> Deserialize<'de>
        + HasWide<Wide = Self::Uint>
        + ToMontgomery
        + Zeroize;

    /// A modulo-residue counterpart of `HalfUint`.
    type HalfUintMod: Monty<Integer = Self::HalfUint>
        + Retrieve<Output = Self::HalfUint>
        + Invert<Output = CtOption<Self::HalfUintMod>>;

    /// An integer that fits the RSA modulus.
    type Uint: Integer<Monty = Self::UintMod>
        + Bounded
        + ConditionallySelectable
        + Encoding
        + Hashable
        + HasWide<Wide = Self::WideUint>
        + InvMod
        + RandomMod
        + RandomPrimeWithRng
        + Serialize
        + for<'de> Deserialize<'de>
        + ToMontgomery
        + Zeroize;
    /// A modulo-residue counterpart of `Uint`.
    type UintMod: ConditionallySelectable
        + Exponentiable<Self::Uint>
        + Monty<Integer = Self::Uint>
        + Retrieve<Output = Self::Uint>
        + Invert<Output = CtOption<Self::UintMod>>
        + Zeroize;

    /// An integer that fits the squared RSA modulus.
    /// Used for Paillier ciphertexts.
    type WideUint: Integer<Monty = Self::WideUintMod>
        + Bounded
        + ConditionallySelectable
        + Encoding
        + Hashable
        + HasWide<Wide = Self::ExtraWideUint>
        + RandomMod
        + Serialize
        + for<'de> Deserialize<'de>
        + ToMontgomery;

    /// A modulo-residue counterpart of `WideUint`.
    type WideUintMod: Monty<Integer = Self::WideUint>
        + Exponentiable<Self::WideUint>
        + ConditionallyNegatable
        + ConditionallySelectable
        + Invert<Output = CtOption<Self::WideUintMod>>
        + Retrieve<Output = Self::WideUint>;

    /// An integer that fits the squared RSA modulus times a small factor.
    /// Used in some ZK proofs.
    // Technically, it doesn't have to be that large, but the time spent multiplying these
    // is negligible, and when it is used as an exponent, it is bounded anyway.
    // So it is easier to keep it as a double of `WideUint`.
    // type ExtraWideUint: UintLike + Serialize + for<'de> Deserialize<'de>;
    type ExtraWideUint: Bounded
        + ConditionallySelectable
        + Encoding
        + Hashable
        + Integer
        + RandomMod
        + Serialize
        + for<'de> Deserialize<'de>;
}

/// Paillier parameters for unit tests in this submodule.
#[cfg(test)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct PaillierTest;

#[cfg(test)]
impl PaillierParams for PaillierTest {
    const PRIME_BITS: usize = 512;
    type HalfUint = U512;
    type HalfUintMod = U512Mod;
    type Uint = U1024;
    type UintMod = U1024Mod;
    type WideUint = U2048;
    type WideUintMod = U2048Mod;
    type ExtraWideUint = U4096;
}
