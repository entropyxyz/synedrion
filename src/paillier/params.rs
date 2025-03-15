use crypto_bigint::{
    modular::Retrieve,
    subtle::{ConditionallyNegatable, ConditionallySelectable, ConstantTimeGreater, CtOption},
    Bounded, Gcd, Integer, InvMod, Invert, Monty, PowBoundedExp, RandomBits, RandomMod,
};
use crypto_primes::RandomPrimeWithRng;
use zeroize::Zeroize;

use crate::{
    tools::hashing::Chain,
    tools::hashing::Hashable,
    uint::{BoxedEncoding, Extendable, MulWide},
};

pub trait PaillierParams: core::fmt::Debug + PartialEq + Eq + Clone + Send + Sync {
    /// The size of one of the pair of RSA primes.
    const PRIME_BITS: u32;

    /// The size of the RSA modulus (a product of two primes).
    const MODULUS_BITS: u32 = Self::PRIME_BITS * 2;

    /// An integer that fits a single RSA prime.
    type HalfUint: Integer<Monty = Self::HalfUintMod>
        + Bounded
        + RandomMod
        + RandomBits
        + RandomPrimeWithRng
        + BoxedEncoding
        + MulWide<Self::HalfUint, Self::Uint>
        + Extendable<Self::Uint>
        + Zeroize;

    /// A modulo-residue counterpart of `HalfUint`.
    type HalfUintMod: Monty<Integer = Self::HalfUint>
        + Retrieve<Output = Self::HalfUint>
        + Invert<Output = CtOption<Self::HalfUintMod>>
        + Zeroize;

    /// An integer that fits the RSA modulus.
    type Uint: Integer<Monty = Self::UintMod>
        + Bounded
        + Gcd<Output = Self::Uint>
        + ConditionallySelectable
        + ConstantTimeGreater
        + Hashable
        + MulWide<Self::Uint, Self::WideUint>
        + Extendable<Self::WideUint>
        + InvMod<Output = Self::Uint>
        + RandomMod
        + RandomPrimeWithRng
        + BoxedEncoding
        + Zeroize;

    /// A modulo-residue counterpart of `Uint`.
    type UintMod: ConditionallySelectable
        + PowBoundedExp<Self::Uint>
        + PowBoundedExp<Self::WideUint>
        + PowBoundedExp<Self::ExtraWideUint>
        + Monty<Integer = Self::Uint>
        + Retrieve<Output = Self::Uint>
        + Invert<Output = CtOption<Self::UintMod>>
        + Zeroize;

    /// An integer that fits the squared RSA modulus.
    /// Used for Paillier ciphertexts.
    type WideUint: Integer<Monty = Self::WideUintMod>
        + Bounded
        + ConditionallySelectable
        + Hashable
        + MulWide<Self::WideUint, Self::ExtraWideUint>
        + Extendable<Self::ExtraWideUint>
        + RandomMod
        + BoxedEncoding
        + Zeroize;

    /// A modulo-residue counterpart of `WideUint`.
    type WideUintMod: Monty<Integer = Self::WideUint>
        + PowBoundedExp<Self::Uint>
        + PowBoundedExp<Self::WideUint>
        + ConditionallyNegatable
        + ConditionallySelectable
        + Invert<Output = CtOption<Self::WideUintMod>>
        + Retrieve<Output = Self::WideUint>
        + Zeroize;

    /// An integer that fits the squared RSA modulus times a small factor.
    /// Used in some ZK proofs.
    // Technically, it doesn't have to be that large, but the time spent multiplying these
    // is negligible, and when it is used as an exponent, it is bounded anyway.
    // So it is easier to keep it as a double of `WideUint`.
    type ExtraWideUint: Bounded + ConditionallySelectable + Hashable + Integer + RandomMod + BoxedEncoding + Zeroize;
}

pub(crate) fn chain_paillier_params<P, C>(digest: C) -> C
where
    P: PaillierParams,
    C: Chain,
{
    digest.chain_bytes(&P::PRIME_BITS.to_be_bytes())
}
