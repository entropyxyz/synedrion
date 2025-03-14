use crypto_bigint::{
    modular::Retrieve,
    subtle::{ConditionallyNegatable, ConditionallySelectable, ConstantTimeGreater, CtOption},
    Bounded, Gcd, Integer, InvMod, Invert, Monty, PowBoundedExp, RandomBits, RandomMod,
};
use crypto_primes::RandomPrimeWithRng;
use zeroize::Zeroize;

use crate::{
    tools::hashing::Chain,
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
        + Monty<Integer = Self::Uint>
        + Retrieve<Output = Self::Uint>
        + Invert<Output = CtOption<Self::UintMod>>
        + Zeroize;

    /// An integer that fits the squared RSA modulus.
    /// Used for Paillier ciphertexts.
    type WideUint: Integer<Monty = Self::WideUintMod>
        + Bounded
        + ConditionallySelectable
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

    /// Evaluates to `true` if the associated constants and the sizes of associated types are self-consistent.
    const SELF_CONSISTENT: bool = Self::MODULUS_BITS == 2 * Self::PRIME_BITS
        && Self::HalfUint::BITS >= Self::PRIME_BITS
        && Self::Uint::BITS >= Self::MODULUS_BITS
        && Self::Uint::BITS >= Self::HalfUint::BITS
        && Self::WideUint::BITS >= Self::MODULUS_BITS * 2
        && Self::WideUint::BITS >= Self::Uint::BITS;
}

pub(crate) fn chain_paillier_params<P, C>(digest: C) -> C
where
    P: PaillierParams,
    C: Chain,
{
    digest.chain_bytes(&P::PRIME_BITS.to_be_bytes())
}
