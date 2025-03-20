use crypto_bigint::{
    modular::Retrieve,
    subtle::{ConditionallyNegatable, ConditionallySelectable, ConstantTimeGreater, CtOption},
    Bounded, Gcd, Integer, InvMod, Invert, PowBoundedExp, RandomBits, RandomMod,
};
use crypto_primes::RandomPrimeWithRng;
use zeroize::Zeroize;

use crate::{
    tools::hashing::Chain,
    uint::{BoxedEncoding, Extendable, MulWide},
};

/// Parameters of Paillier encryption.
pub trait PaillierParams: core::fmt::Debug + PartialEq + Eq + Clone + Send + Sync {
    /// The size of one of the pair of RSA primes.
    const PRIME_BITS: u32;

    /// The size of the RSA modulus (a product of two primes).
    const MODULUS_BITS: u32 = Self::PRIME_BITS * 2;

    /// An integer that fits a single RSA prime.
    type HalfUint: Integer<
            Monty: Retrieve<Output = Self::HalfUint>
                       + Invert<Output = CtOption<<Self::HalfUint as Integer>::Monty>>
                       + Zeroize,
        > + Bounded
        + RandomMod
        + RandomBits
        + RandomPrimeWithRng
        + BoxedEncoding
        + MulWide<Self::HalfUint, Self::Uint>
        + Extendable<Self::Uint>
        + Zeroize;

    /// An integer that fits the RSA modulus.
    type Uint: Integer<
            Monty: Retrieve<Output = Self::Uint>
                       + Invert<Output = CtOption<<Self::Uint as Integer>::Monty>>
                       + Zeroize
                       + ConditionallySelectable
                       + PowBoundedExp<Self::Uint>
                       + PowBoundedExp<Self::WideUint>,
        > + Bounded
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

    /// An integer that fits the squared RSA modulus.
    ///
    /// Used for Paillier ciphertexts.
    type WideUint: Integer<
            Monty: PowBoundedExp<Self::Uint>
                       + PowBoundedExp<Self::WideUint>
                       + ConditionallyNegatable
                       + ConditionallySelectable
                       + Invert<Output = CtOption<<Self::WideUint as Integer>::Monty>>
                       + Retrieve<Output = Self::WideUint>
                       + Zeroize,
        > + Bounded
        + ConditionallySelectable
        + RandomMod
        + BoxedEncoding
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
