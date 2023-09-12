use serde::{Deserialize, Serialize};

use crate::uint::{
    FromScalar, HasWide, U1024Mod, U2048Mod, U4096Mod, U512Mod, UintLike, UintModLike, U1024,
    U2048, U4096, U512, U8192,
};

pub trait PaillierParams: PartialEq + Eq + Clone + core::fmt::Debug + Send {
    /// The size of one of the pair of RSA primes.
    const PRIME_BITS: usize;
    /// The size of the RSA modulus (a product of two primes).
    const MODULUS_BITS: usize = Self::PRIME_BITS * 2;
    /// An integer that fits a single RSA prime.
    type HalfUint: UintLike + HasWide<Wide = Self::Uint>;
    /// A modulo-residue counterpart of `HalfUint`.
    type HalfUintMod: UintModLike<RawUint = Self::HalfUint>;
    /// An integer that fits the RSA modulus.
    type Uint: UintLike
        + FromScalar
        + HasWide<Wide = Self::WideUint>
        + Serialize
        + for<'de> Deserialize<'de>;
    /// A modulo-residue counterpart of `Uint`.
    type UintMod: UintModLike<RawUint = Self::Uint>;
    /// An integer that fits the squared RSA modulus.
    /// Used for Paillier ciphertexts.
    type WideUint: UintLike
        + Serialize
        + for<'de> Deserialize<'de>
        + HasWide<Wide = Self::ExtraWideUint>;
    /// A modulo-residue counterpart of `WideUint`.
    type WideUintMod: UintModLike<RawUint = Self::WideUint>;
    /// An integer that fits the squared RSA modulus times a small factor.
    /// Used in some ZK proofs.
    // Technically, it doesn't have to be that large, but the time spent multiplying these
    // is negligible, and when it is used as an exponent, it is bounded anyway.
    // So it is easier to keep it as a double of `WideUint`.
    type ExtraWideUint: UintLike + Serialize + for<'de> Deserialize<'de>;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PaillierTest;

impl PaillierParams for PaillierTest {
    // We need 257-bit primes because we need MODULUS_BITS to accommodate all the possible
    // values of curve scalar squared, which is 512 bits.

    // The prime size is chosen to be minimal for which the `TestSchemeParams` still work.
    // In the presigning, we are constructing a ciphertext of `x * y + z` where
    // `0 < x, y < q < 2^L` and `-2^LP < z < 2^LP`
    // (`q` is the curve order, `L` and `LP` are constants in `TestSchemeParams`).
    // We need the final result to be `-N/2 < x * y + z < N/2`
    // (that is, it may be negative, and it cannot wrap around modulo N).
    // `N` is a product of two primes of the size `PRIME_BITS`, so `N > 2^(2 * PRIME_BITS - 2)`.
    // Therefore we require `2^(2*L) + 2^LP < 2^(2 * PRIME_BITS - 3)`
    // Since in `TestSchemeParams` `L = LP = 256`, this leads to `2 * PRIME_BITS - 3 >= 2 * L + 1`.
    // TODO: add an assertion for `SchemeParams` checking that?
    const PRIME_BITS: usize = 258;
    type HalfUint = U512;
    type HalfUintMod = U512Mod;
    type Uint = U1024;
    type UintMod = U1024Mod;
    type WideUint = U2048;
    type WideUintMod = U2048Mod;
    type ExtraWideUint = U4096;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PaillierProduction;

impl PaillierParams for PaillierProduction {
    const PRIME_BITS: usize = 1024;
    type HalfUint = U1024;
    type HalfUintMod = U1024Mod;
    type Uint = U2048;
    type UintMod = U2048Mod;
    type WideUint = U4096;
    type WideUintMod = U4096Mod;
    type ExtraWideUint = U8192;
}
