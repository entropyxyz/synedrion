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
    type SingleUint: UintLike + HasWide<Wide = Self::DoubleUint>;
    /// A modulo-residue counterpart of `SingleUint`.
    type SingleUintMod: UintModLike<RawUint = Self::SingleUint>;
    /// An integer that fits the RSA modulus.
    type DoubleUint: UintLike
        + FromScalar
        + HasWide<Wide = Self::QuadUint>
        + Serialize
        + for<'de> Deserialize<'de>;
    /// A modulo-residue counterpart of `DoubleUint`.
    type DoubleUintMod: UintModLike<RawUint = Self::DoubleUint>;
    /// An integer that fits the squared RSA modulus.
    /// Used for Paillier ciphertexts.
    type QuadUint: UintLike + Serialize + for<'de> Deserialize<'de> + HasWide<Wide = Self::OctoUint>;
    /// A modulo-residue counterpart of `QuadUint`.
    type QuadUintMod: UintModLike<RawUint = Self::QuadUint>;
    /// An integer that fits the squared RSA modulus times a small factor.
    /// Used in some ZK proofs.
    // Technically, it doesn't have to be that large, but the time spent multiplying these
    // is negligible, and when it is used as an exponent, it is bounded anyway.
    // So it is easier to keep it as a double of `QuadUint`.
    type OctoUint: UintLike + Serialize + for<'de> Deserialize<'de>;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PaillierTest;

impl PaillierParams for PaillierTest {
    // We need 257-bit primes because we need MODULUS_BITS to accommodate all the possible
    // values of curve scalar squared, which is 512 bits.
    const PRIME_BITS: usize = 257;
    type SingleUint = U512;
    type SingleUintMod = U512Mod;
    type DoubleUint = U1024;
    type DoubleUintMod = U1024Mod;
    type QuadUint = U2048;
    type QuadUintMod = U2048Mod;
    type OctoUint = U4096;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PaillierProduction;

impl PaillierParams for PaillierProduction {
    const PRIME_BITS: usize = 1024;
    type SingleUint = U1024;
    type SingleUintMod = U1024Mod;
    type DoubleUint = U2048;
    type DoubleUintMod = U2048Mod;
    type QuadUint = U4096;
    type QuadUintMod = U4096Mod;
    type OctoUint = U8192;
}
