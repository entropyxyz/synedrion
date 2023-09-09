use serde::{Deserialize, Serialize};

use crate::uint::{
    FromScalar, HasWide, U1024Mod, U2048Mod, U4096Mod, U512Mod, UintLike, UintModLike, U1024,
    U2048, U4096, U512, U8192,
};

pub trait PaillierParams: PartialEq + Eq + Clone + core::fmt::Debug + Send {
    const PRIME_BITS: usize;
    type SingleUint: UintLike + HasWide<Wide = Self::DoubleUint>;
    type SingleUintMod: UintModLike<RawUint = Self::SingleUint>;
    type DoubleUint: UintLike
        + FromScalar
        + HasWide<Wide = Self::QuadUint>
        + Serialize
        + for<'de> Deserialize<'de>;
    type DoubleUintMod: UintModLike<RawUint = Self::DoubleUint>;
    type QuadUint: UintLike + Serialize + for<'de> Deserialize<'de> + HasWide<Wide = Self::OctoUint>;
    type QuadUintMod: UintModLike<RawUint = Self::QuadUint>;
    type OctoUint: UintLike + Serialize + for<'de> Deserialize<'de>;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PaillierTest;

impl PaillierParams for PaillierTest {
    // We need 257-bit primes because we need DoubleUint to accommodate all the possible
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
    // We need 257-bit primes because we need DoubleUint to accommodate all the possible
    // values of curve scalar squared, which is 512 bits.
    const PRIME_BITS: usize = 1024;
    type SingleUint = U1024;
    type SingleUintMod = U1024Mod;
    type DoubleUint = U2048;
    type DoubleUintMod = U2048Mod;
    type QuadUint = U4096;
    type QuadUintMod = U4096Mod;
    type OctoUint = U8192;
}
