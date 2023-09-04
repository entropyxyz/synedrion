use serde::{Deserialize, Serialize};

use crate::tools::hashing::Hashable;
use crate::uint::{
    FromScalar, HasWide, U1024Mod, U1280Mod, U2048Mod, U320Mod, U4096Mod, U640Mod, UintLike,
    UintModLike, U1024, U1280, U2048, U320, U4096, U640,
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
    type DoubleUintMod: Hashable + UintModLike<RawUint = Self::DoubleUint>;
    type QuadUint: UintLike + Serialize + for<'de> Deserialize<'de>;
    type QuadUintMod: Hashable + UintModLike<RawUint = Self::QuadUint>;
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PaillierTest;

impl PaillierParams for PaillierTest {
    // We need 257-bit primes because we need DoubleUint to accommodate all the possible
    // values of curve scalar squared, which is 512 bits.
    const PRIME_BITS: usize = 257;
    type SingleUint = U320;
    type SingleUintMod = U320Mod;
    type DoubleUint = U640;
    type DoubleUintMod = U640Mod;
    type QuadUint = U1280;
    type QuadUintMod = U1280Mod;
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
}
