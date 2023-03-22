use serde::{Deserialize, Serialize};

use super::uint::{
    FromScalar, HasWide, U192Mod, U384Mod, U768Mod, UintLike, UintModLike, U192, U384, U768,
};
use crate::tools::hashing::Hashable;

pub trait PaillierParams: PartialEq + Eq + Clone + core::fmt::Debug {
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
    const PRIME_BITS: usize = 129;
    type SingleUint = U192;
    type SingleUintMod = U192Mod;
    type DoubleUint = U384;
    type DoubleUintMod = U384Mod;
    type QuadUint = U768;
    type QuadUintMod = U768Mod;
}
