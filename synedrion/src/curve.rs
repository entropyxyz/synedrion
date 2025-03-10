//! This module is an adapter to the ECC backend.
//! `elliptic_curves` has a somewhat unstable API,
//! and we isolate all the related logic here.

mod arithmetic;
mod ecdsa;

#[cfg(feature = "bip32")]
mod bip32;

pub(crate) use arithmetic::{secret_split, Point, Scalar};

pub use self::ecdsa::RecoverableSignature;

#[cfg(feature = "bip32")]
pub use bip32::{DeriveChildKey, PublicTweakable, SecretTweakable};

#[cfg(feature = "bip32")]
pub(crate) use bip32::{apply_tweaks_public, derive_tweaks};
