//! This module is an adapter to the ECC backend.
//! `elliptic_curves` has a somewhat unstable API,
//! and we isolate all the related logic here.

mod arithmetic;
mod bip32;
mod ecdsa;

pub(crate) use arithmetic::{secret_split, Point, Scalar};

pub use self::ecdsa::RecoverableSignature;
pub use bip32::DeriveChildKey;
