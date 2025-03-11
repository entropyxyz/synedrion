#![cfg_attr(not(any(test, feature = "private-benches")), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    missing_docs,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications
)]
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::indexing_slicing))]

/*!
## Features

`k256`: Secp256k1 parameters using [`k256`](`::k256`) crate. See the [`k256`] module.

`dev`: Non-secure development parameters using [`tiny-curve`](`::tiny_curve`) crate. See the [`dev`] module.

`bip32`: enables BIP32 support for [`ThresholdKeyShare`].
*/

extern crate alloc;

mod curve;
mod entities;
mod paillier;
mod protocols;
mod tools;
mod uint;
mod zk;

#[cfg(feature = "k256")]
pub mod k256;

#[cfg(any(test, feature = "dev"))]
pub mod dev;

#[cfg(test)]
mod tests;

// Some re-exports to avoid the need for version-matching
#[cfg(feature = "bip32")]
pub use bip32;

pub use signature;

pub use curve::RecoverableSignature;
pub use entities::{AuxInfo, KeyShare, KeyShareChange, ThresholdKeyShare};
pub use protocols::{
    AuxGen, AuxGenAssociatedData, AuxGenProtocol, InteractiveSigning, InteractiveSigningAssociatedData,
    InteractiveSigningProtocol, KeyInit, KeyInitAssociatedData, KeyInitProtocol, KeyRefresh, KeyRefreshAssociatedData,
    KeyRefreshProtocol, KeyResharing, KeyResharingProtocol, NewHolder, OldHolder, PrehashedMessage, SchemeParams,
};

#[cfg(feature = "bip32")]
pub use curve::{DeriveChildKey, PublicTweakable, SecretTweakable};

#[cfg(feature = "private-benches")]
#[allow(missing_docs)]
#[doc(hidden)]
// Hack to expose internals for benchmarking purposes
pub mod private_benches;
