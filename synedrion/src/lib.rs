#![cfg_attr(not(test), no_std)]
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

extern crate alloc;

mod cggmp21;
mod curve;
mod paillier;
mod tools;
mod uint;
mod www02;

// Some re-exports to avoid the need for version-matching
#[cfg(feature = "bip32")]
pub use bip32;
pub use signature;

pub use cggmp21::{
    AuxGen, AuxGenAssociatedData, AuxGenProtocol, AuxInfo, InteractiveSigning, InteractiveSigningAssociatedData,
    InteractiveSigningProtocol, KeyInit, KeyInitAssociatedData, KeyInitProtocol, KeyRefresh, KeyRefreshAssociatedData,
    KeyRefreshProtocol, KeyShare, KeyShareChange, PrehashedMessage, ProductionParams112, SchemeParams, TestParams,
};
pub use curve::RecoverableSignature;
#[cfg(feature = "bip32")]
pub use www02::DeriveChildKey;
pub use www02::{KeyResharing, KeyResharingProtocol, NewHolder, OldHolder, ThresholdKeyShare};

#[cfg(feature = "private_benches")]
#[allow(missing_docs)]
#[doc(hidden)]
// Hack to expose internals for benchmarking purposes
pub mod private_benches;
