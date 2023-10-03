#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../../README.md")]
#![deny(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    // TODO: handle unwraps gracefully and enable this lint
    // clippy::unwrap_used,
    missing_docs,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications
)]

extern crate alloc;

cfg_if::cfg_if! {
    if #[cfg(feature = "bench-internals")] {
        pub mod cggmp21;
    }
    else {
        mod cggmp21;
    }
}

mod curve;
mod paillier;
pub mod sessions;
mod tools;
mod uint;

// Some re-exports to avoid the need for version-matching
pub use k256;
pub use k256::ecdsa;
pub use signature;

pub use cggmp21::{
    InitError, KeyShare, KeyShareChange, PartyIdx, ProductionParams, SchemeParams, TestParams,
    ThresholdKeyShare,
};
pub use curve::RecoverableSignature;
