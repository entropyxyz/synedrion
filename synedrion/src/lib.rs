#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(
    clippy::mod_module_files,
    // TODO (#76): handle unwraps gracefully and enable this lint
    // clippy::unwrap_used,
    missing_docs,
    missing_copy_implementations,
    rust_2018_idioms,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications
)]

extern crate alloc;

// Expose interal entities for benchmarks
#[cfg(feature = "bench-internals")]
pub mod bench_internals;

mod cggmp21;
mod constructors;
mod curve;
mod paillier;
mod rounds;
pub mod sessions;
mod tools;
mod uint;
mod www02;

// Some re-exports to avoid the need for version-matching
pub use k256;
pub use k256::ecdsa;
pub use signature;

pub use cggmp21::{
    AuxGenError, AuxGenResult, AuxInfo, InteractiveSigningError, InteractiveSigningProof,
    InteractiveSigningResult, KeyGenError, KeyGenProof, KeyGenResult, KeyInitError, KeyInitResult,
    KeyRefreshResult, KeyShare, KeyShareChange, PresigningError, PresigningProof, PresigningResult,
    ProductionParams, SchemeParams, SigningProof, SigningResult, TestParams,
};
pub use constructors::{
    make_aux_gen_session, make_interactive_signing_session, make_key_gen_session,
    make_key_init_session, make_key_refresh_session, make_key_resharing_session, PrehashedMessage,
};
pub use curve::RecoverableSignature;
pub use rounds::ProtocolResult;
pub use sessions::{FinalizeOutcome, MessageBundle, Session};
pub use www02::{KeyResharingInputs, KeyResharingResult, NewHolder, OldHolder, ThresholdKeyShare};
