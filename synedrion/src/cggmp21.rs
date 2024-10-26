//! The implementation of "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts"
//! by Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled.
//! (CCS'20: Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security
//! 1769-1787 (2020),
//! DOI: 10.1145/3372297.3423367)
//!
//! The equation and figure numbers in the comments, and the notation used
//! refers to the version of the paper published at <https://eprint.iacr.org/2021/060.pdf>

mod entities;
mod params;
mod protocols;
mod sigma;

pub use entities::{AuxInfo, KeyShare, KeyShareChange};
pub(crate) use entities::{PublicAuxInfo, SecretAuxInfo};
pub use params::{ProductionParams, SchemeParams, TestParams};
pub use protocols::{
    AuxGen, AuxGenProtocol, InteractiveSigning, InteractiveSigningProtocol, KeyInit,
    KeyInitProtocol, KeyRefresh, KeyRefreshProtocol, PrehashedMessage,
};
