//! The implementation of "UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts"
//! by Ran Canetti, Rosario Gennaro, Steven Goldfeder, Nikolaos Makriyannis, and Udi Peled.
//! (CCS'20: Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security
//! 1769-1787 (2020),
//! DOI: 10.1145/3372297.3423367)
//!
//! The equation and figure numbers in the comments, and the notation used
//! refers to the version of the paper published at <https://eprint.iacr.org/2021/060.pdf>

mod params;
mod protocols;
pub(crate) mod sigma;

pub use params::{ProductionParams, SchemeParams, TestParams};
pub(crate) use protocols::{
    auxiliary, interactive_signing, keygen_and_aux, FinalizeError, FinalizeSuccess, FirstRound,
    InitError, ReceiveError, Round, ToSendTyped,
};
pub use protocols::{KeyShare, KeyShareChange, PartyIdx, ThresholdKeyShare};
