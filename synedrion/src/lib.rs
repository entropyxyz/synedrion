#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod centralized_keygen;
mod cggmp21;
mod curve;
mod paillier;
pub mod sessions;
mod tools;
mod uint;

// Some re-exports to avoid the need for version-matching
pub use k256;
pub use k256::ecdsa;
pub use signature;

pub use centralized_keygen::{make_key_shares, make_threshold_key_shares};
pub use cggmp21::{KeyShare, PartyIdx, SchemeParams, TestSchemeParams, ThresholdKeyShare};
pub use curve::RecoverableSignature;
