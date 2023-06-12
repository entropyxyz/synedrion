#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod centralized_keygen;
mod curve;
mod paillier;
mod protocols;
pub mod sessions;
mod sigma;
mod tools;

pub use k256;

pub use centralized_keygen::{make_key_shares, make_threshold_key_shares};
pub use curve::{RecoverableSignature, Signer, Verifier};
pub use protocols::{
    common::{KeyShare, PartyIdx, SchemeParams, TestSchemeParams},
    threshold::ThresholdKeyShare,
};
