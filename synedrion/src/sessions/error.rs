use alloc::string::String;
use core::fmt;

use super::type_erased;
use crate::cggmp21::PartyIdx;

/// Possible errors returned by session methods.
#[derive(Clone, Debug)]
pub enum Error {
    /// Indicates an error on this party's side:
    /// incorrect implementation, or some environment error.
    MyFault(MyFault),
    /// Not enough messages received to finalize the round.
    NotEnoughMessages,
    /// Failed to finalize the round.
    Finalize,
    /// A provable fault of another party.
    TheirFault {
        /// The index of the failed party.
        party: PartyIdx,
        /// The error that occurred.
        error: TheirFault,
    },
    /// An unprovable fault of another party.
    TheirFaultUnprovable {
        /// The index of the failed party.
        party: PartyIdx,
        /// The error that occurred.
        error: TheirFault,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        // TODO: make proper Display impls
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug)]
pub enum MyFault {
    /// A mutable object was in an invalid state for calling a method.
    ///
    /// This indicates a logic error either in the calling code or in the method code.
    InvalidState(String),
    /// A message could not be serialized.
    ///
    /// Refer to the documentation of the chosen serialization library for more info.
    SerializationError(String),
    InvalidId(PartyIdx),
    SigningError(String),
    TypeErased(type_erased::Error),
}

#[derive(Clone, Debug)]
pub enum TheirFault {
    DeserializationError(String),
    DuplicateMessage,
    OutOfOrderMessage,
    InvalidSessionId,
    Receive(String),
    VerificationFail(String),
    TypeErased(type_erased::Error),
}
