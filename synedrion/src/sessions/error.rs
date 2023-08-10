use alloc::string::String;
use core::fmt;

use crate::protocols::common::PartyIdx;

#[derive(Clone, Debug)]
pub enum Error {
    MyFault(MyFault),
    NotEnoughMessages,
    Finalize,
    TheirFault { party: PartyIdx, error: TheirFault },
    TheirFaultUnprovable { party: PartyIdx, error: TheirFault },
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
}

#[derive(Clone, Debug)]
pub enum TheirFault {
    DeserializationError(String),
    DuplicateMessage,
    OutOfOrderMessage,
    InvalidSessionId,
    Receive(String),
    VerificationFail(String),
}