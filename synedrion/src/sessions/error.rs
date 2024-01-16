use alloc::string::String;
use core::fmt;

use super::broadcast::ConsensusError;
use crate::rounds::ProtocolResult;

/// Possible errors returned by session methods.
#[derive(Clone, Debug)]
pub enum Error<Res: ProtocolResult, Verifier> {
    /// Indicates an error on this party's side.
    Local(LocalError),
    /// A provable fault of another party.
    // TODO (#43): attach the party's messages up to this round
    // for this to be verifiable by a third party
    Provable {
        /// The index of the failed party.
        party: Verifier,
        /// The error that occurred.
        error: ProvableError<Res>,
    },
    /// An error occurred, but the fault of a specific party cannot be immediately proven.
    /// This structure instead proves that this party performed its calculations correctly.
    Proof {
        // TODO (#43): attach all received messages from other parties.
        // What else do we need to verify it?
        /// The proof of correctness.
        proof: Res::CorrectnessProof,
    },
    /// An error caused by remote party, unprovable at this level.
    ///
    /// This error may be eventually provable if there are some external guarantees
    /// provided by the communication channel.
    Remote(RemoteError<Verifier>),
}

/// An error on this party's side.
/// Can be caused by an incorrect usage, a bug in the implementation, or some environment error.
#[derive(Clone, Debug)]
pub struct LocalError(pub(crate) String);

/// An unprovable fault of another party.
#[derive(Clone, Debug)]
pub struct RemoteError<Verifier> {
    /// The offending party.
    pub party: Verifier,
    /// The error type
    pub error: RemoteErrorEnum,
}

/// Types of unprovable faults of another party.
#[derive(Clone, Debug)]
pub enum RemoteErrorEnum {
    /// Session ID does not match the one provided to the local session constructor.
    UnexpectedSessionId,
    /// A message is intended for an unexpected round (not the current one or the next one).
    OutOfOrderMessage,
    /// A message from this party has already been received.
    DuplicateMessage,
    /// The message signature does not match its contents.
    InvalidSignature(String),
}

/// A provable fault of another party.
#[derive(Clone, Debug)]
pub enum ProvableError<Res: ProtocolResult> {
    /// A protocol error.
    Protocol(Res::ProvableError),
    /// Failed to deserialize the message.
    CannotDeserialize(String),
    /// Broadcast consensus check failed.
    Consensus(ConsensusError),
}

// TODO (#88): add a customized impl, don't just use `Debug`.
impl fmt::Display for LocalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self)
    }
}

// TODO (#88): add a customized impl, don't just use `Debug`.
impl<Verifier: fmt::Debug> fmt::Display for RemoteError<Verifier> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self)
    }
}

// TODO (#88): add a customized impl, don't just use `Debug`.
impl<Res: ProtocolResult, Verifier: fmt::Debug> fmt::Display for Error<Res, Verifier> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self)
    }
}
