use alloc::string::String;

use super::broadcast::ConsensusError;
use super::type_erased::{AccumAddError, AccumFinalizeError};
use crate::cggmp21::{PartyIdx, ProtocolResult};

/// Possible errors returned by session methods.
#[derive(Clone, Debug)]
pub enum Error<Res: ProtocolResult> {
    /// Indicates an error on this party's side.
    /// Can be caused by an incorrect usage, a bug in the implementation, or some environment error.
    Local(LocalError),
    /// An unprovable fault of another party.
    Remote {
        /// The index of the failed party.
        party: PartyIdx,
        /// The error that occurred.
        error: RemoteError,
    },
    /// A provable fault of another party.
    // TODO: attach the party's messages up to this round for this to be verifiable by a third party
    Provable {
        /// The index of the failed party.
        party: PartyIdx,
        /// The error that occurred.
        error: ProvableError<Res>,
    },
    /// An error occurred, but the fault of a specific party cannot be immediately proven.
    /// This structure instead proves that this party performed its calculations correctly.
    Proof {
        // TODO: attach all received messages from other parties.
        // What else do we need to verify it?
        /// The proof of correctness.
        proof: Res::CorrectnessProof,
    },
}

#[derive(Clone, Debug)]
pub enum LocalError {
    /// An error while initializing the first round of a protocol.
    ///
    /// Note that it can be returned in the middle of the session in case of
    /// sequentially merged protocols (e.g. Presigning and Signing).
    Init(String),
    /// A mutable object was in an invalid state for calling a method.
    ///
    /// This indicates a logic error either in the calling code or in the method code.
    InvalidState(String),
    /// A message could not be serialized.
    ///
    /// Refer to the documentation of the chosen serialization library for more info.
    CannotSerialize(String),
    /// A message could not be signed.
    ///
    /// Refer to the documentation of the chosen ECDSA library for more info.
    CannotSign(String),
    AccumFinalize(AccumFinalizeError),
    AccumAdd(AccumAddError),
}

#[derive(Clone, Debug)]
pub enum RemoteError {
    UnexpectedSessionId,
    OutOfOrderMessage,
    DuplicateMessage,
    InvalidSignature(String),
}

#[derive(Clone, Debug)]
pub enum ProvableError<Res: ProtocolResult> {
    Protocol(Res::ProvableError),
    CannotDeserialize(String),
    Consensus(ConsensusError),
}
