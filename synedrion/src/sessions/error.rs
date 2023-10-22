use alloc::string::String;

use super::broadcast::ConsensusError;
use crate::cggmp21::ProtocolResult;

/// Possible errors returned by session methods.
#[derive(Clone, Debug)]
pub enum Error<Res: ProtocolResult, Verifier> {
    /// Indicates an error on this party's side.
    /// Can be caused by an incorrect usage, a bug in the implementation, or some environment error.
    Local(LocalError),
    /// A provable fault of another party.
    // TODO: attach the party's messages up to this round for this to be verifiable by a third party
    Provable {
        /// The index of the failed party.
        party: Verifier,
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
    /// An error caused by remote party, unprovable at this level.
    ///
    /// This error may be eventually provable if there are some external guarantees
    /// provided by the communication channel.
    Remote(RemoteError<Verifier>),
}

#[derive(Clone, Debug)]
pub struct LocalError(pub(crate) String);

/// An unprovable fault of another party.
#[derive(Clone, Debug)]
pub struct RemoteError<Verifier> {
    pub party: Verifier,
    pub error: RemoteErrorEnum,
}

#[derive(Clone, Debug)]
pub enum RemoteErrorEnum {
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
