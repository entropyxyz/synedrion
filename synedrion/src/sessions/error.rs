use alloc::string::String;

use displaydoc::Display;

use super::echo::EchoError;
use super::evidence::Evidence;
use crate::rounds::ProtocolResult;

/// Possible errors returned by session methods.
#[derive(Debug)]
pub enum Error<Res: ProtocolResult<Verifier>, Sig, Verifier> {
    /// Indicates an error on this party's side.
    Local(LocalError),
    Evidence(Evidence<Res, Sig, Verifier>),
    /// A provable fault of another party.
    // TODO (#43): attach the party's messages up to this round
    // for this to be verifiable by a third party
    Provable {
        /// The index of the failed party.
        party: Verifier,
        /// The error that occurred.
        error: ProvableError<Res, Verifier>,
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
#[derive(Clone, Debug, Display)]
#[displaydoc("Local error: {0}")]
pub struct LocalError(pub(crate) String);

/// An unprovable fault of another party.
#[derive(Clone, Debug, Display)]
pub struct RemoteError<Verifier> {
    /// The offending party.
    pub party: Verifier,
    /// The error type
    pub error: RemoteErrorEnum,
}

/// Types of unprovable faults of another party.
#[derive(Clone, Debug, Display)]
pub enum RemoteErrorEnum {
    /// Session ID does not match the one provided to the local session constructor.
    UnexpectedSessionId,
    /// A message is intended for an unexpected round (not the current one or the next one).
    OutOfOrderMessage,
    /// A message from this party has already been received.
    DuplicateMessage,
    /// The message signature does not match its contents: {0}.
    InvalidSignature(String),
    /// The message has invalid contents, but the fault is unprovable: {0}.
    // (e.g. correctly signed messages belonging to a different session, possibly a replay attack)
    InvalidContents(String),
}

/// A provable fault of another party.
#[derive(Debug)]
pub enum ProvableError<Res: ProtocolResult<Verifier>, Verifier> {
    /// A protocol error.
    Protocol(Res::ProvableError),
    /// Failed to deserialize the message.
    CannotDeserialize(String),
    /// Echo round failed.
    Echo(EchoError),
}
