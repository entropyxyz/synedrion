//! Mutable wrappers around the protocols for easier handling.

mod broadcast;
mod combined_message;
mod error;
mod signed_message;
mod states;
mod type_erased;

pub use broadcast::ConsensusError;
pub use combined_message::CombinedMessage;
pub use error::{Error, LocalError, ProvableError, RemoteError, RemoteErrorEnum};
pub use states::{
    Artifact, FinalizeOutcome, PreprocessedMessage, ProcessedMessage, RoundAccumulator, Session,
};
