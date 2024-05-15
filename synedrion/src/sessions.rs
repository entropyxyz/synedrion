//! Mutable wrappers around the protocols for easier handling.

mod combined_message;
mod echo;
mod error;
mod session;
mod signed_message;
mod type_erased;

pub use combined_message::CombinedMessage;
pub use echo::EchoError;
pub use error::{Error, LocalError, ProvableError, RemoteError, RemoteErrorEnum};
pub use session::{
    Artifact, FinalizeOutcome, MappedResult, PreprocessedMessage, ProcessedMessage,
    RoundAccumulator, Session,
};
