//! Mutable wrappers around the protocols for easier handling.

mod message_bundle;
mod echo;
mod error;
mod session;
mod signed_message;
mod type_erased;

pub use message_bundle::MessageBundle;
pub use echo::EchoError;
pub use error::{Error, LocalError, ProvableError, RemoteError, RemoteErrorEnum};
pub use session::{
    Artifact, FinalizeOutcome, PreprocessedMessage, ProcessedMessage, RoundAccumulator, Session,
};
