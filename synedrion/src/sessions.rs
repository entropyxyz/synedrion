//! Mutable wrappers around the protocols for easier handling.

mod echo;
mod error;
mod evidence;
mod message_bundle;
mod session;
mod signed_message;
mod type_erased;

pub use echo::EchoError;
pub use error::{Error, LocalError, ProvableError, RemoteError, RemoteErrorEnum};
pub use message_bundle::MessageBundle;
pub use session::{
    Artifact, FinalizeOutcome, PreprocessedMessage, ProcessedMessage, RoundAccumulator, Session,
};
pub use signed_message::SessionId;

pub(crate) use signed_message::Message;
