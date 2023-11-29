//! Mutable wrappers around the protocols for easier handling.

mod broadcast;
mod constructors;
mod error;
mod signed_message;
mod states;
mod type_erased;

pub use broadcast::ConsensusError;
pub use constructors::{
    make_interactive_signing_session, make_key_gen_session, make_key_refresh_session,
    PrehashedMessage,
};
pub use error::{Error, LocalError, ProvableError, RemoteError, RemoteErrorEnum};
pub use signed_message::SignedMessage;
pub use states::{
    Artefact, FinalizeOutcome, PreprocessedMessage, ProcessedMessage, RoundAccumulator, Session,
};
