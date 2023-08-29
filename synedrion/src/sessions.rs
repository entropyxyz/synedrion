//! Mutable wrappers around the protocols for easier handling.

mod broadcast;
mod constructors;
mod error;
mod signed_message;
mod states;
mod type_erased;

pub use constructors::{
    make_interactive_signing_session, make_key_refresh_session, make_keygen_and_aux_session,
    PrehashedMessage,
};
pub use error::Error;
pub use signed_message::SignedMessage;
pub use states::{FinalizeOutcome, ReceivingState, SendingState, ToSend};
