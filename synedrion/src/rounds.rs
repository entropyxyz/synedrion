mod generic;
mod wrappers;

#[cfg(any(test, feature = "bench-internals"))]
pub(crate) mod test_utils;

pub(crate) use generic::{
    no_broadcast_messages, no_direct_messages, EvidenceRequiresMessages, FinalizableToNextRound,
    FinalizableToResult, FinalizationRequirement, FinalizeError, FirstRound, InitError, Round,
    ToNextRound, ToResult,
};
pub use generic::{PartyId, ProtocolResult};
pub(crate) use wrappers::{
    wrap_finalize_error, CorrectnessProofWrapper, ProvableErrorWrapper, RoundWrapper, WrappedRound,
};

#[cfg(test)]
pub mod malicious;
