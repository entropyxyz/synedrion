mod generic;
mod wrappers;

#[cfg(any(test, feature = "bench-internals"))]
pub(crate) mod test_utils;

pub use generic::ProtocolResult;
pub(crate) use generic::{
    no_broadcast_messages, no_direct_messages, FinalizableToNextRound, FinalizableToResult,
    FinalizationRequirement, FinalizeError, FirstRound, InitError, Round, ToNextRound, ToResult,
};
pub(crate) use wrappers::{
    wrap_finalize_error, CorrectnessProofWrapper, ProvableErrorWrapper, RoundWrapper, WrappedRound,
};
