mod generic;
mod wrappers;

#[cfg(any(test, feature = "bench-internals"))]
pub(crate) mod test_utils;

pub use generic::ProtocolResult;
pub(crate) use generic::{
    all_parties_except, no_broadcast_messages, no_direct_messages, try_to_holevec,
    FinalizableToNextRound, FinalizableToResult, FinalizationRequirement, FinalizeError,
    FirstRound, InitError, PartyIdx, Round, ToNextRound, ToResult,
};
pub(crate) use wrappers::{
    wrap_finalize_error, CorrectnessProofWrapper, ProvableErrorWrapper, RoundWrapper,
};
