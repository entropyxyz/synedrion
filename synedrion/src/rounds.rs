mod generic;
mod wrappers;

#[cfg(any(test, feature = "bench-internals"))]
pub(crate) mod test_utils;

pub use generic::ProtocolResult;
pub(crate) use generic::{
    all_parties_except, try_to_holevec, BaseRound, BroadcastRound, DirectRound, Finalizable,
    FinalizableToNextRound, FinalizableToResult, FinalizationRequirement, FinalizeError,
    FirstRound, InitError, PartyIdx, ReceiveError, Round, ToNextRound, ToResult,
};
pub(crate) use wrappers::{wrap_finalize_error, wrap_receive_error, ResultWrapper, RoundWrapper};
