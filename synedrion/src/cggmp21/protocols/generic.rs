use alloc::string::String;
use core::fmt;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::PartyIdx;
use crate::tools::collections::{HoleRange, HoleVec};

pub(crate) trait BroadcastRound {
    const REQUIRES_CONSENSUS: bool = false;
    type Message: Sized + Clone + Serialize + for<'de> Deserialize<'de>;
    type Payload: Sized + Send + 'static;
    fn broadcast_destinations(&self) -> Option<HoleRange> {
        None
    }
    fn make_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut impl CryptoRngCore,
    ) -> Result<Self::Message, String> {
        Err("This round does not send out broadcasts".into())
    }
    fn verify_broadcast(
        &self,
        #[allow(unused_variables)] from: PartyIdx,
        #[allow(unused_variables)] msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        Err(ReceiveError::UnexpectedMessage(
            "This round does not receive broadcasts".into(),
        ))
    }
}

pub(crate) trait DirectRound {
    type Message: Sized + Clone + Serialize + for<'de> Deserialize<'de>;
    type Payload: Sized + Send + 'static;
    type Artefact: Sized + Send + 'static;
    fn direct_message_destinations(&self) -> Option<HoleRange> {
        None
    }
    fn make_direct_message(
        &self,
        #[allow(unused_variables)] rng: &mut impl CryptoRngCore,
        #[allow(unused_variables)] destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artefact), String> {
        Err("This round does not send out direct messages".into())
    }
    fn verify_direct_message(
        &self,
        #[allow(unused_variables)] from: PartyIdx,
        #[allow(unused_variables)] msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        Err(ReceiveError::UnexpectedMessage(
            "This round does not receive direct messages".into(),
        ))
    }
}

pub trait FinalizableType {}

pub struct ToResult;

impl FinalizableType for ToResult {}

pub struct ToNextRound;

impl FinalizableType for ToNextRound {}

pub(crate) trait Round: Sized + Send + BroadcastRound + DirectRound {
    type Type: FinalizableType;
    type Result: Sized + Send;
    const ROUND_NUM: u8;
    // TODO: find a way to derive it from `ROUND_NUM`
    const NEXT_ROUND_NUM: Option<u8>;
}

pub(crate) trait FinalizableToResult: Round {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        dm_artefacts: Option<HoleVec<<Self as DirectRound>::Artefact>>,
    ) -> Result<Self::Result, FinalizeError>;
}

pub(crate) trait FinalizableToNextRound: Round {
    type NextRound: Round<Result = Self::Result>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        dm_artefacts: Option<HoleVec<<Self as DirectRound>::Artefact>>,
    ) -> Result<Self::NextRound, FinalizeError>;
}

#[derive(Debug, Clone)]
pub enum ReceiveError {
    VerificationFail(String),
    UnexpectedMessage(String),
}

#[derive(Debug, Clone)]
pub enum FinalizeError {
    /// Returned when there is an error chaining the start of another protocol
    /// on the finalization of the previous one.
    ProtocolMergeSequential(InitError),
    ProtocolMergeParallel(String),
    Unspecified(String), // TODO: add fine-grained errors
}

/// An error that can occur when initializing a protocol.
#[derive(Debug, Clone)]
pub struct InitError(pub(crate) String);

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        // TODO: make proper Display impls
        write!(f, "{self:?}")
    }
}

pub(crate) trait FirstRound: Round {
    type Context;
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        context: Self::Context,
    ) -> Result<Self, InitError>;
}
