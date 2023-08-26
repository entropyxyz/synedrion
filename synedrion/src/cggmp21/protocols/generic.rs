use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::PartyIdx;
use crate::tools::collections::HoleVec;

#[derive(Debug)]
pub(crate) enum ReceiveError {
    VerificationFail(String),
}

pub(crate) enum FinalizeSuccess<R: Round> {
    Result(R::Result),
    AnotherRound(R::NextRound),
}

#[derive(Debug)]
pub(crate) enum FinalizeError {
    /// Returned when there is an error chaining the start of another protocol
    /// on the finalization of the previous one.
    ProtocolMergeSequential(InitError),
    ProtocolMergeParallel(String),
    Unspecified(String), // TODO: add fine-grained errors
}

pub(crate) enum ToSendTyped<Message> {
    Broadcast(Message),
    // TODO: return an iterator instead, since preparing one message can take some time
    Direct(Vec<(PartyIdx, Message)>),
}

pub(crate) trait BaseRound: Sized + Send {
    type Message: Sized + Clone + Serialize + for<'de> Deserialize<'de>;
    type Payload: Sized + Send;

    const ROUND_NUM: u8;
    const REQUIRES_BROADCAST_CONSENSUS: bool;

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message>;
    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError>;
}

pub(crate) trait Round: BaseRound {
    type NextRound: Round<Result = Self::Result>;
    type Result: Sized + Send;
    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError>;
    // TODO: these may be possible to implement generically without needing to specify them
    // in every `Round` impl. See the mutually exclusive trait trick.
    const NEXT_ROUND_NUM: Option<u8>;
}

#[derive(Debug)]
pub struct InitError(pub(crate) String);

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        // TODO: make proper Display impls
        write!(f, "{self:?}")
    }
}

pub(crate) trait FirstRound: BaseRound {
    type Context;
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        context: Self::Context,
    ) -> Result<Self, InitError>;
}

/// A dummy round to use as the `Round::NextRound` when there is no actual next round.
pub(crate) struct NonExistent<Res>(PhantomData<Res>);

impl<Res: Send> BaseRound for NonExistent<Res> {
    type Message = ();
    type Payload = ();

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        unreachable!()
    }
    fn verify_received(
        &self,
        _from: PartyIdx,
        _msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        unreachable!()
    }

    const ROUND_NUM: u8 = 0;
    const REQUIRES_BROADCAST_CONSENSUS: bool = false;
}

impl<Res: Send> Round for NonExistent<Res> {
    type NextRound = Self;
    type Result = Res;
    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        unreachable!()
    }

    const NEXT_ROUND_NUM: Option<u8> = None;
}
