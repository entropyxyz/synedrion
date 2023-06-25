use alloc::string::String;
use alloc::vec::Vec;
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
    Unspecified(String), // TODO: add fine-grained errors
}

pub(crate) enum ToSendTyped<Message> {
    Broadcast(Message),
    // TODO: return an iterator instead, since preparing one message can take some time
    Direct(Vec<(PartyIdx, Message)>),
}

pub(crate) trait Round: Sized + Send {
    type Message: Sized + Clone + Serialize + for<'de> Deserialize<'de>;
    type Payload: Sized + Clone + Send;
    type NextRound: Round<Result = Self::Result>;
    type Result: Sized + Send;

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message>;
    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError>;
    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError>;
    fn round_num() -> u8;
    fn party_idx(&self) -> PartyIdx;
    fn num_parties(&self) -> usize;

    // TODO: these may be possible to implement generically without needing to specify them
    // in every `Round` impl. See the mutually exclusive trait trick.
    fn next_round_num() -> Option<u8>;
    fn requires_broadcast_consensus() -> bool;
}

pub(crate) trait FirstRound: Round {
    type Context;
    fn new(
        rng: &mut impl CryptoRngCore,
        num_parties: usize,
        party_idx: PartyIdx,
        context: &Self::Context,
    ) -> Self;
}

/// A dummy round to use as the `Round::NextRound` when there is no actual next round.
pub(crate) struct NonExistent<Res>(PhantomData<Res>);

impl<Res: Send> Round for NonExistent<Res> {
    type Message = ();
    type Payload = ();
    type NextRound = Self;
    type Result = Res;

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
    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        _payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        unreachable!()
    }
    fn round_num() -> u8 {
        unreachable!()
    }
    fn next_round_num() -> Option<u8> {
        unreachable!()
    }
    fn requires_broadcast_consensus() -> bool {
        unreachable!()
    }
    fn party_idx(&self) -> PartyIdx {
        unreachable!()
    }
    fn num_parties(&self) -> usize {
        unreachable!()
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*; // TODO: remove glob import
    use crate::tools::collections::{HoleRange, HoleVecAccum};

    #[derive(Debug)]
    pub(crate) enum StepError {
        AccumFinalize,
        InvalidIndex,
        RepeatingMessage,
        Receive(ReceiveError),
        Finalize(FinalizeError),
    }

    pub(crate) fn assert_next_round<R: Round>(
        results: impl IntoIterator<Item = FinalizeSuccess<R>>,
    ) -> Result<Vec<R::NextRound>, String> {
        let mut rounds = Vec::new();
        for result in results.into_iter() {
            match result {
                FinalizeSuccess::Result(_) => {
                    return Err("Expected the next round, got result".into())
                }
                FinalizeSuccess::AnotherRound(round) => rounds.push(round),
            }
        }
        Ok(rounds)
    }

    pub(crate) fn assert_result<R: Round>(
        outcomes: impl IntoIterator<Item = FinalizeSuccess<R>>,
    ) -> Result<Vec<R::Result>, String> {
        let mut results = Vec::new();
        for outcome in outcomes.into_iter() {
            match outcome {
                FinalizeSuccess::Result(result) => results.push(result),
                FinalizeSuccess::AnotherRound(_) => {
                    return Err("Expected the result, got another round".into())
                }
            }
        }
        Ok(results)
    }

    pub(crate) fn step<R: Round>(
        rng: &mut impl CryptoRngCore,
        init: Vec<R>,
    ) -> Result<Vec<FinalizeSuccess<R>>, StepError> {
        // Collect outgoing messages

        let mut accums = (0..init.len())
            .map(|idx| HoleVecAccum::<R::Payload>::new(init.len(), idx))
            .collect::<Vec<_>>();
        // `to, from, message`
        let mut all_messages = Vec::<(PartyIdx, PartyIdx, R::Message)>::new();

        for (idx_from, round) in init.iter().enumerate() {
            let to_send = round.to_send(rng);
            let idx_from = PartyIdx::from_usize(idx_from);

            match to_send {
                ToSendTyped::Broadcast(message) => {
                    for idx_to in HoleRange::new(init.len(), idx_from.as_usize()) {
                        all_messages.push((
                            PartyIdx::from_usize(idx_to),
                            idx_from,
                            message.clone(),
                        ));
                    }
                }
                ToSendTyped::Direct(messages) => {
                    for (idx_to, message) in messages.into_iter() {
                        all_messages.push((idx_to, idx_from, message));
                    }
                }
            }
        }

        // Send out messages

        for (idx_to, idx_from, message) in all_messages.into_iter() {
            let round = &init[idx_to.as_usize()];
            let accum = accums.get_mut(idx_to.as_usize()).unwrap();
            let slot = accum
                .get_mut(idx_from.as_usize())
                .ok_or(StepError::InvalidIndex)?;
            if slot.is_some() {
                return Err(StepError::RepeatingMessage);
            }
            *slot = Some(
                round
                    .verify_received(idx_from, message)
                    .map_err(StepError::Receive)?,
            );
        }

        // Check that all the states are finished

        let mut result = Vec::new();

        for (round, accum) in init.into_iter().zip(accums.into_iter()) {
            let accum_final = accum.finalize().map_err(|_| StepError::AccumFinalize)?;
            let outcome = round
                .finalize(rng, accum_final)
                .map_err(StepError::Finalize)?;
            result.push(outcome);
        }

        Ok(result)
    }
}
