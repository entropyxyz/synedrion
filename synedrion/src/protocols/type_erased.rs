use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::generic::{FinalizeError, FinalizeSuccess, ReceiveError, Round, ToSendTyped};
use crate::tools::collections::HoleVecAccum;
use crate::PartyIdx;

pub(crate) fn serialize_message(
    message: &impl Serialize,
) -> Result<Box<[u8]>, rmp_serde::encode::Error> {
    rmp_serde::encode::to_vec(message).map(|serialized| serialized.into_boxed_slice())
}

pub(crate) fn deserialize_message<M: for<'de> Deserialize<'de>>(
    message_bytes: &[u8],
) -> Result<M, rmp_serde::decode::Error> {
    rmp_serde::decode::from_slice(message_bytes)
}

struct RoundAndAccum<R: Round> {
    round: R,
    accum: HoleVecAccum<R::Payload>,
}

impl<R: Round> RoundAndAccum<R> {
    pub fn new(
        round: R,
        rng: &mut impl CryptoRngCore,
        num_parties: usize,
        index: usize,
    ) -> (Self, ToSendTyped<R::Message>) {
        // TODO: could get length and hole_at from round
        let to_send = round.to_send(rng);
        let state = Self {
            round,
            accum: HoleVecAccum::new(num_parties, index),
        };
        (state, to_send)
    }

    fn receive_typed(&mut self, from: PartyIdx, msg: R::Message) -> ReceiveOutcome {
        let payload = match self.round.verify_received(from, msg) {
            Ok(payload) => payload,
            Err(err) => return ReceiveOutcome::Error(err),
        };
        match self.accum.insert(from.as_usize(), payload) {
            None => return ReceiveOutcome::AlreadyReceived,
            _ => {}
        }
        ReceiveOutcome::Success
    }
    fn finalize_typed(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> FinalizeOutcomeTyped<R::Result, R::NextRound> {
        let payloads = match self.accum.finalize() {
            Ok(payloads) => payloads,
            Err(_) => return FinalizeOutcomeTyped::NotEnoughMessages,
        };
        match self.round.finalize(rng, payloads) {
            Ok(FinalizeSuccess::Result(res)) => FinalizeOutcomeTyped::Result(res),
            Ok(FinalizeSuccess::AnotherRound(round)) => FinalizeOutcomeTyped::AnotherRound(round),
            Err(err) => FinalizeOutcomeTyped::Error(err),
        }
    }
}

/// Serialized messages without the stage number specified.
pub(crate) enum ToSendSerialized {
    Broadcast(Box<[u8]>),
    // TODO: return an iterator instead, since preparing one message can take some time
    Direct(Vec<(PartyIdx, Box<[u8]>)>),
}

pub(crate) enum ReceiveOutcome {
    Success,
    Error(ReceiveError),
    AlreadyReceived,
    DeserializationFail(String),
}

enum FinalizeOutcomeTyped<R, R2: Round> {
    Result(R),
    Error(FinalizeError),
    NotEnoughMessages, // TODO: include the indices of parties whose messages are missing
    AnotherRound(R2),
}

pub(crate) enum FinalizeOutcome<R> {
    Result(R),
    Error(FinalizeError),
    NotEnoughMessages, // TODO: include the indices of parties whose messages are missing
    AnotherRound(Box<dyn TypeErasedRound<R>>),
}

struct BoxedRng<'a>(Box<&'a mut dyn CryptoRngCore>);

impl<'a> rand_core::CryptoRng for BoxedRng<'a> {}

impl<'a> rand_core::RngCore for BoxedRng<'a> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

pub(crate) trait TypeErasedRound<Res> {
    fn to_receiving_state(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
    ) -> (Box<dyn TypeErasedReceivingRound<Res>>, ToSendSerialized);
}

pub(crate) trait TypeErasedReceivingRound<Res>: Send {
    // Possible outcomes:
    // - success
    // - ReceiveError (verification fail etc)
    // - deserialization fail
    // - message already received
    fn receive(&mut self, from: PartyIdx, msg: &[u8]) -> ReceiveOutcome;
    // Possible outcomes:
    // - result
    // - next round
    // - finalization error
    // - not enough messages received
    // - (TODO) error round
    fn finalize(self: Box<Self>, rng: &mut dyn CryptoRngCore) -> FinalizeOutcome<Res>;
    fn round_num(&self) -> u8;
    fn next_round_num(&self) -> Option<u8>;
    fn requires_broadcast_consensus(&self) -> bool;
    fn is_finished_receiving(&self) -> bool;
}

impl<R: Round + 'static> TypeErasedRound<R::Result> for R {
    fn to_receiving_state(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
    ) -> (
        Box<dyn TypeErasedReceivingRound<R::Result>>,
        ToSendSerialized,
    ) {
        let mut boxed_rng = BoxedRng(Box::new(rng));
        let num_parties = self.num_parties();
        let party_idx = self.party_idx().as_usize();
        let (receiving_round, to_send) =
            RoundAndAccum::new(*self, &mut boxed_rng, num_parties, party_idx);
        let to_send = match to_send {
            ToSendTyped::Broadcast(message) => {
                let message = serialize_message(&message).unwrap();
                ToSendSerialized::Broadcast(message)
            }
            ToSendTyped::Direct(messages) => ToSendSerialized::Direct({
                let mut serialized = Vec::with_capacity(messages.len());
                for (idx, message) in messages.into_iter() {
                    serialized.push((idx, serialize_message(&message).unwrap()));
                }
                serialized
            }),
        };
        let receiving_round: Box<dyn TypeErasedReceivingRound<R::Result>> =
            Box::new(receiving_round);
        (receiving_round, to_send)
    }
}

impl<R: Round + 'static + Send> TypeErasedReceivingRound<R::Result> for RoundAndAccum<R> {
    fn round_num(&self) -> u8 {
        R::round_num()
    }
    fn next_round_num(&self) -> Option<u8> {
        R::next_round_num()
    }
    fn requires_broadcast_consensus(&self) -> bool {
        R::requires_broadcast_consensus()
    }
    fn receive(&mut self, from: PartyIdx, msg: &[u8]) -> ReceiveOutcome {
        let message: R::Message = match deserialize_message(msg) {
            Ok(message) => message,
            Err(err) => return ReceiveOutcome::DeserializationFail(format!("{}", err)),
        };
        self.receive_typed(from, message)
    }

    fn finalize(self: Box<Self>, rng: &mut dyn CryptoRngCore) -> FinalizeOutcome<R::Result> {
        let mut boxed_rng = BoxedRng(Box::new(rng));
        match self.finalize_typed(&mut boxed_rng) {
            FinalizeOutcomeTyped::Result(res) => FinalizeOutcome::Result(res),
            FinalizeOutcomeTyped::AnotherRound(round) => {
                FinalizeOutcome::AnotherRound(Box::new(round))
            }
            FinalizeOutcomeTyped::NotEnoughMessages => FinalizeOutcome::NotEnoughMessages,
            FinalizeOutcomeTyped::Error(err) => FinalizeOutcome::Error(err),
        }
    }

    fn is_finished_receiving(&self) -> bool {
        self.accum.can_finalize()
    }
}
