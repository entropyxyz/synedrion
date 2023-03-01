use serde::{Deserialize, Serialize};

use crate::protocols::generic::{
    ConsensusBroadcastRound, ConsensusRound, ConsensusWrapper, Round, SessionId, ToSendTyped,
};
use crate::tools::collections::{HoleVec, HoleVecAccum, PartyIdx};

/// Serialized messages without the stage number specified.
pub enum ToSendSerialized {
    Broadcast(Box<[u8]>),
    // TODO: return an iterator instead, since preparing one message can take some time
    Direct(Vec<(PartyIdx, Box<[u8]>)>),
}

/// Serialized messages with the stage number specified.
pub enum ToSend<Id> {
    Broadcast { ids: Vec<Id>, message: Box<[u8]> },
    // TODO: return an iterator instead, since preparing one message can take some time
    Direct(Vec<(Id, Box<[u8]>)>),
}

fn serialize_message(message: &impl Serialize) -> Box<[u8]> {
    rmp_serde::encode::to_vec(message)
        .unwrap()
        .into_boxed_slice()
}

fn deserialize_message<M: for<'de> Deserialize<'de>>(message_bytes: &[u8]) -> M {
    rmp_serde::decode::from_slice(message_bytes).unwrap()
}

fn serialize_with_round(round: u8, message: &[u8]) -> Box<[u8]> {
    rmp_serde::encode::to_vec(&(round, message))
        .unwrap()
        .into_boxed_slice()
}

fn deserialize_with_round(message_bytes: &[u8]) -> (u8, Box<[u8]>) {
    rmp_serde::decode::from_slice(message_bytes).unwrap()
}

#[derive(Clone)]
pub(crate) struct PreConsensusSubstage<R: ConsensusBroadcastRound>
where
    for<'de> <R as Round>::Message: Deserialize<'de>,
{
    round: ConsensusWrapper<R>,
    accum: Option<HoleVecAccum<<ConsensusWrapper<R> as Round>::Payload>>,
}

impl<R: ConsensusBroadcastRound> PreConsensusSubstage<R>
where
    for<'de> <R as Round>::Message: Deserialize<'de>,
{
    pub(crate) fn new(round: R) -> Self {
        Self {
            round: ConsensusWrapper(round),
            accum: None,
        }
    }

    pub(crate) fn get_messages(&mut self, num_parties: usize, index: PartyIdx) -> ToSendSerialized {
        if self.accum.is_some() {
            panic!();
        }

        let to_send = get_messages(&self.round);
        let accum =
            HoleVecAccum::<<ConsensusWrapper<R> as Round>::Payload>::new(num_parties, index);
        self.accum = Some(accum);
        to_send
    }

    pub(crate) fn receive(&mut self, from: PartyIdx, message_bytes: &[u8]) {
        match self.accum.as_mut() {
            Some(accum) => receive(&self.round, accum, from, message_bytes),
            None => panic!(),
        }
    }

    pub(crate) fn is_finished_receiving(&self) -> bool {
        match &self.accum {
            Some(accum) => accum.can_finalize(),
            None => panic!(),
        }
    }

    pub(crate) fn finalize(self) -> <ConsensusWrapper<R> as Round>::NextRound {
        // TODO: make it so that finalize() result could be immediately passed
        // to the new() of the next round withour restructuring
        finalize(self.round, self.accum.unwrap())
    }
}

#[derive(Clone)]
pub(crate) struct ConsensusSubstage<R: ConsensusBroadcastRound>
where
    R::Message: PartialEq,
    for<'de> <R as Round>::Message: Deserialize<'de>,
{
    round: ConsensusRound<R>,
    next_round: R::NextRound,
    accum: Option<HoleVecAccum<<ConsensusRound<R> as Round>::Payload>>,
}

impl<R: ConsensusBroadcastRound> ConsensusSubstage<R>
where
    R::Message: PartialEq,
    for<'de> <R as Round>::Message: Deserialize<'de>,
{
    pub(crate) fn new(next_round: R::NextRound, broadcasts: HoleVec<R::Message>) -> Self {
        Self {
            next_round,
            round: ConsensusRound { broadcasts },
            accum: None,
        }
    }

    pub(crate) fn get_messages(&mut self, num_parties: usize, index: PartyIdx) -> ToSendSerialized {
        if self.accum.is_some() {
            panic!();
        }

        let to_send = get_messages(&self.round);
        let accum = HoleVecAccum::<<ConsensusRound<R> as Round>::Payload>::new(num_parties, index);
        self.accum = Some(accum);
        to_send
    }

    pub(crate) fn receive(&mut self, from: PartyIdx, message_bytes: &[u8]) {
        match self.accum.as_mut() {
            Some(accum) => receive(&self.round, accum, from, message_bytes),
            None => panic!(),
        }
    }

    pub(crate) fn is_finished_receiving(&self) -> bool {
        match &self.accum {
            Some(accum) => accum.can_finalize(),
            None => panic!(),
        }
    }

    pub(crate) fn finalize(self) -> R::NextRound {
        finalize(self.round, self.accum.unwrap());
        self.next_round
    }
}

#[derive(Clone)]
pub(crate) struct NormalSubstage<R: Round>
where
    for<'de> <R as Round>::Message: Deserialize<'de>,
{
    round: R,
    accum: Option<HoleVecAccum<R::Payload>>,
}

impl<R: Round> NormalSubstage<R>
where
    for<'de> <R as Round>::Message: Deserialize<'de>,
{
    pub(crate) fn new(round: R) -> Self {
        Self { round, accum: None }
    }

    pub(crate) fn get_messages(&mut self, num_parties: usize, index: PartyIdx) -> ToSendSerialized {
        if self.accum.is_some() {
            panic!();
        }

        let to_send = get_messages(&self.round);
        let accum = HoleVecAccum::<R::Payload>::new(num_parties, index);
        self.accum = Some(accum);
        to_send
    }

    pub(crate) fn receive(&mut self, from: PartyIdx, message_bytes: &[u8]) {
        match self.accum.as_mut() {
            Some(accum) => receive(&self.round, accum, from, message_bytes),
            None => panic!(),
        }
    }

    pub(crate) fn is_finished_receiving(&self) -> bool {
        match &self.accum {
            Some(accum) => accum.can_finalize(),
            None => panic!(),
        }
    }

    pub(crate) fn finalize(self) -> R::NextRound {
        finalize(self.round, self.accum.unwrap())
    }
}

fn get_messages<R: Round>(round: &R) -> ToSendSerialized
where
    R::Message: Serialize,
{
    match round.to_send() {
        ToSendTyped::Broadcast(message) => {
            let message = serialize_message(&message);
            ToSendSerialized::Broadcast(message)
        }
        ToSendTyped::Direct(messages) => ToSendSerialized::Direct(
            messages
                .into_iter()
                .map(|(idx, message)| (idx, serialize_message(&message)))
                .collect(),
        ),
    }
}

fn receive<R: Round>(
    round: &R,
    accum: &mut HoleVecAccum<R::Payload>,
    from: PartyIdx,
    message_bytes: &[u8],
) where
    for<'de> R::Message: Deserialize<'de>,
{
    let message: R::Message = deserialize_message(message_bytes);

    let slot = match accum.get_mut(from) {
        Some(slot) => slot,
        None => panic!("Invalid ID"),
    };

    if slot.is_some() {
        panic!("Already received from this ID");
    }

    let payload = match round.verify_received(from, message) {
        Ok(res) => res,
        Err(_) => panic!("Error validating message"),
    };

    *slot = Some(payload);
}

fn finalize<R: Round>(round: R, accum: HoleVecAccum<R::Payload>) -> R::NextRound {
    if accum.can_finalize() {
        match accum.finalize() {
            Ok(finalized) => round.finalize(finalized),
            Err(_) => panic!("Could not finalize"),
        }
    } else {
        panic!();
    }
}

// TODO: may be able to get rid of the clone requirement - perhaps with `take_mut`.
pub trait SessionState: Clone {
    type Context;
    fn new(session_id: &SessionId, context: &Self::Context, index: PartyIdx) -> Self;
    fn get_messages(&mut self, num_parties: usize, index: PartyIdx) -> ToSendSerialized;
    fn receive_current_stage(&mut self, from: PartyIdx, message_bytes: &[u8]);
    fn is_finished_receiving(&self) -> bool;
    fn finalize_stage(self) -> Self;
    fn is_final_stage(&self) -> bool;
    fn current_stage_num(&self) -> u8;
    fn stages_num(&self) -> u8;
    fn result(&self) -> Self::Result;
    type Result;
}

pub trait PartyId: Clone + PartialEq {}

pub struct Session<S: SessionState, I: PartyId> {
    index: PartyIdx,
    my_id: I,
    all_parties: Vec<I>,
    next_stage_messages: Vec<(PartyIdx, Box<[u8]>)>,
    state: S,
}

impl<S: SessionState, I: PartyId> Session<S, I> {
    pub fn new(
        session_id: &SessionId,
        all_parties: &[I],
        party_id: &I,
        context: &S::Context,
    ) -> Self {
        let index = all_parties.iter().position(|id| id == party_id).unwrap();
        let index = PartyIdx::from_usize(index);

        // CHECK: in the paper session id includes all the party ID's;
        // but since it's going to contain a random component too
        // (to distinguish sessions on the same node sets),
        // it might as well be completely random, right?

        let state = S::new(session_id, context, index);
        Self {
            index,
            my_id: party_id.clone(),
            all_parties: all_parties.to_vec(),
            next_stage_messages: Vec::new(),
            state,
        }
    }

    pub fn get_messages(&mut self) -> ToSend<I> {
        let to_send = self.state.get_messages(self.all_parties.len(), self.index);
        let stage_num = self.state.current_stage_num();
        match to_send {
            ToSendSerialized::Broadcast(message) => {
                let ids = self
                    .all_parties
                    .iter()
                    .cloned()
                    .filter(|id| id != &self.my_id)
                    .collect();
                let message = serialize_with_round(stage_num, &message);
                ToSend::Broadcast { ids, message }
            }
            ToSendSerialized::Direct(messages) => ToSend::Direct(
                messages
                    .into_iter()
                    .map(|(index, message)| {
                        let id = self.all_parties[index.as_usize()].clone();
                        let message = serialize_with_round(stage_num, &message);
                        (id, message)
                    })
                    .collect(),
            ),
        }
    }

    pub fn receive(&mut self, from: &I, message_bytes: &[u8]) {
        let stage_num = self.state.current_stage_num();
        let max_stages = self.state.stages_num();
        let (stage, message_bytes) = deserialize_with_round(message_bytes);
        let index = self.all_parties.iter().position(|id| id == from).unwrap();
        let index = PartyIdx::from_usize(index);

        if stage == stage_num + 1 && stage <= max_stages {
            self.next_stage_messages.push((index, message_bytes));
        } else if stage == stage_num {
            self.state.receive_current_stage(index, &message_bytes);
        } else {
            panic!("Unexpected message from round {stage} (current stage: {stage_num})");
        }
    }

    pub fn receive_cached_message(&mut self) {
        let (from, message_bytes) = self.next_stage_messages.pop().unwrap();
        self.state.receive_current_stage(from, &message_bytes);
    }

    pub fn is_finished_receiving(&self) -> bool {
        self.state.is_finished_receiving()
    }

    pub fn finalize_stage(&mut self) {
        // TODO: check that there are no cached messages left
        self.state = self.state.clone().finalize_stage();
    }

    pub fn result(&self) -> S::Result {
        self.state.result()
    }

    pub fn is_final_stage(&self) -> bool {
        self.state.is_final_stage()
    }

    pub fn current_stage_num(&self) -> u8 {
        self.state.current_stage_num()
    }

    pub fn stages_num(&self) -> u8 {
        self.state.stages_num()
    }

    pub fn has_cached_messages(&self) -> bool {
        !self.next_stage_messages.is_empty()
    }
}
