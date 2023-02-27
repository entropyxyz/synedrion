use alloc::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::protocols::generic::{
    ConsensusBroadcastRound, ConsensusRound, ConsensusWrapper, OnFinalize, OnReceive, Round,
    ToSendTyped,
};
use crate::protocols::keygen::PartyId;
use crate::tools::collections::HoleMap;

/// Serialized messages without the stage number specified.
pub enum ToSendSerialized<Id> {
    Broadcast { ids: Vec<Id>, message: Box<[u8]> },
    // TODO: return an iterator instead, since preparing one message can take some time
    Direct(Vec<(Id, Box<[u8]>)>),
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
pub(crate) struct PreConsensusSubstage<R: ConsensusBroadcastRound<Id = PartyId>>
where
    for<'de> <R as Round>::Message: Deserialize<'de>,
{
    round: ConsensusWrapper<R>,
    accum: Option<HoleMap<R::Id, <ConsensusWrapper<R> as Round>::Payload>>,
}

impl<R: ConsensusBroadcastRound<Id = PartyId>> PreConsensusSubstage<R>
where
    for<'de> <R as Round>::Message: Deserialize<'de>,
{
    pub(crate) fn new(round: R) -> Self {
        Self {
            round: ConsensusWrapper(round),
            accum: None,
        }
    }

    pub(crate) fn get_messages(&mut self) -> ToSendSerialized<R::Id> {
        if self.accum.is_some() {
            panic!();
        }

        let (accum, to_send) = get_messages(&self.round);
        self.accum = Some(accum);
        to_send
    }

    pub(crate) fn receive(&mut self, from: R::Id, message_bytes: &[u8]) {
        match self.accum.as_mut() {
            Some(accum) => receive(&self.round, accum, &from, message_bytes),
            None => panic!(),
        }
    }

    pub(crate) fn is_finished_receiving(&self) -> bool {
        match &self.accum {
            Some(accum) => ConsensusWrapper::<R>::can_finalize(accum),
            None => panic!(),
        }
    }

    pub(crate) fn finalize(self) -> (R::Id, <ConsensusWrapper<R> as Round>::NextRound) {
        // TODO: make it so that finalize() result could be immediately passed
        // to the new() of the next round withour restructuring
        (self.round.id(), finalize(self.round, self.accum.unwrap()))
    }
}

#[derive(Clone)]
pub(crate) struct ConsensusSubstage<R: ConsensusBroadcastRound<Id = PartyId>>
where
    R::Message: PartialEq,
    for<'de> <R as Round>::Message: Deserialize<'de>,
{
    round: ConsensusRound<R>,
    next_round: R::NextRound,
    accum: Option<HoleMap<R::Id, <ConsensusRound<R> as Round>::Payload>>,
}

impl<R: ConsensusBroadcastRound<Id = PartyId>> ConsensusSubstage<R>
where
    R::Message: PartialEq,
    for<'de> <R as Round>::Message: Deserialize<'de>,
{
    pub(crate) fn new(
        id: R::Id,
        next_round: R::NextRound,
        broadcasts: BTreeMap<R::Id, R::Message>,
    ) -> Self {
        Self {
            next_round,
            round: ConsensusRound { broadcasts, id },
            accum: None,
        }
    }

    pub(crate) fn get_messages(&mut self) -> ToSendSerialized<R::Id> {
        if self.accum.is_some() {
            panic!();
        }

        let (accum, to_send) = get_messages(&self.round);
        self.accum = Some(accum);
        to_send
    }

    pub(crate) fn receive(&mut self, from: R::Id, message_bytes: &[u8]) {
        match self.accum.as_mut() {
            Some(accum) => receive(&self.round, accum, &from, message_bytes),
            None => panic!(),
        }
    }

    pub(crate) fn is_finished_receiving(&self) -> bool {
        match &self.accum {
            Some(accum) => ConsensusRound::<R>::can_finalize(accum),
            None => panic!(),
        }
    }

    pub(crate) fn finalize(self) -> R::NextRound {
        finalize(self.round, self.accum.unwrap());
        self.next_round
    }
}

#[derive(Clone)]
pub(crate) struct NormalSubstage<R: Round<Id = PartyId>>
where
    for<'de> <R as Round>::Message: Deserialize<'de>,
{
    round: R,
    accum: Option<HoleMap<R::Id, R::Payload>>,
}

impl<R: Round<Id = PartyId>> NormalSubstage<R>
where
    for<'de> <R as Round>::Message: Deserialize<'de>,
{
    pub(crate) fn new(round: R) -> Self {
        Self { round, accum: None }
    }

    pub(crate) fn get_messages(&mut self) -> ToSendSerialized<R::Id> {
        if self.accum.is_some() {
            panic!();
        }

        let (accum, to_send) = get_messages(&self.round);
        self.accum = Some(accum);
        to_send
    }

    pub(crate) fn receive(&mut self, from: R::Id, message_bytes: &[u8]) {
        match self.accum.as_mut() {
            Some(accum) => receive(&self.round, accum, &from, message_bytes),
            None => panic!(),
        }
    }

    pub(crate) fn is_finished_receiving(&self) -> bool {
        match &self.accum {
            Some(accum) => R::can_finalize(accum),
            None => panic!(),
        }
    }

    pub(crate) fn finalize(self) -> R::NextRound {
        finalize(self.round, self.accum.unwrap())
    }
}

fn get_messages<R: Round<Id = PartyId>>(
    round: &R,
) -> (HoleMap<R::Id, R::Payload>, ToSendSerialized<R::Id>)
where
    R::Message: Serialize,
{
    let (accum, to_send) = round.get_messages();
    let to_send = match to_send {
        ToSendTyped::Broadcast { message, ids, .. } => {
            let message = serialize_message(&message);
            ToSendSerialized::Broadcast { message, ids }
        }
        ToSendTyped::Direct(msgs) => ToSendSerialized::Direct(
            msgs.into_iter()
                .map(|(id, message)| (id, serialize_message(&message)))
                .collect(),
        ),
    };
    (accum, to_send)
}

fn receive<R: Round<Id = PartyId>>(
    round: &R,
    accum: &mut HoleMap<R::Id, R::Payload>,
    from: &R::Id,
    message_bytes: &[u8],
) where
    for<'de> R::Message: Deserialize<'de>,
{
    let message: R::Message = deserialize_message(message_bytes);
    match round.receive(accum, from, message) {
        OnReceive::Ok => {}
        OnReceive::InvalidId => panic!("Invalid ID"),
        OnReceive::AlreadyReceived => panic!("Already received from this ID"),
        OnReceive::Fatal(_err) => panic!("Error validating message"),
    };
}

fn finalize<R: Round<Id = PartyId>>(round: R, accum: HoleMap<R::Id, R::Payload>) -> R::NextRound {
    if R::can_finalize(&accum) {
        match round.try_finalize(accum) {
            OnFinalize::NotFinished(_) => panic!("Could not finalize"),
            OnFinalize::Finished(next_round) => next_round,
        }
    } else {
        panic!();
    }
}

// TODO: may be able to get rid of the clone requirement - perhaps with `take_mut`.
pub trait SessionState: Clone {
    fn get_messages(&mut self) -> ToSendSerialized<PartyId>;
    fn receive_current_stage(&mut self, from: PartyId, message_bytes: &[u8]);
    fn is_finished_receiving(&self) -> bool;
    fn finalize_stage(self) -> Self;
    fn is_final_stage(&self) -> bool;
    fn current_stage_num(&self) -> u8;
    fn stages_num(&self) -> u8;
    fn result(&self) -> Self::Result;
    type Result;
}

pub struct Session<S: SessionState> {
    next_stage_messages: Vec<(PartyId, Box<[u8]>)>,
    state: S,
}

impl<S: SessionState> Session<S> {
    pub fn new(state: S) -> Self {
        Self {
            next_stage_messages: Vec::new(),
            state,
        }
    }

    pub fn get_messages(&mut self) -> ToSend<PartyId> {
        let to_send = self.state.get_messages();
        let stage_num = self.state.current_stage_num();
        match to_send {
            ToSendSerialized::Broadcast { ids, message } => ToSend::Broadcast {
                ids,
                message: serialize_with_round(stage_num, &message),
            },
            ToSendSerialized::Direct(messages) => ToSend::Direct(
                messages
                    .into_iter()
                    .map(|(id, message)| (id, serialize_with_round(stage_num, &message)))
                    .collect(),
            ),
        }
    }

    pub fn receive(&mut self, from: PartyId, message_bytes: &[u8]) {
        let stage_num = self.state.current_stage_num();
        let max_stages = self.state.stages_num();
        let (stage, message_bytes) = deserialize_with_round(message_bytes);

        if stage == stage_num + 1 && stage <= max_stages {
            self.next_stage_messages.push((from, message_bytes));
        } else if stage == stage_num {
            self.state.receive_current_stage(from, &message_bytes);
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
