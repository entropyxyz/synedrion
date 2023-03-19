use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::tools::collections::{HoleVec, PartyIdx};
use crate::tools::hashing::{Chain, Hashable};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionId([u8; 32]);

impl SessionId {
    pub fn random() -> Self {
        use rand_core::{OsRng, RngCore};
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl Hashable for SessionId {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain_constant_sized_bytes(&self.0)
    }
}

pub(crate) enum ToSendTyped<Message> {
    Broadcast(Message),
    // TODO: return an iterator instead, since preparing one message can take some time
    Direct(Vec<(PartyIdx, Message)>),
}

pub(crate) trait Round: Sized {
    type Error: Sized;
    type Message: Sized + Clone + Serialize;
    type Payload: Sized + Clone;
    type NextRound: Sized;

    fn to_send(&self) -> ToSendTyped<Self::Message>;
    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error>;
    fn finalize(self, payloads: HoleVec<Self::Payload>) -> Self::NextRound;
}

// TODO: find a way to move `get_messages()` in this trait.
// For now it will just stay a marker trait.
pub(crate) trait BroadcastRound: Round {}

pub(crate) trait DirectRound: Round {}

pub(crate) trait NeedsConsensus: BroadcastRound {}

#[derive(Clone)]
pub(crate) struct PreConsensusSubround<R: NeedsConsensus>(pub(crate) R);

impl<R: NeedsConsensus> PreConsensusSubround<R> {}

impl<R: NeedsConsensus> Round for PreConsensusSubround<R>
where
    R::NextRound: Round,
{
    type Error = R::Error;
    type Message = R::Message;
    type Payload = (R::Payload, R::Message);
    type NextRound = ConsensusSubround<R>;

    fn to_send(&self) -> ToSendTyped<Self::Message> {
        self.0.to_send()
    }
    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        self.0
            .verify_received(from, msg.clone())
            .map(|payload| (payload, msg))
    }
    fn finalize(self, payloads: HoleVec<Self::Payload>) -> Self::NextRound {
        let (payloads, messages) = payloads.unzip();
        let next_round = self.0.finalize(payloads);
        ConsensusSubround {
            next_round,
            broadcasts: messages,
        }
    }
}

impl<R: NeedsConsensus> BroadcastRound for PreConsensusSubround<R> where R::NextRound: Round {}

#[derive(Clone)]
pub(crate) struct ConsensusSubround<R: Round> {
    next_round: R::NextRound,
    pub(crate) broadcasts: HoleVec<R::Message>,
}

impl<R: NeedsConsensus> Round for ConsensusSubround<R>
where
    <R as Round>::Message: PartialEq,
{
    type Error = String;
    type Message = HoleVec<R::Message>;
    type Payload = ();
    type NextRound = R::NextRound;

    fn to_send(&self) -> ToSendTyped<Self::Message> {
        ToSendTyped::Broadcast(self.broadcasts.clone())
    }
    fn verify_received(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error> {
        // CHECK: should we save our own broadcast,
        // and check that the other nodes received it?
        // Or is this excessive since they are signed by us anyway?
        if msg.len() != self.broadcasts.len() {
            return Err("Unexpected number of broadcasts received".into());
        }
        for (idx, broadcast) in msg.range().zip(msg.iter()) {
            if !self
                .broadcasts
                .get(idx)
                .map(|bc| bc == broadcast)
                .unwrap_or(true)
            {
                // TODO: specify which node the conflicting broadcast was from
                return Err("Received conflicting broadcasts".into());
            }
        }
        Ok(())
    }
    fn finalize(self, _payloads: HoleVec<Self::Payload>) -> Self::NextRound {
        self.next_round
    }
}

impl<R: NeedsConsensus> BroadcastRound for ConsensusSubround<R> where
    <R as Round>::Message: PartialEq
{
}

#[cfg(test)]
pub(crate) mod tests {

    use super::*;
    use crate::tools::collections::{HoleRange, HoleVecAccum};

    #[derive(Debug)]
    pub(crate) enum StepError<Error> {
        Finalize,
        InvalidIndex,
        RepeatingMessage,
        Receive(Error),
    }

    pub(crate) fn step<R: Round>(init: Vec<R>) -> Result<Vec<R::NextRound>, StepError<R::Error>> {
        // Collect outgoing messages

        let mut accums = (0..init.len())
            .map(|idx| HoleVecAccum::<R::Payload>::new(init.len(), PartyIdx::from_usize(idx)))
            .collect::<Vec<_>>();
        // `to, from, message`
        let mut all_messages = Vec::<(PartyIdx, PartyIdx, R::Message)>::new();

        for (idx_from, round) in init.iter().enumerate() {
            let to_send = round.to_send();
            let idx_from = PartyIdx::from_usize(idx_from);

            match to_send {
                ToSendTyped::Broadcast(message) => {
                    for idx_to in HoleRange::new(init.len(), idx_from) {
                        all_messages.push((idx_to, idx_from, message.clone()));
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
            let slot = accum.get_mut(idx_from).ok_or(StepError::InvalidIndex)?;
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

        let mut result = Vec::<R::NextRound>::new();

        for (round, accum) in init.into_iter().zip(accums.into_iter()) {
            let accum_final = accum.finalize().map_err(|_| StepError::Finalize)?;
            let next_state = round.finalize(accum_final);
            result.push(next_state);
        }

        Ok(result)
    }
}
