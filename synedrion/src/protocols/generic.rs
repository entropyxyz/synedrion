use alloc::vec::Vec;

use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use super::common::PartyIdx;
use crate::sessions::TheirFault;
use crate::tools::collections::HoleVec;
use crate::tools::hashing::{Chain, Hash, HashOutput, Hashable};

pub(crate) enum ToSendTyped<Message> {
    Broadcast(Message),
    // TODO: return an iterator instead, since preparing one message can take some time
    Direct(Vec<(PartyIdx, Message)>),
}

pub(crate) trait Round: Sized {
    type Message: Sized + Clone + Serialize + for<'de> Deserialize<'de>;
    type Payload: Sized + Clone;
    type NextRound: Sized;
    type ErrorRound: Sized;

    fn to_send(&self, rng: &mut (impl RngCore + CryptoRng)) -> ToSendTyped<Self::Message>;
    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, TheirFault>;
    fn finalize(
        self,
        rng: &mut (impl RngCore + CryptoRng),
        payloads: HoleVec<Self::Payload>,
    ) -> Result<Self::NextRound, Self::ErrorRound>;
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
    R::Message: Hashable,
{
    type Message = R::Message;
    type Payload = (R::Payload, R::Message);
    type NextRound = ConsensusSubround<R>;
    type ErrorRound = ();

    fn to_send(&self, rng: &mut (impl RngCore + CryptoRng)) -> ToSendTyped<Self::Message> {
        self.0.to_send(rng)
    }
    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, TheirFault> {
        self.0
            // TODO: save a hash here right away to avoid cloning
            .verify_received(from, msg.clone())
            .map(|payload| (payload, msg))
    }
    fn finalize(
        self,
        rng: &mut (impl RngCore + CryptoRng),
        payloads: HoleVec<Self::Payload>,
    ) -> Result<Self::NextRound, Self::ErrorRound> {
        let (payloads, messages) = payloads.unzip();
        let next_round = self.0.finalize(rng, payloads).or(Err(()))?;
        let broadcast_hashes = messages.map(|msg| {
            Hash::new_with_dst(b"BroadcastConsensus")
                .chain(&msg)
                .finalize()
        });
        Ok(ConsensusSubround {
            next_round,
            broadcast_hashes,
        })
    }
}

impl<R: NeedsConsensus> BroadcastRound for PreConsensusSubround<R> where
    PreConsensusSubround<R>: Round
{
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct BroadcastHashes(HoleVec<HashOutput>);

#[derive(Clone)]
pub(crate) struct ConsensusSubround<R: Round> {
    next_round: R::NextRound,
    broadcast_hashes: HoleVec<HashOutput>,
}

impl<R: NeedsConsensus> Round for ConsensusSubround<R> {
    type Message = BroadcastHashes;
    type Payload = ();
    type NextRound = R::NextRound;
    type ErrorRound = ();

    fn to_send(&self, _rng: &mut (impl RngCore + CryptoRng)) -> ToSendTyped<Self::Message> {
        ToSendTyped::Broadcast(BroadcastHashes(self.broadcast_hashes.clone()))
    }
    fn verify_received(
        &self,
        _from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, TheirFault> {
        // CHECK: should we save our own broadcast,
        // and check that the other nodes received it?
        // Or is this excessive since they are signed by us anyway?
        if msg.0.len() != self.broadcast_hashes.len() {
            return Err(TheirFault::VerificationFail(
                "Unexpected number of broadcasts received".into(),
            ));
        }
        for (idx, broadcast) in msg.0.range().zip(msg.0.iter()) {
            if !self
                .broadcast_hashes
                .get(idx)
                .map(|bc| bc == broadcast)
                .unwrap_or(true)
            {
                // TODO: specify which node the conflicting broadcast was from
                return Err(TheirFault::VerificationFail(
                    "Received conflicting broadcasts".into(),
                ));
            }
        }
        Ok(())
    }
    fn finalize(
        self,
        _rng: &mut (impl RngCore + CryptoRng),
        _payloads: HoleVec<Self::Payload>,
    ) -> Result<Self::NextRound, Self::ErrorRound> {
        Ok(self.next_round)
    }
}

impl<R: NeedsConsensus> BroadcastRound for ConsensusSubround<R> where ConsensusSubround<R>: Round {}

#[cfg(test)]
pub(crate) mod tests {

    use super::*; // TODO: remove glob import
    use crate::sessions::TheirFault;
    use crate::tools::collections::{HoleRange, HoleVecAccum};

    #[derive(Debug)]
    pub(crate) enum StepError {
        AccumFinalize,
        InvalidIndex,
        RepeatingMessage,
        Receive(TheirFault),
        Finalize,
    }

    pub(crate) fn step<R: Round>(
        rng: &mut (impl RngCore + CryptoRng),
        init: Vec<R>,
    ) -> Result<Vec<R::NextRound>, StepError> {
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

        let mut result = Vec::<R::NextRound>::new();

        for (round, accum) in init.into_iter().zip(accums.into_iter()) {
            let accum_final = accum.finalize().map_err(|_| StepError::AccumFinalize)?;
            let next_state = round
                .finalize(rng, accum_final)
                .map_err(|_err| StepError::Finalize)?;
            result.push(next_state);
        }

        Ok(result)
    }
}
