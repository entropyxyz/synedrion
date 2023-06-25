use serde::{Deserialize, Serialize};

use super::error::TheirFault;
use super::generic::ToSendSerialized;
use super::signed_message::{serialize_message, SignedMessage, VerifiedMessage};
use crate::tools::collections::{HoleVec, HoleVecAccum};

pub(crate) struct BroadcastConsensus<Sig: Clone> {
    broadcasts: HoleVec<SignedMessage<Sig>>,
    accum: Option<HoleVecAccum<SignedMessage<Sig>>>,
}

#[derive(Serialize, Deserialize)]
struct Message<Sig> {
    broadcasts: HoleVec<SignedMessage<Sig>>,
}

impl<Sig: Clone + Serialize> BroadcastConsensus<Sig> {
    pub(crate) fn new(broadcasts: HoleVec<SignedMessage<Sig>>) -> Self {
        Self {
            broadcasts,
            accum: None,
        }
    }

    pub(crate) fn to_send(&self) -> ToSendSerialized {
        let message = Message { broadcasts: self.broadcasts.clone() };
        ToSendSerialized::Broadcast(serialize_message(&message).unwrap())
    }

    pub(crate) fn receive(&mut self, verified_message: VerifiedMessage) -> Result<(), TheirFault> {

    }
}

/*

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

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
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
        rng: &mut impl CryptoRngCore,
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

    fn to_send(&self, _rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
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
        _rng: &mut impl CryptoRngCore,
        _payloads: HoleVec<Self::Payload>,
    ) -> Result<Self::NextRound, Self::ErrorRound> {
        Ok(self.next_round)
    }
}

impl<R: NeedsConsensus> BroadcastRound for ConsensusSubround<R> where ConsensusSubround<R>: Round {}
*/
