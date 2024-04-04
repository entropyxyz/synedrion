use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::signed_message::{SignedMessage, VerifiedMessage};
use super::type_erased::{deserialize_message, serialize_message};
use crate::rounds::PartyIdx;
use crate::tools::collections::HoleVecAccum;

#[derive(Clone)]
pub(crate) struct BroadcastConsensus<Sig> {
    broadcasts: Vec<(PartyIdx, VerifiedMessage<Sig>)>,
}

#[derive(Serialize, Deserialize)]
struct Message<Sig> {
    broadcasts: Vec<(PartyIdx, SignedMessage<Sig>)>,
}

/// Errors that can occur during broadcast consensus check.
#[derive(Debug, Clone)]
pub enum ConsensusError {
    /// Cannot deserialize the message.
    CannotDeserialize(String),
    /// Unexpected number of broadcasts in the message.
    UnexpectedNumberOfBroadcasts,
    /// A broadcast from one of the parties is missing.
    MissingBroadcast,
    /// The broadcasts received during the consensus round
    /// do not match the ones received previously.
    ConflictingBroadcasts,
}

impl<Sig> BroadcastConsensus<Sig>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
{
    pub fn new(broadcasts: Vec<(PartyIdx, VerifiedMessage<Sig>)>) -> Self {
        Self { broadcasts }
    }

    pub fn make_broadcast(&self) -> Box<[u8]> {
        let message = Message {
            broadcasts: self
                .broadcasts
                .iter()
                .cloned()
                .map(|(idx, msg)| (idx, msg.into_unverified()))
                .collect(),
        };
        serialize_message(&message).unwrap()
    }

    pub fn verify_broadcast(
        &self,
        from: PartyIdx,
        verified_message: VerifiedMessage<Sig>,
    ) -> Result<(), ConsensusError> {
        let message: Message<Sig> = deserialize_message(verified_message.payload())
            .map_err(|err| ConsensusError::CannotDeserialize(err.to_string()))?;

        // TODO (#68): check that there are no repeating indices, and the indices are in range.
        let bc_map = message.broadcasts.into_iter().collect::<BTreeMap<_, _>>();

        if bc_map.len() != self.broadcasts.len() {
            return Err(ConsensusError::UnexpectedNumberOfBroadcasts);
        }

        for (idx, broadcast) in self.broadcasts.iter() {
            // The party `from` won't send us its own broadcast the second time.
            // It gives no additional assurance.
            if idx == &from {
                continue;
            }

            let echoed_bc = bc_map.get(idx).ok_or(ConsensusError::MissingBroadcast)?;

            if !broadcast.as_unverified().is_same_as(echoed_bc) {
                return Err(ConsensusError::ConflictingBroadcasts);
            }
        }

        Ok(())
    }
}

pub(crate) struct BcConsensusAccum {
    received_echo_from: HoleVecAccum<()>,
}

impl BcConsensusAccum {
    pub fn new(num_parties: usize, party_idx: PartyIdx) -> Self {
        Self {
            received_echo_from: HoleVecAccum::new(num_parties, party_idx.as_usize()),
        }
    }

    pub fn missing_messages(&self) -> Vec<PartyIdx> {
        self.received_echo_from
            .missing()
            .into_iter()
            .map(PartyIdx::from_usize)
            .collect()
    }

    pub fn contains(&self, party_idx: PartyIdx) -> bool {
        self.received_echo_from
            .contains(party_idx.as_usize())
            .unwrap()
    }

    pub fn add_echo_received(&mut self, from: PartyIdx) -> Option<()> {
        self.received_echo_from.insert(from.as_usize(), ())
    }

    pub fn can_finalize(&self) -> bool {
        self.received_echo_from.can_finalize()
    }

    pub fn finalize(self) -> Option<()> {
        if self.can_finalize() {
            Some(())
        } else {
            None
        }
    }
}
