use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::signed_message::{SignedMessage, VerifiedMessage};
use super::type_erased::{deserialize_message, serialize_message};
use crate::cggmp21::PartyIdx;
use crate::tools::collections::HoleVecAccum;

#[derive(Clone)]
pub(crate) struct BroadcastConsensus<Sig> {
    broadcasts: Vec<(PartyIdx, VerifiedMessage<Sig>)>,
}

#[derive(Serialize, Deserialize)]
struct Message<Sig> {
    broadcasts: Vec<(PartyIdx, SignedMessage<Sig>)>,
}

/// Errors that can occur during broadcast consesnsus check.
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
        // TODO: don't have to clone `verifiers` here, can just keep a ref.
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
        // TODO: check that `from` is valid here?
        let message: Message<Sig> = deserialize_message(verified_message.payload())
            .map_err(|err| ConsensusError::CannotDeserialize(err.to_string()))?;

        // TODO: check that there are no repeating indices?
        let bc_map = message.broadcasts.into_iter().collect::<BTreeMap<_, _>>();

        if bc_map.len() != self.broadcasts.len() {
            return Err(ConsensusError::UnexpectedNumberOfBroadcasts);
        }

        // CHECK: should we save our own broadcast,
        // and check that the other nodes received it?
        // Or is this excessive since they are signed by us anyway?

        for (idx, broadcast) in self.broadcasts.iter() {
            // CHECK: the party `from` won't send us its own broadcast the second time.
            // It gives no additional assurance.
            if idx == &from {
                continue;
            }

            let echoed_bc = bc_map.get(idx).ok_or(ConsensusError::MissingBroadcast)?;

            if broadcast.as_unverified() != echoed_bc {
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
