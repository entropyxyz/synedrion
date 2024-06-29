use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::error::LocalError;
use super::signed_message::{Message, SignedMessage};

#[derive(Clone)]
pub(crate) struct EchoRound<I> {
    destinations: BTreeSet<I>,
    broadcasts: BTreeMap<I, SignedMessage>,
}

#[derive(Serialize, Deserialize)]
struct EchoMessage<I> {
    broadcasts: Vec<(I, SignedMessage)>,
}

/// Errors that can occur during an echo round.
#[derive(Debug, Clone)]
pub enum EchoError {
    /// Cannot deserialize the message.
    CannotDeserialize(String),
    /// Unexpected number of broadcasts in the message.
    UnexpectedNumberOfBroadcasts,
    /// A broadcast from one of the parties is missing.
    MissingBroadcast,
    /// The broadcasts received during the echo round
    /// do not match the ones received previously.
    ConflictingBroadcasts,
}

impl<I> EchoRound<I>
where
    I: Clone + Ord + PartialEq + Serialize + for<'de> Deserialize<'de>,
{
    pub fn new(broadcasts: BTreeMap<I, SignedMessage>) -> Self {
        let destinations = broadcasts.keys().cloned().collect();
        Self {
            broadcasts,
            destinations,
        }
    }

    pub fn message_destinations(&self) -> &BTreeSet<I> {
        &self.destinations
    }

    pub fn expecting_messages_from(&self) -> &BTreeSet<I> {
        &self.destinations
    }

    pub fn make_broadcast(&self) -> Message {
        let message = EchoMessage {
            broadcasts: self.broadcasts.clone().into_iter().collect(),
        };
        Message::new(&message).unwrap()
    }

    pub fn verify_broadcast(&self, from: &I, message: &Message) -> Result<(), EchoError> {
        // TODO (#68): check that the direct message is empty?
        let message = message
            .to_typed::<EchoMessage<I>>()
            .map_err(|err| EchoError::CannotDeserialize(err.to_string()))?;

        // TODO (#68): check that there are no repeating indices, and the indices are in range.
        let bc_map = message.broadcasts.into_iter().collect::<BTreeMap<_, _>>();

        if bc_map.len() != self.broadcasts.len() {
            return Err(EchoError::UnexpectedNumberOfBroadcasts);
        }

        for (id, broadcast) in self.broadcasts.iter() {
            // The party `from` won't send us its own broadcast the second time.
            // It gives no additional assurance.
            if id == from {
                continue;
            }

            let echoed_bc = bc_map.get(id).ok_or(EchoError::MissingBroadcast)?;

            if broadcast != echoed_bc {
                return Err(EchoError::ConflictingBroadcasts);
            }
        }

        Ok(())
    }

    pub fn missing_messages(&self, accum: &EchoAccum<I>) -> BTreeSet<I> {
        self.expecting_messages_from()
            .difference(&accum.received_messages)
            .cloned()
            .collect()
    }

    pub fn can_finalize(&self, accum: &EchoAccum<I>) -> bool {
        &accum.received_messages == self.expecting_messages_from()
    }

    pub fn finalize(self, accum: EchoAccum<I>) -> Result<(), LocalError> {
        if &accum.received_messages == self.expecting_messages_from() {
            Ok(())
        } else {
            Err(LocalError(
                "Not enough messages to finalize the echo round".into(),
            ))
        }
    }
}

pub(crate) struct EchoAccum<I> {
    received_messages: BTreeSet<I>,
}

impl<I: Ord + Clone> EchoAccum<I> {
    pub fn new() -> Self {
        Self {
            received_messages: BTreeSet::new(),
        }
    }

    pub fn contains(&self, from: &I) -> bool {
        self.received_messages.contains(from)
    }

    pub fn add_echo_received(&mut self, from: &I) -> Option<()> {
        if self.received_messages.insert(from.clone()) {
            Some(())
        } else {
            None
        }
    }
}
