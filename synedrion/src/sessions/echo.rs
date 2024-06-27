use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::error::LocalError;
use super::signed_message::SignedMessage;
use super::type_erased::{deserialize_message, serialize_message};

#[derive(Clone)]
pub(crate) struct EchoRound<I, Sig> {
    destinations: BTreeSet<I>,
    broadcasts: BTreeMap<I, SignedMessage<Sig>>,
}

#[derive(Serialize, Deserialize)]
struct Message<I, Sig> {
    broadcasts: Vec<(I, SignedMessage<Sig>)>,
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

impl<I, Sig> EchoRound<I, Sig>
where
    I: Clone + Ord + PartialEq + Serialize + for<'de> Deserialize<'de>,
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
{
    pub fn new(broadcasts: BTreeMap<I, SignedMessage<Sig>>) -> Self {
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

    pub fn make_broadcast(&self) -> Box<[u8]> {
        let message = Message {
            broadcasts: self.broadcasts.clone().into_iter().collect(),
        };
        serialize_message(&message).unwrap()
    }

    pub fn verify_broadcast(&self, from: &I, payload: &[u8]) -> Result<(), EchoError> {
        // TODO (#68): check that the direct payload is empty?
        let message: Message<I, Sig> = deserialize_message(payload)
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

            if !broadcast.is_same_as(echoed_bc) {
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
