use rmp_serde;
use serde::{Deserialize, Serialize};

use crate::protocols::keygen;
use crate::protocols::keygen::{PartyId, SessionInfo};
use crate::protocols::rounds::{self, Round};
use crate::tools::collections::HoleMap;

pub enum KeygenSession {
    Round1(keygen::Round1),
    Round1Receiving {
        round: keygen::Round1,
        accum: HoleMap<PartyId, <keygen::Round1 as rounds::Round>::Payload>,
    },
    Round2(keygen::Round2),
    //Round3(keygen::Round3),
}

pub enum ToSend<Id> {
    Broadcast {
        ids: Vec<Id>,
        message: Box<[u8]>,
        needs_consensus: bool,
    },
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

fn serialize_with_round(round: u8, message: &impl Serialize) -> Box<[u8]> {
    let message_bytes = serialize_message(message);
    rmp_serde::encode::to_vec(&(round, message_bytes))
        .unwrap()
        .into_boxed_slice()
}

fn deserialize_with_round(message_bytes: &[u8]) -> (u8, Box<[u8]>) {
    rmp_serde::decode::from_slice(message_bytes).unwrap()
}

fn pack_to_send<Id, Message: Serialize>(
    round: u8,
    to_send: rounds::ToSend<Id, Message>,
) -> ToSend<Id> {
    match to_send {
        rounds::ToSend::Broadcast {
            ids,
            message,
            needs_consensus,
        } => ToSend::Broadcast {
            ids,
            message: serialize_with_round(round, &message),
            needs_consensus,
        },
        rounds::ToSend::Direct(messages) => ToSend::Direct(
            messages
                .into_iter()
                .map(|(id, msg)| (id, serialize_with_round(round, &msg)))
                .collect(),
        ),
    }
}

impl KeygenSession {
    pub fn new(session_info: &SessionInfo, party_id: &PartyId) -> Self {
        Self::Round1(keygen::Round1::new(session_info, party_id))
    }

    pub fn round_number(&self) -> (u8, u8) {
        match self {
            Self::Round1(_) => (1, 0),
            Self::Round1Receiving { .. } => (1, 1),
            Self::Round2(_) => (2, 0),
        }
    }

    pub fn total_rounds(&self) -> u8 {
        2
    }

    pub fn to_send(&mut self) -> ToSend<PartyId> {
        let (round, _) = self.round_number();
        match self {
            Self::Round1(r1) => pack_to_send(round, r1.to_send()),
            Self::Round1(r2) => pack_to_send(round, r2.to_send()),
            _ => unimplemented!(),
        }
    }

    pub fn receive(&mut self, from: &PartyId, full_message_bytes: &[u8]) {
        let (round_num, message_bytes) = deserialize_with_round(full_message_bytes);
        let (current_round, _) = self.round_number();

        if round_num == current_round {
            match self {
                Self::Round1Receiving { round, accum } => {
                    let message: <keygen::Round1 as Round>::Message =
                        deserialize_message(&message_bytes);
                    round.receive(accum, &from, message);
                }
                _ => unimplemented!(),
            }
        } else if round_num == current_round + 1 && round_num < self.total_rounds() {
            // put in the cache
            panic!();
        } else {
            panic!();
        }
    }

    pub fn is_final_round(&self) -> bool {
        true
    }
    pub fn receive_cached_message(&self) {}
    pub fn has_cached_messages(&self) -> bool {
        true
    }
    pub fn is_finished_receiving(&self) -> bool {
        true
    }
    pub fn finalize_round(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::keygen::{PartyId, SessionInfo};

    fn send_messages(to_send: &ToSend<PartyId>) {}

    fn receive_message() -> (PartyId, Box<[u8]>) {
        (PartyId(0), (*b"abcdef").into())
    }

    fn execute_session(session_info: &SessionInfo, party_id: &PartyId) {
        let mut session = KeygenSession::new(session_info, party_id);

        while !session.is_final_round() {
            let to_send = session.to_send(); // Vec<(Id, Box<[u8]>)>
            send_messages(&to_send);

            while session.has_cached_messages() {
                session.receive_cached_message();
            }

            while !session.is_finished_receiving() {
                let (id_from, msg_bytes) = receive_message();
                session.receive(&id_from, &msg_bytes);
            }
            session.finalize_round();
        }
    }

    #[test]
    fn keygen() {
        let parties = [PartyId(111), PartyId(222), PartyId(333)];
        let session_info = SessionInfo {
            parties: parties.to_vec(),
            kappa: 256,
        };

        execute_session(&session_info, &parties[0]);
    }
}
