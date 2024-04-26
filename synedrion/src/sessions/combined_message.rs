use alloc::string::String;

use serde::{Deserialize, Serialize};
use signature::hazmat::PrehashVerifier;

use super::signed_message::{MessageType, SessionId, SignedMessage, VerifiedMessage};

/// Combined message from a single round
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CombinedMessage<Sig> {
    /// One message (broadcast, direct, or echo)
    One(SignedMessage<Sig>),
    /// A broadcast and a direct message
    Both {
        /// The broadcast part
        broadcast: SignedMessage<Sig>,
        /// The direct part
        direct: SignedMessage<Sig>,
    },
}

impl<Sig> CombinedMessage<Sig> {
    pub(crate) fn check(self) -> Result<CheckedCombinedMessage<Sig>, String> {
        let messages = match self {
            CombinedMessage::One(msg) => match msg.message_type() {
                MessageType::Broadcast => CombinedMessageEnum::Broadcast(msg),
                MessageType::Direct => CombinedMessageEnum::Direct(msg),
                MessageType::Echo => CombinedMessageEnum::Echo(msg),
            },
            CombinedMessage::Both { broadcast, direct } => {
                if broadcast.session_id() != direct.session_id() {
                    return Err("Mismatched session IDs".into());
                }
                if broadcast.round() != direct.round() {
                    return Err("Mismatched round numbers".into());
                }
                if broadcast.message_type() != MessageType::Broadcast {
                    return Err("Invalid message type of the broadcast field".into());
                }
                if direct.message_type() != MessageType::Direct {
                    return Err("Invalid message type of the direct field".into());
                }
                CombinedMessageEnum::Both { broadcast, direct }
            }
        };
        Ok(CheckedCombinedMessage(messages))
    }
}

#[derive(Clone, Debug)]
enum CombinedMessageEnum<M> {
    Broadcast(M),
    Direct(M),
    Both { broadcast: M, direct: M },
    Echo(M),
}

#[derive(Clone, Debug)]
pub struct CheckedCombinedMessage<Sig>(CombinedMessageEnum<SignedMessage<Sig>>);

impl<Sig> CheckedCombinedMessage<Sig> {
    pub fn session_id(&self) -> &SessionId {
        match &self.0 {
            CombinedMessageEnum::Broadcast(msg) => msg.session_id(),
            CombinedMessageEnum::Direct(msg) => msg.session_id(),
            CombinedMessageEnum::Echo(msg) => msg.session_id(),
            CombinedMessageEnum::Both { broadcast, .. } => broadcast.session_id(),
        }
    }

    pub fn round(&self) -> u8 {
        match &self.0 {
            CombinedMessageEnum::Broadcast(msg) => msg.round(),
            CombinedMessageEnum::Direct(msg) => msg.round(),
            CombinedMessageEnum::Echo(msg) => msg.round(),
            CombinedMessageEnum::Both { broadcast, .. } => broadcast.round(),
        }
    }

    pub fn is_echo(&self) -> bool {
        matches!(&self.0, CombinedMessageEnum::Echo(_))
    }

    pub(crate) fn verify(
        self,
        verifier: &impl PrehashVerifier<Sig>,
    ) -> Result<VerifiedCombinedMessage<Sig>, String> {
        let verified_messages = match self.0 {
            CombinedMessageEnum::Broadcast(msg) => {
                CombinedMessageEnum::Broadcast(msg.verify(verifier)?)
            }
            CombinedMessageEnum::Direct(msg) => CombinedMessageEnum::Direct(msg.verify(verifier)?),
            CombinedMessageEnum::Echo(msg) => CombinedMessageEnum::Echo(msg.verify(verifier)?),
            CombinedMessageEnum::Both { broadcast, direct } => CombinedMessageEnum::Both {
                broadcast: broadcast.verify(verifier)?,
                direct: direct.verify(verifier)?,
            },
        };
        Ok(VerifiedCombinedMessage(verified_messages))
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedCombinedMessage<Sig>(CombinedMessageEnum<VerifiedMessage<Sig>>);

impl<Sig> VerifiedCombinedMessage<Sig> {
    pub fn broadcast_payload(&self) -> Option<&[u8]> {
        match &self.0 {
            CombinedMessageEnum::Broadcast(msg) => Some(msg.payload()),
            CombinedMessageEnum::Both { broadcast, .. } => Some(broadcast.payload()),
            _ => None,
        }
    }

    pub fn broadcast_message(&self) -> Option<&VerifiedMessage<Sig>> {
        match &self.0 {
            CombinedMessageEnum::Broadcast(msg) => Some(msg),
            CombinedMessageEnum::Both { broadcast, .. } => Some(broadcast),
            _ => None,
        }
    }

    pub fn direct_payload(&self) -> Option<&[u8]> {
        match &self.0 {
            CombinedMessageEnum::Direct(msg) => Some(msg.payload()),
            CombinedMessageEnum::Both { direct, .. } => Some(direct.payload()),
            _ => None,
        }
    }

    pub fn echo_payload(&self) -> Option<&[u8]> {
        match &self.0 {
            CombinedMessageEnum::Echo(msg) => Some(msg.payload()),
            _ => None,
        }
    }

    pub fn is_echo(&self) -> bool {
        matches!(&self.0, CombinedMessageEnum::Echo(_))
    }
}
