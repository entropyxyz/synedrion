use alloc::string::String;

use serde::{Deserialize, Serialize, Serializer, Deserializer, de::Error as _};
use signature::hazmat::PrehashVerifier;

use super::error::LocalError;
use super::signed_message::{MessageType, SessionId, SignedMessage, VerifiedMessage};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum MessageBundleEnum<M> {
    Broadcast(M),
    Direct(M),
    Both { broadcast: M, direct: M },
    Echo(M),
}

/// Combined message from a single round
#[derive(Clone, Debug)]
pub struct MessageBundle<Sig> {
    session_id: SessionId,
    round: u8,
    is_echo: bool,
    bundle: MessageBundleEnum<SignedMessage<Sig>>
}

impl<Sig: Serialize> Serialize for MessageBundle<Sig> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        self.bundle.serialize(serializer)
    }
}

impl<'de, Sig: Deserialize<'de>> Deserialize<'de> for MessageBundle<Sig> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
        let unchecked = MessageBundleEnum::deserialize(deserializer)?;
        MessageBundle::try_from(unchecked).map_err(D::Error::custom)
    }
}

impl<Sig> TryFrom<MessageBundleEnum<SignedMessage<Sig>>> for MessageBundle<Sig> {
    type Error = LocalError;
    fn try_from(unchecked: MessageBundleEnum<SignedMessage<Sig>>) -> Result<Self, Self::Error> {
        let (session_id, round, is_echo) = match &unchecked {
            MessageBundleEnum::Broadcast(msg) => {
                if msg.message_type() != MessageType::Broadcast {
                    return Err(LocalError("Invalid message type of the broadcast field".into()));
                }
                (msg.session_id(), msg.round(), false)
            }
            MessageBundleEnum::Direct(msg) => {
                if msg.message_type() != MessageType::Direct {
                    return Err(LocalError("Invalid message type of the direct field".into()));
                }
                (msg.session_id(), msg.round(), false)
            }
            MessageBundleEnum::Echo(msg) => {
                if msg.message_type() != MessageType::Echo {
                    return Err(LocalError("Invalid message type of the echo field".into()));
                }
                (msg.session_id(), msg.round(), true)
            }
            MessageBundleEnum::Both { broadcast, direct } => {
                if broadcast.session_id() != direct.session_id() {
                    return Err(LocalError("Mismatched session IDs".into()));
                }
                if broadcast.round() != direct.round() {
                    return Err(LocalError("Mismatched round numbers".into()));
                }
                if broadcast.message_type() != MessageType::Broadcast {
                    return Err(LocalError("Invalid message type of the broadcast field".into()));
                }
                if direct.message_type() != MessageType::Direct {
                    return Err(LocalError("Invalid message type of the direct field".into()));
                }
                (broadcast.session_id(), broadcast.round(), false)
            }
        };
        Ok(Self {
            session_id: *session_id,
            round,
            is_echo,
            bundle: unchecked
        })
    }
}

impl<Sig> MessageBundle<Sig> {
    /// The session ID of the messages.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// The round of the messages.
    pub fn round(&self) -> u8 {
        self.round
    }

    /// Whether the bundle corresponds to an echo round.
    pub fn is_echo(&self) -> bool {
        self.is_echo
    }

    pub(crate) fn verify(
        self,
        verifier: &impl PrehashVerifier<Sig>,
    ) -> Result<VerifiedMessageBundle<Sig>, String> {
        let verified_messages = match self.bundle {
            MessageBundleEnum::Broadcast(msg) => {
                MessageBundleEnum::Broadcast(msg.verify(verifier)?)
            }
            MessageBundleEnum::Direct(msg) => MessageBundleEnum::Direct(msg.verify(verifier)?),
            MessageBundleEnum::Echo(msg) => MessageBundleEnum::Echo(msg.verify(verifier)?),
            MessageBundleEnum::Both { broadcast, direct } => MessageBundleEnum::Both {
                broadcast: broadcast.verify(verifier)?,
                direct: direct.verify(verifier)?,
            },
        };
        Ok(VerifiedMessageBundle(verified_messages))
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedMessageBundle<Sig>(MessageBundleEnum<VerifiedMessage<Sig>>);

impl<Sig> VerifiedMessageBundle<Sig> {
    pub fn broadcast_payload(&self) -> Option<&[u8]> {
        match &self.0 {
            MessageBundleEnum::Broadcast(msg) => Some(msg.payload()),
            MessageBundleEnum::Both { broadcast, .. } => Some(broadcast.payload()),
            _ => None,
        }
    }

    pub fn broadcast_message(&self) -> Option<&VerifiedMessage<Sig>> {
        match &self.0 {
            MessageBundleEnum::Broadcast(msg) => Some(msg),
            MessageBundleEnum::Both { broadcast, .. } => Some(broadcast),
            _ => None,
        }
    }

    pub fn direct_payload(&self) -> Option<&[u8]> {
        match &self.0 {
            MessageBundleEnum::Direct(msg) => Some(msg.payload()),
            MessageBundleEnum::Both { direct, .. } => Some(direct.payload()),
            _ => None,
        }
    }

    pub fn echo_payload(&self) -> Option<&[u8]> {
        match &self.0 {
            MessageBundleEnum::Echo(msg) => Some(msg.payload()),
            _ => None,
        }
    }

    pub fn is_echo(&self) -> bool {
        matches!(&self.0, MessageBundleEnum::Echo(_))
    }
}
