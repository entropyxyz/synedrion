use alloc::string::String;

use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use signature::hazmat::PrehashVerifier;

use super::error::LocalError;
use super::signed_message::{Message, MessageType, SessionId, SignedMessage, VerifiedMessage};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum MessageBundleEnum<M> {
    Broadcast(M),
    Direct(M),
    Both { broadcast: M, direct: M },
    Echo(M),
}

/// Combined message from a single round
#[derive(Clone, Debug)]
pub struct MessageBundle {
    session_id: SessionId,
    round: u8,
    is_echo: bool,
    bundle: MessageBundleEnum<SignedMessage>,
}

impl Serialize for MessageBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.bundle.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MessageBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let unchecked = MessageBundleEnum::deserialize(deserializer)?;
        MessageBundle::try_from(unchecked).map_err(D::Error::custom)
    }
}

impl TryFrom<MessageBundleEnum<SignedMessage>> for MessageBundle {
    type Error = LocalError;
    fn try_from(unchecked: MessageBundleEnum<SignedMessage>) -> Result<Self, Self::Error> {
        let (session_id, round, is_echo) = match &unchecked {
            MessageBundleEnum::Broadcast(msg) => {
                if msg.message_type() != MessageType::Broadcast {
                    return Err(LocalError(
                        "Invalid message type of the broadcast field".into(),
                    ));
                }
                (msg.session_id(), msg.round(), false)
            }
            MessageBundleEnum::Direct(msg) => {
                if msg.message_type() != MessageType::Direct {
                    return Err(LocalError(
                        "Invalid message type of the direct field".into(),
                    ));
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
                    return Err(LocalError(
                        "Invalid message type of the broadcast field".into(),
                    ));
                }
                if direct.message_type() != MessageType::Direct {
                    return Err(LocalError(
                        "Invalid message type of the direct field".into(),
                    ));
                }
                (broadcast.session_id(), broadcast.round(), false)
            }
        };
        Ok(Self {
            session_id: *session_id,
            round,
            is_echo,
            bundle: unchecked,
        })
    }
}

impl MessageBundle {
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

    pub(crate) fn verify<Sig: for<'de> Deserialize<'de>>(
        self,
        verifier: &impl PrehashVerifier<Sig>,
    ) -> Result<VerifiedMessageBundle, String> {
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
pub(crate) struct VerifiedMessageBundle(MessageBundleEnum<VerifiedMessage>);

impl VerifiedMessageBundle {
    pub fn broadcast_message(&self) -> Option<&Message> {
        match &self.0 {
            MessageBundleEnum::Broadcast(msg) => Some(msg.serialized_message()),
            MessageBundleEnum::Both { broadcast, .. } => Some(broadcast.serialized_message()),
            _ => None,
        }
    }

    pub fn broadcast_full(&self) -> Option<&VerifiedMessage> {
        match &self.0 {
            MessageBundleEnum::Broadcast(msg) => Some(msg),
            MessageBundleEnum::Both { broadcast, .. } => Some(broadcast),
            _ => None,
        }
    }

    pub fn direct_message(&self) -> Option<&Message> {
        match &self.0 {
            MessageBundleEnum::Direct(msg) => Some(msg.serialized_message()),
            MessageBundleEnum::Both { direct, .. } => Some(direct.serialized_message()),
            _ => None,
        }
    }

    pub fn echo_message(&self) -> Option<&Message> {
        match &self.0 {
            MessageBundleEnum::Echo(msg) => Some(msg.serialized_message()),
            _ => None,
        }
    }

    pub fn is_echo(&self) -> bool {
        matches!(&self.0, MessageBundleEnum::Echo(_))
    }
}
