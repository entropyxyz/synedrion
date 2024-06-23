use alloc::string::String;

use serde::{Deserialize, Serialize};
use signature::hazmat::PrehashVerifier;

use super::signed_message::{MessageType, SessionId, SignedMessage, VerifiedMessage};

/// Combined message from a single round
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MessageBundle<Sig> {
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

impl<Sig> MessageBundle<Sig> {
    pub(crate) fn check(self) -> Result<CheckedMessageBundle<Sig>, String> {
        let messages = match self {
            MessageBundle::One(msg) => match msg.message_type() {
                MessageType::Broadcast => MessageBundleEnum::Broadcast(msg),
                MessageType::Direct => MessageBundleEnum::Direct(msg),
                MessageType::Echo => MessageBundleEnum::Echo(msg),
            },
            MessageBundle::Both { broadcast, direct } => {
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
                MessageBundleEnum::Both { broadcast, direct }
            }
        };
        Ok(CheckedMessageBundle(messages))
    }
}

#[derive(Clone, Debug)]
enum MessageBundleEnum<M> {
    Broadcast(M),
    Direct(M),
    Both { broadcast: M, direct: M },
    Echo(M),
}

#[derive(Clone, Debug)]
pub struct CheckedMessageBundle<Sig>(MessageBundleEnum<SignedMessage<Sig>>);

impl<Sig> CheckedMessageBundle<Sig> {
    pub fn session_id(&self) -> &SessionId {
        match &self.0 {
            MessageBundleEnum::Broadcast(msg) => msg.session_id(),
            MessageBundleEnum::Direct(msg) => msg.session_id(),
            MessageBundleEnum::Echo(msg) => msg.session_id(),
            MessageBundleEnum::Both { broadcast, .. } => broadcast.session_id(),
        }
    }

    pub fn round(&self) -> u8 {
        match &self.0 {
            MessageBundleEnum::Broadcast(msg) => msg.round(),
            MessageBundleEnum::Direct(msg) => msg.round(),
            MessageBundleEnum::Echo(msg) => msg.round(),
            MessageBundleEnum::Both { broadcast, .. } => broadcast.round(),
        }
    }

    pub fn is_echo(&self) -> bool {
        matches!(&self.0, MessageBundleEnum::Echo(_))
    }

    pub(crate) fn verify(
        self,
        verifier: &impl PrehashVerifier<Sig>,
    ) -> Result<VerifiedMessageBundle<Sig>, String> {
        let verified_messages = match self.0 {
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
pub struct VerifiedMessageBundle<Sig>(MessageBundleEnum<VerifiedMessage<Sig>>);

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
