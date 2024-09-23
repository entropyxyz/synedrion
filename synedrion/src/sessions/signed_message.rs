use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};

use super::echo::EchoMessage;
use super::error::LocalError;
use crate::tools::hashing::{Chain, FofHasher, HashOutput};
use crate::tools::serde_bytes;

/// A session identifier shared between the parties.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct SessionId(HashOutput);

impl SessionId {
    /// Deterministically creates a session ID from the given bytestring.
    pub fn from_seed(seed: &[u8]) -> Self {
        Self(
            FofHasher::new_with_dst(b"SessionId")
                .chain(&seed)
                .finalize(),
        )
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Protocol message type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub enum MessageType {
    Broadcast,
    /// Regular messaging part of the round.
    Direct,
    /// A service message for echo-broadcast.
    Echo,
}

/// A (yet) unverified message from a round that includes the signature of the payload.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SignedMessage {
    signature: Signature,
    message_with_metadata: MessageWithMetadata,
}

impl SignedMessage {
    pub(crate) fn new<Sig: Serialize>(
        rng: &mut impl CryptoRngCore,
        signer: &impl RandomizedPrehashSigner<Sig>,
        session_id: &SessionId,
        round: u8,
        message_type: MessageType,
        message: Message,
    ) -> Result<Self, LocalError> {
        // In order for the messages be impossible to reuse by a malicious third party,
        // we need to sign, besides the message itself, the session and the round in this session
        // it belongs to.
        // We also need the exact way we sign this to be a part of the public ABI,
        // so that these signatures could be verified by a third party.

        let metadata = Metadata {
            session_id: *session_id,
            round,
            message_type,
        };
        let message_with_metadata = MessageWithMetadata { message, metadata };
        let signature = signer
            .sign_prehash_with_rng(rng, message_with_metadata.hash().as_ref())
            .map_err(|err| LocalError(err.to_string()))?;
        let signature = Signature::new(&signature)?;

        Ok(Self {
            signature,
            message_with_metadata,
        })
    }

    pub(crate) fn verify<Sig: for<'de> Deserialize<'de>>(
        self,
        verifier: &impl PrehashVerifier<Sig>,
    ) -> Result<VerifiedMessage, String> {
        let signature = self.signature.to_typed()?;
        verifier
            .verify_prehash(self.message_with_metadata.hash().as_ref(), &signature)
            .map_err(|err| format!("{:?}", err))?;
        Ok(VerifiedMessage {
            signature: self.signature,
            message_with_metadata: self.message_with_metadata,
        })
    }

    /// The session ID of this message.
    pub fn session_id(&self) -> &SessionId {
        &self.message_with_metadata.metadata.session_id
    }

    /// The round of this message.
    pub fn round(&self) -> u8 {
        self.message_with_metadata.metadata.round
    }

    /// The message type.
    pub fn message_type(&self) -> MessageType {
        self.message_with_metadata.metadata.message_type
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct VerifiedMessage {
    signature: Signature,
    message_with_metadata: MessageWithMetadata,
}

impl VerifiedMessage {
    pub fn into_unverified(self) -> SignedMessage {
        SignedMessage {
            signature: self.signature,
            message_with_metadata: self.message_with_metadata,
        }
    }

    pub fn serialized_message(&self) -> &Message {
        &self.message_with_metadata.message
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct MessageWithMetadata {
    message: Message,
    metadata: Metadata,
}

impl MessageWithMetadata {
    fn hash(&self) -> HashOutput {
        FofHasher::new_with_dst(b"Message")
            .chain(&self.metadata)
            .chain(&self.message)
            .finalize()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
struct Metadata {
    session_id: SessionId,
    round: u8,
    message_type: MessageType,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Message {
    #[serde(with = "serde_bytes::as_base64")]
    serialized_message: Box<[u8]>,
}

impl Message {
    pub fn new<T: Serialize>(message: &T) -> Result<Self, LocalError> {
        bincode::serde::encode_to_vec(message, bincode::config::standard())
            .map(|serialized| Self {
                serialized_message: serialized.into(),
            })
            .map_err(|err| LocalError(format!("Failed to serialize: {err:?}")))
    }

    /// Returns a `Message` that would deserialize into `()`.
    pub fn unit_type() -> Self {
        // This is really a consequence of `Round::verify_message()` taking message types directly
        // and not wrapped in `Option`.
        // We denote a non-existent message by a unit type `()`,
        // and Rust does not allow type-dependent branches in the code,
        // so we need to create something that would deserialize into `()` in runtime.
        Self {
            serialized_message: Box::new([]),
        }
    }

    pub fn to_typed<T: for<'de> Deserialize<'de>>(&self) -> Result<T, String> {
        bincode::serde::decode_borrowed_from_slice(
            &self.serialized_message,
            bincode::config::standard(),
        )
        .map_err(|err| err.to_string())
    }

    pub fn to_typed_echo<I, T>(&self) -> Result<BTreeMap<I, T>, String>
    where
        I: Clone + Ord + for<'de> Deserialize<'de>,
        T: for<'de> Deserialize<'de>,
    {
        // TODO: should this logic be here, or somewhere in the echo module?
        let echo_message = self.to_typed::<EchoMessage<I>>()?;
        Ok(echo_message
            .broadcasts
            .iter()
            .map(|(id, broadcast)| {
                (
                    id.clone(),
                    broadcast
                        .message_with_metadata
                        .message
                        .to_typed::<T>()
                        .unwrap(),
                )
            })
            .collect())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
struct Signature {
    #[serde(with = "serde_bytes::as_hex")]
    serialized_signature: Box<[u8]>,
}

impl Signature {
    pub fn new<T: Serialize>(signature: &T) -> Result<Self, LocalError> {
        bincode::serde::encode_to_vec(signature, bincode::config::standard())
            .map(|serialized| Self {
                serialized_signature: serialized.into(),
            })
            .map_err(|err| LocalError(format!("Failed to serialize: {err:?}")))
    }

    pub fn to_typed<T: for<'de> Deserialize<'de>>(&self) -> Result<T, String> {
        bincode::serde::decode_borrowed_from_slice(
            &self.serialized_signature,
            bincode::config::standard(),
        )
        .map_err(|err| err.to_string())
    }
}
