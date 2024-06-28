use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};

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

/// A (yet) unverified message from a round that includes the payload signature.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SignedMessage {
    #[serde(with = "serde_bytes::as_hex")]
    signature: Box<[u8]>,
    message: Message,
}

impl SignedMessage {
    pub(crate) fn new<Sig: Serialize>(
        rng: &mut impl CryptoRngCore,
        signer: &impl RandomizedPrehashSigner<Sig>,
        session_id: &SessionId,
        round: u8,
        message_type: MessageType,
        message_bytes: &[u8],
    ) -> Result<Self, LocalError> {
        // In order for the messages be impossible to reuse by a malicious third party,
        // we need to sign, besides the message itself, the session and the round in this session
        // it belongs to.
        // We also need the exact way we sign this to be a part of the public ABI,
        // so that these signatures could be verified by a third party.

        let message = Message {
            session_id: *session_id,
            round,
            message_type,
            payload: message_bytes.into(),
        };
        let signature = signer
            .sign_prehash_with_rng(rng, message.hash().as_ref())
            .map_err(|err| LocalError(err.to_string()))?;
        let signature_bytes =
            bincode::serde::encode_to_vec(&signature, bincode::config::standard())
                .map_err(|err| LocalError(format!("Failed to serialize: {err:?}")))?;

        Ok(Self {
            signature: signature_bytes.into(),
            message,
        })
    }

    pub(crate) fn verify<Sig: for<'de> Deserialize<'de>>(
        self,
        verifier: &impl PrehashVerifier<Sig>,
    ) -> Result<VerifiedMessage, String> {
        let signature = bincode::serde::decode_borrowed_from_slice(
            &self.signature,
            bincode::config::standard(),
        )
        .map_err(|err| format!("{}", err))?;
        verifier
            .verify_prehash(self.message.hash().as_ref(), &signature)
            .map_err(|err| format!("{:?}", err))?;
        Ok(VerifiedMessage {
            signature: self.signature,
            message: self.message,
        })
    }

    /// The session ID of this message.
    pub fn session_id(&self) -> &SessionId {
        &self.message.session_id
    }

    /// The round of this message.
    pub fn round(&self) -> u8 {
        self.message.round
    }

    /// The message type.
    pub fn message_type(&self) -> MessageType {
        self.message.message_type
    }

    /// Compares the "significant" part of the messages (that is, everything but signatures)
    pub fn is_same_as(&self, other: &Self) -> bool {
        self.session_id() == other.session_id()
            && self.round() == other.round()
            && self.message_type() == other.message_type()
            && self.message.payload == other.message.payload
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct VerifiedMessage {
    signature: Box<[u8]>,
    message: Message,
}

impl VerifiedMessage {
    pub fn into_unverified(self) -> SignedMessage {
        SignedMessage {
            signature: self.signature,
            message: self.message,
        }
    }

    pub fn payload(&self) -> &[u8] {
        &self.message.payload
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Message {
    session_id: SessionId,
    round: u8,
    message_type: MessageType,
    #[serde(with = "serde_bytes::as_base64")]
    payload: Box<[u8]>,
}

impl Message {
    fn hash(&self) -> HashOutput {
        FofHasher::new_with_dst(b"Message")
            .chain(&self.session_id)
            .chain(&self.round)
            .chain(&self.message_type)
            .chain(&self.payload)
            .finalize()
    }
}
