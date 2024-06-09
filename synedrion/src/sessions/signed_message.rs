use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};

use super::error::LocalError;
use crate::tools::hashing::{Chain, FofHasher, HashOutput, Hashable};
use crate::tools::serde_bytes;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
pub struct SessionId(HashOutput);

impl SessionId {
    pub(crate) fn from_seed(seed: &[u8]) -> Self {
        Self(
            FofHasher::new_with_dst(b"SessionId")
                .chain(&seed)
                .finalize(),
        )
    }
}

impl Hashable for SessionId {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain_constant_sized_bytes(&self.0)
    }
}

fn message_hash(
    session_id: &SessionId,
    round: u8,
    message_type: MessageType,
    payload: &[u8],
) -> HashOutput {
    FofHasher::new_with_dst(b"SignedMessage")
        .chain(session_id)
        .chain(&round)
        .chain(&message_type)
        .chain(&payload)
        .finalize()
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

impl Hashable for MessageType {
    fn chain<C: Chain>(&self, digest: C) -> C {
        let value: u8 = match self {
            Self::Broadcast => 0,
            Self::Direct => 1,
            Self::Echo => 2,
        };
        digest.chain(&value)
    }
}

/// A (yet) unverified message from a round that includes the payload signature.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SignedMessage<Sig> {
    session_id: SessionId,
    round: u8,
    message_type: MessageType,
    #[serde(with = "serde_bytes::as_base64")]
    payload: Box<[u8]>,
    signature: Sig,
}

impl<Sig> SignedMessage<Sig> {
    pub(crate) fn verify(
        self,
        verifier: &impl PrehashVerifier<Sig>,
    ) -> Result<VerifiedMessage<Sig>, String> {
        verifier
            .verify_prehash(
                message_hash(
                    &self.session_id,
                    self.round,
                    self.message_type,
                    &self.payload,
                )
                .as_ref(),
                &self.signature,
            )
            .map_err(|err| format!("{:?}", err))?;
        Ok(VerifiedMessage(self))
    }

    /// The session ID of this message.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// The round of this message.
    pub fn round(&self) -> u8 {
        self.round
    }

    /// The message type.
    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// Compares the "significant" part of the messages (that is, everything but signatures)
    pub fn is_same_as(&self, other: &Self) -> bool {
        self.session_id == other.session_id
            && self.round == other.round
            && self.message_type == other.message_type
            && self.payload == other.payload
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct VerifiedMessage<Sig>(SignedMessage<Sig>);

impl<Sig> VerifiedMessage<Sig> {
    pub(crate) fn new(
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

        let signature = signer
            .sign_prehash_with_rng(
                rng,
                message_hash(session_id, round, message_type, message_bytes).as_ref(),
            )
            .map_err(|err| LocalError(err.to_string()))?;
        Ok(Self(SignedMessage {
            session_id: *session_id,
            round,
            message_type,
            payload: message_bytes.into(),
            signature,
        }))
    }

    pub fn as_unverified(&self) -> &SignedMessage<Sig> {
        &self.0
    }

    pub fn into_unverified(self) -> SignedMessage<Sig> {
        self.0
    }

    pub fn payload(&self) -> &[u8] {
        &self.0.payload
    }
}
