use alloc::boxed::Box;
use alloc::format;

use serde::{Deserialize, Serialize};

use super::error::{MyFault, TheirFault};
use crate::curve::{Signature, Signer, Verifier};
use crate::tools::hashing::{Chain, Hash};

pub(crate) fn serialize_message(message: &impl Serialize) -> Result<Box<[u8]>, MyFault> {
    rmp_serde::encode::to_vec(message)
        .map(|serialized| serialized.into_boxed_slice())
        .map_err(MyFault::SerializationError)
}

pub(crate) fn deserialize_message<M: for<'de> Deserialize<'de>>(
    message_bytes: &[u8],
) -> Result<M, rmp_serde::decode::Error> {
    rmp_serde::decode::from_slice(message_bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    // TODO
    //session_id: SessionId,
    stage: u8,
    payload: Box<[u8]>, // TODO: add serialization attribute to avoid serializing as Vec<u8>
    signature: Signature,
}

impl SignedMessage {
    pub(crate) fn verify(self, verifier: &Verifier) -> Result<VerifiedMessage, TheirFault> {
        let digest = Hash::new_with_dst(b"SignedMessage")
            .chain(&self.stage)
            .chain(&self.payload)
            .digest();
        verifier
            .verify_digest(digest, &self.signature)
            .map_err(|err| TheirFault::VerificationFail(format!("{}", err)))?;
        Ok(VerifiedMessage(self))
    }
}

pub(crate) struct VerifiedMessage(SignedMessage);

impl VerifiedMessage {
    pub(crate) fn new(signer: &Signer, stage: u8, message_bytes: &[u8]) -> Self {
        // In order for the messages be impossible to reuse by a malicious third party,
        // we need to sign, besides the message itself, the session and the stage in this session
        // it belongs to.
        // We also need the exact way we sign this to be a part of the public ABI,
        // so that these signatures could be verified by a third party.

        let digest = Hash::new_with_dst(b"SignedMessage")
            .chain(&stage)
            .chain(&message_bytes)
            .digest();
        let signature = signer.sign_digest(digest);
        Self(SignedMessage {
            stage,
            payload: message_bytes.into(),
            signature,
        })
    }

    pub fn into_unverified(self) -> SignedMessage {
        self.0
    }

    pub fn payload(&self) -> &[u8] {
        &self.0.payload
    }

    pub fn stage(&self) -> u8 {
        self.0.stage
    }
}
