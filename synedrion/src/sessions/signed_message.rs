use alloc::boxed::Box;
use alloc::format;

use serde::{Deserialize, Serialize};
use signature::{
    hazmat::{PrehashSigner, PrehashVerifier},
    SignatureEncoding,
};

use super::error::{MyFault, TheirFault};
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
    signature: Box<[u8]>,
}

impl SignedMessage {
    pub(crate) fn verify<V, Sig>(self, verifier: &V) -> Result<VerifiedMessage, TheirFault>
    where
        V: PrehashVerifier<Sig>,
        Sig: for<'a> TryFrom<&'a [u8]>,
        for<'a> <Sig as TryFrom<&'a [u8]>>::Error: core::fmt::Display,
    {
        let digest = Hash::new_with_dst(b"SignedMessage")
            .chain(&self.stage)
            .chain(&self.payload)
            .finalize();
        let signature = Sig::try_from(&self.signature)
            .map_err(|err| TheirFault::SignatureFormatError(format!("{}", err)))?;
        verifier
            .verify_prehash(digest.as_ref(), &signature)
            .map_err(|err| TheirFault::VerificationFail(format!("{}", err)))?;
        Ok(VerifiedMessage(self))
    }
}

pub(crate) struct VerifiedMessage(SignedMessage);

impl VerifiedMessage {
    pub(crate) fn new<S, Sig>(signer: &S, stage: u8, message_bytes: &[u8]) -> Self
    where
        S: PrehashSigner<Sig>,
        Sig: SignatureEncoding,
    {
        // In order for the messages be impossible to reuse by a malicious third party,
        // we need to sign, besides the message itself, the session and the stage in this session
        // it belongs to.
        // We also need the exact way we sign this to be a part of the public ABI,
        // so that these signatures could be verified by a third party.

        let digest = Hash::new_with_dst(b"SignedMessage")
            .chain(&stage)
            .chain(&message_bytes)
            .finalize();
        // TODO: propagate the failure here
        let signature = signer.sign_prehash(digest.as_ref()).unwrap();
        Self(SignedMessage {
            stage,
            payload: message_bytes.into(),
            signature: signature.to_vec().into(),
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
