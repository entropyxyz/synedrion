use alloc::boxed::Box;
use alloc::string::ToString;

use serde::{Deserialize, Serialize};
use signature::hazmat::{PrehashSigner, PrehashVerifier};

use super::error::{MyFault, TheirFault};
use crate::tools::hashing::{Chain, Hash, HashOutput};

fn message_hash(round: u8, broadcast_consensus: bool, payload: &[u8]) -> HashOutput {
    Hash::new_with_dst(b"SignedMessage")
        .chain(&round)
        .chain(&broadcast_consensus)
        .chain(&payload)
        .finalize()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedMessage<Sig> {
    // TODO
    //session_id: SessionId,
    round: u8,
    broadcast_consensus: bool,
    payload: Box<[u8]>, // TODO: add serialization attribute to avoid serializing as Vec<u8>
    signature: Sig,
}

impl<Sig> SignedMessage<Sig> {
    pub(crate) fn verify(
        self,
        verifier: &impl PrehashVerifier<Sig>,
    ) -> Result<VerifiedMessage<Sig>, TheirFault> {
        verifier
            .verify_prehash(
                message_hash(self.round, self.broadcast_consensus, &self.payload).as_ref(),
                &self.signature,
            )
            .map_err(|err| TheirFault::VerificationFail(err.to_string()))?;
        Ok(VerifiedMessage(self))
    }
}

pub(crate) struct VerifiedMessage<Sig>(SignedMessage<Sig>);

impl<Sig> VerifiedMessage<Sig> {
    pub(crate) fn new(
        signer: &impl PrehashSigner<Sig>,
        round: u8,
        broadcast_consensus: bool,
        message_bytes: &[u8],
    ) -> Result<Self, MyFault> {
        // In order for the messages be impossible to reuse by a malicious third party,
        // we need to sign, besides the message itself, the session and the round in this session
        // it belongs to.
        // We also need the exact way we sign this to be a part of the public ABI,
        // so that these signatures could be verified by a third party.

        let signature = signer
            .sign_prehash(message_hash(round, broadcast_consensus, message_bytes).as_ref())
            .map_err(|err| MyFault::SigningError(err.to_string()))?;
        Ok(Self(SignedMessage {
            round,
            broadcast_consensus,
            payload: message_bytes.into(),
            signature,
        }))
    }

    pub fn into_unverified(self) -> SignedMessage<Sig> {
        self.0
    }

    pub fn payload(&self) -> &[u8] {
        &self.0.payload
    }

    pub fn round(&self) -> u8 {
        self.0.round
    }

    pub fn broadcast_consensus(&self) -> bool {
        self.0.broadcast_consensus
    }
}
