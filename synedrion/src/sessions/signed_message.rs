use alloc::boxed::Box;
use alloc::string::ToString;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};

use super::error::{MyFault, TheirFault};
use crate::tools::hashing::{Chain, Hash, HashOutput, Hashable};
use crate::tools::serde_bytes;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SessionId(HashOutput);

impl SessionId {
    pub(crate) fn from_seed(seed: &[u8]) -> Self {
        Self(Hash::new_with_dst(b"SessionId").chain(&seed).finalize())
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
    broadcast_consensus: bool,
    payload: &[u8],
) -> HashOutput {
    Hash::new_with_dst(b"SignedMessage")
        .chain(session_id)
        .chain(&round)
        .chain(&broadcast_consensus)
        .chain(&payload)
        .finalize()
}

/// A (yet) unverified message from a round that includes the payload signature.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SignedMessage<Sig> {
    session_id: SessionId,
    round: u8,
    broadcast_consensus: bool,
    #[serde(with = "serde_bytes::as_base64")]
    payload: Box<[u8]>,
    signature: Sig,
}

impl<Sig> SignedMessage<Sig> {
    pub(crate) fn verify(
        self,
        verifier: &impl PrehashVerifier<Sig>,
    ) -> Result<VerifiedMessage<Sig>, TheirFault> {
        verifier
            .verify_prehash(
                message_hash(
                    &self.session_id,
                    self.round,
                    self.broadcast_consensus,
                    &self.payload,
                )
                .as_ref(),
                &self.signature,
            )
            .map_err(|err| TheirFault::VerificationFail(err.to_string()))?;
        Ok(VerifiedMessage(self))
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
        broadcast_consensus: bool,
        message_bytes: &[u8],
    ) -> Result<Self, MyFault> {
        // In order for the messages be impossible to reuse by a malicious third party,
        // we need to sign, besides the message itself, the session and the round in this session
        // it belongs to.
        // We also need the exact way we sign this to be a part of the public ABI,
        // so that these signatures could be verified by a third party.

        let signature = signer
            .sign_prehash_with_rng(
                rng,
                message_hash(session_id, round, broadcast_consensus, message_bytes).as_ref(),
            )
            .map_err(|err| MyFault::SigningError(err.to_string()))?;
        Ok(Self(SignedMessage {
            session_id: session_id.clone(),
            round,
            broadcast_consensus,
            payload: message_bytes.into(),
            signature,
        }))
    }

    pub fn into_unverified(self) -> SignedMessage<Sig> {
        self.0
    }

    pub fn session_id(&self) -> &SessionId {
        &self.0.session_id
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
