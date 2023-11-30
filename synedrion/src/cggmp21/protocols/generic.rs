use alloc::string::String;
use core::fmt::Debug;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::common::PartyIdx;
use crate::tools::collections::{HoleRange, HoleVec};

/// A round that sends out a broadcast.
pub(crate) trait BroadcastRound: BaseRound {
    /// Whether all the nodes receiving the broadcast should make sure they got the same message.
    const REQUIRES_CONSENSUS: bool = false;

    /// The broadcast type.
    type Message: Serialize + for<'de> Deserialize<'de>;

    /// The processed broadcast from another node, to be collected to finalize the round.
    type Payload;

    /// The indices of the parties that should receive the broadcast,
    /// or `None` if this round does not send any broadcasts.
    fn broadcast_destinations(&self) -> Option<HoleRange> {
        None
    }

    /// Creates a broadcast.
    fn make_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut impl CryptoRngCore,
    ) -> Result<Self::Message, String> {
        Err("This round does not send out broadcasts".into())
    }

    /// Processes a broadcast received from the party `from`.
    fn verify_broadcast(
        &self,
        #[allow(unused_variables)] from: PartyIdx,
        #[allow(unused_variables)] msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        Err(ReceiveError::InvalidType)
    }
}

/// A round that sends out direct messages.
pub(crate) trait DirectRound: BaseRound {
    /// The direct message type.
    type Message: Serialize + for<'de> Deserialize<'de>;

    /// The processed direct message from another node, to be collected to finalize the round.
    type Payload;

    /// Data created when creating a direct message, to be preserved until the finalization stage.
    type Artifact;

    /// The indices of the parties that should receive the direct messages,
    /// or `None` if this round does not send any direct messages.
    fn direct_message_destinations(&self) -> Option<HoleRange> {
        None
    }

    /// Creates a direct message for the given party.
    fn make_direct_message(
        &self,
        #[allow(unused_variables)] rng: &mut impl CryptoRngCore,
        #[allow(unused_variables)] destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artifact), String> {
        Err("This round does not send out direct messages".into())
    }

    /// Processes a direct messsage received from the party `from`.
    fn verify_direct_message(
        &self,
        #[allow(unused_variables)] from: PartyIdx,
        #[allow(unused_variables)] msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        Err(ReceiveError::InvalidType)
    }
}

/// Typed outcomes of a protocol, specific for each protocol
/// (in addition to non-specific errors common for all protocols).
pub trait ProtocolResult: Debug {
    /// The result obtained on successful termination of the protocol.
    type Success;
    /// A collection of data which, in combination with the messages received,
    /// can be used to prove malicious behavior of a remote node.
    type ProvableError: Debug + Clone;
    /// A collection of data which, in combination with the messages received,
    /// can be used to prove correct behavior of this node.
    ///
    /// That is, on errors where the culprit cannot be immediately identified,
    /// each node will have to provide the correctness proof for itself.
    type CorrectnessProof: Debug + Clone;
}

pub trait FinalizableType {}

pub struct ToResult;

impl FinalizableType for ToResult {}

pub struct ToNextRound;

impl FinalizableType for ToNextRound {}

pub(crate) trait BaseRound {
    type Type: FinalizableType;
    type Result: ProtocolResult;
    const ROUND_NUM: u8;
    // TODO (#78): find a way to derive it from `ROUND_NUM`
    const NEXT_ROUND_NUM: Option<u8>;
}

pub(crate) trait Round: BroadcastRound + DirectRound + BaseRound {}

impl<R: BroadcastRound + DirectRound + BaseRound> Round for R {}

pub(crate) trait FinalizableToResult: Round + BaseRound<Type = ToResult> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        dm_artifacts: Option<HoleVec<<Self as DirectRound>::Artifact>>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>>;
}

pub(crate) trait FinalizableToNextRound: Round + BaseRound<Type = ToNextRound> {
    type NextRound: Round<Result = Self::Result>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        dm_artifacts: Option<HoleVec<<Self as DirectRound>::Artifact>>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>>;
}

#[derive(Debug, Clone)]
pub enum ReceiveError<Res: ProtocolResult> {
    Provable(Res::ProvableError),
    /// This round does not expect messages of the given type (broadcast/direct)
    InvalidType,
}

#[derive(Debug, Clone)]
pub enum FinalizeError<Res: ProtocolResult> {
    Provable {
        party: PartyIdx,
        error: Res::ProvableError,
    },
    Proof(Res::CorrectnessProof),
    /// Returned when there is an error chaining the start of another protocol
    /// on the finalization of the previous one.
    Init(InitError),
}

/// An error that can occur when initializing a protocol.
#[derive(Debug, Clone)]
pub struct InitError(pub(crate) String);

pub(crate) trait FirstRound: Round + Sized {
    type Context;
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        context: Self::Context,
    ) -> Result<Self, InitError>;
}
