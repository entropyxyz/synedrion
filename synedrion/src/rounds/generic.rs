use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;

use displaydoc::Display;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::tools::collections::{HoleRange, HoleVec, HoleVecAccum};
use crate::tools::hashing::{Chain, Hashable};

/// A typed integer denoting the index of a party in the group.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PartyIdx(u32);

impl PartyIdx {
    /// Converts the party index to a regular integer.
    pub fn as_usize(self) -> usize {
        self.0.try_into().unwrap()
    }

    /// Wraps an integers into the party index.
    pub fn from_usize(val: usize) -> Self {
        Self(val.try_into().unwrap())
    }
}

impl Hashable for PartyIdx {
    fn chain<C: Chain>(&self, digest: C) -> C {
        digest.chain(&self.0)
    }
}

/// A round that sends out direct messages.
pub(crate) trait Round {
    type Type: FinalizableType;
    type Result: ProtocolResult;
    const ROUND_NUM: u8;
    // TODO (#78): find a way to derive it from `ROUND_NUM`
    const NEXT_ROUND_NUM: Option<u8>;

    fn num_parties(&self) -> usize;
    fn party_idx(&self) -> PartyIdx;

    /// The part of the message sent directly to nodes, and can be different for each node.
    type DirectMessage: Serialize + for<'de> Deserialize<'de>;

    /// The part of the message that is the same for each destination node.
    type BroadcastMessage: Serialize + for<'de> Deserialize<'de>;

    /// Whether all the nodes receiving the broadcast should make sure they got the same message.
    const REQUIRES_ECHO: bool = false;

    /// The processed message from another node, to be collected to finalize the round.
    type Payload;

    /// Data created when creating a message, to be preserved until the finalization stage.
    type Artifact;

    /// The indices of the parties that should receive the messages.
    fn message_destinations(&self) -> Vec<PartyIdx>;

    /// Creates the direct message for the given party.
    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> (Self::DirectMessage, Self::Artifact);

    /// Creates the broadcast message.
    fn make_broadcast_message(&self, rng: &mut impl CryptoRngCore) -> Self::BroadcastMessage;

    /// Processes a direct messsage received from the party `from`.
    fn verify_message(
        &self,
        from: PartyIdx,
        broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>>;

    fn finalization_requirement() -> FinalizationRequirement {
        FinalizationRequirement::All
    }

    fn can_finalize<'a>(
        &self,
        payloads: impl Iterator<Item = &'a PartyIdx>,
        artifacts: impl Iterator<Item = &'a PartyIdx>,
    ) -> bool {
        match Self::finalization_requirement() {
            FinalizationRequirement::All => {
                contains_all_except(payloads, self.num_parties(), self.party_idx())
                    && contains_all_except(artifacts, self.num_parties(), self.party_idx())
            }
            FinalizationRequirement::Custom => panic!("`can_finalize` must be implemented"),
        }
    }

    fn missing_payloads<'a>(
        &self,
        payloads: impl Iterator<Item = &'a PartyIdx>,
        artifacts: impl Iterator<Item = &'a PartyIdx>,
    ) -> BTreeSet<PartyIdx> {
        match Self::finalization_requirement() {
            FinalizationRequirement::All => {
                let mut missing = missing_payloads(payloads, self.num_parties(), self.party_idx());
                missing.append(&mut missing_payloads(
                    artifacts,
                    self.num_parties(),
                    self.party_idx(),
                ));
                missing
            }
            FinalizationRequirement::Custom => panic!("`missing_payloads` must be implemented"),
        }
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

#[allow(clippy::enum_variant_names)]
pub(crate) enum FinalizationRequirement {
    All,
    Custom,
}

pub(crate) trait FinalizableToResult: Round<Type = ToResult> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>>;
}

pub(crate) trait FinalizableToNextRound: Round<Type = ToNextRound> {
    type NextRound: Round<Result = Self::Result>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>>;
}

#[derive(Debug, Clone)]
pub enum ReceiveError<Res: ProtocolResult> {
    Provable(Res::ProvableError),
}

#[derive(Debug, Clone)]
pub enum FinalizeError<Res: ProtocolResult> {
    Proof(Res::CorrectnessProof),
    /// Returned when there is an error chaining the start of another protocol
    /// on the finalization of the previous one.
    Init(InitError),
}

/// An error that can occur when initializing a protocol.
#[derive(Debug, Clone, Display)]
#[displaydoc("Error when initializing a protocol ({0})")]
pub struct InitError(pub(crate) String);

pub(crate) trait FirstRound: Round + Sized {
    type Inputs;
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        inputs: Self::Inputs,
    ) -> Result<Self, InitError>;
}

pub(crate) fn all_parties_except(num_parties: usize, party_idx: PartyIdx) -> Vec<PartyIdx> {
    HoleRange::new(num_parties, party_idx.as_usize())
        .map(PartyIdx::from_usize)
        .collect()
}

fn contains_all_except<'a>(
    party_idxs: impl Iterator<Item = &'a PartyIdx>,
    num_parties: usize,
    party_idx: PartyIdx,
) -> bool {
    let set = party_idxs.cloned().collect::<BTreeSet<_>>();
    for idx in HoleRange::new(num_parties, party_idx.as_usize()) {
        if !set.contains(&PartyIdx::from_usize(idx)) {
            return false;
        }
    }
    true
}

fn missing_payloads<'a>(
    party_idxs: impl Iterator<Item = &'a PartyIdx>,
    num_parties: usize,
    party_idx: PartyIdx,
) -> BTreeSet<PartyIdx> {
    let set = party_idxs.cloned().collect::<BTreeSet<_>>();
    let mut missing = BTreeSet::new();
    for idx in HoleRange::new(num_parties, party_idx.as_usize()) {
        let party_idx = PartyIdx::from_usize(idx);
        if !set.contains(&party_idx) {
            missing.insert(party_idx);
        }
    }
    missing
}

pub(crate) fn try_to_holevec<T>(
    payloads: BTreeMap<PartyIdx, T>,
    num_parties: usize,
    party_idx: PartyIdx,
) -> Option<HoleVec<T>> {
    let mut accum = HoleVecAccum::new(num_parties, party_idx.as_usize());
    for (idx, elem) in payloads.into_iter() {
        accum.insert(idx.as_usize(), elem)?;
    }
    accum.finalize()
}

// These will be possible to do via trait specialization when it becomes stable.

macro_rules! no_broadcast_messages {
    () => {
        fn make_broadcast_message(&self, _rng: &mut impl CryptoRngCore) -> Self::BroadcastMessage {}
    };
}

pub(crate) use no_broadcast_messages;

macro_rules! no_direct_messages {
    () => {
        fn make_direct_message(
            &self,
            _rng: &mut impl CryptoRngCore,
            _destination: PartyIdx,
        ) -> (Self::DirectMessage, Self::Artifact) {
            ((), ())
        }
    };
}

pub(crate) use no_direct_messages;
