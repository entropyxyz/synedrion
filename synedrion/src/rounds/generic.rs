use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Debug;

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
    fn broadcast_destinations(&self) -> Option<Vec<PartyIdx>> {
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
    fn direct_message_destinations(&self) -> Option<Vec<PartyIdx>> {
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

    fn num_parties(&self) -> usize;
    fn party_idx(&self) -> PartyIdx;
}

pub(crate) trait Round: BroadcastRound + DirectRound + BaseRound + Finalizable {}

impl<R: BroadcastRound + DirectRound + BaseRound + Finalizable> Round for R {}

#[allow(clippy::enum_variant_names)]
pub(crate) enum FinalizationRequirement {
    AllBroadcasts,
    AllDms,
    AllBroadcastsAndDms,
    Custom,
}

pub(crate) trait Finalizable: BroadcastRound + DirectRound {
    fn requirement() -> FinalizationRequirement;

    fn can_finalize<'a>(
        &self,
        bc_payloads: impl Iterator<Item = &'a PartyIdx>,
        dm_payloads: impl Iterator<Item = &'a PartyIdx>,
        dm_artifacts: impl Iterator<Item = &'a PartyIdx>,
    ) -> bool {
        match Self::requirement() {
            FinalizationRequirement::AllBroadcasts => {
                contains_all_except(bc_payloads, self.num_parties(), self.party_idx())
            }
            FinalizationRequirement::AllDms => {
                contains_all_except(dm_payloads, self.num_parties(), self.party_idx())
                    && contains_all_except(dm_artifacts, self.num_parties(), self.party_idx())
            }
            FinalizationRequirement::AllBroadcastsAndDms => {
                contains_all_except(bc_payloads, self.num_parties(), self.party_idx())
                    && contains_all_except(dm_payloads, self.num_parties(), self.party_idx())
                    && contains_all_except(dm_artifacts, self.num_parties(), self.party_idx())
            }
            FinalizationRequirement::Custom => panic!("`can_finalize` must be implemented"),
        }
    }

    fn missing_payloads<'a>(
        &self,
        bc_payloads: impl Iterator<Item = &'a PartyIdx>,
        dm_payloads: impl Iterator<Item = &'a PartyIdx>,
        dm_artifacts: impl Iterator<Item = &'a PartyIdx>,
    ) -> BTreeSet<PartyIdx> {
        match Self::requirement() {
            FinalizationRequirement::AllBroadcasts => {
                missing_payloads(bc_payloads, self.num_parties(), self.party_idx())
            }
            FinalizationRequirement::AllDms => {
                let mut missing =
                    missing_payloads(dm_payloads, self.num_parties(), self.party_idx());
                missing.append(&mut missing_payloads(
                    dm_artifacts,
                    self.num_parties(),
                    self.party_idx(),
                ));
                missing
            }
            FinalizationRequirement::AllBroadcastsAndDms => {
                let mut missing =
                    missing_payloads(bc_payloads, self.num_parties(), self.party_idx());
                missing.append(&mut missing_payloads(
                    dm_payloads,
                    self.num_parties(),
                    self.party_idx(),
                ));
                missing.append(&mut missing_payloads(
                    dm_artifacts,
                    self.num_parties(),
                    self.party_idx(),
                ));
                missing
            }
            FinalizationRequirement::Custom => panic!("`missing_payloads` must be implemented"),
        }
    }
}

pub(crate) trait FinalizableToResult: Round + BaseRound<Type = ToResult> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: BTreeMap<PartyIdx, <Self as BroadcastRound>::Payload>,
        dm_payloads: BTreeMap<PartyIdx, <Self as DirectRound>::Payload>,
        dm_artifacts: BTreeMap<PartyIdx, <Self as DirectRound>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>>;
}

pub(crate) trait FinalizableToNextRound: Round + BaseRound<Type = ToNextRound> {
    type NextRound: Round<Result = Self::Result>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: BTreeMap<PartyIdx, <Self as BroadcastRound>::Payload>,
        dm_payloads: BTreeMap<PartyIdx, <Self as DirectRound>::Payload>,
        dm_artifacts: BTreeMap<PartyIdx, <Self as DirectRound>::Artifact>,
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
