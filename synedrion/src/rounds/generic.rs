use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use core::fmt::Debug;

use displaydoc::Display;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

/// A type suitable to serve as a party identifier.
pub trait PartyId: Debug + Ord + Clone + Serialize + for<'de> Deserialize<'de> {}

impl<T: Debug + Ord + Clone + Serialize + for<'de> Deserialize<'de>> PartyId for T {}

/// A round that sends out direct messages.
pub(crate) trait Round<I: PartyId> {
    type Type: FinalizableType;
    type Result: ProtocolResult<I>;
    const ROUND_NUM: u8;
    // TODO (#78): find a way to derive it from `ROUND_NUM`
    const NEXT_ROUND_NUM: Option<u8>;

    fn other_ids(&self) -> &BTreeSet<I>;
    fn my_id(&self) -> &I;

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
    // Assuming these destinations are for both broadcast and direct messages;
    // the broadcasts are only separated to allow optimizations (create once, sign once)
    // and support echo-broadcasting.
    fn message_destinations(&self) -> &BTreeSet<I> {
        self.other_ids()
    }

    fn expecting_messages_from(&self) -> &BTreeSet<I> {
        self.other_ids()
    }

    /// Creates the direct message for the given party.
    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &I,
    ) -> (Self::DirectMessage, Self::Artifact);

    /// Creates the broadcast message.
    ///
    /// Returns ``None`` if the node does not send messages this round
    /// (that is, [`message_destinations`] returns an empty list).
    fn make_broadcast_message(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage>;

    /// Processes a direct messsage received from the party `from`.
    // Note that since we assume broadcast and direct messages have the same list of destinations,
    // if `BroadcastMessage` is not `()` there will be a serialized broadcast
    // in the received message, from which we can construct `broadcast_msg`.
    fn verify_message(
        &self,
        rng: &mut impl CryptoRngCore,
        from: &I,
        broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult<I>>::ProvableError>;

    fn finalization_requirement() -> FinalizationRequirement {
        FinalizationRequirement::All
    }

    fn can_finalize(&self, received: &BTreeSet<I>) -> bool {
        match Self::finalization_requirement() {
            FinalizationRequirement::All => self.other_ids().is_subset(received),
            FinalizationRequirement::Custom => panic!("`can_finalize` must be implemented"),
        }
    }

    fn missing_messages(&self, received: &BTreeSet<I>) -> BTreeSet<I> {
        match Self::finalization_requirement() {
            FinalizationRequirement::All => {
                self.other_ids().difference(received).cloned().collect()
            }
            FinalizationRequirement::Custom => panic!("`missing_messages` must be implemented"),
        }
    }
}

/// Typed outcomes of a protocol, specific for each protocol
/// (in addition to non-specific errors common for all protocols).
pub trait ProtocolResult<I>: Debug {
    /// The result obtained on successful termination of the protocol.
    type Success;
    /// A collection of data which, in combination with the messages received,
    /// can be used to prove malicious behavior of a remote node.
    type ProvableError: Debug + Clone + EvidenceRequiresMessages<I>;
    /// A collection of data which, in combination with the messages received,
    /// can be used to prove correct behavior of this node.
    ///
    /// That is, on errors where the culprit cannot be immediately identified,
    /// each node will have to provide the correctness proof for itself.
    type CorrectnessProof: Debug;
}

// This trait is used to fix the possible options for `Round::Type`.
// Techincally it is not used besides that, so clippy complains.
#[allow(dead_code)]
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

pub(crate) trait FinalizableToResult<I: PartyId>: Round<I, Type = ToResult> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult<I>>::Success, FinalizeError<I, Self::Result>>;
}

pub(crate) trait FinalizableToNextRound<I: PartyId>: Round<I, Type = ToNextRound> {
    type NextRound: Round<I, Result = Self::Result>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<I, Self::Result>>;
}

#[derive(Debug)]
pub enum FinalizeError<I, Res: ProtocolResult<I>> {
    Proof(Res::CorrectnessProof),
    /// Returned when there is an error chaining the start of another protocol
    /// on the finalization of the previous one.
    Init(InitError),
}

/// An error that can occur when initializing a protocol.
#[derive(Debug, Clone, Display)]
#[displaydoc("Error when initializing a protocol ({0})")]
pub struct InitError(pub(crate) String);

pub(crate) trait FirstRound<I: PartyId>: Round<I> + Sized {
    type Inputs;
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        other_ids: BTreeSet<I>,
        my_id: I,
        inputs: Self::Inputs,
    ) -> Result<Self, InitError>;
}

// These will be possible to do via trait specialization when it becomes stable.

macro_rules! no_broadcast_messages {
    () => {
        fn make_broadcast_message(
            &self,
            _rng: &mut impl CryptoRngCore,
        ) -> Option<Self::BroadcastMessage> {
            Some(())
        }
    };
}

pub(crate) use no_broadcast_messages;

macro_rules! no_direct_messages {
    ($id_type: ty) => {
        fn make_direct_message(
            &self,
            _rng: &mut impl CryptoRngCore,
            _destination: &$id_type,
        ) -> (Self::DirectMessage, Self::Artifact) {
            ((), ())
        }
    };
}

pub(crate) use no_direct_messages;

use crate::sessions::Message;

/// A trait specifying which messages the evidence needs to prove a party's fault,
/// and how to do it.
// TODO: rename this
// TODO (#74): this trait should not be visible to the user,
// but I can't figure out at the moment how to do that.
pub trait EvidenceRequiresMessages<I> {
    /// Returns the list of rounds and the indicator of whether a regular message
    /// or the echo of all messages is needed.
    fn requires_bcs(&self) -> &[u8] {
        unimplemented!()
    }

    fn requires_dms(&self) -> &[u8] {
        unimplemented!()
    }

    fn requires_echos(&self) -> &[u8] {
        unimplemented!()
    }

    /// Given the required messages, returns ``true`` if the party was proven to be malicious.
    fn verify_malicious(
        &self,
        _shared_randomness: &[u8],
        _other_ids: &BTreeSet<I>,
        _my_id: &I,
        _bcs: &BTreeMap<u8, Message>,
        _dms: &BTreeMap<u8, Message>,
        _echos: &BTreeMap<u8, Message>,
    ) -> bool {
        unimplemented!()
    }
}

impl<I> EvidenceRequiresMessages<I> for () {}
