/*!
This module maps the static typed interface of the rounds into boxable traits.
This way they can be used in a state machine loop without code repetition.
*/

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use core::any::{Any, TypeId};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::error::LocalError;
use crate::rounds::{
    self, FinalizableToNextRound, FinalizableToResult, ProtocolResult, Round, ToNextRound, ToResult,
};

pub(crate) fn serialize_message(message: &impl Serialize) -> Result<Box<[u8]>, LocalError> {
    bincode::serde::encode_to_vec(message, bincode::config::standard())
        .map(|serialized| serialized.into_boxed_slice())
        .map_err(|err| LocalError(format!("Failed to serialize: {err:?}")))
}

pub(crate) fn deserialize_message<M: for<'de> Deserialize<'de>>(
    message_bytes: &[u8],
) -> Result<M, String> {
    bincode::serde::decode_borrowed_from_slice(message_bytes, bincode::config::standard())
        .map_err(|err| err.to_string())
}

pub(crate) enum FinalizeOutcome<I, Res: ProtocolResult> {
    Success(Res::Success),
    AnotherRound(Box<dyn DynFinalizable<I, Res>>),
}

#[derive(Debug)]
pub enum AccumAddError {
    /// An item with the given origin has already been added to the accumulator.
    SlotTaken,
}

#[derive(Debug)]
pub(crate) enum ReceiveError<Res: ProtocolResult> {
    InvalidContents(String),
    /// Error while deserializing the given message.
    CannotDeserialize(String),
    /// An error from the protocol level
    Protocol(Res::ProvableError),
}

#[derive(Debug)]
pub(crate) enum FinalizeError<Res: ProtocolResult> {
    /// An error from the protocol level
    Protocol(rounds::FinalizeError<Res>),
    /// Cannot finalize.
    Accumulator(String),
}

/// Since object-safe trait methods cannot take `impl CryptoRngCore` arguments,
/// this structure wraps the dynamic object and exposes a `CryptoRngCore` interface,
/// to be passed to statically typed round methods.
struct BoxedRng<'a>(&'a mut dyn CryptoRngCore);

impl rand_core::CryptoRng for BoxedRng<'_> {}

impl rand_core::RngCore for BoxedRng<'_> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

pub(crate) struct DynPayload(Box<dyn Any + Send>);

pub(crate) struct DynArtifact(Box<dyn Any + Send>);

impl DynArtifact {
    pub fn null() -> Self {
        Self(Box::new(()))
    }
}

/// An object-safe trait wrapping `Round`.
pub(crate) trait DynRound<I, Res: ProtocolResult>: Send + Sync {
    fn round_num(&self) -> u8;
    fn next_round_num(&self) -> Option<u8>;

    fn requires_echo(&self) -> bool;
    fn message_destinations(&self) -> &BTreeSet<I>;
    fn expecting_messages_from(&self) -> &BTreeSet<I>;
    fn make_broadcast_message(
        &self,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Option<Box<[u8]>>, LocalError>;
    #[allow(clippy::type_complexity)]
    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        destination: &I,
    ) -> Result<(Option<Box<[u8]>>, DynArtifact), LocalError>;
    fn verify_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        from: &I,
        broadcast_data: Option<&[u8]>,
        direct_data: Option<&[u8]>,
    ) -> Result<DynPayload, ReceiveError<Res>>;
    fn can_finalize(&self, accum: &DynRoundAccum<I>) -> bool;
    fn missing_messages(&self, accum: &DynRoundAccum<I>) -> BTreeSet<I>;
}

fn is_null_type<T: 'static>() -> bool {
    TypeId::of::<T>() == TypeId::of::<()>()
}

impl<I, R> DynRound<I, R::Result> for R
where
    I: Ord + Clone,
    R: Round<I> + Send + Sync,
    <R as Round<I>>::BroadcastMessage: 'static,
    <R as Round<I>>::DirectMessage: 'static,
    <R as Round<I>>::Payload: 'static + Send,
    <R as Round<I>>::Artifact: 'static + Send,
{
    fn round_num(&self) -> u8 {
        R::ROUND_NUM
    }

    fn next_round_num(&self) -> Option<u8> {
        R::NEXT_ROUND_NUM
    }

    fn message_destinations(&self) -> &BTreeSet<I> {
        self.message_destinations()
    }

    fn expecting_messages_from(&self) -> &BTreeSet<I> {
        self.expecting_messages_from()
    }

    fn make_broadcast_message(
        &self,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Option<Box<[u8]>>, LocalError> {
        if is_null_type::<R::BroadcastMessage>() {
            return Ok(None);
        }

        let mut boxed_rng = BoxedRng(rng);
        let typed_message = self.make_broadcast_message(&mut boxed_rng);
        let serialized = typed_message
            .map(|message| serialize_message(&message))
            .transpose()?;
        Ok(serialized)
    }

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        destination: &I,
    ) -> Result<(Option<Box<[u8]>>, DynArtifact), LocalError> {
        let null_message = is_null_type::<R::DirectMessage>();
        let null_artifact = is_null_type::<R::Artifact>();

        if null_message && null_artifact {
            return Ok((None, DynArtifact::null()));
        }

        let mut boxed_rng = BoxedRng(rng);
        let (typed_message, typed_artifact) = self.make_direct_message(&mut boxed_rng, destination);

        let message = if null_message {
            None
        } else {
            Some(serialize_message(&typed_message)?)
        };

        Ok((message, DynArtifact(Box::new(typed_artifact))))
    }

    fn verify_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        from: &I,
        broadcast_data: Option<&[u8]>,
        direct_data: Option<&[u8]>,
    ) -> Result<DynPayload, ReceiveError<R::Result>> {
        let null_broadcast = is_null_type::<R::BroadcastMessage>();
        let null_direct = is_null_type::<R::DirectMessage>();

        let broadcast_data = if let Some(data) = broadcast_data {
            data
        } else {
            if !null_broadcast {
                return Err(ReceiveError::InvalidContents(
                    "Expected a non-null broadcast message".into(),
                ));
            }
            b""
        };

        let broadcast_message: <R as Round<I>>::BroadcastMessage =
            match deserialize_message(broadcast_data) {
                Ok(message) => message,
                Err(err) => return Err(ReceiveError::CannotDeserialize(err)),
            };

        let direct_data = if let Some(data) = direct_data {
            data
        } else {
            if !null_direct {
                return Err(ReceiveError::InvalidContents(
                    "Expected a non-null direct message".into(),
                ));
            }
            b""
        };

        let direct_message: <R as Round<I>>::DirectMessage = match deserialize_message(direct_data)
        {
            Ok(message) => message,
            Err(err) => return Err(ReceiveError::CannotDeserialize(err)),
        };

        let mut boxed_rng = BoxedRng(rng);

        let payload = self
            .verify_message(&mut boxed_rng, from, broadcast_message, direct_message)
            .map_err(ReceiveError::Protocol)?;

        Ok(DynPayload(Box::new(payload)))
    }

    fn requires_echo(&self) -> bool {
        <R as Round<I>>::REQUIRES_ECHO
    }

    fn can_finalize(&self, accum: &DynRoundAccum<I>) -> bool {
        self.can_finalize(&accum.received)
    }

    fn missing_messages(&self, accum: &DynRoundAccum<I>) -> BTreeSet<I> {
        self.missing_messages(&accum.received)
    }
}

pub(crate) struct DynRoundAccum<I> {
    received: BTreeSet<I>,
    payloads: BTreeMap<I, DynPayload>,
    artifacts: BTreeMap<I, DynArtifact>,
}

struct RoundAccum<I: Ord + Clone, R: Round<I>> {
    payloads: BTreeMap<I, <R as Round<I>>::Payload>,
    artifacts: BTreeMap<I, <R as Round<I>>::Artifact>,
}

impl<I: Ord + Clone> DynRoundAccum<I> {
    pub fn new() -> Self {
        Self {
            received: BTreeSet::new(),
            payloads: BTreeMap::new(),
            artifacts: BTreeMap::new(),
        }
    }

    pub fn contains(&self, from: &I) -> bool {
        self.received.contains(from)
    }

    pub fn add_payload(&mut self, from: &I, payload: DynPayload) -> Result<(), AccumAddError> {
        if self.received.contains(from) {
            return Err(AccumAddError::SlotTaken);
        }
        self.received.insert(from.clone());
        self.payloads.insert(from.clone(), payload);
        Ok(())
    }

    pub fn add_artifact(
        &mut self,
        destination: &I,
        artifact: DynArtifact,
    ) -> Result<(), AccumAddError> {
        if self.artifacts.contains_key(destination) {
            return Err(AccumAddError::SlotTaken);
        }
        self.artifacts.insert(destination.clone(), artifact);
        Ok(())
    }

    fn finalize<R: Round<I>>(self) -> Result<RoundAccum<I, R>, String>
    where
        <R as Round<I>>::Payload: 'static,
        <R as Round<I>>::Artifact: 'static,
    {
        let payloads = self
            .payloads
            .into_iter()
            .map(|(id, elem)| downcast::<<R as Round<I>>::Payload>(elem.0).map(|elem| (id, elem)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let artifacts = self
            .artifacts
            .into_iter()
            .map(|(id, elem)| downcast::<<R as Round<I>>::Artifact>(elem.0).map(|elem| (id, elem)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(RoundAccum {
            payloads,
            artifacts,
        })
    }
}

fn downcast<T: 'static>(boxed: Box<dyn Any>) -> Result<T, String> {
    Ok(*(boxed
        .downcast::<T>()
        .map_err(|_| format!("Failed to downcast into {}", core::any::type_name::<T>()))?))
}

pub(crate) trait DynFinalizable<I, Res: ProtocolResult>: DynRound<I, Res> {
    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        accum: DynRoundAccum<I>,
    ) -> Result<FinalizeOutcome<I, Res>, FinalizeError<Res>>;
}

// This is needed because Rust does not currently support exclusive trait implementations.
// We want to implement `DynFinalizable` depending on whether the type is
// `FinalizableToResult` or `FinalizableToNextRound`.
// A way to do it is to exploit the fact that a trait with an associated type (in our case, `Round`)
// can only be implemented for one value of the associated type (in our case, `Round::Type`),
// and the compiler knows that.
const _: () = {
    // This is the boilerplate:
    // 1) A helper trait parametrized by a type `T` that will take the values
    //    of the target associated type, with the same methods as the target trait;
    // 2) A blanket implementation for the target trait.

    trait _DynFinalizable<I, Res: ProtocolResult, T> {
        fn finalize(
            self: Box<Self>,
            rng: &mut dyn CryptoRngCore,
            accum: DynRoundAccum<I>,
        ) -> Result<FinalizeOutcome<I, Res>, FinalizeError<Res>>;
    }

    impl<I, R> DynFinalizable<I, R::Result> for R
    where
        I: Ord + Clone,
        R: Round<I> + Send + Sync + 'static,
        <R as Round<I>>::BroadcastMessage: 'static,
        <R as Round<I>>::DirectMessage: 'static,
        <R as Round<I>>::Payload: Send + 'static,
        <R as Round<I>>::Artifact: Send + 'static,
        Self: _DynFinalizable<I, R::Result, R::Type>,
    {
        fn finalize(
            self: Box<Self>,
            rng: &mut dyn CryptoRngCore,
            accum: DynRoundAccum<I>,
        ) -> Result<FinalizeOutcome<I, R::Result>, FinalizeError<R::Result>> {
            Self::finalize(self, rng, accum)
        }
    }

    // Actual diverging implementations.

    impl<I, R> _DynFinalizable<I, R::Result, ToResult> for R
    where
        I: Ord + Clone,
        <R as Round<I>>::Payload: Send + 'static,
        <R as Round<I>>::Artifact: Send + 'static,
        R: 'static + FinalizableToResult<I>,
    {
        fn finalize(
            self: Box<Self>,
            rng: &mut dyn CryptoRngCore,
            accum: DynRoundAccum<I>,
        ) -> Result<FinalizeOutcome<I, R::Result>, FinalizeError<R::Result>> {
            let mut boxed_rng = BoxedRng(rng);
            let typed_accum = accum.finalize::<R>().map_err(FinalizeError::Accumulator)?;
            let result = (*self)
                .finalize_to_result(&mut boxed_rng, typed_accum.payloads, typed_accum.artifacts)
                .map_err(FinalizeError::Protocol)?;
            Ok(FinalizeOutcome::Success(result))
        }
    }

    impl<I, R> _DynFinalizable<I, R::Result, ToNextRound> for R
    where
        I: Ord + Clone,
        <R as Round<I>>::Payload: Send + 'static,
        <R as Round<I>>::Artifact: Send + 'static,
        R: 'static + FinalizableToNextRound<I>,
        <R as FinalizableToNextRound<I>>::NextRound: DynFinalizable<I, R::Result> + 'static,
    {
        fn finalize(
            self: Box<Self>,
            rng: &mut dyn CryptoRngCore,
            accum: DynRoundAccum<I>,
        ) -> Result<FinalizeOutcome<I, R::Result>, FinalizeError<R::Result>> {
            let mut boxed_rng = BoxedRng(rng);
            let typed_accum = accum.finalize::<R>().map_err(FinalizeError::Accumulator)?;
            let next_round = (*self)
                .finalize_to_next_round(&mut boxed_rng, typed_accum.payloads, typed_accum.artifacts)
                .map_err(FinalizeError::Protocol)?;
            Ok(FinalizeOutcome::AnotherRound(Box::new(next_round)))
        }
    }
};
