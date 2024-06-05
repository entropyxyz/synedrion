/*!
This module maps the static typed interface of the rounds into boxable traits.
This way they can be used in a state machine loop without code repetition.
*/

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::any::{Any, TypeId};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::error::LocalError;
use crate::rounds::{
    self, FinalizableToNextRound, FinalizableToResult, PartyIdx, ProtocolResult, Round,
    ToNextRound, ToResult,
};

pub(crate) fn serialize_message(message: &impl Serialize) -> Result<Box<[u8]>, LocalError> {
    bincode::serialize(message)
        .map(|serialized| serialized.into_boxed_slice())
        .map_err(|err| LocalError(format!("Failed to serialize: {err:?}")))
}

pub(crate) fn deserialize_message<M: for<'de> Deserialize<'de>>(
    message_bytes: &[u8],
) -> Result<M, String> {
    bincode::deserialize(message_bytes).map_err(|err| err.to_string())
}

pub(crate) enum FinalizeOutcome<Res: ProtocolResult> {
    Success(Res::Success),
    AnotherRound(Box<dyn DynFinalizable<Res>>),
}

#[derive(Debug, Clone, Copy)]
pub enum AccumAddError {
    /// An item with the given origin has already been added to the accumulator.
    SlotTaken,
}

#[derive(Debug, Clone)]
pub enum AccumFinalizeError {
    // Rustc thinks the String field is never accessed, which is incorrect.
    #[allow(dead_code)]
    Downcast(String),
}

#[derive(Debug, Clone)]
pub(crate) enum ReceiveError<Res: ProtocolResult> {
    InvalidContents(String),
    /// Error while deserializing the given message.
    CannotDeserialize(String),
    /// An error from the protocol level
    Protocol(Res::ProvableError),
}

#[derive(Debug, Clone)]
pub(crate) enum FinalizeError<Res: ProtocolResult> {
    /// An error from the protocol level
    Protocol(rounds::FinalizeError<Res>),
    /// Cannot finalize (an accumulator still has empty slots).
    Accumulator(AccumFinalizeError),
}

/// Since object-safe trait methods cannot take `impl CryptoRngCore` arguments,
/// this structure wraps the dynamic object and exposes a `CryptoRngCore` interface,
/// to be passed to statically typed round methods.
struct BoxedRng<'a>(&'a mut dyn CryptoRngCore);

impl<'a> rand_core::CryptoRng for BoxedRng<'a> {}

impl<'a> rand_core::RngCore for BoxedRng<'a> {
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
pub(crate) trait DynRound<Res: ProtocolResult>: Send + Sync {
    fn round_num(&self) -> u8;
    fn next_round_num(&self) -> Option<u8>;

    fn requires_echo(&self) -> bool;
    fn message_destinations(&self) -> Vec<PartyIdx>;
    fn make_broadcast_message(
        &self,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Option<Box<[u8]>>, LocalError>;
    #[allow(clippy::type_complexity)]
    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Option<Box<[u8]>>, DynArtifact), LocalError>;
    fn verify_message(
        &self,
        from: PartyIdx,
        broadcast_data: Option<&[u8]>,
        direct_data: Option<&[u8]>,
    ) -> Result<DynPayload, ReceiveError<Res>>;
    fn can_finalize(&self, accum: &DynRoundAccum) -> bool;
    fn missing_payloads(&self, accum: &DynRoundAccum) -> BTreeSet<PartyIdx>;
}

fn is_null_type<T: 'static>() -> bool {
    TypeId::of::<T>() == TypeId::of::<()>()
}

impl<R> DynRound<R::Result> for R
where
    R: Round + Send + Sync,
    <R as Round>::BroadcastMessage: 'static,
    <R as Round>::DirectMessage: 'static,
    <R as Round>::Payload: 'static + Send,
    <R as Round>::Artifact: 'static + Send,
{
    fn round_num(&self) -> u8 {
        R::ROUND_NUM
    }

    fn next_round_num(&self) -> Option<u8> {
        R::NEXT_ROUND_NUM
    }

    fn message_destinations(&self) -> Vec<PartyIdx> {
        self.message_destinations()
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
        destination: PartyIdx,
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
        from: PartyIdx,
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

        let broadcast_message: <R as Round>::BroadcastMessage =
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

        let direct_message: <R as Round>::DirectMessage = match deserialize_message(direct_data) {
            Ok(message) => message,
            Err(err) => return Err(ReceiveError::CannotDeserialize(err)),
        };

        let payload = self
            .verify_message(from, broadcast_message, direct_message)
            .map_err(ReceiveError::Protocol)?;

        Ok(DynPayload(Box::new(payload)))
    }

    fn requires_echo(&self) -> bool {
        <R as Round>::REQUIRES_ECHO
    }

    fn can_finalize(&self, accum: &DynRoundAccum) -> bool {
        self.can_finalize(accum.payloads.keys(), accum.artifacts.keys())
    }

    fn missing_payloads(&self, accum: &DynRoundAccum) -> BTreeSet<PartyIdx> {
        self.missing_payloads(accum.payloads.keys(), accum.artifacts.keys())
    }
}

pub(crate) struct DynRoundAccum {
    payloads: BTreeMap<PartyIdx, DynPayload>,
    artifacts: BTreeMap<PartyIdx, DynArtifact>,
}

struct RoundAccum<R: Round> {
    payloads: BTreeMap<PartyIdx, <R as Round>::Payload>,
    artifacts: BTreeMap<PartyIdx, <R as Round>::Artifact>,
}

impl DynRoundAccum {
    pub fn new() -> Self {
        Self {
            payloads: BTreeMap::new(),
            artifacts: BTreeMap::new(),
        }
    }

    pub fn contains(&self, from: PartyIdx) -> bool {
        self.payloads.contains_key(&from)
    }

    pub fn add_payload(
        &mut self,
        from: PartyIdx,
        payload: DynPayload,
    ) -> Result<(), AccumAddError> {
        if self.payloads.contains_key(&from) {
            return Err(AccumAddError::SlotTaken);
        }
        self.payloads.insert(from, payload);
        Ok(())
    }

    pub fn add_artifact(
        &mut self,
        destination: PartyIdx,
        artifact: DynArtifact,
    ) -> Result<(), AccumAddError> {
        if self.artifacts.contains_key(&destination) {
            return Err(AccumAddError::SlotTaken);
        }
        self.artifacts.insert(destination, artifact);
        Ok(())
    }

    fn finalize<R: Round>(self) -> Result<RoundAccum<R>, AccumFinalizeError>
    where
        <R as Round>::Payload: 'static,
        <R as Round>::Artifact: 'static,
    {
        let payloads = self
            .payloads
            .into_iter()
            .map(|(idx, elem)| downcast::<<R as Round>::Payload>(elem.0).map(|elem| (idx, elem)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let artifacts = self
            .artifacts
            .into_iter()
            .map(|(idx, elem)| downcast::<<R as Round>::Artifact>(elem.0).map(|elem| (idx, elem)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(RoundAccum {
            payloads,
            artifacts,
        })
    }
}

fn downcast<T: 'static>(boxed: Box<dyn Any>) -> Result<T, AccumFinalizeError> {
    Ok(*(boxed.downcast::<T>().map_err(|_| {
        AccumFinalizeError::Downcast(format!(
            "Failed to downcast into {}",
            core::any::type_name::<T>()
        ))
    })?))
}

pub(crate) trait DynFinalizable<Res: ProtocolResult>: DynRound<Res> {
    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        accum: DynRoundAccum,
    ) -> Result<FinalizeOutcome<Res>, FinalizeError<Res>>;
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

    trait _DynFinalizable<Res: ProtocolResult, T> {
        fn finalize(
            self: Box<Self>,
            rng: &mut dyn CryptoRngCore,
            accum: DynRoundAccum,
        ) -> Result<FinalizeOutcome<Res>, FinalizeError<Res>>;
    }

    impl<R> DynFinalizable<R::Result> for R
    where
        R: Round + Send + Sync + 'static,
        <R as Round>::Payload: Send,
        <R as Round>::Artifact: Send,
        Self: _DynFinalizable<R::Result, R::Type>,
    {
        fn finalize(
            self: Box<Self>,
            rng: &mut dyn CryptoRngCore,
            accum: DynRoundAccum,
        ) -> Result<FinalizeOutcome<R::Result>, FinalizeError<R::Result>> {
            Self::finalize(self, rng, accum)
        }
    }

    // Actual diverging implementations.

    impl<R> _DynFinalizable<R::Result, ToResult> for R
    where
        R: 'static + FinalizableToResult,
    {
        fn finalize(
            self: Box<Self>,
            rng: &mut dyn CryptoRngCore,
            accum: DynRoundAccum,
        ) -> Result<FinalizeOutcome<R::Result>, FinalizeError<R::Result>> {
            let mut boxed_rng = BoxedRng(rng);
            let typed_accum = accum.finalize::<R>().map_err(FinalizeError::Accumulator)?;
            let result = (*self)
                .finalize_to_result(&mut boxed_rng, typed_accum.payloads, typed_accum.artifacts)
                .map_err(FinalizeError::Protocol)?;
            Ok(FinalizeOutcome::Success(result))
        }
    }

    impl<R> _DynFinalizable<R::Result, ToNextRound> for R
    where
        R: 'static + FinalizableToNextRound,
        <R as FinalizableToNextRound>::NextRound: DynFinalizable<R::Result>,
    {
        fn finalize(
            self: Box<Self>,
            rng: &mut dyn CryptoRngCore,
            accum: DynRoundAccum,
        ) -> Result<FinalizeOutcome<R::Result>, FinalizeError<R::Result>> {
            let mut boxed_rng = BoxedRng(rng);
            let typed_accum = accum.finalize::<R>().map_err(FinalizeError::Accumulator)?;
            let next_round = (*self)
                .finalize_to_next_round(&mut boxed_rng, typed_accum.payloads, typed_accum.artifacts)
                .map_err(FinalizeError::Protocol)?;
            Ok(FinalizeOutcome::AnotherRound(Box::new(next_round)))
        }
    }
};
