/*!
This module maps the static typed interface of the rounds into boxable traits.
This way they can be used in a state machine loop without code repetition.
*/

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::any::Any;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::error::LocalError;
use crate::rounds::{
    self, BroadcastRound, DirectRound, FinalizableToNextRound, FinalizableToResult, PartyIdx,
    ProtocolResult, Round, ToNextRound, ToResult,
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
    Downcast(String),
}

#[derive(Debug, Clone)]
pub(crate) enum ReceiveError<Res: ProtocolResult> {
    /// Error while deserializing the given message.
    CannotDeserialize(String),
    /// An error from the protocol level
    Protocol(rounds::ReceiveError<Res>),
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

pub(crate) struct DynBcPayload(Box<dyn Any + Send>);

pub(crate) struct DynDmPayload(Box<dyn Any + Send>);

pub(crate) struct DynDmArtifact(Box<dyn Any + Send>);

/// An object-safe trait wrapping `Round`.
pub(crate) trait DynRound<Res: ProtocolResult>: Send {
    fn round_num(&self) -> u8;
    fn next_round_num(&self) -> Option<u8>;

    fn broadcast_destinations(&self) -> Option<Vec<PartyIdx>>;
    fn make_broadcast(&self, rng: &mut dyn CryptoRngCore) -> Result<Box<[u8]>, LocalError>;
    fn requires_broadcast_consensus(&self) -> bool;
    fn direct_message_destinations(&self) -> Option<Vec<PartyIdx>>;
    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Box<[u8]>, DynDmArtifact), LocalError>;

    fn verify_broadcast(
        &self,
        from: PartyIdx,
        message: &[u8],
    ) -> Result<DynBcPayload, ReceiveError<Res>>;
    fn verify_direct_message(
        &self,
        from: PartyIdx,
        message: &[u8],
    ) -> Result<DynDmPayload, ReceiveError<Res>>;
    fn can_finalize(&self, accum: &DynRoundAccum) -> bool;
    fn missing_payloads(&self, accum: &DynRoundAccum) -> BTreeSet<PartyIdx>;
}

impl<R> DynRound<R::Result> for R
where
    R: Round + Send,
    <R as BroadcastRound>::Payload: 'static + Send,
    <R as DirectRound>::Payload: 'static + Send,
    <R as DirectRound>::Artifact: 'static + Send,
{
    fn round_num(&self) -> u8 {
        R::ROUND_NUM
    }

    fn next_round_num(&self) -> Option<u8> {
        R::NEXT_ROUND_NUM
    }

    fn verify_broadcast(
        &self,
        from: PartyIdx,
        message: &[u8],
    ) -> Result<DynBcPayload, ReceiveError<R::Result>> {
        let typed_message: <R as BroadcastRound>::Message = match deserialize_message(message) {
            Ok(message) => message,
            Err(err) => return Err(ReceiveError::CannotDeserialize(err)),
        };

        let payload = self
            .verify_broadcast(from, typed_message)
            .map_err(ReceiveError::Protocol)?;

        Ok(DynBcPayload(Box::new(payload)))
    }

    fn verify_direct_message(
        &self,
        from: PartyIdx,
        message: &[u8],
    ) -> Result<DynDmPayload, ReceiveError<R::Result>> {
        let typed_message: <R as DirectRound>::Message = match deserialize_message(message) {
            Ok(message) => message,
            Err(err) => return Err(ReceiveError::CannotDeserialize(err)),
        };

        let payload = self
            .verify_direct_message(from, typed_message)
            .map_err(ReceiveError::Protocol)?;

        Ok(DynDmPayload(Box::new(payload)))
    }

    fn broadcast_destinations(&self) -> Option<Vec<PartyIdx>> {
        self.broadcast_destinations()
    }

    fn make_broadcast(&self, rng: &mut dyn CryptoRngCore) -> Result<Box<[u8]>, LocalError> {
        let mut boxed_rng = BoxedRng(rng);
        let serialized = self
            .make_broadcast(&mut boxed_rng)
            .map_err(|err| LocalError(format!("Failed to make a broadcast message: {err:?}")))?;
        serialize_message(&serialized)
    }

    fn requires_broadcast_consensus(&self) -> bool {
        <R as BroadcastRound>::REQUIRES_CONSENSUS
    }

    fn direct_message_destinations(&self) -> Option<Vec<PartyIdx>> {
        self.direct_message_destinations()
    }

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Box<[u8]>, DynDmArtifact), LocalError> {
        let mut boxed_rng = BoxedRng(rng);
        let (typed_message, typed_artifact) = self
            .make_direct_message(&mut boxed_rng, destination)
            .map_err(|err| LocalError(format!("Failed to make a direct message: {err:?}")))?;
        let message = serialize_message(&typed_message)?;
        Ok((message, DynDmArtifact(Box::new(typed_artifact))))
    }

    fn can_finalize(&self, accum: &DynRoundAccum) -> bool {
        self.can_finalize(
            accum.bc_payloads.keys(),
            accum.dm_payloads.keys(),
            accum.dm_artifacts.keys(),
        )
    }

    fn missing_payloads(&self, accum: &DynRoundAccum) -> BTreeSet<PartyIdx> {
        self.missing_payloads(
            accum.bc_payloads.keys(),
            accum.dm_payloads.keys(),
            accum.dm_artifacts.keys(),
        )
    }
}

pub(crate) struct DynRoundAccum {
    bc_payloads: BTreeMap<PartyIdx, DynBcPayload>,
    dm_payloads: BTreeMap<PartyIdx, DynDmPayload>,
    dm_artifacts: BTreeMap<PartyIdx, DynDmArtifact>,
}

struct RoundAccum<R: Round> {
    bc_payloads: BTreeMap<PartyIdx, <R as BroadcastRound>::Payload>,
    dm_payloads: BTreeMap<PartyIdx, <R as DirectRound>::Payload>,
    dm_artifacts: BTreeMap<PartyIdx, <R as DirectRound>::Artifact>,
}

impl DynRoundAccum {
    pub fn new() -> Self {
        Self {
            bc_payloads: BTreeMap::new(),
            dm_payloads: BTreeMap::new(),
            dm_artifacts: BTreeMap::new(),
        }
    }

    pub fn contains(&self, from: PartyIdx, broadcast: bool) -> bool {
        if broadcast {
            self.bc_payloads.contains_key(&from)
        } else {
            self.dm_payloads.contains_key(&from)
        }
    }

    pub fn add_bc_payload(
        &mut self,
        from: PartyIdx,
        payload: DynBcPayload,
    ) -> Result<(), AccumAddError> {
        if self.bc_payloads.contains_key(&from) {
            return Err(AccumAddError::SlotTaken);
        }
        self.bc_payloads.insert(from, payload);
        Ok(())
    }

    pub fn add_dm_payload(
        &mut self,
        from: PartyIdx,
        payload: DynDmPayload,
    ) -> Result<(), AccumAddError> {
        if self.dm_payloads.contains_key(&from) {
            return Err(AccumAddError::SlotTaken);
        }
        self.dm_payloads.insert(from, payload);
        Ok(())
    }

    pub fn add_dm_artifact(
        &mut self,
        destination: PartyIdx,
        artifact: DynDmArtifact,
    ) -> Result<(), AccumAddError> {
        if self.dm_artifacts.contains_key(&destination) {
            return Err(AccumAddError::SlotTaken);
        }
        self.dm_artifacts.insert(destination, artifact);
        Ok(())
    }

    fn finalize<R: Round>(self) -> Result<RoundAccum<R>, AccumFinalizeError>
    where
        <R as BroadcastRound>::Payload: 'static,
        <R as DirectRound>::Payload: 'static,
        <R as DirectRound>::Artifact: 'static,
    {
        let bc_payloads = self
            .bc_payloads
            .into_iter()
            .map(|(idx, elem)| {
                downcast::<<R as BroadcastRound>::Payload>(elem.0).map(|elem| (idx, elem))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let dm_payloads = self
            .dm_payloads
            .into_iter()
            .map(|(idx, elem)| {
                downcast::<<R as DirectRound>::Payload>(elem.0).map(|elem| (idx, elem))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let dm_artifacts = self
            .dm_artifacts
            .into_iter()
            .map(|(idx, elem)| {
                downcast::<<R as DirectRound>::Artifact>(elem.0).map(|elem| (idx, elem))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok(RoundAccum {
            bc_payloads,
            dm_payloads,
            dm_artifacts,
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
        R: Round + Send + 'static,
        <R as BroadcastRound>::Payload: Send,
        <R as DirectRound>::Payload: Send,
        <R as DirectRound>::Artifact: Send,
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
                .finalize_to_result(
                    &mut boxed_rng,
                    typed_accum.bc_payloads,
                    typed_accum.dm_payloads,
                    typed_accum.dm_artifacts,
                )
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
                .finalize_to_next_round(
                    &mut boxed_rng,
                    typed_accum.bc_payloads,
                    typed_accum.dm_payloads,
                    typed_accum.dm_artifacts,
                )
                .map_err(FinalizeError::Protocol)?;
            Ok(FinalizeOutcome::AnotherRound(Box::new(next_round)))
        }
    }
};
