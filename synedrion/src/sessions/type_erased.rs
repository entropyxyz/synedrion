/*!
This module maps the static typed interface of the rounds into boxable traits.
This way they can be used in a state machine loop without code repetition.
*/

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use core::any::Any;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::error::LocalError;
use crate::cggmp21::{
    self, BroadcastRound, DirectRound, FinalizableToNextRound, FinalizableToResult, PartyIdx,
    ProtocolResult, Round, ToNextRound, ToResult,
};
use crate::tools::collections::{HoleRange, HoleVec, HoleVecAccum};

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
    /// Trying to add an item to an accumulator that was not initialized on construction.
    NoAccumulator,
}

#[derive(Debug, Clone)]
pub enum AccumFinalizeError {
    NotEnoughMessages,
    Downcast(String),
}

#[derive(Debug, Clone)]
pub(crate) enum ReceiveError<Res: ProtocolResult> {
    /// Error while deserializing the given message.
    CannotDeserialize(String),
    /// An error from the protocol level
    Protocol(cggmp21::ReceiveError<Res>),
}

#[derive(Debug, Clone)]
pub(crate) enum FinalizeError<Res: ProtocolResult> {
    /// An error from the protocol level
    Protocol(cggmp21::FinalizeError<Res>),
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

pub(crate) struct DynDmArtefact(Box<dyn Any + Send>);

/// An object-safe trait wrapping `Round`.
pub(crate) trait DynRound<Res: ProtocolResult>: Send {
    fn round_num(&self) -> u8;
    fn next_round_num(&self) -> Option<u8>;

    fn broadcast_destinations(&self) -> Option<HoleRange>;
    fn make_broadcast(&self, rng: &mut dyn CryptoRngCore) -> Result<Box<[u8]>, LocalError>;
    fn requires_broadcast_consensus(&self) -> bool;
    fn direct_message_destinations(&self) -> Option<HoleRange>;
    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Box<[u8]>, DynDmArtefact), LocalError>;

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
}

impl<R> DynRound<R::Result> for R
where
    R: Round + Send,
    <R as BroadcastRound>::Payload: 'static + Send,
    <R as DirectRound>::Payload: 'static + Send,
    <R as DirectRound>::Artefact: 'static + Send,
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

    fn broadcast_destinations(&self) -> Option<HoleRange> {
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

    fn direct_message_destinations(&self) -> Option<HoleRange> {
        self.direct_message_destinations()
    }

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Box<[u8]>, DynDmArtefact), LocalError> {
        let mut boxed_rng = BoxedRng(rng);
        let (typed_message, typed_artefact) = self
            .make_direct_message(&mut boxed_rng, destination)
            .map_err(|err| LocalError(format!("Failed to make a direct message: {err:?}")))?;
        let message = serialize_message(&typed_message)?;
        Ok((message, DynDmArtefact(Box::new(typed_artefact))))
    }
}

pub(crate) struct DynRoundAccum {
    bc_payloads: Option<HoleVecAccum<DynBcPayload>>,
    dm_payloads: Option<HoleVecAccum<DynDmPayload>>,
    dm_artefacts: Option<HoleVecAccum<DynDmArtefact>>,
}

struct RoundAccum<R: Round> {
    bc_payloads: Option<HoleVec<<R as BroadcastRound>::Payload>>,
    dm_payloads: Option<HoleVec<<R as DirectRound>::Payload>>,
    dm_artefacts: Option<HoleVec<<R as DirectRound>::Artefact>>,
}

impl DynRoundAccum {
    pub fn new(num_parties: usize, idx: PartyIdx, is_bc_round: bool, is_dm_round: bool) -> Self {
        Self {
            bc_payloads: if is_bc_round {
                Some(HoleVecAccum::new(num_parties, idx.as_usize()))
            } else {
                None
            },
            dm_payloads: if is_dm_round {
                Some(HoleVecAccum::new(num_parties, idx.as_usize()))
            } else {
                None
            },
            dm_artefacts: if is_dm_round {
                Some(HoleVecAccum::new(num_parties, idx.as_usize()))
            } else {
                None
            },
        }
    }

    pub fn contains(&self, from: PartyIdx, broadcast: bool) -> bool {
        if broadcast {
            return self
                .bc_payloads
                .as_ref()
                .unwrap()
                .contains(from.as_usize())
                .unwrap();
        } else {
            return self
                .dm_payloads
                .as_ref()
                .unwrap()
                .contains(from.as_usize())
                .unwrap();
        }
    }

    pub fn add_bc_payload(
        &mut self,
        from: PartyIdx,
        payload: DynBcPayload,
    ) -> Result<(), AccumAddError> {
        match &mut self.bc_payloads {
            Some(payloads) => payloads
                .insert(from.as_usize(), payload)
                .ok_or(AccumAddError::SlotTaken),
            None => Err(AccumAddError::NoAccumulator),
        }
    }

    pub fn add_dm_payload(
        &mut self,
        from: PartyIdx,
        payload: DynDmPayload,
    ) -> Result<(), AccumAddError> {
        match &mut self.dm_payloads {
            Some(payloads) => payloads
                .insert(from.as_usize(), payload)
                .ok_or(AccumAddError::SlotTaken),
            None => Err(AccumAddError::NoAccumulator),
        }
    }

    pub fn add_dm_artefact(
        &mut self,
        destination: PartyIdx,
        artefact: DynDmArtefact,
    ) -> Result<(), AccumAddError> {
        match &mut self.dm_artefacts {
            Some(artefacts) => artefacts
                .insert(destination.as_usize(), artefact)
                .ok_or(AccumAddError::SlotTaken),
            None => Err(AccumAddError::NoAccumulator),
        }
    }

    pub fn can_finalize(&self) -> bool {
        // TODO: should this be the job of the round itself?
        self.bc_payloads
            .as_ref()
            .map_or(true, |accum| accum.can_finalize())
            && self
                .dm_payloads
                .as_ref()
                .map_or(true, |accum| accum.can_finalize())
            && self
                .dm_artefacts
                .as_ref()
                .map_or(true, |accum| accum.can_finalize())
    }

    fn finalize<R: Round>(self) -> Result<RoundAccum<R>, AccumFinalizeError>
    where
        <R as BroadcastRound>::Payload: 'static,
        <R as DirectRound>::Payload: 'static,
        <R as DirectRound>::Artefact: 'static,
    {
        let bc_payloads = match self.bc_payloads {
            Some(accum) => {
                let hvec = accum
                    .finalize()
                    .map_err(|_| AccumFinalizeError::NotEnoughMessages)?;
                Some(hvec.map_fallible(|elem| downcast::<<R as BroadcastRound>::Payload>(elem.0))?)
            }
            None => None,
        };
        let dm_payloads = match self.dm_payloads {
            Some(accum) => {
                let hvec = accum
                    .finalize()
                    .map_err(|_| AccumFinalizeError::NotEnoughMessages)?;
                Some(hvec.map_fallible(|elem| downcast::<<R as DirectRound>::Payload>(elem.0))?)
            }
            None => None,
        };
        let dm_artefacts = match self.dm_artefacts {
            Some(accum) => {
                let hvec = accum
                    .finalize()
                    .map_err(|_| AccumFinalizeError::NotEnoughMessages)?;
                Some(hvec.map_fallible(|elem| downcast::<<R as DirectRound>::Artefact>(elem.0))?)
            }
            None => None,
        };
        Ok(RoundAccum {
            bc_payloads,
            dm_payloads,
            dm_artefacts,
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

// This is needed because Rust does not currently support exclusive trait imlpementations.
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
        <R as DirectRound>::Artefact: Send,
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

    // Actual diverging imlpementations.

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
                    typed_accum.dm_artefacts,
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
                    typed_accum.dm_artefacts,
                )
                .map_err(FinalizeError::Protocol)?;
            Ok(FinalizeOutcome::AnotherRound(Box::new(next_round)))
        }
    }
};
