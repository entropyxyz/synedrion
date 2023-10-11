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

use crate::cggmp21::{
    BroadcastRound, DirectRound, FinalizableToNextRound, FinalizableToResult, FinalizeError,
    ReceiveError, Round, ToNextRound, ToResult,
};
use crate::tools::collections::{HoleRange, HoleVec, HoleVecAccum};
use crate::PartyIdx;

pub(crate) fn serialize_message(
    message: &impl Serialize,
) -> Result<Box<[u8]>, rmp_serde::encode::Error> {
    rmp_serde::encode::to_vec(message).map(|serialized| serialized.into_boxed_slice())
}

pub(crate) fn deserialize_message<M: for<'de> Deserialize<'de>>(
    message_bytes: &[u8],
) -> Result<M, rmp_serde::decode::Error> {
    rmp_serde::decode::from_slice(message_bytes)
}

#[derive(Debug, Clone)]
pub enum Error {
    Generic(String),
    AccumFinalize(String),
    Finalize(FinalizeError),
    SerializationFail(String),
    DeserializationFail(String),
    VerificationFail(ReceiveError),
    MessageCreationFail(String),
}

pub(crate) enum FinalizeOutcome<Res> {
    Result(Res),
    AnotherRound(Box<dyn DynFinalizable<Res>>),
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
pub(crate) trait DynRound<Res>: Send {
    fn round_num(&self) -> u8;
    fn next_round_num(&self) -> Option<u8>;

    fn broadcast_destinations(&self) -> Option<HoleRange>;
    fn make_broadcast(&self, rng: &mut dyn CryptoRngCore) -> Result<Box<[u8]>, Error>;
    fn requires_broadcast_consensus(&self) -> bool;
    fn direct_message_destinations(&self) -> Option<HoleRange>;
    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Box<[u8]>, DynDmArtefact), Error>;

    fn verify_broadcast(&self, from: PartyIdx, message: &[u8]) -> Result<DynBcPayload, Error>;
    fn verify_direct_message(&self, from: PartyIdx, message: &[u8]) -> Result<DynDmPayload, Error>;
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

    fn verify_broadcast(&self, from: PartyIdx, message: &[u8]) -> Result<DynBcPayload, Error> {
        let typed_message: <R as BroadcastRound>::Message = match deserialize_message(message) {
            Ok(message) => message,
            Err(err) => return Err(Error::DeserializationFail(format!("{}", err))),
        };

        let payload = match self.verify_broadcast(from, typed_message) {
            Ok(payload) => payload,
            Err(err) => return Err(Error::VerificationFail(err)),
        };

        Ok(DynBcPayload(Box::new(payload)))
    }

    fn verify_direct_message(&self, from: PartyIdx, message: &[u8]) -> Result<DynDmPayload, Error> {
        let typed_message: <R as DirectRound>::Message = match deserialize_message(message) {
            Ok(message) => message,
            Err(err) => return Err(Error::DeserializationFail(format!("{}", err))),
        };

        let payload = match self.verify_direct_message(from, typed_message) {
            Ok(payload) => payload,
            Err(err) => return Err(Error::VerificationFail(err)),
        };

        Ok(DynDmPayload(Box::new(payload)))
    }

    fn broadcast_destinations(&self) -> Option<HoleRange> {
        self.broadcast_destinations()
    }

    fn make_broadcast(&self, rng: &mut dyn CryptoRngCore) -> Result<Box<[u8]>, Error> {
        let mut boxed_rng = BoxedRng(rng);
        let serialized = self
            .make_broadcast(&mut boxed_rng)
            .map_err(|err| Error::MessageCreationFail(err.to_string()))?;
        serialize_message(&serialized).map_err(|err| Error::SerializationFail(err.to_string()))
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
    ) -> Result<(Box<[u8]>, DynDmArtefact), Error> {
        let mut boxed_rng = BoxedRng(rng);
        let (typed_message, typed_artefact) = self
            .make_direct_message(&mut boxed_rng, destination)
            .map_err(|err| Error::MessageCreationFail(err.to_string()))?;
        let message = serialize_message(&typed_message)
            .map_err(|err| Error::SerializationFail(err.to_string()))?;
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

    pub fn add_bc_payload(&mut self, from: PartyIdx, payload: DynBcPayload) -> Result<(), String> {
        match &mut self.bc_payloads {
            Some(payloads) => payloads
                .insert(from.as_usize(), payload)
                .ok_or("Failed to insert BC payload".into()),
            None => Err("This round does not expect broadcast messages".into()),
        }
    }

    pub fn add_dm_payload(&mut self, from: PartyIdx, payload: DynDmPayload) -> Result<(), String> {
        match &mut self.dm_payloads {
            Some(payloads) => payloads
                .insert(from.as_usize(), payload)
                .ok_or("Failed to insert DM payload".into()),
            None => Err("This round does not expect direct messages".into()),
        }
    }

    pub fn add_dm_artefact(
        &mut self,
        destination: PartyIdx,
        artefact: DynDmArtefact,
    ) -> Result<(), String> {
        match &mut self.dm_artefacts {
            Some(artefacts) => artefacts
                .insert(destination.as_usize(), artefact)
                .ok_or("Failed to insert DM artefact".into()),
            None => Err("This round does not send direct messages".into()),
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

    fn finalize<R: Round>(self) -> Result<RoundAccum<R>, String>
    where
        <R as BroadcastRound>::Payload: 'static,
        <R as DirectRound>::Payload: 'static,
        <R as DirectRound>::Artefact: 'static,
    {
        let bc_payloads = match self.bc_payloads {
            Some(accum) => {
                let hvec = accum
                    .finalize()
                    .map_err(|_| "Failed to finalize BC payloads")?;
                Some(hvec.map_fallible(|elem| downcast::<<R as BroadcastRound>::Payload>(elem.0))?)
            }
            None => None,
        };
        let dm_payloads = match self.dm_payloads {
            Some(accum) => {
                let hvec = accum
                    .finalize()
                    .map_err(|_| "Failed to finalize DM payloads")?;
                Some(hvec.map_fallible(|elem| downcast::<<R as DirectRound>::Payload>(elem.0))?)
            }
            None => None,
        };
        let dm_artefacts = match self.dm_artefacts {
            Some(accum) => {
                let hvec = accum
                    .finalize()
                    .map_err(|_| "Failed to finalize DM artefacts")?;
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

fn downcast<T: 'static>(boxed: Box<dyn Any>) -> Result<T, String> {
    Ok(*(boxed
        .downcast::<T>()
        .map_err(|_| format!("Failed to downcast into {}", core::any::type_name::<T>()))?))
}

pub(crate) trait DynFinalizable<Res>: DynRound<Res> {
    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        accum: DynRoundAccum,
    ) -> Result<FinalizeOutcome<Res>, Error>;
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

    trait _DynFinalizable<Res, T> {
        fn finalize(
            self: Box<Self>,
            rng: &mut dyn CryptoRngCore,
            accum: DynRoundAccum,
        ) -> Result<FinalizeOutcome<Res>, Error>;
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
        ) -> Result<FinalizeOutcome<R::Result>, Error> {
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
        ) -> Result<FinalizeOutcome<R::Result>, Error> {
            let mut boxed_rng = BoxedRng(rng);
            let typed_accum = accum.finalize::<R>().map_err(Error::AccumFinalize)?;
            let result = (*self)
                .finalize_to_result(
                    &mut boxed_rng,
                    typed_accum.bc_payloads,
                    typed_accum.dm_payloads,
                    typed_accum.dm_artefacts,
                )
                .map_err(Error::Finalize)?;
            Ok(FinalizeOutcome::Result(result))
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
        ) -> Result<FinalizeOutcome<R::Result>, Error> {
            let mut boxed_rng = BoxedRng(rng);
            let typed_accum = accum.finalize::<R>().map_err(Error::AccumFinalize)?;
            let next_round = (*self)
                .finalize_to_next_round(
                    &mut boxed_rng,
                    typed_accum.bc_payloads,
                    typed_accum.dm_payloads,
                    typed_accum.dm_artefacts,
                )
                .map_err(Error::Finalize)?;
            Ok(FinalizeOutcome::AnotherRound(Box::new(next_round)))
        }
    }
};
