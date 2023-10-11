use alloc::string::String;

use rand_core::CryptoRngCore;

use super::common::PartyIdx;
use super::generic::{BroadcastRound, DirectRound, FinalizableType, ReceiveError, Round};
use crate::tools::collections::HoleRange;

pub(crate) trait RoundWrapper: 'static + Sized + Send {
    type Result: Sized + Send;
    type Type: FinalizableType;
    type InnerRound: Round;
    const ROUND_NUM: u8;
    const NEXT_ROUND_NUM: Option<u8>;
    fn inner_round(&self) -> &Self::InnerRound;
}

impl<T: RoundWrapper> Round for T {
    type Type = T::Type;
    type Result = T::Result;
    const ROUND_NUM: u8 = T::ROUND_NUM;
    const NEXT_ROUND_NUM: Option<u8> = T::NEXT_ROUND_NUM;
}

impl<T: RoundWrapper> BroadcastRound for T {
    const REQUIRES_CONSENSUS: bool = T::InnerRound::REQUIRES_CONSENSUS;
    type Message = <T::InnerRound as BroadcastRound>::Message;
    type Payload = <T::InnerRound as BroadcastRound>::Payload;
    fn broadcast_destinations(&self) -> Option<HoleRange> {
        self.inner_round().broadcast_destinations()
    }
    fn make_broadcast(&self, rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        self.inner_round().make_broadcast(rng)
    }
    fn verify_broadcast(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        self.inner_round().verify_broadcast(from, msg)
    }
}

impl<T: RoundWrapper> DirectRound for T {
    type Message = <T::InnerRound as DirectRound>::Message;
    type Payload = <T::InnerRound as DirectRound>::Payload;
    type Artefact = <T::InnerRound as DirectRound>::Artefact;
    fn direct_message_destinations(&self) -> Option<HoleRange> {
        self.inner_round().direct_message_destinations()
    }
    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artefact), String> {
        self.inner_round().make_direct_message(rng, destination)
    }
    fn verify_direct_message(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        self.inner_round().verify_direct_message(from, msg)
    }
}
