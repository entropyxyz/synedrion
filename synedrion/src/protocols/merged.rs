use rand_core::CryptoRngCore;

use super::common::PartyIdx;
use super::generic::*;

pub(crate) trait BaseRoundWrapper: Sized + Send {
    type InnerRound: BaseRound;
    const ROUND_NUM: u8;
    fn inner_round(&self) -> &Self::InnerRound;
}

pub(crate) trait FirstRoundWrapper: BaseRoundWrapper {
    type Context;
    fn make_inner_context(context: &Self::Context) -> <Self::InnerRound as FirstRound>::Context
    where
        Self::InnerRound: FirstRound;
    fn make_round(round: Self::InnerRound, context: Self::Context) -> Self;
}

impl<T: BaseRoundWrapper> BaseRound for T {
    type Message = <T::InnerRound as BaseRound>::Message;
    type Payload = <T::InnerRound as BaseRound>::Payload;

    const ROUND_NUM: u8 = T::ROUND_NUM;
    const REQUIRES_BROADCAST_CONSENSUS: bool = T::InnerRound::REQUIRES_BROADCAST_CONSENSUS;

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        self.inner_round().to_send(rng)
    }
    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        self.inner_round().verify_received(from, msg)
    }
}
