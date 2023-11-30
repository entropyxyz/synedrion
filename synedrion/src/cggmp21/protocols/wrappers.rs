use alloc::string::String;

use rand_core::CryptoRngCore;

use super::common::PartyIdx;
use super::generic::{
    BaseRound, BroadcastRound, DirectRound, FinalizableType, FinalizeError, ProtocolResult,
    ReceiveError, Round,
};
use crate::tools::collections::HoleRange;

pub(crate) trait ResultWrapper<Res: ProtocolResult>: ProtocolResult {
    fn wrap_error(error: Res::ProvableError) -> Self::ProvableError;
    fn wrap_proof(proof: Res::CorrectnessProof) -> Self::CorrectnessProof;
}

pub(crate) fn wrap_receive_error<T: ProtocolResult, Res: ResultWrapper<T>>(
    error: ReceiveError<T>,
) -> ReceiveError<Res> {
    match error {
        ReceiveError::InvalidType => ReceiveError::InvalidType,
        ReceiveError::Provable(err) => ReceiveError::Provable(Res::wrap_error(err)),
    }
}

pub(crate) fn wrap_finalize_error<T: ProtocolResult, Res: ResultWrapper<T>>(
    error: FinalizeError<T>,
) -> FinalizeError<Res> {
    match error {
        FinalizeError::Init(msg) => FinalizeError::Init(msg),
        FinalizeError::Provable { party, error } => FinalizeError::Provable {
            party,
            error: Res::wrap_error(error),
        },
        FinalizeError::Proof(proof) => FinalizeError::Proof(Res::wrap_proof(proof)),
    }
}

pub(crate) trait RoundWrapper: 'static + Sized + Send {
    type Result: ProtocolResult + ResultWrapper<<Self::InnerRound as BaseRound>::Result>;
    type Type: FinalizableType;
    type InnerRound: Round;
    const ROUND_NUM: u8;
    const NEXT_ROUND_NUM: Option<u8>;
    fn inner_round(&self) -> &Self::InnerRound;
}

impl<T: RoundWrapper> BaseRound for T {
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
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        self.inner_round()
            .verify_broadcast(from, msg)
            .map_err(wrap_receive_error)
    }
}

impl<T: RoundWrapper> DirectRound for T {
    type Message = <T::InnerRound as DirectRound>::Message;
    type Payload = <T::InnerRound as DirectRound>::Payload;
    type Artifact = <T::InnerRound as DirectRound>::Artifact;
    fn direct_message_destinations(&self) -> Option<HoleRange> {
        self.inner_round().direct_message_destinations()
    }
    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artifact), String> {
        self.inner_round().make_direct_message(rng, destination)
    }
    fn verify_direct_message(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        self.inner_round()
            .verify_direct_message(from, msg)
            .map_err(wrap_receive_error)
    }
}
