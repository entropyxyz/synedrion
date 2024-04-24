use alloc::vec::Vec;

use rand_core::CryptoRngCore;

use super::generic::{
    FinalizableType, FinalizationRequirement, FinalizeError, PartyIdx, ProtocolResult,
    ReceiveError, Round,
};

pub(crate) trait ResultWrapper<Res: ProtocolResult>: ProtocolResult {
    fn wrap_error(error: Res::ProvableError) -> Self::ProvableError;
    fn wrap_proof(proof: Res::CorrectnessProof) -> Self::CorrectnessProof;
}

pub(crate) fn wrap_receive_error<T: ProtocolResult, Res: ResultWrapper<T>>(
    error: ReceiveError<T>,
) -> ReceiveError<Res> {
    match error {
        ReceiveError::Provable(err) => ReceiveError::Provable(Res::wrap_error(err)),
    }
}

pub(crate) fn wrap_finalize_error<T: ProtocolResult, Res: ResultWrapper<T>>(
    error: FinalizeError<T>,
) -> FinalizeError<Res> {
    match error {
        FinalizeError::Init(msg) => FinalizeError::Init(msg),
        FinalizeError::Proof(proof) => FinalizeError::Proof(Res::wrap_proof(proof)),
    }
}

pub(crate) trait RoundWrapper: 'static + Sized + Send {
    type Result: ProtocolResult + ResultWrapper<<Self::InnerRound as Round>::Result>;
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

    fn num_parties(&self) -> usize {
        self.inner_round().num_parties()
    }
    fn party_idx(&self) -> PartyIdx {
        self.inner_round().party_idx()
    }

    const REQUIRES_ECHO: bool = T::InnerRound::REQUIRES_ECHO;
    type BroadcastMessage = <T::InnerRound as Round>::BroadcastMessage;
    type DirectMessage = <T::InnerRound as Round>::DirectMessage;
    type Payload = <T::InnerRound as Round>::Payload;
    type Artifact = <T::InnerRound as Round>::Artifact;

    fn message_destinations(&self) -> Vec<PartyIdx> {
        self.inner_round().message_destinations()
    }

    fn make_broadcast_message(&self, rng: &mut impl CryptoRngCore) -> Self::BroadcastMessage {
        self.inner_round().make_broadcast_message(rng)
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> (Self::DirectMessage, Self::Artifact) {
        self.inner_round().make_direct_message(rng, destination)
    }

    fn verify_message(
        &self,
        from: PartyIdx,
        broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        self.inner_round()
            .verify_message(from, broadcast_msg, direct_msg)
            .map_err(wrap_receive_error)
    }
    fn finalization_requirement() -> FinalizationRequirement {
        T::InnerRound::finalization_requirement()
    }
}
