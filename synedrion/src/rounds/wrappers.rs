use alloc::collections::BTreeSet;

use rand_core::CryptoRngCore;

use super::generic::{
    FinalizableType, FinalizationRequirement, FinalizeError, PartyId, ProtocolResult, Round,
};

pub(crate) trait ProvableErrorWrapper<I, Res: ProtocolResult<I>>: ProtocolResult<I> {
    fn wrap_error(error: Res::ProvableError) -> Self::ProvableError;
}

pub(crate) trait CorrectnessProofWrapper<I, Res: ProtocolResult<I>>:
    ProtocolResult<I>
{
    fn wrap_proof(proof: Res::CorrectnessProof) -> Self::CorrectnessProof;
}

pub(crate) fn wrap_finalize_error<I, T: ProtocolResult<I>, Res: CorrectnessProofWrapper<I, T>>(
    error: FinalizeError<I, T>,
) -> FinalizeError<I, Res> {
    match error {
        FinalizeError::Init(msg) => FinalizeError::Init(msg),
        FinalizeError::Proof(proof) => FinalizeError::Proof(Res::wrap_proof(proof)),
    }
}

pub(crate) trait RoundWrapper<I: PartyId> {
    type Result: ProtocolResult<I> + ProvableErrorWrapper<I, <Self::InnerRound as Round<I>>::Result>;
    type Type: FinalizableType;
    type InnerRound: Round<I>;
    const ROUND_NUM: u8;
    const NEXT_ROUND_NUM: Option<u8>;
    fn inner_round(&self) -> &Self::InnerRound;
}

pub(crate) trait WrappedRound {}

impl<I: PartyId, T: RoundWrapper<I> + WrappedRound> Round<I> for T {
    type Type = T::Type;
    type Result = T::Result;
    const ROUND_NUM: u8 = T::ROUND_NUM;
    const NEXT_ROUND_NUM: Option<u8> = T::NEXT_ROUND_NUM;

    fn other_ids(&self) -> &BTreeSet<I> {
        self.inner_round().other_ids()
    }

    fn my_id(&self) -> &I {
        self.inner_round().my_id()
    }

    const REQUIRES_ECHO: bool = T::InnerRound::REQUIRES_ECHO;
    type BroadcastMessage = <T::InnerRound as Round<I>>::BroadcastMessage;
    type DirectMessage = <T::InnerRound as Round<I>>::DirectMessage;
    type Payload = <T::InnerRound as Round<I>>::Payload;
    type Artifact = <T::InnerRound as Round<I>>::Artifact;

    fn message_destinations(&self) -> &BTreeSet<I> {
        self.inner_round().message_destinations()
    }

    fn make_broadcast_message(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        self.inner_round().make_broadcast_message(rng)
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &I,
    ) -> (Self::DirectMessage, Self::Artifact) {
        self.inner_round().make_direct_message(rng, destination)
    }

    fn verify_message(
        &self,
        rng: &mut impl CryptoRngCore,
        from: &I,
        broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult<I>>::ProvableError> {
        self.inner_round()
            .verify_message(rng, from, broadcast_msg, direct_msg)
            .map_err(Self::Result::wrap_error)
    }
    fn finalization_requirement() -> FinalizationRequirement {
        T::InnerRound::finalization_requirement()
    }
}
