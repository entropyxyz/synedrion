use alloc::boxed::Box;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;

use super::common::{KeyShare, PartyIdx};
use super::generic::{
    BroadcastRound, DirectRound, FinalizableToNextRound, FinalizableToResult, FinalizeError,
    FirstRound, InitError, ProtocolResult, ToNextRound, ToResult,
};
use super::presigning::{self, PresigningResult};
use super::signing::{self, SigningResult};
use super::wrappers::{wrap_finalize_error, ResultWrapper, RoundWrapper};
use crate::cggmp21::params::SchemeParams;
use crate::curve::{RecoverableSignature, Scalar};
use crate::tools::collections::HoleVec;

/// Possible results of the merged Presigning and Signing protocols.
#[derive(Debug, Clone, Copy)]
pub struct InteractiveSigningResult<P: SchemeParams>(PhantomData<P>);

impl<P: SchemeParams> ProtocolResult for InteractiveSigningResult<P> {
    type Success = RecoverableSignature;
    type ProvableError = InteractiveSigningError<P>;
    type CorrectnessProof = InteractiveSigningProof<P>;
}

/// Possible verifiable errors of the merged Presigning and Signing protocols.
#[derive(Debug, Clone)]
pub enum InteractiveSigningError<P: SchemeParams> {
    /// An error in the Presigning part of the protocol.
    Presigning(<PresigningResult<P> as ProtocolResult>::ProvableError),
    /// An error in the Signing part of the protocol.
    Signing(<SigningResult<P> as ProtocolResult>::ProvableError),
}

/// A proof of a node's correct behavior for the merged Presigning and Signing protocols.
#[derive(Debug, Clone)]
pub enum InteractiveSigningProof<P: SchemeParams> {
    /// A proof for the Presigning part of the protocol.
    Presigning(<PresigningResult<P> as ProtocolResult>::CorrectnessProof),
    /// A proof for the Signing part of the protocol.
    Signing(<SigningResult<P> as ProtocolResult>::CorrectnessProof),
}

impl<P: SchemeParams> ResultWrapper<PresigningResult<P>> for InteractiveSigningResult<P> {
    fn wrap_error(
        error: <PresigningResult<P> as ProtocolResult>::ProvableError,
    ) -> Self::ProvableError {
        InteractiveSigningError::Presigning(error)
    }
    fn wrap_proof(
        proof: <PresigningResult<P> as ProtocolResult>::CorrectnessProof,
    ) -> Self::CorrectnessProof {
        InteractiveSigningProof::Presigning(proof)
    }
}

impl<P: SchemeParams> ResultWrapper<SigningResult<P>> for InteractiveSigningResult<P> {
    fn wrap_error(
        error: <SigningResult<P> as ProtocolResult>::ProvableError,
    ) -> Self::ProvableError {
        InteractiveSigningError::Signing(error)
    }
    fn wrap_proof(
        proof: <SigningResult<P> as ProtocolResult>::CorrectnessProof,
    ) -> Self::CorrectnessProof {
        InteractiveSigningProof::Signing(proof)
    }
}

struct RoundContext<P: SchemeParams> {
    shared_randomness: Box<[u8]>,
    key_share: KeyShare<P>,
    message: Scalar,
}

#[derive(Clone)]
pub(crate) struct Context<P: SchemeParams> {
    pub(crate) key_share: KeyShare<P>,
    pub(crate) message: Scalar,
}

pub(crate) struct Round1<P: SchemeParams> {
    round: presigning::Round1<P>,
    context: RoundContext<P>,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Context = Context<P>;
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        context: Self::Context,
    ) -> Result<Self, InitError> {
        let round = presigning::Round1::new(
            rng,
            shared_randomness,
            num_parties,
            party_idx,
            context.key_share.clone(),
        )?;
        let context = RoundContext {
            shared_randomness: shared_randomness.into(),
            key_share: context.key_share,
            message: context.message,
        };
        Ok(Self { context, round })
    }
}

impl<P: SchemeParams> RoundWrapper for Round1<P> {
    type Type = ToNextRound;
    type Result = InteractiveSigningResult<P>;
    type InnerRound = presigning::Round1<P>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);
    fn inner_round(&self) -> &Self::InnerRound {
        &self.round
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round1<P> {
    type NextRound = Round2<P>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        dm_artifacts: Option<HoleVec<<Self as DirectRound>::Artifact>>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let round = self
            .round
            .finalize_to_next_round(rng, bc_payloads, dm_payloads, dm_artifacts)
            .map_err(wrap_finalize_error)?;
        Ok(Round2 {
            round,
            context: self.context,
        })
    }
}

pub(crate) struct Round2<P: SchemeParams> {
    round: presigning::Round2<P>,
    context: RoundContext<P>,
}

impl<P: SchemeParams> RoundWrapper for Round2<P> {
    type Type = ToNextRound;
    type Result = InteractiveSigningResult<P>;
    type InnerRound = presigning::Round2<P>;
    const ROUND_NUM: u8 = 2;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);
    fn inner_round(&self) -> &Self::InnerRound {
        &self.round
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round2<P> {
    type NextRound = Round3<P>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        dm_artifacts: Option<HoleVec<<Self as DirectRound>::Artifact>>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let round = self
            .round
            .finalize_to_next_round(rng, bc_payloads, dm_payloads, dm_artifacts)
            .map_err(wrap_finalize_error)?;
        Ok(Round3 {
            round,
            context: self.context,
        })
    }
}

pub(crate) struct Round3<P: SchemeParams> {
    round: presigning::Round3<P>,
    context: RoundContext<P>,
}

impl<P: SchemeParams> RoundWrapper for Round3<P> {
    type Type = ToNextRound;
    type Result = InteractiveSigningResult<P>;
    type InnerRound = presigning::Round3<P>;
    const ROUND_NUM: u8 = 3;
    const NEXT_ROUND_NUM: Option<u8> = Some(4);
    fn inner_round(&self) -> &Self::InnerRound {
        &self.round
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round3<P> {
    type NextRound = Round4<P>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        dm_artifacts: Option<HoleVec<<Self as DirectRound>::Artifact>>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let presigning_data = self
            .round
            .finalize_to_result(rng, bc_payloads, dm_payloads, dm_artifacts)
            .map_err(wrap_finalize_error)?;
        let num_parties = self.context.key_share.num_parties();
        let party_idx = self.context.key_share.party_index();
        let signing_context = signing::Context {
            message: self.context.message,
            presigning: presigning_data,
            key_share: self.context.key_share.to_precomputed(),
        };
        let signing_round = signing::Round1::new(
            rng,
            &self.context.shared_randomness,
            num_parties,
            PartyIdx::from_usize(party_idx),
            signing_context,
        )
        .map_err(FinalizeError::Init)?;

        Ok(Round4 {
            round: signing_round,
            phantom: PhantomData,
        })
    }
}

pub(crate) struct Round4<P: SchemeParams> {
    round: signing::Round1<P>,
    phantom: PhantomData<P>,
}

impl<P: SchemeParams> RoundWrapper for Round4<P> {
    type Type = ToResult;
    type Result = InteractiveSigningResult<P>;
    type InnerRound = signing::Round1<P>;
    const ROUND_NUM: u8 = 4;
    const NEXT_ROUND_NUM: Option<u8> = None;
    fn inner_round(&self) -> &Self::InnerRound {
        &self.round
    }
}

impl<P: SchemeParams> FinalizableToResult for Round4<P> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        dm_artifacts: Option<HoleVec<<Self as DirectRound>::Artifact>>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        self.round
            .finalize_to_result(rng, bc_payloads, dm_payloads, dm_artifacts)
            .map_err(wrap_finalize_error)
    }
}
