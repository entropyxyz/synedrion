use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;

use super::super::params::SchemeParams;
use super::super::{AuxInfo, KeyShare};
use super::presigning::{self, PresigningResult};
use super::signing::{self, SigningResult};
use crate::curve::{RecoverableSignature, Scalar};
use crate::rounds::{
    wrap_finalize_error, CorrectnessProofWrapper, EvidenceRequiresMessages, FinalizableToNextRound,
    FinalizableToResult, FinalizeError, FirstRound, InitError, PartyId, ProtocolResult,
    ProvableErrorWrapper, Round, RoundWrapper, ToNextRound, ToResult, WrappedRound,
};

/// Possible results of the merged Presigning and Signing protocols.
#[derive(Debug)]
pub struct InteractiveSigningResult<P: SchemeParams, I: PartyId>(PhantomData<P>, PhantomData<I>);

impl<P: SchemeParams, I: PartyId> ProtocolResult<I> for InteractiveSigningResult<P, I> {
    type Success = RecoverableSignature;
    type ProvableError = InteractiveSigningError<P, I>;
    type CorrectnessProof = InteractiveSigningProof<P, I>;
}

/// Possible verifiable errors of the merged Presigning and Signing protocols.
#[derive(Debug, Clone)]
pub enum InteractiveSigningError<P: SchemeParams, I: PartyId> {
    /// An error in the Presigning part of the protocol.
    Presigning(<PresigningResult<P, I> as ProtocolResult<I>>::ProvableError),
    /// An error in the Signing part of the protocol.
    Signing(<SigningResult<P, I> as ProtocolResult<I>>::ProvableError),
}

impl<P: SchemeParams, I: PartyId> EvidenceRequiresMessages<I> for InteractiveSigningError<P, I> {}

/// A proof of a node's correct behavior for the merged Presigning and Signing protocols.
#[derive(Debug)]
pub enum InteractiveSigningProof<P: SchemeParams, I: PartyId> {
    /// A proof for the Presigning part of the protocol.
    Presigning(<PresigningResult<P, I> as ProtocolResult<I>>::CorrectnessProof),
    /// A proof for the Signing part of the protocol.
    Signing(<SigningResult<P, I> as ProtocolResult<I>>::CorrectnessProof),
}

impl<P: SchemeParams, I: PartyId> ProvableErrorWrapper<I, PresigningResult<P, I>>
    for InteractiveSigningResult<P, I>
{
    fn wrap_error(
        error: <PresigningResult<P, I> as ProtocolResult<I>>::ProvableError,
    ) -> Self::ProvableError {
        InteractiveSigningError::Presigning(error)
    }
}

impl<P: SchemeParams, I: PartyId> CorrectnessProofWrapper<I, PresigningResult<P, I>>
    for InteractiveSigningResult<P, I>
{
    fn wrap_proof(
        proof: <PresigningResult<P, I> as ProtocolResult<I>>::CorrectnessProof,
    ) -> Self::CorrectnessProof {
        InteractiveSigningProof::Presigning(proof)
    }
}

impl<P: SchemeParams, I: PartyId> ProvableErrorWrapper<I, SigningResult<P, I>>
    for InteractiveSigningResult<P, I>
{
    fn wrap_error(
        error: <SigningResult<P, I> as ProtocolResult<I>>::ProvableError,
    ) -> Self::ProvableError {
        InteractiveSigningError::Signing(error)
    }
}

impl<P: SchemeParams, I: PartyId> CorrectnessProofWrapper<I, SigningResult<P, I>>
    for InteractiveSigningResult<P, I>
{
    fn wrap_proof(
        proof: <SigningResult<P, I> as ProtocolResult<I>>::CorrectnessProof,
    ) -> Self::CorrectnessProof {
        InteractiveSigningProof::Signing(proof)
    }
}

struct Context<P: SchemeParams, I: Ord> {
    shared_randomness: Box<[u8]>,
    key_share: KeyShare<P, I>,
    aux_info: AuxInfo<P, I>,
    message: Scalar,
}

#[derive(Clone)]
pub(crate) struct Inputs<P: SchemeParams, I: Ord> {
    pub(crate) key_share: KeyShare<P, I>,
    pub(crate) aux_info: AuxInfo<P, I>,
    pub(crate) message: Scalar,
}

pub(crate) struct Round1<P: SchemeParams, I: Ord> {
    round: presigning::Round1<P, I>,
    context: Context<P, I>,
}

impl<P: SchemeParams, I: PartyId> FirstRound<I> for Round1<P, I> {
    type Inputs = Inputs<P, I>;
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        other_ids: BTreeSet<I>,
        my_id: I,
        inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        let round = presigning::Round1::new(
            rng,
            shared_randomness,
            other_ids,
            my_id,
            (inputs.key_share.clone(), inputs.aux_info.clone()),
        )?;
        let context = Context {
            shared_randomness: shared_randomness.into(),
            key_share: inputs.key_share,
            aux_info: inputs.aux_info,
            message: inputs.message,
        };
        Ok(Self { context, round })
    }
}

impl<P: SchemeParams, I: PartyId> RoundWrapper<I> for Round1<P, I> {
    type Type = ToNextRound;
    type Result = InteractiveSigningResult<P, I>;
    type InnerRound = presigning::Round1<P, I>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);
    fn inner_round(&self) -> &Self::InnerRound {
        &self.round
    }
}

impl<P: SchemeParams, I: PartyId> WrappedRound for Round1<P, I> {}

impl<P: SchemeParams, I: PartyId> FinalizableToNextRound<I> for Round1<P, I> {
    type NextRound = Round2<P, I>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<I, Self::Result>> {
        let round = self
            .round
            .finalize_to_next_round(rng, payloads, artifacts)
            .map_err(wrap_finalize_error)?;
        Ok(Round2 {
            round,
            context: self.context,
        })
    }
}

pub(crate) struct Round2<P: SchemeParams, I: Ord> {
    round: presigning::Round2<P, I>,
    context: Context<P, I>,
}

impl<P: SchemeParams, I: PartyId> RoundWrapper<I> for Round2<P, I> {
    type Type = ToNextRound;
    type Result = InteractiveSigningResult<P, I>;
    type InnerRound = presigning::Round2<P, I>;
    const ROUND_NUM: u8 = 2;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);
    fn inner_round(&self) -> &Self::InnerRound {
        &self.round
    }
}

impl<P: SchemeParams, I: PartyId> WrappedRound for Round2<P, I> {}

impl<P: SchemeParams, I: PartyId> FinalizableToNextRound<I> for Round2<P, I> {
    type NextRound = Round3<P, I>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<I, Self::Result>> {
        let round = self
            .round
            .finalize_to_next_round(rng, payloads, artifacts)
            .map_err(wrap_finalize_error)?;
        Ok(Round3 {
            round,
            context: self.context,
        })
    }
}

pub(crate) struct Round3<P: SchemeParams, I: Ord> {
    round: presigning::Round3<P, I>,
    context: Context<P, I>,
}

impl<P: SchemeParams, I: PartyId> RoundWrapper<I> for Round3<P, I> {
    type Type = ToNextRound;
    type Result = InteractiveSigningResult<P, I>;
    type InnerRound = presigning::Round3<P, I>;
    const ROUND_NUM: u8 = 3;
    const NEXT_ROUND_NUM: Option<u8> = Some(4);
    fn inner_round(&self) -> &Self::InnerRound {
        &self.round
    }
}

impl<P: SchemeParams, I: PartyId> WrappedRound for Round3<P, I> {}

impl<P: SchemeParams, I: PartyId> FinalizableToNextRound<I> for Round3<P, I> {
    type NextRound = Round4<P, I>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<I, Self::Result>> {
        let other_ids = self.other_ids().clone();
        let my_id = self.my_id().clone();
        let presigning_data = self
            .round
            .finalize_to_result(rng, payloads, artifacts)
            .map_err(wrap_finalize_error)?;
        let signing_context = signing::Inputs {
            message: self.context.message,
            presigning: presigning_data,
            key_share: self.context.key_share,
            aux_info: self.context.aux_info,
        };
        let signing_round = signing::Round1::new(
            rng,
            &self.context.shared_randomness,
            other_ids,
            my_id,
            signing_context,
        )
        .map_err(FinalizeError::Init)?;

        Ok(Round4 {
            round: signing_round,
        })
    }
}

pub(crate) struct Round4<P: SchemeParams, I: Ord> {
    round: signing::Round1<P, I>,
}

impl<P: SchemeParams, I: PartyId> RoundWrapper<I> for Round4<P, I> {
    type Type = ToResult;
    type Result = InteractiveSigningResult<P, I>;
    type InnerRound = signing::Round1<P, I>;
    const ROUND_NUM: u8 = 4;
    const NEXT_ROUND_NUM: Option<u8> = None;
    fn inner_round(&self) -> &Self::InnerRound {
        &self.round
    }
}

impl<P: SchemeParams, I: PartyId> WrappedRound for Round4<P, I> {}

impl<P: SchemeParams, I: PartyId> FinalizableToResult<I> for Round4<P, I> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult<I>>::Success, FinalizeError<I, Self::Result>> {
        self.round
            .finalize_to_result(rng, payloads, artifacts)
            .map_err(wrap_finalize_error)
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
    use rand_core::{OsRng, RngCore};

    use super::{Inputs, Round1};
    use crate::cggmp21::{AuxInfo, KeyShare, TestParams};
    use crate::curve::Scalar;
    use crate::rounds::{
        test_utils::{step_next_round, step_result, step_round, Id, Without},
        FirstRound,
    };

    #[test]
    fn execute_interactive_signing() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let message = Scalar::random(&mut OsRng);

        let ids = BTreeSet::from([Id(0), Id(1), Id(2)]);

        let key_shares = KeyShare::new_centralized(&mut OsRng, &ids, None);
        let aux_infos = AuxInfo::new_centralized(&mut OsRng, &ids);

        let r1 = ids
            .iter()
            .map(|id| {
                let round = Round1::<TestParams, Id>::new(
                    &mut OsRng,
                    &shared_randomness,
                    ids.clone().without(id),
                    *id,
                    Inputs {
                        message,
                        key_share: key_shares[id].clone(),
                        aux_info: aux_infos[id].clone(),
                    },
                )
                .unwrap();
                (*id, round)
            })
            .collect();

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let r2 = step_next_round(&mut OsRng, r1a).unwrap();
        let r2a = step_round(&mut OsRng, r2).unwrap();
        let r3 = step_next_round(&mut OsRng, r2a).unwrap();
        let r3a = step_round(&mut OsRng, r3).unwrap();
        let r4 = step_next_round(&mut OsRng, r3a).unwrap();
        let r4a = step_round(&mut OsRng, r4).unwrap();
        let signatures = step_result(&mut OsRng, r4a).unwrap();

        for signature in signatures.values() {
            let (sig, rec_id) = signature.to_backend();

            let vkey = key_shares[&Id(0)].verifying_key();

            // Check that the signature can be verified
            vkey.verify_prehash(&message.to_bytes(), &sig).unwrap();

            // Check that the key can be recovered
            let recovered_key =
                VerifyingKey::recover_from_prehash(&message.to_bytes(), &sig, rec_id).unwrap();
            assert_eq!(recovered_key, vkey);
        }
    }
}
