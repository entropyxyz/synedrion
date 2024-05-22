use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;

use super::super::params::SchemeParams;
use super::super::{AuxInfo, KeyShare};
use super::presigning::{self, PresigningResult};
use super::signing::{self, SigningResult};
use crate::curve::{RecoverableSignature, Scalar};
use crate::rounds::{
    wrap_finalize_error, CorrectnessProofWrapper, FinalizableToNextRound, FinalizableToResult,
    FinalizeError, FirstRound, InitError, PartyIdx, ProtocolResult, ProvableErrorWrapper, Round,
    RoundWrapper, ToNextRound, ToResult,
};

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

impl<P: SchemeParams> ProvableErrorWrapper<PresigningResult<P>> for InteractiveSigningResult<P> {
    fn wrap_error(
        error: <PresigningResult<P> as ProtocolResult>::ProvableError,
    ) -> Self::ProvableError {
        InteractiveSigningError::Presigning(error)
    }
}

impl<P: SchemeParams> CorrectnessProofWrapper<PresigningResult<P>> for InteractiveSigningResult<P> {
    fn wrap_proof(
        proof: <PresigningResult<P> as ProtocolResult>::CorrectnessProof,
    ) -> Self::CorrectnessProof {
        InteractiveSigningProof::Presigning(proof)
    }
}

impl<P: SchemeParams> ProvableErrorWrapper<SigningResult<P>> for InteractiveSigningResult<P> {
    fn wrap_error(
        error: <SigningResult<P> as ProtocolResult>::ProvableError,
    ) -> Self::ProvableError {
        InteractiveSigningError::Signing(error)
    }
}

impl<P: SchemeParams> CorrectnessProofWrapper<SigningResult<P>> for InteractiveSigningResult<P> {
    fn wrap_proof(
        proof: <SigningResult<P> as ProtocolResult>::CorrectnessProof,
    ) -> Self::CorrectnessProof {
        InteractiveSigningProof::Signing(proof)
    }
}

struct RoundContext<P: SchemeParams> {
    shared_randomness: Box<[u8]>,
    key_share: KeyShare<P>,
    aux_info: AuxInfo<P>,
    message: Scalar,
}

#[derive(Clone)]
pub(crate) struct Inputs<P: SchemeParams> {
    pub(crate) key_share: KeyShare<P>,
    pub(crate) aux_info: AuxInfo<P>,
    pub(crate) message: Scalar,
}

pub(crate) struct Round1<P: SchemeParams> {
    round: presigning::Round1<P>,
    context: RoundContext<P>,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Inputs = Inputs<P>;
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        let round = presigning::Round1::new(
            rng,
            shared_randomness,
            num_parties,
            party_idx,
            (inputs.key_share.clone(), inputs.aux_info.clone()),
        )?;
        let context = RoundContext {
            shared_randomness: shared_randomness.into(),
            key_share: inputs.key_share,
            aux_info: inputs.aux_info,
            message: inputs.message,
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
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
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
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
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
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let num_parties = self.num_parties();
        let party_idx = self.party_idx();
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
            num_parties,
            party_idx,
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
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        self.round
            .finalize_to_result(rng, payloads, artifacts)
            .map_err(wrap_finalize_error)
    }
}

#[cfg(test)]
mod tests {
    use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
    use rand_core::{OsRng, RngCore};

    use super::{Inputs, Round1};
    use crate::cggmp21::{AuxInfo, KeyShare, TestParams};
    use crate::curve::Scalar;
    use crate::rounds::{
        test_utils::{step_next_round, step_result, step_round},
        FirstRound, PartyIdx,
    };

    #[test]
    fn execute_interactive_signing() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let message = Scalar::random(&mut OsRng);

        let num_parties = 3;
        let key_shares = KeyShare::new_centralized(&mut OsRng, num_parties, None);
        let aux_infos = AuxInfo::new_centralized(&mut OsRng, num_parties);
        let r1 = (0..num_parties)
            .map(|idx| {
                Round1::<TestParams>::new(
                    &mut OsRng,
                    &shared_randomness,
                    num_parties,
                    PartyIdx::from_usize(idx),
                    Inputs {
                        message,
                        key_share: key_shares[idx].clone(),
                        aux_info: aux_infos[idx].clone(),
                    },
                )
                .unwrap()
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

        for signature in signatures {
            let (sig, rec_id) = signature.to_backend();

            let vkey = key_shares[0].verifying_key();

            // Check that the signature can be verified
            vkey.verify_prehash(&message.to_bytes(), &sig).unwrap();

            // Check that the key can be recovered
            let recovered_key =
                VerifyingKey::recover_from_prehash(&message.to_bytes(), &sig, rec_id).unwrap();
            assert_eq!(recovered_key, vkey);
        }
    }
}
