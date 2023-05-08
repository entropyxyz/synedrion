use alloc::string::String;

use rand_core::{CryptoRng, RngCore};

use super::generic::{SessionState, Stage, ToSendSerialized};
use crate::protocols::common::{KeyShare, SchemeParams, SessionId};
use crate::protocols::generic::{ConsensusSubround, PreConsensusSubround};
use crate::protocols::presigning;
use crate::protocols::signing;
use crate::tools::collections::PartyIdx;
use crate::tools::group::{Point, Scalar, Signature};

#[allow(clippy::large_enum_variant)] // TODO: should we box them?
#[derive(Clone)]
enum InteractiveSigningStage<P: SchemeParams> {
    Round1Part1(Stage<PreConsensusSubround<presigning::Round1Part1<P>>>),
    Round1Part1Consensus(Stage<ConsensusSubround<presigning::Round1Part1<P>>>),
    Round1Part2(Stage<presigning::Round1Part2<P>>),
    Round2(Stage<presigning::Round2<P>>),
    Round3(Stage<presigning::Round3<P>>),
    SigningRound(Stage<signing::Round1>),
    Result(Signature),
}

#[derive(Clone)]
pub struct InteractiveSigningState<P: SchemeParams> {
    stage: InteractiveSigningStage<P>,
    message: Scalar,
    verifying_key: Point,
}

impl<P: SchemeParams> SessionState for InteractiveSigningState<P> {
    type Result = Signature;
    type Context = (usize, KeyShare<P>, Scalar);

    fn new(
        rng: &mut (impl RngCore + CryptoRng),
        session_id: &SessionId,
        context: &Self::Context,
        index: PartyIdx,
    ) -> Self {
        let (num_parties, key_share, message) = context;
        let verifying_key = key_share.verifying_key_as_point();
        let round1 =
            presigning::Round1Part1::<P>::new(rng, session_id, index, *num_parties, key_share);
        let stage = InteractiveSigningStage::Round1Part1(Stage::new(PreConsensusSubround(round1)));
        Self {
            stage,
            message: *message,
            verifying_key,
        }
    }

    fn get_messages(
        &mut self,
        rng: &mut (impl RngCore + CryptoRng),
        num_parties: usize,
        index: PartyIdx,
    ) -> Result<ToSendSerialized, String> {
        Ok(match &mut self.stage {
            InteractiveSigningStage::Round1Part1(r) => r.get_messages(rng, num_parties, index)?,
            InteractiveSigningStage::Round1Part1Consensus(r) => {
                r.get_messages(rng, num_parties, index)?
            }
            InteractiveSigningStage::Round1Part2(r) => r.get_messages(rng, num_parties, index)?,
            InteractiveSigningStage::Round2(r) => r.get_messages(rng, num_parties, index)?,
            InteractiveSigningStage::Round3(r) => r.get_messages(rng, num_parties, index)?,
            InteractiveSigningStage::SigningRound(r) => r.get_messages(rng, num_parties, index)?,
            _ => return Err("Not in a sending state".into()),
        })
    }

    fn receive_current_stage(
        &mut self,
        from: PartyIdx,
        message_bytes: &[u8],
    ) -> Result<(), String> {
        match &mut self.stage {
            InteractiveSigningStage::Round1Part1(r) => r.receive(from, message_bytes),
            InteractiveSigningStage::Round1Part1Consensus(r) => r.receive(from, message_bytes),
            InteractiveSigningStage::Round1Part2(r) => r.receive(from, message_bytes),
            InteractiveSigningStage::Round2(r) => r.receive(from, message_bytes),
            InteractiveSigningStage::Round3(r) => r.receive(from, message_bytes),
            InteractiveSigningStage::SigningRound(r) => r.receive(from, message_bytes),
            _ => Err("Not in a receiving stage".into()),
        }
    }

    fn is_finished_receiving(&self) -> Result<bool, String> {
        match &self.stage {
            InteractiveSigningStage::Round1Part1(r) => r.is_finished_receiving(),
            InteractiveSigningStage::Round1Part1Consensus(r) => r.is_finished_receiving(),
            InteractiveSigningStage::Round1Part2(r) => r.is_finished_receiving(),
            InteractiveSigningStage::Round2(r) => r.is_finished_receiving(),
            InteractiveSigningStage::Round3(r) => r.is_finished_receiving(),
            InteractiveSigningStage::SigningRound(r) => r.is_finished_receiving(),
            _ => Err("Not in a receiving stage".into()),
        }
    }

    fn finalize_stage(self, rng: &mut (impl RngCore + CryptoRng)) -> Result<Self, String> {
        let stage = match self.stage {
            InteractiveSigningStage::Round1Part1(r) => {
                InteractiveSigningStage::Round1Part1Consensus(Stage::new(r.finalize(rng)?))
            }
            InteractiveSigningStage::Round1Part1Consensus(r) => {
                InteractiveSigningStage::Round1Part2(Stage::new(r.finalize(rng)?))
            }
            InteractiveSigningStage::Round1Part2(r) => {
                InteractiveSigningStage::Round2(Stage::new(r.finalize(rng)?))
            }
            InteractiveSigningStage::Round2(r) => {
                InteractiveSigningStage::Round3(Stage::new(r.finalize(rng)?))
            }
            InteractiveSigningStage::Round3(r) => {
                let presigning_data = r.finalize(rng)?;
                let signing_round =
                    signing::Round1::new(&presigning_data, &self.message, &self.verifying_key);
                InteractiveSigningStage::SigningRound(Stage::new(signing_round))
            }
            InteractiveSigningStage::SigningRound(r) => {
                InteractiveSigningStage::Result(r.finalize(rng)?)
            }
            _ => return Err("Not in a receiving stage".into()),
        };
        Ok(Self {
            stage,
            message: self.message,
            verifying_key: self.verifying_key,
        })
    }

    fn result(&self) -> Result<Self::Result, String> {
        match &self.stage {
            InteractiveSigningStage::Result(r) => Ok(r.clone()),
            _ => Err("Not in the result stage".into()),
        }
    }

    fn is_final_stage(&self) -> bool {
        matches!(self.stage, InteractiveSigningStage::Result(_))
    }

    fn current_stage_num(&self) -> u8 {
        match self.stage {
            InteractiveSigningStage::Round1Part1(_) => 1,
            InteractiveSigningStage::Round1Part1Consensus(_) => 2,
            InteractiveSigningStage::Round1Part2(_) => 3,
            InteractiveSigningStage::Round2(_) => 4,
            InteractiveSigningStage::Round3(_) => 5,
            InteractiveSigningStage::SigningRound(_) => 6,
            _ => panic!(),
        }
    }

    fn stages_num(&self) -> u8 {
        6
    }
}
