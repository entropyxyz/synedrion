use alloc::string::String;

use rand_core::{CryptoRng, RngCore};

use super::generic::{SessionState, Stage, ToSendSerialized};
use crate::protocols::common::{KeyShare, PresigningData, SchemeParams, SessionId};
use crate::protocols::generic::{ConsensusSubround, PreConsensusSubround};
use crate::protocols::presigning::{Round1Part1, Round1Part2, Round2, Round3};
use crate::tools::collections::PartyIdx;

#[allow(clippy::large_enum_variant)] // TODO: should we box them?
#[derive(Clone)]
enum PresigningStage<P: SchemeParams> {
    Round1Part1(Stage<PreConsensusSubround<Round1Part1<P>>>),
    Round1Part1Consensus(Stage<ConsensusSubround<Round1Part1<P>>>),
    Round1Part2(Stage<Round1Part2<P>>),
    Round2(Stage<Round2<P>>),
    Round3(Stage<Round3<P>>),
    Result(PresigningData),
}

#[derive(Clone)]
pub struct PresigningState<P: SchemeParams>(PresigningStage<P>);

impl<P: SchemeParams> SessionState for PresigningState<P> {
    type Result = PresigningData;
    type Context = (usize, KeyShare<P>);

    fn new(
        rng: &mut (impl RngCore + CryptoRng),
        session_id: &SessionId,
        context: &Self::Context,
        index: PartyIdx,
    ) -> Self {
        let (num_parties, key_share) = context;
        let round1 = Round1Part1::<P>::new(rng, session_id, index, *num_parties, key_share);
        Self(PresigningStage::Round1Part1(Stage::new(
            PreConsensusSubround(round1),
        )))
    }

    fn get_messages(
        &mut self,
        rng: &mut (impl RngCore + CryptoRng),
        num_parties: usize,
        index: PartyIdx,
    ) -> Result<ToSendSerialized, String> {
        Ok(match &mut self.0 {
            PresigningStage::Round1Part1(r) => r.get_messages(rng, num_parties, index)?,
            PresigningStage::Round1Part1Consensus(r) => r.get_messages(rng, num_parties, index)?,
            PresigningStage::Round1Part2(r) => r.get_messages(rng, num_parties, index)?,
            PresigningStage::Round2(r) => r.get_messages(rng, num_parties, index)?,
            PresigningStage::Round3(r) => r.get_messages(rng, num_parties, index)?,
            _ => return Err("Not in a sending state".into()),
        })
    }

    fn receive_current_stage(
        &mut self,
        from: PartyIdx,
        message_bytes: &[u8],
    ) -> Result<(), String> {
        match &mut self.0 {
            PresigningStage::Round1Part1(r) => r.receive(from, message_bytes),
            PresigningStage::Round1Part1Consensus(r) => r.receive(from, message_bytes),
            PresigningStage::Round1Part2(r) => r.receive(from, message_bytes),
            PresigningStage::Round2(r) => r.receive(from, message_bytes),
            PresigningStage::Round3(r) => r.receive(from, message_bytes),
            _ => Err("Not in a receiving stage".into()),
        }
    }

    fn is_finished_receiving(&self) -> Result<bool, String> {
        match &self.0 {
            PresigningStage::Round1Part1(r) => r.is_finished_receiving(),
            PresigningStage::Round1Part1Consensus(r) => r.is_finished_receiving(),
            PresigningStage::Round1Part2(r) => r.is_finished_receiving(),
            PresigningStage::Round2(r) => r.is_finished_receiving(),
            PresigningStage::Round3(r) => r.is_finished_receiving(),
            _ => Err("Not in a receiving stage".into()),
        }
    }

    fn finalize_stage(self, rng: &mut (impl RngCore + CryptoRng)) -> Result<Self, String> {
        Ok(Self(match self.0 {
            PresigningStage::Round1Part1(r) => {
                PresigningStage::Round1Part1Consensus(Stage::new(r.finalize(rng)?))
            }
            PresigningStage::Round1Part1Consensus(r) => {
                PresigningStage::Round1Part2(Stage::new(r.finalize(rng)?))
            }
            PresigningStage::Round1Part2(r) => {
                PresigningStage::Round2(Stage::new(r.finalize(rng)?))
            }
            PresigningStage::Round2(r) => PresigningStage::Round3(Stage::new(r.finalize(rng)?)),
            PresigningStage::Round3(r) => PresigningStage::Result(r.finalize(rng)?),
            _ => return Err("Not in a receiving stage".into()),
        }))
    }

    fn result(&self) -> Result<Self::Result, String> {
        match &self.0 {
            PresigningStage::Result(r) => Ok(r.clone()),
            _ => Err("Not in the result stage".into()),
        }
    }

    fn is_final_stage(&self) -> bool {
        matches!(self.0, PresigningStage::Result(_))
    }

    fn current_stage_num(&self) -> u8 {
        match self.0 {
            PresigningStage::Round1Part1(_) => 1,
            PresigningStage::Round1Part1Consensus(_) => 2,
            PresigningStage::Round1Part2(_) => 3,
            PresigningStage::Round2(_) => 4,
            PresigningStage::Round3(_) => 5,
            _ => panic!(),
        }
    }

    fn stages_num(&self) -> u8 {
        5
    }
}