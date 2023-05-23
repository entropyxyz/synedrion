use alloc::string::String;

use rand_core::{CryptoRng, RngCore};

use super::generic::{SessionState, Stage, ToSendSerialized};
use crate::protocols::common::{KeyShareSeed, PartyIdx, SchemeParams, SessionId};
use crate::protocols::generic::{ConsensusSubround, PreConsensusSubround};
use crate::protocols::keygen::{Round1, Round2, Round3};

#[derive(Clone)]
enum KeygenStage<P: SchemeParams> {
    Round1(Stage<PreConsensusSubround<Round1<P>>>),
    Round1Consensus(Stage<ConsensusSubround<Round1<P>>>),
    Round2(Stage<Round2<P>>),
    Round3(Stage<Round3<P>>),
    Result(KeyShareSeed),
}

#[derive(Clone)]
pub struct KeygenState<P: SchemeParams>(KeygenStage<P>);

impl<P: SchemeParams> SessionState for KeygenState<P> {
    type Result = KeyShareSeed;
    type Context = ();

    fn new(
        rng: &mut (impl RngCore + CryptoRng),
        session_id: &SessionId,
        _context: &(),
        index: PartyIdx,
    ) -> Self {
        let round1 = Round1::<P>::new(rng, session_id, index);
        Self(KeygenStage::Round1(Stage::new(PreConsensusSubround(
            round1,
        ))))
    }

    fn get_messages(
        &mut self,
        rng: &mut (impl RngCore + CryptoRng),
        num_parties: usize,
        index: PartyIdx,
    ) -> Result<ToSendSerialized, String> {
        Ok(match &mut self.0 {
            KeygenStage::Round1(r) => r.get_messages(rng, num_parties, index)?,
            KeygenStage::Round1Consensus(r) => r.get_messages(rng, num_parties, index)?,
            KeygenStage::Round2(r) => r.get_messages(rng, num_parties, index)?,
            KeygenStage::Round3(r) => r.get_messages(rng, num_parties, index)?,
            _ => return Err("Not in a sending state".into()),
        })
    }

    fn receive_current_stage(
        &mut self,
        from: PartyIdx,
        message_bytes: &[u8],
    ) -> Result<(), String> {
        match &mut self.0 {
            KeygenStage::Round1(r) => r.receive(from, message_bytes),
            KeygenStage::Round1Consensus(r) => r.receive(from, message_bytes),
            KeygenStage::Round2(r) => r.receive(from, message_bytes),
            KeygenStage::Round3(r) => r.receive(from, message_bytes),
            _ => Err("Not in a receiving stage".into()),
        }
    }

    fn is_finished_receiving(&self) -> Result<bool, String> {
        match &self.0 {
            KeygenStage::Round1(r) => r.is_finished_receiving(),
            KeygenStage::Round1Consensus(r) => r.is_finished_receiving(),
            KeygenStage::Round2(r) => r.is_finished_receiving(),
            KeygenStage::Round3(r) => r.is_finished_receiving(),
            _ => Err("Not in a receiving stage".into()),
        }
    }

    fn finalize_stage(self, rng: &mut (impl RngCore + CryptoRng)) -> Result<Self, String> {
        Ok(Self(match self.0 {
            KeygenStage::Round1(r) => KeygenStage::Round1Consensus(Stage::new(r.finalize(rng)?)),
            KeygenStage::Round1Consensus(r) => KeygenStage::Round2(Stage::new(r.finalize(rng)?)),
            KeygenStage::Round2(r) => KeygenStage::Round3(Stage::new(r.finalize(rng)?)),
            KeygenStage::Round3(r) => KeygenStage::Result(r.finalize(rng)?),
            _ => return Err("Not in a receiving stage".into()),
        }))
    }

    fn result(&self) -> Result<Self::Result, String> {
        match &self.0 {
            KeygenStage::Result(r) => Ok(r.clone()),
            _ => Err("Not in the result stage".into()),
        }
    }

    fn is_final_stage(&self) -> bool {
        matches!(self.0, KeygenStage::Result(_))
    }

    fn current_stage_num(&self) -> u8 {
        match self.0 {
            KeygenStage::Round1(_) => 1,
            KeygenStage::Round1Consensus(_) => 2,
            KeygenStage::Round2(_) => 3,
            KeygenStage::Round3(_) => 4,
            _ => panic!(),
        }
    }

    fn stages_num(&self) -> u8 {
        4
    }
}
