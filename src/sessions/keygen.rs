use super::generic::{ConsensusSubstage, NormalSubstage, SessionState, ToSendSerialized};
use crate::protocols::generic::{ConsensusWrapper, SessionId};
use crate::protocols::keygen::{KeyShare, Round1, Round2, Round3, SchemeParams};
use crate::tools::collections::PartyIdx;

#[derive(Clone)]
enum KeygenStage {
    Round1(NormalSubstage<ConsensusWrapper<Round1>>),
    Round1Consensus(ConsensusSubstage<Round1>),
    Round2(NormalSubstage<Round2>),
    Round3(NormalSubstage<Round3>),
    Result(KeyShare),
}

#[derive(Clone)]
pub struct KeygenState(KeygenStage);

impl SessionState for KeygenState {
    type Result = KeyShare;

    type Context = SchemeParams;

    fn new(session_id: &SessionId, params: &SchemeParams, index: PartyIdx) -> Self {
        let round1 = Round1::new(session_id, params, index);
        Self(KeygenStage::Round1(NormalSubstage::new(ConsensusWrapper(
            round1,
        ))))
    }

    fn get_messages(&mut self, num_parties: usize, index: PartyIdx) -> ToSendSerialized {
        match &mut self.0 {
            KeygenStage::Round1(r) => r.get_messages(num_parties, index),
            KeygenStage::Round1Consensus(r) => r.get_messages(num_parties, index),
            KeygenStage::Round2(r) => r.get_messages(num_parties, index),
            KeygenStage::Round3(r) => r.get_messages(num_parties, index),
            _ => panic!(),
        }
    }

    fn receive_current_stage(&mut self, from: PartyIdx, message_bytes: &[u8]) {
        match &mut self.0 {
            KeygenStage::Round1(r) => r.receive(from, message_bytes),
            KeygenStage::Round1Consensus(r) => r.receive(from, message_bytes),
            KeygenStage::Round2(r) => r.receive(from, message_bytes),
            KeygenStage::Round3(r) => r.receive(from, message_bytes),
            _ => panic!(),
        }
    }

    fn is_finished_receiving(&self) -> bool {
        match &self.0 {
            KeygenStage::Round1(r) => r.is_finished_receiving(),
            KeygenStage::Round1Consensus(r) => r.is_finished_receiving(),
            KeygenStage::Round2(r) => r.is_finished_receiving(),
            KeygenStage::Round3(r) => r.is_finished_receiving(),
            _ => panic!(),
        }
    }

    fn finalize_stage(self) -> Self {
        Self(match self.0 {
            KeygenStage::Round1(r) => {
                let (new_round, broadcasts) = r.finalize();
                KeygenStage::Round1Consensus(ConsensusSubstage::new(new_round, broadcasts))
            }
            KeygenStage::Round1Consensus(r) => {
                KeygenStage::Round2(NormalSubstage::new(r.finalize()))
            }
            KeygenStage::Round2(r) => KeygenStage::Round3(NormalSubstage::new(r.finalize())),
            KeygenStage::Round3(r) => KeygenStage::Result(r.finalize()),
            _ => panic!(),
        })
    }

    fn result(&self) -> KeyShare {
        match &self.0 {
            KeygenStage::Result(r) => r.clone(),
            _ => panic!(),
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
