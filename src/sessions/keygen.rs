use super::generic::{ConsensusSubstage, NormalSubstage, PreConsensusSubstage, SessionState};
use crate::protocols::generic::ToSend;
use crate::protocols::keygen::{KeyShare, PartyId, Round1, Round2, Round3, SessionInfo};

#[derive(Clone)]
enum KeygenStage {
    Round1(PreConsensusSubstage<Round1>),
    Round1Consensus(ConsensusSubstage<Round1>),
    Round2(NormalSubstage<Round2>),
    Round3(NormalSubstage<Round3>),
    Result(KeyShare),
}

#[derive(Clone)]
pub struct KeygenState(KeygenStage);

impl KeygenState {
    pub fn new(session_info: &SessionInfo, my_id: &PartyId) -> Self {
        let round1 = Round1::new(session_info, my_id);
        Self(KeygenStage::Round1(PreConsensusSubstage::new(round1)))
    }
}

impl SessionState for KeygenState {
    type Result = KeyShare;

    fn get_messages(&mut self) -> ToSend<PartyId, Box<[u8]>> {
        match &mut self.0 {
            KeygenStage::Round1(r) => r.get_messages(),
            KeygenStage::Round1Consensus(r) => r.get_messages(),
            KeygenStage::Round2(r) => r.get_messages(),
            KeygenStage::Round3(r) => r.get_messages(),
            _ => panic!(),
        }
    }

    fn receive_current_stage(&mut self, from: PartyId, message_bytes: &[u8]) {
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
                let (id, (new_round, broadcasts)) = r.finalize();
                KeygenStage::Round1Consensus(ConsensusSubstage::new(id, new_round, broadcasts))
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
