use rand_core::CryptoRngCore;

use super::generic::{SessionState, Stage, ToSendSerialized};
use super::{Error, MyFault};
use crate::protocols::common::{PartyIdx, PresigningData, SessionId};
use crate::protocols::signing::Round1;
use crate::tools::group::{Point, Scalar, Signature};

#[derive(Clone)]
enum SigningStage {
    Round1(Stage<Round1>),
    Result(Signature),
}

#[derive(Clone)]
pub struct SigningState(SigningStage);

impl SessionState for SigningState {
    type Result = Signature;
    type Context = (PresigningData, Scalar, Point);

    fn new(
        _rng: &mut impl CryptoRngCore,
        _session_id: &SessionId,
        context: &Self::Context,
        _index: PartyIdx,
    ) -> Self {
        let (presigning_data, message, verifying_key) = context;
        let round1 = Round1::new(presigning_data, message, verifying_key);
        Self(SigningStage::Round1(Stage::new(round1)))
    }

    fn get_messages(
        &mut self,
        rng: &mut impl CryptoRngCore,
        num_parties: usize,
        index: PartyIdx,
    ) -> Result<ToSendSerialized, MyFault> {
        Ok(match &mut self.0 {
            SigningStage::Round1(r) => r.get_messages(rng, num_parties, index)?,
            SigningStage::Result(_) => {
                return Err(MyFault::InvalidState(
                    "This protocol has reached a result".into(),
                ))
            }
        })
    }

    fn receive_current_stage(&mut self, from: PartyIdx, message_bytes: &[u8]) -> Result<(), Error> {
        match &mut self.0 {
            SigningStage::Round1(r) => r.receive(from, message_bytes),
            SigningStage::Result(_) => Err(Error::MyFault(MyFault::InvalidState(
                "This protocol has reached a result".into(),
            ))),
        }
    }

    fn is_finished_receiving(&self) -> Result<bool, MyFault> {
        match &self.0 {
            SigningStage::Round1(r) => r.is_finished_receiving(),
            SigningStage::Result(_) => Err(MyFault::InvalidState(
                "This protocol has reached a result".into(),
            )),
        }
    }

    fn finalize_stage(self, rng: &mut impl CryptoRngCore) -> Result<Self, Error> {
        Ok(Self(match self.0 {
            SigningStage::Round1(r) => SigningStage::Result(r.finalize(rng)?),
            SigningStage::Result(_) => {
                return Err(Error::MyFault(MyFault::InvalidState(
                    "This protocol has reached a result".into(),
                )))
            }
        }))
    }

    fn result(&self) -> Result<Self::Result, MyFault> {
        match &self.0 {
            SigningStage::Result(r) => Ok(r.clone()),
            _ => Err(MyFault::InvalidState("Not in the result stage".into())),
        }
    }

    fn is_final_stage(&self) -> bool {
        matches!(self.0, SigningStage::Result(_))
    }

    fn current_stage_num(&self) -> u8 {
        match self.0 {
            SigningStage::Round1(_) => 1,
            _ => panic!(),
        }
    }

    fn stages_num(&self) -> u8 {
        1
    }
}
