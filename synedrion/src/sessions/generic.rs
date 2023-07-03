use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::hazmat::{PrehashSigner, PrehashVerifier};

use super::broadcast::BroadcastConsensus;
use super::error::{Error, MyFault, TheirFault};
use super::signed_message::{SignedMessage, VerifiedMessage};
use crate::protocols::generic::{FirstRound, Round};
use crate::protocols::type_erased::{
    FinalizeOutcome, ReceiveOutcome, ToSendSerialized, TypeErasedReceivingRound, TypeErasedRound,
};
use crate::PartyIdx;

pub enum ToSend<Sig> {
    Broadcast(SignedMessage<Sig>),
    // TODO: return an iterator instead, since preparing one message can take some time
    Direct(Vec<(PartyIdx, SignedMessage<Sig>)>),
}

// TODO: technically we don't need to clone the state, but doing state transitions without cloning
// requires a lot of boilerplate.
#[derive(Clone)]
enum State<Res, Sig, Verifier> {
    Result(Res),
    Sending(Box<dyn TypeErasedRound<Res>>),
    Receiving(Box<dyn TypeErasedReceivingRound<Res>>),
    SendingBc {
        round: Box<dyn TypeErasedRound<Res>>,
        bc: BroadcastConsensus<Sig, Verifier>,
    },
    ReceivingBc {
        round: Box<dyn TypeErasedRound<Res>>,
        bc: BroadcastConsensus<Sig, Verifier>,
    },
    Halted(Error),
}

pub struct Session<Res, Sig, Signer, Verifier> {
    state: State<Res, Sig, Verifier>,
    signer: Signer,
    verifiers: Vec<Verifier>,
    message_cache: Vec<(PartyIdx, VerifiedMessage<Sig>)>, // could it be in the state as well?
    party_idx: PartyIdx,
    // TODO: do we need to save broadcast conesnsus messages too?
    received_messages: BTreeMap<u8, Vec<(PartyIdx, VerifiedMessage<Sig>)>>,
}

impl<Res, Sig, Signer, Verifier> Session<Res, Sig, Signer, Verifier>
where
    Res: Clone,
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    Signer: PrehashSigner<Sig> + Clone,
    Verifier: Clone + PrehashVerifier<Sig> + Clone,
{
    pub(crate) fn new<R: FirstRound + 'static>(
        rng: &mut impl CryptoRngCore,
        // TODO: merge signers and verifiers into one struct to make getting party_idx more natural?
        signer: &Signer,
        party_idx: PartyIdx,
        verifiers: &[Verifier],
        context: &R::Context,
    ) -> Self
    where
        R: Round<Result = Res>,
    {
        let round = R::new(rng, verifiers.len(), party_idx, context);
        let boxed_round: Box<dyn TypeErasedRound<Res>> = Box::new(round);
        let state = State::Sending(boxed_round);
        Self {
            state,
            signer: signer.clone(),
            verifiers: verifiers.into(),
            message_cache: Vec::new(),
            party_idx,
            received_messages: BTreeMap::new(),
        }
    }

    pub fn party_idx(&self) -> PartyIdx {
        self.party_idx
    }

    pub fn num_parties(&self) -> usize {
        self.verifiers.len()
    }

    fn sign_messages(
        &self,
        to_send: &ToSendSerialized,
        round_num: u8,
        bc_consensus: bool,
    ) -> Result<ToSend<Sig>, Error> {
        Ok(match &to_send {
            ToSendSerialized::Broadcast(message_bytes) => {
                let message =
                    VerifiedMessage::new(&self.signer, round_num, bc_consensus, message_bytes)
                        .map_err(Error::MyFault)?;
                ToSend::Broadcast(message.into_unverified())
            }
            ToSendSerialized::Direct(messages) => {
                let mut signed_messages = Vec::with_capacity(messages.len());
                for (index, message_bytes) in messages.iter() {
                    let signed_message =
                        VerifiedMessage::new(&self.signer, round_num, bc_consensus, message_bytes)
                            .map_err(Error::MyFault)?;
                    signed_messages.push((*index, signed_message.into_unverified()));
                }
                ToSend::Direct(signed_messages)
            }
        })
    }

    pub fn start_receiving(&mut self, rng: &mut impl CryptoRngCore) -> Result<ToSend<Sig>, Error> {
        let state = self.state.clone();
        let (state, to_send) = match state {
            State::Sending(round) => {
                let round_num = round.round_num();
                let (receiving_round, to_send) = round.to_receiving_state(rng);
                let signed_to_send = self.sign_messages(&to_send, round_num, false)?;
                self.received_messages.insert(round_num, Vec::new());
                (State::Receiving(receiving_round), signed_to_send)
            }
            State::SendingBc { round, bc } => {
                let round_num = round.round_num() - 1;
                let to_send = bc.to_send();
                let signed_to_send = self.sign_messages(&to_send, round_num, true)?;
                (State::ReceivingBc { round, bc }, signed_to_send)
            }
            _ => {
                return Err(Error::MyFault(MyFault::InvalidState(
                    "Invalid state".into(),
                )))
            }
        };
        self.state = state;
        Ok(to_send)
    }

    pub fn receive(&mut self, from: PartyIdx, message: SignedMessage<Sig>) -> Result<(), Error> {
        let verified_message = message.verify(&self.verifiers[from.as_usize()]).unwrap();

        let (for_this_round, for_next_round) = match &self.state {
            State::Receiving(round) => (
                Self::message_for_this_round_normal(round.as_ref(), &verified_message),
                Self::message_for_next_round_normal(round.as_ref(), &verified_message),
            ),
            State::ReceivingBc { round, .. } => (
                Self::message_for_this_round_bc(round.as_ref(), &verified_message),
                Self::message_for_next_round_bc(round.as_ref(), &verified_message),
            ),
            _ => {
                return Err(Error::MyFault(MyFault::InvalidState(
                    "Invalid state".into(),
                )))
            }
        };

        if for_this_round {
            self.receive_verified(from, verified_message)
        } else if for_next_round {
            self.message_cache.push((from, verified_message));
            Ok(())
        } else {
            Err(Error::TheirFault {
                party: from,
                error: TheirFault::OutOfOrderMessage,
            })
        }
    }

    fn receive_verified(
        &mut self,
        from: PartyIdx,
        verified_message: VerifiedMessage<Sig>,
    ) -> Result<(), Error> {
        match &mut self.state {
            State::Receiving(round) => {
                self.received_messages
                    .get_mut(&round.round_num())
                    .unwrap()
                    .push((from, verified_message.clone()));
                Self::receive_normal(round.as_mut(), from, verified_message)
            }
            State::ReceivingBc { bc, .. } => Self::receive_bc(bc, from, verified_message),
            _ => Err(Error::MyFault(MyFault::InvalidState(
                "Invalid state".into(),
            ))),
        }
    }

    fn receive_normal(
        round: &mut dyn TypeErasedReceivingRound<Res>,
        from: PartyIdx,
        message: VerifiedMessage<Sig>,
    ) -> Result<(), Error> {
        match round.receive(from, message.payload()) {
            ReceiveOutcome::Success => Ok(()),
            ReceiveOutcome::Error(err) => Err(Error::TheirFault {
                party: from,
                error: TheirFault::Receive(format!("{:?}", err)),
            }),
            // TODO: here we may check if the message is a duplicate, or has different contents
            // the latter should be a more serious error.
            ReceiveOutcome::AlreadyReceived => Err(Error::TheirFault {
                party: from,
                error: TheirFault::DuplicateMessage,
            }),
            ReceiveOutcome::DeserializationFail(err) => Err(Error::TheirFault {
                party: from,
                error: TheirFault::DeserializationError(err),
            }),
        }
    }

    fn receive_bc(
        bc: &mut BroadcastConsensus<Sig, Verifier>,
        from: PartyIdx,
        message: VerifiedMessage<Sig>,
    ) -> Result<(), Error> {
        bc.receive_message(from, message)
    }

    fn message_for_this_round_normal(
        round: &dyn TypeErasedReceivingRound<Res>,
        message: &VerifiedMessage<Sig>,
    ) -> bool {
        message.round() == round.round_num() && !message.broadcast_consensus()
    }

    fn message_for_this_round_bc(
        next_round: &dyn TypeErasedRound<Res>,
        message: &VerifiedMessage<Sig>,
    ) -> bool {
        message.round() == next_round.round_num() - 1 && message.broadcast_consensus()
    }

    fn message_for_next_round_normal(
        round: &dyn TypeErasedReceivingRound<Res>,
        message: &VerifiedMessage<Sig>,
    ) -> bool {
        let this_round = round.round_num();
        let next_round = round.next_round_num();
        let requires_bc = round.requires_broadcast_consensus();

        let message_round = message.round();
        let message_bc = message.broadcast_consensus();

        // This is a non-broadcast round, and the next round exists, and the message is for it
        (!requires_bc && next_round.is_some() && message_round == next_round.unwrap() && !message_bc) ||
        // This is a broadcast round, and the message is from the broadcast consensus round
        (requires_bc && message_round == this_round && message_bc)
    }

    fn message_for_next_round_bc(
        next_round: &dyn TypeErasedRound<Res>,
        message: &VerifiedMessage<Sig>,
    ) -> bool {
        // This is a broadcast consensus round, and the next round exists, and the message is for it
        message.round() == next_round.round_num() && !message.broadcast_consensus()
    }

    fn finalize_regular_round(
        &mut self,
        round: Box<dyn TypeErasedReceivingRound<Res>>,
        rng: &mut impl CryptoRngCore,
    ) -> State<Res, Sig, Verifier> {
        let round_num = round.round_num();
        let requires_bc = round.requires_broadcast_consensus();

        match round.finalize(rng) {
            FinalizeOutcome::Result(res) => State::Result(res),
            FinalizeOutcome::AnotherRound(round) => {
                if requires_bc {
                    let broadcasts = self.received_messages[&round_num].clone();
                    let bc = BroadcastConsensus::new(broadcasts, &self.verifiers);
                    State::SendingBc { round, bc }
                } else {
                    State::Sending(round)
                }
            }
            FinalizeOutcome::NotEnoughMessages => State::Halted(Error::NotEnoughMessages),
            FinalizeOutcome::Error(_) => State::Halted(Error::Finalize),
        }
    }

    fn finalize_bc_round(
        &mut self,
        round: Box<dyn TypeErasedRound<Res>>,
        bc: BroadcastConsensus<Sig, Verifier>,
    ) -> State<Res, Sig, Verifier> {
        match bc.finalize() {
            Ok(_) => {}
            Err(err) => return State::Halted(err),
        };
        State::Sending(round)
    }

    pub fn finalize_round(&mut self, rng: &mut impl CryptoRngCore) -> Result<(), Error> {
        let state = self.state.clone();
        self.state = match state {
            State::Receiving(round) => self.finalize_regular_round(round, rng),
            State::ReceivingBc { round, bc } => self.finalize_bc_round(round, bc),
            _ => {
                return Err(Error::MyFault(MyFault::InvalidState(
                    "Invalid state".into(),
                )))
            }
        };

        if let State::Halted(err) = &self.state {
            return Err(err.clone());
        }

        Ok(())
    }

    pub fn has_cached_messages(&self) -> bool {
        !self.message_cache.is_empty()
    }

    pub fn receive_cached_message(&mut self) -> Result<(), Error> {
        let (from, verified_message) = self.message_cache.pop().ok_or_else(|| {
            Error::MyFault(MyFault::InvalidState("No more cached messages left".into()))
        })?;
        self.receive_verified(from, verified_message)
    }

    pub fn can_finalize(&self) -> Result<bool, Error> {
        match &self.state {
            State::Receiving(round) => Ok(round.can_finalize()),
            State::ReceivingBc { bc, .. } => Ok(bc.can_finalize()),
            _ => Err(Error::MyFault(MyFault::InvalidState(
                "Invalid state".into(),
            ))),
        }
    }

    pub fn is_finished(&self) -> bool {
        matches!(&self.state, State::Result(_) | State::Halted(_))
    }

    pub fn result(&self) -> Result<&Res, Error> {
        match &self.state {
            State::Result(res) => Ok(res),
            State::Halted(err) => Err(err.clone()),
            _ => Err(Error::MyFault(MyFault::InvalidState(
                "Invalid state".into(),
            ))),
        }
    }
}
