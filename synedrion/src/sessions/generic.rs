use alloc::boxed::Box;
use alloc::format;
use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use signature::hazmat::{PrehashSigner, PrehashVerifier};

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

enum State<Res> {
    Result(Res),
    Receiving {
        round: Box<dyn TypeErasedReceivingRound<Res>>,
        to_send: ToSendSerialized,
    },
    Halted(Error),
}

impl<Res> State<Res> {
    fn mutate(&mut self, callable: impl FnOnce(Self) -> Self) {
        let state = core::mem::replace(self, State::Halted(Error::Finalize));
        let new_state = callable(state);
        *self = new_state;
    }
}

pub struct Session<Res, Sig, Signer, Verifier>
where
    Signer: PrehashSigner<Sig>,
    Verifier: PrehashVerifier<Sig>,
{
    signer: Signer,
    verifiers: Vec<Verifier>,
    message_cache: Vec<(PartyIdx, VerifiedMessage<Sig>)>,
    state: State<Res>,
    party_idx: PartyIdx,
    //broadcast_consensus: Option<BroadcastConsensus<Sig>>,
    phantom_signature: PhantomData<Sig>,
}

impl<Res, Sig, Signer, Verifier> Session<Res, Sig, Signer, Verifier>
where
    Signer: PrehashSigner<Sig> + Clone,
    Verifier: PrehashVerifier<Sig> + Clone,
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

        let (round, to_send) = boxed_round.to_receiving_state(rng);

        Self {
            signer: signer.clone(),
            verifiers: verifiers.into(),
            message_cache: Vec::new(),
            state: State::Receiving { round, to_send },
            party_idx: party_idx,
            phantom_signature: PhantomData,
        }
    }

    pub fn party_idx(&self) -> PartyIdx {
        self.party_idx
    }

    pub fn num_parties(&self) -> usize {
        self.verifiers.len()
    }

    fn round_ref(&self) -> Result<&Box<dyn TypeErasedReceivingRound<Res>>, Error> {
        match &self.state {
            State::Receiving { round, .. } => Ok(&round),
            State::Result(_) => Err(Error::MyFault(MyFault::InvalidState(
                "Result is reached".into(),
            ))),
            State::Halted(_) => Err(Error::MyFault(MyFault::InvalidState("Halted".into()))),
        }
    }

    fn round_ref_mut(&mut self) -> Result<&mut Box<dyn TypeErasedReceivingRound<Res>>, Error> {
        match &mut self.state {
            State::Receiving { round, .. } => Ok(round),
            State::Result(_) => Err(Error::MyFault(MyFault::InvalidState(
                "Result is reached".into(),
            ))),
            State::Halted(_) => Err(Error::MyFault(MyFault::InvalidState("Halted".into()))),
        }
    }

    pub fn get_messages(&mut self) -> Result<ToSend<Sig>, Error> {
        let (round, to_send) = match &self.state {
            State::Receiving { round, to_send } => Ok((round, to_send)),
            State::Result(_) => Err(Error::MyFault(MyFault::InvalidState(
                "Result is reached".into(),
            ))),
            State::Halted(_) => Err(Error::MyFault(MyFault::InvalidState("Halted".into()))),
        }?;

        let round_num = round.round_num();
        Ok(match &to_send {
            ToSendSerialized::Broadcast(message_bytes) => {
                let message = VerifiedMessage::new(&self.signer, round_num, false, &message_bytes)
                    .map_err(Error::MyFault)?;
                ToSend::Broadcast(message.into_unverified())
            }
            ToSendSerialized::Direct(messages) => {
                let mut signed_messages = Vec::with_capacity(messages.len());
                for (index, message_bytes) in messages.iter() {
                    let signed_message =
                        VerifiedMessage::new(&self.signer, round_num, false, &message_bytes)
                            .map_err(Error::MyFault)?;
                    signed_messages.push((*index, signed_message.into_unverified()));
                }
                ToSend::Direct(signed_messages)
            }
        })
    }

    fn receive_message(
        &mut self,
        from: PartyIdx,
        message: VerifiedMessage<Sig>,
    ) -> Result<(), Error> {
        let round = self.round_ref_mut()?;
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

    pub fn receive(&mut self, from: PartyIdx, message: SignedMessage<Sig>) -> Result<(), Error> {
        let round = self.round_ref()?;
        let this_round = round.round_num();
        let next_round = round.next_round_num();

        let verified_message = message.verify(&self.verifiers[from.as_usize()]).unwrap();

        let message_round = verified_message.round();

        let message_for_this_round = message_round == this_round;
        let message_for_next_round = next_round.is_some() && message_round == next_round.unwrap();

        if message_for_this_round {
            return self.receive_message(from, verified_message);
        } else if message_for_next_round {
            self.message_cache.push((from, verified_message));
        } else {
            return Err(Error::TheirFault {
                party: from,
                error: TheirFault::OutOfOrderMessage {
                    current_stage: this_round,
                    message_stage: message_round,
                },
            });
        }

        Ok(())
    }

    pub fn receive_cached_message(&mut self) -> Result<(), Error> {
        let (from, verified_message) = self.message_cache.pop().ok_or_else(|| {
            Error::MyFault(MyFault::InvalidState("No more cached messages left".into()))
        })?;
        self.receive_message(from, verified_message)
    }

    pub fn is_finished_receiving(&self) -> Result<bool, Error> {
        self.round_ref().map(|round| round.is_finished_receiving())
    }

    fn finalize_impl(state: State<Res>, rng: &mut impl CryptoRngCore) -> State<Res> {
        let round = match state {
            State::Receiving { round, .. } => round,
            _ => {
                return State::Halted(Error::MyFault(MyFault::InvalidState(
                    "Not in receiving state".into(),
                )))
            }
        };

        // TODO: check that there are no cached messages left

        match round.finalize(rng) {
            FinalizeOutcome::Result(res) => State::Result(res),
            FinalizeOutcome::AnotherRound(round) => {
                let (round, to_send) = round.to_receiving_state(rng);
                State::Receiving { round, to_send }
            }
            FinalizeOutcome::NotEnoughMessages => State::Halted(Error::NotEnoughMessages),
            FinalizeOutcome::Error(_) => State::Halted(Error::Finalize),
        }
    }

    pub fn finalize_round(&mut self, rng: &mut impl CryptoRngCore) -> Result<(), Error> {
        self.state.mutate(|state| Self::finalize_impl(state, rng));

        Ok(())
    }

    pub fn result(&self) -> Option<&Res> {
        match &self.state {
            State::Receiving { .. } => None,
            State::Result(res) => Some(res),
            State::Halted(_) => None,
        }
    }

    pub fn has_cached_messages(&self) -> bool {
        !self.message_cache.is_empty()
    }

    pub fn is_finished(&self) -> bool {
        match &self.state {
            State::Receiving { .. } => false,
            _ => true,
        }
    }
}

/*
impl<Res, Sig, Signer, Verifier> Session<Res, Sig, Signer, Verifier>
where
    Signer: PrehashSigner<Sig> + Clone,
    Verifier: PrehashVerifier<Sig> + Clone,
{
    pub fn new<R: Round<Result=Res>>(
        rng: &mut impl CryptoRngCore,
        round: R,
        signer: &Signer,
        verifiers: &[Verifier],
        // TODO: `num_parties` and `index` can be merged with signer and verifier in a single struct
        num_parties: usize,
        index: PartyIdx,
    ) -> Self
    {
        let with_accum = RoundAndAccum::new(round, num_parties, index.as_usize());
        let type_erased: Box<dyn TypeErasedRound> = Box::new(with_accum);
    }

    pub fn get_messages(&mut self, rng: &mut impl CryptoRngCore) -> Result<ToSend<Sig>, Error> {
        let to_send = self.round.to_send(rng).unwrap();
        let round_num = self.round.round_num();
        Ok(match to_send {
            ToSendSerialized::Broadcast(message_bytes) => {
                let message = VerifiedMessage::new(&self.signer, round_num, &message_bytes)
                    .map_err(Error::MyFault)?;
                ToSend::Broadcast(message.into_unverified())
            }
            ToSendSerialized::Direct(messages) => {
                let mut signed_messages = Vec::with_capacity(messages.len());
                for (index, message_bytes) in messages.into_iter() {
                    let signed_message =
                        VerifiedMessage::new(&self.signer, round_num, &message_bytes)
                            .map_err(Error::MyFault)?;
                    signed_messages.push((index, signed_message.into_unverified()));
                }
                ToSend::Direct(signed_messages)
            }
        })
    }

    pub fn receive(&mut self, from: PartyIdx, message: SignedMessage<Sig>) -> Result<(), Error> {
        let this_round = self.round.round_num();
        let next_round = self.round.next_round_num();
        let requires_bc = self.round.requires_broadcast();
        let bc_round = self.broadcast_consensus.is_some();

        let verified_message = message.verify(&self.verifiers[from.as_usize()]).unwrap();

        let message_round = verified_message.round();
        let message_bc = verified_message.broadcast_consensus();

        let message_for_this_round = message_round == this_round && message_bc == bc_round;
        let message_for_next_round =
            // This is a non-broadcast round, and the next round exists, and the message is for it
            (next_round.is_some() && message_round == next_round.unwrap() && !bc_round && !requires_bc) ||
            // This is a broadcast consensus round, and the next round exists, and the message is for it
            (next_round.is_some() && message_round == next_round.unwrap() && bc_round) ||
            // This is a broadcast round, and the message is from the broadcast consensus round
            (message_round == this_round && !bc_round && requires_bc && message_bc);

        if message_for_this_round {
            if bc_round {
                self.broadcast_consensus.receive(from, verified_message).unwrap();
            }
            else {
                self.round.receive(from, verified_message.payload())?;
            }
        }
        else if message_for_next_round {
            self.message_cache.push((from, verified_message));
        } else {
            return Err(Error::TheirFault {
                party: from,
                error: TheirFault::OutOfOrderMessage {
                    current_stage: this_round,
                    message_stage: message_round,
                },
            });
        }

        Ok(())
    }

    pub fn receive_cached_message(&mut self) -> Result<(), Error> {
        let (from, verified_message) = self.message_cache.pop().ok_or_else(|| {
            Error::MyFault(MyFault::InvalidState("No more cached messages left".into()))
        })?;

        if let Some(bc) = self.broadcast_consensus {
            bc.receive(from, verified_message)
        }
        else {
            self.round.receive(from, verified_message.payload())
        }
    }

    pub fn is_finished_receiving(&self) -> Result<bool, Error> {
        self.round.is_finished_receiving().map_err(Error::MyFault)
    }

    pub fn finalize_round(&mut self, rng: &mut impl CryptoRngCore) -> Result<(), Error> {
        // TODO: check that there are no cached messages left
        let result = self.round.finalize(rng)?;
        match result {
            TypeErasedResult::Result(res) => self.result = Some(res),
            TypeErasedResult::HappyPath(round) => self.round = round,
            TypeErasedResult::ErrorPath(round) => self.round = round,
        }

        Ok(())
    }

    pub fn result(&self) -> Option<Res> {
        self.result
    }

    pub fn has_cached_messages(&self) -> bool {
        !self.message_cache.is_empty()
    }
}
*/
