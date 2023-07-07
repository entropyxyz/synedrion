use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::hazmat::{PrehashSigner, PrehashVerifier};

use super::broadcast::BroadcastConsensus;
use super::error::{Error, MyFault, TheirFault};
use super::signed_message::{SessionId, SignedMessage, VerifiedMessage};
use super::type_erased::{
    self, ReceiveOutcome, ToSendSerialized, TypeErasedReceivingRound, TypeErasedRound,
};
use crate::protocols::generic::{FirstRound, Round};
use crate::PartyIdx;

pub enum ToSend<Sig> {
    Broadcast(SignedMessage<Sig>),
    // TODO: return an iterator instead, since preparing one message can take some time
    Direct(Vec<(PartyIdx, SignedMessage<Sig>)>),
}

struct Context<Sig, Signer, Verifier> {
    signer: Signer,
    verifiers: Vec<Verifier>,
    session_id: SessionId,
    party_idx: PartyIdx,
    message_cache: Vec<(PartyIdx, VerifiedMessage<Sig>)>, // could it be in the state as well?
    // TODO: do we need to save broadcast conesnsus messages too?
    received_messages: BTreeMap<u8, Vec<(PartyIdx, VerifiedMessage<Sig>)>>,
}

enum SendingType<Res, Sig, Verifier> {
    Normal(Box<dyn TypeErasedRound<Res>>),
    Bc {
        next_round: Box<dyn TypeErasedRound<Res>>,
        bc: BroadcastConsensus<Sig, Verifier>,
    },
}

pub struct SendingState<Res, Sig, Signer, Verifier> {
    tp: SendingType<Res, Sig, Verifier>,
    context: Context<Sig, Signer, Verifier>,
}

enum ReceivingType<Res, Sig, Verifier> {
    Normal(Box<dyn TypeErasedReceivingRound<Res>>),
    Bc {
        next_round: Box<dyn TypeErasedRound<Res>>,
        bc: BroadcastConsensus<Sig, Verifier>,
    },
}

pub struct ReceivingState<Res, Sig, Signer, Verifier> {
    tp: ReceivingType<Res, Sig, Verifier>,
    context: Context<Sig, Signer, Verifier>,
}

impl<Res, Sig, Signer, Verifier> SendingState<Res, Sig, Signer, Verifier>
where
    Signer: PrehashSigner<Sig>,
    Verifier: Clone + PrehashVerifier<Sig>,
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
{
    pub(crate) fn new<R: FirstRound + 'static>(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        // TODO: merge signers and verifiers into one struct to make getting party_idx more natural?
        signer: Signer,
        party_idx: PartyIdx,
        verifiers: &[Verifier],
        context: R::Context,
    ) -> Self
    where
        R: Round<Result = Res>,
    {
        // CHECK: is this enough? Do we need to hash in e.g. the verifier public keys?
        // TODO: Need to specify the requirements for the shared randomness in the docstring.
        let session_id = SessionId::from_seed(shared_randomness);
        let typed_round = R::new(rng, shared_randomness, verifiers.len(), party_idx, context);
        let round: Box<dyn TypeErasedRound<Res>> = Box::new(typed_round);
        let context = Context {
            signer,
            verifiers: verifiers.into(),
            session_id,
            party_idx,
            message_cache: Vec::new(),
            received_messages: BTreeMap::new(),
        };
        Self {
            tp: SendingType::Normal(round),
            context,
        }
    }

    fn sign_messages(
        signer: &Signer,
        session_id: &SessionId,
        to_send: &ToSendSerialized,
        round_num: u8,
        bc_consensus: bool,
    ) -> Result<ToSend<Sig>, Error> {
        Ok(match &to_send {
            ToSendSerialized::Broadcast(message_bytes) => {
                let message = VerifiedMessage::new(
                    signer,
                    session_id,
                    round_num,
                    bc_consensus,
                    message_bytes,
                )
                .map_err(Error::MyFault)?;
                ToSend::Broadcast(message.into_unverified())
            }
            ToSendSerialized::Direct(messages) => {
                let mut signed_messages = Vec::with_capacity(messages.len());
                for (index, message_bytes) in messages.iter() {
                    let signed_message = VerifiedMessage::new(
                        signer,
                        session_id,
                        round_num,
                        bc_consensus,
                        message_bytes,
                    )
                    .map_err(Error::MyFault)?;
                    signed_messages.push((*index, signed_message.into_unverified()));
                }
                ToSend::Direct(signed_messages)
            }
        })
    }

    #[allow(clippy::type_complexity)]
    pub fn start_receiving(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(ReceivingState<Res, Sig, Signer, Verifier>, ToSend<Sig>), Error> {
        let mut context = self.context;
        match self.tp {
            SendingType::Normal(round) => {
                let round_num = round.round_num();
                let (receiving_round, to_send) =
                    round.to_receiving_state(rng, context.verifiers.len(), context.party_idx);
                let signed_to_send = Self::sign_messages(
                    &context.signer,
                    &context.session_id,
                    &to_send,
                    round_num,
                    false,
                )?;
                context.received_messages.insert(round_num, Vec::new());
                let state = ReceivingState {
                    tp: ReceivingType::Normal(receiving_round),
                    context,
                };
                Ok((state, signed_to_send))
            }
            SendingType::Bc { next_round, bc } => {
                let round_num = next_round.round_num() - 1;
                let to_send = bc.to_send();
                let signed_to_send = Self::sign_messages(
                    &context.signer,
                    &context.session_id,
                    &to_send,
                    round_num,
                    true,
                )?;
                let state = ReceivingState {
                    tp: ReceivingType::Bc { next_round, bc },
                    context,
                };
                Ok((state, signed_to_send))
            }
        }
    }
}

enum MessageFor {
    ThisRound,
    NextRound,
    OutOfOrder,
}

fn route_message_normal<Sig, Res>(
    round: &dyn TypeErasedReceivingRound<Res>,
    message: &VerifiedMessage<Sig>,
) -> MessageFor {
    let this_round = round.round_num();
    let next_round = round.next_round_num();
    let requires_bc = round.requires_broadcast_consensus();

    let message_round = message.round();
    let message_bc = message.broadcast_consensus();

    if message_round == this_round && !message_bc {
        return MessageFor::ThisRound;
    }

    let for_next_round =
    // This is a non-broadcast round, and the next round exists, and the message is for it
    (!requires_bc && next_round.is_some() && message_round == next_round.unwrap() && !message_bc) ||
    // This is a broadcast round, and the message is from the broadcast consensus round
    (requires_bc && message_round == this_round && message_bc);

    if for_next_round {
        return MessageFor::NextRound;
    }

    MessageFor::OutOfOrder
}

fn route_message_bc<Sig, Res>(
    next_round: &dyn TypeErasedRound<Res>,
    message: &VerifiedMessage<Sig>,
) -> MessageFor {
    let next_round = next_round.round_num();
    let message_round = message.round();
    let message_bc = message.broadcast_consensus();

    if message_round == next_round - 1 && message_bc {
        return MessageFor::ThisRound;
    }

    if message_round == next_round && !message_bc {
        return MessageFor::NextRound;
    }

    MessageFor::OutOfOrder
}

pub enum FinalizeOutcome<Res, Sig, Signer, Verifier> {
    Result(Res),
    AnotherRound(SendingState<Res, Sig, Signer, Verifier>),
}

impl<Res, Sig, Signer, Verifier> ReceivingState<Res, Sig, Signer, Verifier>
where
    Signer: PrehashSigner<Sig>,
    Verifier: Clone + PrehashVerifier<Sig>,
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
{
    pub fn current_stage(&self) -> (u8, bool) {
        match &self.tp {
            ReceivingType::Normal(round) => (round.round_num(), false),
            ReceivingType::Bc { next_round, .. } => (next_round.round_num() - 1, true),
        }
    }

    pub fn receive(&mut self, from: PartyIdx, message: SignedMessage<Sig>) -> Result<(), Error> {
        let verified_message = message
            .verify(&self.context.verifiers[from.as_usize()])
            .unwrap();

        // TODO: this is an unprovable fault (may be a replay attack)
        if verified_message.session_id() != &self.context.session_id {
            return Err(Error::TheirFault {
                party: from,
                error: TheirFault::InvalidSessionId,
            });
        }

        let message_for = match &self.tp {
            ReceivingType::Normal(round) => route_message_normal(round.as_ref(), &verified_message),
            ReceivingType::Bc { next_round, .. } => {
                route_message_bc(next_round.as_ref(), &verified_message)
            }
        };

        match message_for {
            MessageFor::ThisRound => self.receive_verified(from, verified_message),
            MessageFor::NextRound => {
                self.context.message_cache.push((from, verified_message));
                Ok(())
            }
            // TODO: this is an unprovable fault (may be a replay attack)
            MessageFor::OutOfOrder => Err(Error::TheirFault {
                party: from,
                error: TheirFault::OutOfOrderMessage,
            }),
        }
    }

    fn receive_verified(
        &mut self,
        from: PartyIdx,
        verified_message: VerifiedMessage<Sig>,
    ) -> Result<(), Error> {
        match &mut self.tp {
            ReceivingType::Normal(round) => {
                self.context
                    .received_messages
                    .get_mut(&round.round_num())
                    .unwrap()
                    .push((from, verified_message.clone()));
                Self::receive_normal(round.as_mut(), from, verified_message)
            }
            ReceivingType::Bc { bc, .. } => Self::receive_bc(bc, from, verified_message),
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

    fn finalize_regular_round(
        context: Context<Sig, Signer, Verifier>,
        round: Box<dyn TypeErasedReceivingRound<Res>>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<FinalizeOutcome<Res, Sig, Signer, Verifier>, Error> {
        let round_num = round.round_num();
        let requires_bc = round.requires_broadcast_consensus();

        match round.finalize(rng) {
            type_erased::FinalizeOutcome::Result(res) => Ok(FinalizeOutcome::Result(res)),
            type_erased::FinalizeOutcome::AnotherRound(next_round) => {
                if requires_bc {
                    let broadcasts = context.received_messages[&round_num].clone();
                    let bc = BroadcastConsensus::new(broadcasts, &context.verifiers);
                    Ok(FinalizeOutcome::AnotherRound(SendingState {
                        tp: SendingType::Bc { next_round, bc },
                        context,
                    }))
                } else {
                    Ok(FinalizeOutcome::AnotherRound(SendingState {
                        tp: SendingType::Normal(next_round),
                        context,
                    }))
                }
            }
            type_erased::FinalizeOutcome::NotEnoughMessages => Err(Error::NotEnoughMessages),
            // TODO: propagate the error
            type_erased::FinalizeOutcome::Error(_) => Err(Error::Finalize),
        }
    }

    fn finalize_bc_round(
        context: Context<Sig, Signer, Verifier>,
        round: Box<dyn TypeErasedRound<Res>>,
        bc: BroadcastConsensus<Sig, Verifier>,
    ) -> Result<FinalizeOutcome<Res, Sig, Signer, Verifier>, Error> {
        bc.finalize().map(|_| {
            FinalizeOutcome::AnotherRound(SendingState {
                tp: SendingType::Normal(round),
                context,
            })
        })
    }

    pub fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<FinalizeOutcome<Res, Sig, Signer, Verifier>, Error> {
        match self.tp {
            ReceivingType::Normal(round) => Self::finalize_regular_round(self.context, round, rng),
            ReceivingType::Bc { next_round, bc } => {
                Self::finalize_bc_round(self.context, next_round, bc)
            }
        }
    }

    pub fn has_cached_messages(&self) -> bool {
        !self.context.message_cache.is_empty()
    }

    pub fn receive_cached_message(&mut self) -> Result<(), Error> {
        let (from, verified_message) = self.context.message_cache.pop().ok_or_else(|| {
            Error::MyFault(MyFault::InvalidState("No more cached messages left".into()))
        })?;
        self.receive_verified(from, verified_message)
    }

    pub fn can_finalize(&self) -> bool {
        match &self.tp {
            ReceivingType::Normal(round) => round.can_finalize(),
            ReceivingType::Bc { bc, .. } => bc.can_finalize(),
        }
    }
}
