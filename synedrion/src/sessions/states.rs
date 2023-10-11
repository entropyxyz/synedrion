use alloc::boxed::Box;
use alloc::vec::Vec;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};

use super::broadcast::{BcConsensusAccum, BroadcastConsensus};
use super::error::{Error, MyFault, TheirFault};
use super::signed_message::{MessageType, SessionId, SignedMessage, VerifiedMessage};
use super::type_erased::{
    self, TypeErasedBcPayload, TypeErasedDmArtefact, TypeErasedDmPayload, TypeErasedFinalizable,
    TypeErasedRoundAccum,
};
use crate::cggmp21::{FirstRound, InitError, Round};
use crate::tools::collections::HoleRange;
use crate::PartyIdx;

struct Context<Signer, Verifier> {
    signer: Signer,
    verifiers: Vec<Verifier>,
    session_id: SessionId,
    party_idx: PartyIdx,
}

enum SessionType<Res, Sig, Verifier> {
    Normal(Box<dyn TypeErasedFinalizable<Res>>),
    Bc {
        next_round: Box<dyn TypeErasedFinalizable<Res>>,
        bc: BroadcastConsensus<Sig, Verifier>,
    },
}

/// The session state where it is ready to send messages.
pub struct Session<Res, Sig, Signer, Verifier> {
    tp: SessionType<Res, Sig, Verifier>,
    context: Context<Signer, Verifier>,
}

enum MessageFor {
    ThisRound,
    NextRound,
    OutOfOrder,
}

fn route_message_normal<Sig, Res>(
    round: &dyn TypeErasedFinalizable<Res>,
    message: &SignedMessage<Sig>,
) -> MessageFor {
    let this_round = round.round_num();
    let next_round = round.next_round_num();
    let requires_bc = round.requires_broadcast_consensus();

    let message_round = message.round();
    let message_bc = message.message_type() == MessageType::BroadcastConsensus;

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
    next_round: &dyn TypeErasedFinalizable<Res>,
    message: &SignedMessage<Sig>,
) -> MessageFor {
    let next_round = next_round.round_num();
    let message_round = message.round();
    let message_bc = message.message_type() == MessageType::BroadcastConsensus;

    if message_round == next_round - 1 && message_bc {
        return MessageFor::ThisRound;
    }

    if message_round == next_round && !message_bc {
        return MessageFor::NextRound;
    }

    MessageFor::OutOfOrder
}

/// Possible outcomes of successfully finalizing a round.
pub enum FinalizeOutcome<Res, Sig, Signer, Verifier> {
    /// The protocol result is available.
    Result(Res),
    /// Starting the next round.
    AnotherRound(
        Session<Res, Sig, Signer, Verifier>,
        Vec<(PartyIdx, SignedMessage<Sig>)>,
    ),
}

impl<Res, Sig, Signer, Verifier> Session<Res, Sig, Signer, Verifier>
where
    Signer: RandomizedPrehashSigner<Sig>,
    Verifier: Clone + PrehashVerifier<Sig>,
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
{
    pub(crate) fn new<
        R: FirstRound + TypeErasedFinalizable<Res> + Round<Result = Res> + 'static,
    >(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        // TODO: merge signers and verifiers into one struct to make getting party_idx more natural?
        signer: Signer,
        party_idx: PartyIdx,
        verifiers: &[Verifier],
        context: R::Context,
    ) -> Result<Self, InitError> {
        // CHECK: is this enough? Do we need to hash in e.g. the verifier public keys?
        // TODO: Need to specify the requirements for the shared randomness in the docstring.
        let session_id = SessionId::from_seed(shared_randomness);
        let typed_round = R::new(rng, shared_randomness, verifiers.len(), party_idx, context)?;
        let round: Box<dyn TypeErasedFinalizable<Res>> = Box::new(typed_round);
        let context = Context {
            signer,
            verifiers: verifiers.into(),
            session_id,
            party_idx,
        };
        Ok(Self {
            tp: SessionType::Normal(round),
            context,
        })
    }

    /// Returns a pair of the current round index and whether it is a broadcast consensus stage.
    pub fn current_round(&self) -> (u8, bool) {
        match &self.tp {
            SessionType::Normal(round) => (round.round_num(), false),
            SessionType::Bc { next_round, .. } => (next_round.round_num() - 1, true),
        }
    }

    /// Create an accumulator to store message creation and processing results of this round.
    pub fn make_accumulator(&self) -> RoundAccumulator<Sig> {
        RoundAccumulator::new(
            self.context.verifiers.len(),
            self.context.party_idx,
            self.broadcast_destinations().is_some(),
            self.direct_message_destinations().is_some(),
        )
    }

    /// Returns `true` if the round can be finalized.
    pub fn can_finalize(&self, accum: &RoundAccumulator<Sig>) -> bool {
        match &self.tp {
            SessionType::Normal(_) => accum.processed.can_finalize(),
            SessionType::Bc { .. } => accum.bc_accum.can_finalize(),
        }
    }

    /// Returns the party indices to which the broadcast of this round should be sent;
    /// if `None`, there is no broadcast in this round.
    pub fn broadcast_destinations(&self) -> Option<Vec<PartyIdx>> {
        let range = HoleRange::new(
            self.context.verifiers.len(),
            self.context.party_idx.as_usize(),
        );
        match &self.tp {
            SessionType::Normal(round) => round
                .broadcast_destinations()
                .map(|range| range.map(PartyIdx::from_usize).collect()),
            SessionType::Bc { .. } => Some(range.map(PartyIdx::from_usize).collect()),
        }
    }

    /// Returns the current round's broadcast.
    pub fn make_broadcast(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<SignedMessage<Sig>, Error> {
        let (round_num, payload, is_bc_consensus) = match &self.tp {
            SessionType::Normal(round) => {
                let round_num = round.round_num();
                if round.broadcast_destinations().is_none() {
                    return Err(Error::MyFault(MyFault::InvalidState(
                        "This round does not send out broadcasts".into(),
                    )));
                }

                let payload = round
                    .make_broadcast(rng)
                    .map_err(|err| Error::MyFault(MyFault::TypeErased(err)))?;
                (round_num, payload, false)
            }
            SessionType::Bc { next_round, bc } => {
                let round_num = next_round.round_num() - 1;
                let payload = bc.make_broadcast();
                (round_num, payload, true)
            }
        };

        Ok(VerifiedMessage::new(
            rng,
            &self.context.signer,
            &self.context.session_id,
            round_num,
            if is_bc_consensus {
                MessageType::BroadcastConsensus
            } else {
                MessageType::Broadcast
            },
            &payload,
        )
        .map_err(Error::MyFault)?
        .into_unverified())
    }

    /// Returns the party indices to which the direct messages of this round should be sent;
    /// if `None`, there are no direct messages in this round.
    pub fn direct_message_destinations(&self) -> Option<Vec<PartyIdx>> {
        match &self.tp {
            SessionType::Normal(round) => round
                .direct_message_destinations()
                .map(|range| range.map(PartyIdx::from_usize).collect()),
            _ => None,
        }
    }

    /// Returns the direct message for the given destination
    /// (must be one of those returned by [`Self::direct_message_destinations`].
    pub fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &PartyIdx,
    ) -> Result<(SignedMessage<Sig>, Artefact), Error> {
        match &self.tp {
            SessionType::Normal(round) => {
                let round_num = round.round_num();
                let (payload, artefact) = round
                    .make_direct_message(rng, *destination)
                    .map_err(|err| Error::MyFault(MyFault::TypeErased(err)))?;
                let message = VerifiedMessage::new(
                    rng,
                    &self.context.signer,
                    &self.context.session_id,
                    round_num,
                    MessageType::Direct,
                    &payload,
                )
                .map_err(Error::MyFault)?
                .into_unverified();
                Ok((
                    message,
                    Artefact {
                        destination: *destination,
                        artefact,
                    },
                ))
            }
            _ => Err(Error::MyFault(MyFault::InvalidState(
                "This round does not send direct messages".into(),
            ))),
        }
    }

    /// Process a received message from another party.
    pub fn verify_message(
        &self,
        from: PartyIdx,
        message: SignedMessage<Sig>,
    ) -> Result<ProcessedMessage<Sig>, Error> {
        if message.session_id() != &self.context.session_id {
            // Even though the message was verified, it may be just a replay attack,
            // hence unprovable.
            return Err(Error::TheirFaultUnprovable {
                party: from,
                error: TheirFault::InvalidSessionId,
            });
        }

        let message_for = match &self.tp {
            SessionType::Normal(round) => route_message_normal(round.as_ref(), &message),
            SessionType::Bc { next_round, .. } => route_message_bc(next_round.as_ref(), &message),
        };

        match message_for {
            MessageFor::ThisRound => self.verify_message_inner(from, message),
            // TODO: should we cache the verified or the unverified message?
            MessageFor::NextRound => Ok(ProcessedMessage(ProcessedMessageEnum::Cache {
                from,
                message,
            })),
            // TODO: this is an unprovable fault (may be a replay attack)
            MessageFor::OutOfOrder => Err(Error::TheirFault {
                party: from,
                error: TheirFault::OutOfOrderMessage,
            }),
        }
    }

    fn verify_message_inner(
        &self,
        from: PartyIdx,
        message: SignedMessage<Sig>,
    ) -> Result<ProcessedMessage<Sig>, Error> {
        let verified_message = message
            .verify(&self.context.verifiers[from.as_usize()])
            .unwrap();

        match &self.tp {
            SessionType::Normal(round) => {
                match verified_message.message_type() {
                    MessageType::Direct => {
                        let payload = round
                            .verify_direct_message(from, verified_message.payload())
                            .map_err(|err| Error::TheirFault {
                                party: from,
                                error: TheirFault::TypeErased(err),
                            })?;
                        Ok(ProcessedMessage(ProcessedMessageEnum::DmPayload {
                            from,
                            payload,
                            message: verified_message,
                        }))
                    }
                    MessageType::Broadcast => {
                        let payload = round
                            .verify_broadcast(from, verified_message.payload())
                            .map_err(|err| Error::TheirFault {
                                party: from,
                                error: TheirFault::TypeErased(err),
                            })?;
                        Ok(ProcessedMessage(ProcessedMessageEnum::BcPayload {
                            from,
                            payload,
                            message: verified_message,
                        }))
                    }
                    _ => {
                        // TODO: this branch will never really be reached
                        Err(Error::TheirFault {
                            party: from,
                            error: TheirFault::Receive("Unexpected bc consensus message".into()),
                        })
                    }
                }
            }
            SessionType::Bc { bc, .. } => {
                bc.verify_broadcast(from, verified_message)?;
                Ok(ProcessedMessage(ProcessedMessageEnum::Bc { from }))
            }
        }
    }

    /// Try to finalize the round.
    pub fn finalize_round(
        self,
        rng: &mut impl CryptoRngCore,
        accum: RoundAccumulator<Sig>,
    ) -> Result<FinalizeOutcome<Res, Sig, Signer, Verifier>, Error> {
        match self.tp {
            SessionType::Normal(round) => {
                Self::finalize_regular_round(self.context, round, rng, accum)
            }
            SessionType::Bc { next_round, bc } => {
                Self::finalize_bc_round(self.context, next_round, bc, accum)
            }
        }
    }

    fn finalize_regular_round(
        context: Context<Signer, Verifier>,
        round: Box<dyn TypeErasedFinalizable<Res>>,
        rng: &mut impl CryptoRngCore,
        accum: RoundAccumulator<Sig>,
    ) -> Result<FinalizeOutcome<Res, Sig, Signer, Verifier>, Error> {
        let requires_bc = round.requires_broadcast_consensus();

        match round.finalize(rng, accum.processed).unwrap() {
            type_erased::FinalizeOutcome::Result(res) => Ok(FinalizeOutcome::Result(res)),
            type_erased::FinalizeOutcome::AnotherRound(next_round) => {
                if requires_bc {
                    let broadcasts = accum.received_broadcasts;
                    let bc = BroadcastConsensus::new(broadcasts, &context.verifiers);
                    let new_session = Session {
                        tp: SessionType::Bc { next_round, bc },
                        context,
                    };
                    Ok(FinalizeOutcome::AnotherRound(
                        new_session,
                        accum.cached_messages,
                    ))
                } else {
                    let new_session = Session {
                        tp: SessionType::Normal(next_round),
                        context,
                    };
                    Ok(FinalizeOutcome::AnotherRound(
                        new_session,
                        accum.cached_messages,
                    ))
                }
            }
        }
    }

    fn finalize_bc_round(
        context: Context<Signer, Verifier>,
        round: Box<dyn TypeErasedFinalizable<Res>>,
        bc: BroadcastConsensus<Sig, Verifier>,
        accum: RoundAccumulator<Sig>,
    ) -> Result<FinalizeOutcome<Res, Sig, Signer, Verifier>, Error> {
        accum.bc_accum.finalize()?;
        bc.finalize().map(|_| {
            let new_session = Session {
                tp: SessionType::Normal(round),
                context,
            };
            FinalizeOutcome::AnotherRound(new_session, accum.cached_messages)
        })
    }
}

pub struct RoundAccumulator<Sig> {
    received_direct_messages: Vec<(PartyIdx, VerifiedMessage<Sig>)>,
    received_broadcasts: Vec<(PartyIdx, VerifiedMessage<Sig>)>,
    processed: TypeErasedRoundAccum,
    cached_messages: Vec<(PartyIdx, SignedMessage<Sig>)>,
    bc_accum: BcConsensusAccum,
}

impl<Sig> RoundAccumulator<Sig> {
    fn new(num_parties: usize, party_idx: PartyIdx, is_bc_round: bool, is_dm_round: bool) -> Self {
        Self {
            received_direct_messages: Vec::new(),
            received_broadcasts: Vec::new(),
            processed: TypeErasedRoundAccum::new(num_parties, party_idx, is_bc_round, is_dm_round),
            cached_messages: Vec::new(),
            bc_accum: BcConsensusAccum::new(num_parties, party_idx),
        }
    }

    /// Save an artefact produced by [`Session::make_direct_message`].
    pub fn add_artefact(&mut self, artefact: Artefact) -> Result<(), Error> {
        // TODO: add a check that the index is in range, and wasn't filled yet
        self.processed
            .add_dm_artefact(artefact.destination, artefact.artefact)
            .unwrap();
        Ok(())
    }

    /// Save a processed message produced by [`Session::verify_message`].
    pub fn add_processed_message(&mut self, pm: ProcessedMessage<Sig>) -> Result<(), Error> {
        // TODO: add a check that the index is in range, and wasn't filled yet
        match pm.0 {
            ProcessedMessageEnum::BcPayload {
                from,
                payload,
                message,
            } => {
                self.processed.add_bc_payload(from, payload).unwrap();
                self.received_broadcasts.push((from, message));
            }
            ProcessedMessageEnum::DmPayload {
                from,
                payload,
                message,
            } => {
                self.processed.add_dm_payload(from, payload).unwrap();
                self.received_direct_messages.push((from, message));
            }
            ProcessedMessageEnum::Cache { from, message } => {
                self.cached_messages.push((from, message))
            }
            ProcessedMessageEnum::Bc { from } => self.bc_accum.add_echo_received(from).unwrap(),
        }
        Ok(())
    }
}

pub struct Artefact {
    destination: PartyIdx,
    artefact: TypeErasedDmArtefact,
}

pub struct ProcessedMessage<Sig>(ProcessedMessageEnum<Sig>);

enum ProcessedMessageEnum<Sig> {
    BcPayload {
        from: PartyIdx,
        payload: TypeErasedBcPayload,
        message: VerifiedMessage<Sig>,
    },
    DmPayload {
        from: PartyIdx,
        payload: TypeErasedDmPayload,
        message: VerifiedMessage<Sig>,
    },
    Cache {
        from: PartyIdx,
        message: SignedMessage<Sig>,
    },
    Bc {
        from: PartyIdx,
    },
}
