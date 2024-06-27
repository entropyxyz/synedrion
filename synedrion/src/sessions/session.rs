use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec::Vec;
use core::fmt::Debug;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use signature::{
    hazmat::{PrehashVerifier, RandomizedPrehashSigner},
    Keypair,
};

use super::echo::{EchoAccum, EchoRound};
use super::error::{Error, LocalError, ProvableError, RemoteError, RemoteErrorEnum};
use super::message_bundle::{MessageBundle, MessageBundleEnum, VerifiedMessageBundle};
use super::signed_message::{MessageType, SessionId, SignedMessage};
use super::type_erased::{
    self, AccumAddError, DynArtifact, DynFinalizable, DynPayload, DynRoundAccum, ReceiveError,
};
use crate::rounds::{self, FirstRound, ProtocolResult, Round};

struct Context<Signer, Verifier> {
    signer: Signer,
    my_id: Verifier,
    session_id: SessionId,
}

enum SessionType<Verifier, Res, Sig> {
    Normal {
        this_round: Box<dyn DynFinalizable<Verifier, Res>>,
        broadcast: Option<SignedMessage<Sig>>,
    },
    Echo {
        next_round: Box<dyn DynFinalizable<Verifier, Res>>,
        echo_round: EchoRound<Verifier, Sig>,
    },
}

/// The session state where it is ready to send messages.
pub struct Session<Res, Sig, Signer, Verifier> {
    tp: SessionType<Verifier, Res, Sig>,
    context: Context<Signer, Verifier>,
}

enum MessageFor {
    ThisRound,
    NextRound,
}

fn route_message_normal<Res: ProtocolResult, Sig, Verifier>(
    round: &dyn DynFinalizable<Verifier, Res>,
    message: &MessageBundle<Sig>,
) -> Result<MessageFor, RemoteErrorEnum> {
    let this_round = round.round_num();
    let next_round = round.next_round_num();
    let requires_echo = round.requires_echo();

    let message_round = message.round();
    let message_is_echo = message.is_echo();

    if message_round == this_round && !message_is_echo {
        return Ok(MessageFor::ThisRound);
    }

    let for_next_round =
    // This is a normal round, and the next round exists, and the message is for it
    (!requires_echo && next_round.is_some() && message_round == next_round.unwrap() && !message_is_echo) ||
    // This is an echo round, and the message is from the echo round
    (requires_echo && message_round == this_round && message_is_echo);

    if for_next_round {
        return Ok(MessageFor::NextRound);
    }

    Err(RemoteErrorEnum::OutOfOrderMessage)
}

fn route_message_echo<Res: ProtocolResult, Sig, Verifier>(
    next_round: &dyn DynFinalizable<Verifier, Res>,
    message: &MessageBundle<Sig>,
) -> Result<MessageFor, RemoteErrorEnum> {
    let next_round = next_round.round_num();
    let message_round = message.round();
    let message_is_echo = message.is_echo();

    if message_round == next_round - 1 && message_is_echo {
        return Ok(MessageFor::ThisRound);
    }

    if message_round == next_round && !message_is_echo {
        return Ok(MessageFor::NextRound);
    }

    Err(RemoteErrorEnum::OutOfOrderMessage)
}

fn wrap_receive_result<Res: ProtocolResult, Verifier: Clone, T>(
    from: &Verifier,
    result: Result<T, ReceiveError<Res>>,
) -> Result<T, Error<Res, Verifier>> {
    // TODO (#43): we need to attach all the necessary messages here,
    // to make sure that every provable error can be independently verified
    // given the party's verifying key.
    result.map_err(|err| match err {
        ReceiveError::InvalidContents(msg) => Error::Remote(RemoteError {
            party: from.clone(),
            error: RemoteErrorEnum::InvalidContents(msg),
        }),
        ReceiveError::CannotDeserialize(msg) => Error::Provable {
            party: from.clone(),
            error: ProvableError::CannotDeserialize(msg),
        },
        ReceiveError::Protocol(err) => Error::Provable {
            party: from.clone(),
            error: ProvableError::Protocol(err),
        },
    })
}

/// Possible outcomes of successfully finalizing a round.
pub enum FinalizeOutcome<Res: ProtocolResult, Sig, Signer, Verifier> {
    /// The protocol result is available.
    Success(Res::Success),
    /// Starting the next round.
    AnotherRound {
        /// The new session object.
        session: Session<Res, Sig, Signer, Verifier>,
        /// The messages for the new round received during the previous round.
        cached_messages: Vec<PreprocessedMessage<Sig, Verifier>>,
    },
}

impl<Res, Sig, Signer, Verifier> Session<Res, Sig, Signer, Verifier>
where
    Res: ProtocolResult,
    Signer: RandomizedPrehashSigner<Sig> + Keypair<VerifyingKey = Verifier>,
    Verifier: Debug + Clone + PrehashVerifier<Sig> + Ord + Serialize + for<'de> Deserialize<'de>,
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
{
    pub(crate) fn new<
        R: FirstRound<Verifier>
            + DynFinalizable<Verifier, Res>
            + Round<Verifier, Result = Res>
            + 'static,
    >(
        rng: &mut impl CryptoRngCore,
        session_id: SessionId,
        signer: Signer,
        verifiers: &BTreeSet<Verifier>,
        inputs: R::Inputs,
    ) -> Result<Self, LocalError> {
        let my_id = signer.verifying_key();
        let mut other_parties = verifiers.clone();
        other_parties.remove(&my_id);
        let typed_round = R::new(
            rng,
            session_id.as_ref(),
            other_parties,
            my_id.clone(),
            inputs,
        )
        .map_err(|err| LocalError(format!("Failed to initialize the protocol: {err:?}")))?;
        let round: Box<dyn DynFinalizable<Verifier, Res>> = Box::new(typed_round);
        let context = Context {
            my_id,
            signer,
            session_id,
        };
        Self::new_internal(rng, context, round)
    }

    fn new_internal(
        rng: &mut impl CryptoRngCore,
        context: Context<Signer, Verifier>,
        round: Box<dyn DynFinalizable<Verifier, Res>>,
    ) -> Result<Self, LocalError> {
        let broadcast = round.make_broadcast_message(rng)?;

        let signed_broadcast = if let Some(payload) = broadcast {
            Some(SignedMessage::new(
                rng,
                &context.signer,
                &context.session_id,
                round.round_num(),
                MessageType::Broadcast,
                &payload,
            )?)
        } else {
            None
        };

        Ok(Self {
            tp: SessionType::Normal {
                this_round: round,
                broadcast: signed_broadcast,
            },
            context,
        })
    }

    /// This session's verifier object.
    pub fn verifier(&self) -> Verifier {
        self.context.signer.verifying_key()
    }

    /// This session's ID.
    pub fn session_id(&self) -> SessionId {
        self.context.session_id
    }

    /// Returns a pair of the current round index and whether it is an echo round.
    pub fn current_round(&self) -> (u8, bool) {
        match &self.tp {
            SessionType::Normal { this_round, .. } => (this_round.round_num(), false),
            SessionType::Echo { next_round, .. } => (next_round.round_num() - 1, true),
        }
    }

    /// Create an accumulator to store message creation and processing results of this round.
    pub fn make_accumulator(&self) -> RoundAccumulator<Sig, Verifier> {
        RoundAccumulator::new(self.is_echo_round())
    }

    /// Returns `true` if the round can be finalized.
    pub fn can_finalize(
        &self,
        accum: &RoundAccumulator<Sig, Verifier>,
    ) -> Result<bool, LocalError> {
        match &self.tp {
            SessionType::Normal { this_round, .. } => Ok(this_round.can_finalize(&accum.processed)),
            SessionType::Echo { echo_round, .. } => {
                let echo_accum = accum.echo_accum.as_ref().ok_or(LocalError(
                    "This is an echo round, but the accumulator is in an invalid state".into(),
                ))?;
                Ok(echo_round.can_finalize(echo_accum))
            }
        }
    }

    /// Returns a list of parties whose messages for this round have not been received yet.
    pub fn missing_messages(
        &self,
        accum: &RoundAccumulator<Sig, Verifier>,
    ) -> Result<BTreeSet<Verifier>, LocalError> {
        match &self.tp {
            SessionType::Normal { this_round, .. } => {
                Ok(this_round.missing_messages(&accum.processed))
            }
            SessionType::Echo { echo_round, .. } => {
                let echo_accum = accum.echo_accum.as_ref().ok_or(LocalError(
                    "This is an echo round, but the accumulator is in an invalid state".into(),
                ))?;
                Ok(echo_round.missing_messages(echo_accum))
            }
        }
    }

    fn is_echo_round(&self) -> bool {
        match &self.tp {
            SessionType::Normal { .. } => false,
            SessionType::Echo { .. } => true,
        }
    }

    /// Returns the party indices to which the messages of this round should be sent.
    pub fn message_destinations(&self) -> &BTreeSet<Verifier> {
        match &self.tp {
            SessionType::Normal { this_round, .. } => this_round.message_destinations(),
            SessionType::Echo { echo_round, .. } => echo_round.message_destinations(),
        }
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Verifier> {
        match &self.tp {
            SessionType::Normal { this_round, .. } => this_round.expecting_messages_from(),
            SessionType::Echo { echo_round, .. } => echo_round.expecting_messages_from(),
        }
    }

    /// Returns the message for the given destination
    /// (must be one of those returned by [`Self::message_destinations`].
    pub fn make_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &Verifier,
    ) -> Result<(MessageBundle<Sig>, Artifact<Verifier>), LocalError> {
        match &self.tp {
            SessionType::Normal {
                this_round,
                broadcast,
            } => {
                let round_num = this_round.round_num();
                let (payload, artifact) = this_round.make_direct_message(rng, destination)?;

                let direct_message = if let Some(payload) = payload {
                    Some(SignedMessage::new(
                        rng,
                        &self.context.signer,
                        &self.context.session_id,
                        round_num,
                        MessageType::Direct,
                        &payload,
                    )?)
                } else {
                    None
                };

                let message = MessageBundle::try_from(match (broadcast, direct_message) {
                    (Some(broadcast), Some(direct)) => MessageBundleEnum::Both {
                        broadcast: broadcast.clone(),
                        direct,
                    },
                    (None, Some(direct)) => MessageBundleEnum::Direct(direct),
                    (Some(broadcast), None) => MessageBundleEnum::Broadcast(broadcast.clone()),
                    (None, None) => return Err(LocalError("The round must send messages".into())),
                })?;

                Ok((
                    message,
                    Artifact {
                        destination: destination.clone(),
                        artifact,
                    },
                ))
            }
            SessionType::Echo {
                next_round,
                echo_round,
            } => {
                let round_num = next_round.round_num() - 1;
                let payload = echo_round.make_broadcast();
                let artifact = DynArtifact::null();
                let message = SignedMessage::new(
                    rng,
                    &self.context.signer,
                    &self.context.session_id,
                    round_num,
                    MessageType::Echo,
                    &payload,
                )?;
                Ok((
                    MessageBundle::try_from(MessageBundleEnum::Echo(message))?,
                    Artifact {
                        destination: destination.clone(),
                        artifact,
                    },
                ))
            }
        }
    }

    fn route_message(
        &self,
        from: &Verifier,
        message: &MessageBundle<Sig>,
    ) -> Result<MessageFor, Error<Res, Verifier>> {
        let message_for = match &self.tp {
            SessionType::Normal { this_round, .. } => {
                route_message_normal(this_round.as_ref(), message)
            }
            SessionType::Echo { next_round, .. } => {
                route_message_echo(next_round.as_ref(), message)
            }
        };

        message_for.map_err(|err| {
            Error::Remote(RemoteError {
                party: from.clone(),
                error: err,
            })
        })
    }

    /// Perform quick checks on a received message.
    pub fn preprocess_message(
        &self,
        accum: &mut RoundAccumulator<Sig, Verifier>,
        from: &Verifier,
        message: MessageBundle<Sig>,
    ) -> Result<Option<PreprocessedMessage<Sig, Verifier>>, Error<Res, Verifier>> {
        // This is an unprovable fault (may be a replay attack)
        if message.session_id() != &self.context.session_id {
            return Err(Error::Remote(RemoteError {
                party: from.clone(),
                error: RemoteErrorEnum::UnexpectedSessionId,
            }));
        }

        let message_for = self.route_message(from, &message)?;

        let verified_message = message.verify(from).map_err(|err| {
            Error::Remote(RemoteError {
                party: from.clone(),
                error: RemoteErrorEnum::InvalidSignature(err),
            })
        })?;

        if from == &self.context.my_id {
            return Err(Error::Local(LocalError(
                "Cannot take a message from myself".into(),
            )));
        }

        let preprocessed = PreprocessedMessage {
            from: from.clone(),
            message: verified_message,
        };

        Ok(match message_for {
            MessageFor::ThisRound => {
                if !self.expecting_messages_from().contains(from) {
                    return Err(Error::Local(LocalError(
                        "The sender is not in the list of expected senders.".into(),
                    )));
                }

                if accum.is_already_processed(&preprocessed) {
                    return Err(Error::Remote(RemoteError {
                        party: from.clone(),
                        error: RemoteErrorEnum::DuplicateMessage,
                    }));
                }
                Some(preprocessed)
            }
            MessageFor::NextRound => {
                if accum.is_already_cached(&preprocessed) {
                    return Err(Error::Remote(RemoteError {
                        party: from.clone(),
                        error: RemoteErrorEnum::DuplicateMessage,
                    }));
                }
                accum.add_cached_message(preprocessed);
                None
            }
        })
    }

    /// Process a received message from another party.
    pub fn process_message(
        &self,
        rng: &mut impl CryptoRngCore,
        preprocessed: PreprocessedMessage<Sig, Verifier>,
    ) -> Result<ProcessedMessage<Sig, Verifier>, Error<Res, Verifier>> {
        let from = preprocessed.from;
        let message = preprocessed.message;
        match &self.tp {
            SessionType::Normal { this_round, .. } => {
                let result = this_round.verify_message(
                    rng,
                    &from,
                    message.broadcast_payload(),
                    message.direct_payload(),
                );
                let payload = wrap_receive_result(&from, result)?;
                Ok(ProcessedMessage {
                    from: from.clone(),
                    message: ProcessedMessageEnum::Payload { payload, message },
                })
            }
            SessionType::Echo { echo_round, .. } => {
                echo_round
                    .verify_broadcast(&from, message.echo_payload().unwrap())
                    .map_err(|err| Error::Provable {
                        party: from.clone(),
                        error: ProvableError::Echo(err),
                    })?;
                Ok(ProcessedMessage {
                    from: from.clone(),
                    message: ProcessedMessageEnum::Echo,
                })
            }
        }
    }

    /// Try to finalize the round.
    pub fn finalize_round(
        self,
        rng: &mut impl CryptoRngCore,
        accum: RoundAccumulator<Sig, Verifier>,
    ) -> Result<FinalizeOutcome<Res, Sig, Signer, Verifier>, Error<Res, Verifier>> {
        match self.tp {
            SessionType::Normal { this_round, .. } => {
                Self::finalize_regular_round(self.context, this_round, rng, accum)
            }
            SessionType::Echo {
                echo_round,
                next_round,
            } => Self::finalize_echo_round(self.context, echo_round, next_round, rng, accum),
        }
    }

    fn finalize_regular_round(
        context: Context<Signer, Verifier>,
        round: Box<dyn DynFinalizable<Verifier, Res>>,
        rng: &mut impl CryptoRngCore,
        accum: RoundAccumulator<Sig, Verifier>,
    ) -> Result<FinalizeOutcome<Res, Sig, Signer, Verifier>, Error<Res, Verifier>> {
        let requires_echo = round.requires_echo();

        let outcome = round
            .finalize(rng, accum.processed)
            .map_err(|err| match err {
                type_erased::FinalizeError::Protocol(err) => match err {
                    rounds::FinalizeError::Init(err) => Error::Local(LocalError(format!(
                        "Failed to initialize the protocol: {err:?}"
                    ))),
                    rounds::FinalizeError::Proof(proof) => Error::Proof { proof },
                },
                type_erased::FinalizeError::Accumulator(err) => {
                    Error::Local(LocalError(format!("Failed to finalize: {err:?}")))
                }
            })?;

        match outcome {
            type_erased::FinalizeOutcome::Success(res) => Ok(FinalizeOutcome::Success(res)),
            type_erased::FinalizeOutcome::AnotherRound(next_round) => {
                if requires_echo {
                    let broadcasts = accum
                        .received_messages
                        .iter()
                        .map(|(id, combined)| {
                            (
                                id.clone(),
                                combined
                                    .broadcast_message()
                                    .unwrap()
                                    .clone()
                                    .into_unverified(),
                            )
                        })
                        .collect();

                    let echo_round = EchoRound::new(broadcasts);
                    let session = Session {
                        tp: SessionType::Echo {
                            next_round,
                            echo_round,
                        },
                        context,
                    };
                    Ok(FinalizeOutcome::AnotherRound {
                        session,
                        cached_messages: accum.cached_messages.into_values().collect(),
                    })
                } else {
                    let session =
                        Session::new_internal(rng, context, next_round).map_err(Error::Local)?;
                    Ok(FinalizeOutcome::AnotherRound {
                        session,
                        cached_messages: accum.cached_messages.into_values().collect(),
                    })
                }
            }
        }
    }

    fn finalize_echo_round(
        context: Context<Signer, Verifier>,
        echo_round: EchoRound<Verifier, Sig>,
        next_round: Box<dyn DynFinalizable<Verifier, Res>>,
        rng: &mut impl CryptoRngCore,
        accum: RoundAccumulator<Sig, Verifier>,
    ) -> Result<FinalizeOutcome<Res, Sig, Signer, Verifier>, Error<Res, Verifier>> {
        let echo_accum = accum.echo_accum.ok_or(Error::Local(LocalError(
            "The accumulator is in the invalid state for the echo round".into(),
        )))?;

        echo_round.finalize(echo_accum).map_err(Error::Local)?;

        let session = Session::new_internal(rng, context, next_round).map_err(Error::Local)?;

        Ok(FinalizeOutcome::AnotherRound {
            session,
            cached_messages: accum.cached_messages.into_values().collect(),
        })
    }
}

/// A mutable accumulator created for each round to assemble processed messages from other parties.
pub struct RoundAccumulator<Sig, Verifier> {
    received_messages: BTreeMap<Verifier, VerifiedMessageBundle<Sig>>,
    processed: DynRoundAccum<Verifier>,
    cached_messages: BTreeMap<Verifier, PreprocessedMessage<Sig, Verifier>>,
    echo_accum: Option<EchoAccum<Verifier>>,
}

impl<Sig, Verifier: Ord + Clone + Debug> RoundAccumulator<Sig, Verifier> {
    fn new(is_echo_round: bool) -> Self {
        Self {
            received_messages: BTreeMap::new(),
            processed: DynRoundAccum::new(),
            cached_messages: BTreeMap::new(),
            echo_accum: if is_echo_round {
                Some(EchoAccum::new())
            } else {
                None
            },
        }
    }

    /// Save an artifact produced by [`Session::make_message`].
    pub fn add_artifact(&mut self, artifact: Artifact<Verifier>) -> Result<(), LocalError> {
        self.processed
            .add_artifact(&artifact.destination, artifact.artifact)
            .map_err(|err| match err {
                AccumAddError::SlotTaken => LocalError(format!(
                    "Artifact for the destination {:?} was already added",
                    artifact.destination
                )),
            })
    }

    /// Save a processed message produced by [`Session::process_message`].
    pub fn add_processed_message(
        &mut self,
        pm: ProcessedMessage<Sig, Verifier>,
    ) -> Result<Result<(), RemoteError<Verifier>>, LocalError> {
        match pm.message {
            ProcessedMessageEnum::Payload { payload, message } => {
                if let Err(AccumAddError::SlotTaken) = self.processed.add_payload(&pm.from, payload)
                {
                    return Ok(Err(RemoteError {
                        party: pm.from,
                        error: RemoteErrorEnum::DuplicateMessage,
                    }));
                }
                self.received_messages.insert(pm.from, message);
            }
            ProcessedMessageEnum::Echo => match &mut self.echo_accum {
                Some(accum) => {
                    if accum.add_echo_received(&pm.from).is_none() {
                        return Ok(Err(RemoteError {
                            party: pm.from,
                            error: RemoteErrorEnum::DuplicateMessage,
                        }));
                    }
                }
                None => return Err(LocalError("This is not an echo round".into())),
            },
        }
        Ok(Ok(()))
    }

    fn is_already_processed(&self, preprocessed: &PreprocessedMessage<Sig, Verifier>) -> bool {
        if preprocessed.message.is_echo() {
            self.echo_accum
                .as_ref()
                .unwrap()
                .contains(&preprocessed.from)
        } else {
            self.processed.contains(&preprocessed.from)
        }
    }

    fn is_already_cached(&self, preprocessed: &PreprocessedMessage<Sig, Verifier>) -> bool {
        self.cached_messages.contains_key(&preprocessed.from)
    }

    fn add_cached_message(&mut self, preprocessed: PreprocessedMessage<Sig, Verifier>) {
        self.cached_messages
            .insert(preprocessed.from.clone(), preprocessed);
    }
}

/// Data produced when creating a direct message to another party
/// that has to be preserved for further processing.
pub struct Artifact<Verifier> {
    destination: Verifier,
    artifact: DynArtifact,
}

/// A message that passed initial validity checks.
pub struct PreprocessedMessage<Sig, Verifier> {
    from: Verifier,
    message: VerifiedMessageBundle<Sig>,
}

/// A processed message from another party.
pub struct ProcessedMessage<Sig, Verifier> {
    from: Verifier,
    message: ProcessedMessageEnum<Sig>,
}

enum ProcessedMessageEnum<Sig> {
    Payload {
        payload: DynPayload,
        message: VerifiedMessageBundle<Sig>,
    },
    Echo,
}

#[cfg(test)]
mod tests {
    use impls::impls;
    use k256::ecdsa::{Signature, SigningKey, VerifyingKey};

    use super::{Artifact, MessageBundle, PreprocessedMessage, ProcessedMessage, Session};
    use crate::ProtocolResult;

    #[test]
    fn test_concurrency_bounds() {
        // In order to support parallel message creation and processing we need that
        // certain generic types could be Send and/or Sync.
        //
        // Since they are generic, this depends on the exact type parameters supplied by the user,
        // so if the user does not want parallelism, they may not use Send/Sync generic parameters.
        // But we want to make sure that if the generic parameters are Send/Sync,
        // our types are too.

        #[derive(Debug)]
        struct DummyResult;

        impl ProtocolResult for DummyResult {
            type Success = ();
            type ProvableError = ();
            type CorrectnessProof = ();
        }

        assert!(impls!(Session<DummyResult, Signature, SigningKey, VerifyingKey>: Sync));
        assert!(impls!(MessageBundle<Signature>: Send));
        assert!(impls!(Artifact<VerifyingKey>: Send));
        assert!(impls!(PreprocessedMessage<Signature, VerifyingKey>: Send));
        assert!(impls!(ProcessedMessage<Signature, VerifyingKey>: Send));
    }
}
