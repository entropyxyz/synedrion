use rand_core::CryptoRngCore;

use super::{FinalizeError, FinalizeSuccess, PartyIdx, ReceiveError, Round, ToSendTyped};
use crate::tools::collections::{HoleRange, HoleVecAccum};

#[derive(Debug)]
pub(crate) enum StepError {
    AccumFinalize,
    InvalidIndex,
    RepeatingMessage,
    Receive(ReceiveError),
    Finalize(FinalizeError),
}

pub(crate) fn assert_next_round<R: Round>(
    results: impl IntoIterator<Item = FinalizeSuccess<R>>,
) -> Result<Vec<R::NextRound>, String> {
    let mut rounds = Vec::new();
    for result in results.into_iter() {
        match result {
            FinalizeSuccess::Result(_) => return Err("Expected the next round, got result".into()),
            FinalizeSuccess::AnotherRound(round) => rounds.push(round),
        }
    }
    Ok(rounds)
}

pub(crate) fn assert_result<R: Round>(
    outcomes: impl IntoIterator<Item = FinalizeSuccess<R>>,
) -> Result<Vec<R::Result>, String> {
    let mut results = Vec::new();
    for outcome in outcomes.into_iter() {
        match outcome {
            FinalizeSuccess::Result(result) => results.push(result),
            FinalizeSuccess::AnotherRound(_) => {
                return Err("Expected the result, got another round".into())
            }
        }
    }
    Ok(results)
}

pub(crate) fn step<R: Round>(
    rng: &mut impl CryptoRngCore,
    init: Vec<R>,
) -> Result<Vec<FinalizeSuccess<R>>, StepError> {
    // Collect outgoing messages

    let mut accums = (0..init.len())
        .map(|idx| HoleVecAccum::<R::Payload>::new(init.len(), idx))
        .collect::<Vec<_>>();
    // `to, from, message`
    let mut all_messages = Vec::<(PartyIdx, PartyIdx, R::Message)>::new();

    for (idx_from, round) in init.iter().enumerate() {
        let to_send = round.to_send(rng);
        let idx_from = PartyIdx::from_usize(idx_from);

        match to_send {
            ToSendTyped::Broadcast(message) => {
                for idx_to in HoleRange::new(init.len(), idx_from.as_usize()) {
                    all_messages.push((PartyIdx::from_usize(idx_to), idx_from, message.clone()));
                }
            }
            ToSendTyped::Direct(messages) => {
                for (idx_to, message) in messages.into_iter() {
                    all_messages.push((idx_to, idx_from, message));
                }
            }
        }
    }

    // Send out messages

    for (idx_to, idx_from, message) in all_messages.into_iter() {
        let round = &init[idx_to.as_usize()];
        let accum = accums.get_mut(idx_to.as_usize()).unwrap();
        let slot = accum
            .get_mut(idx_from.as_usize())
            .ok_or(StepError::InvalidIndex)?;
        if slot.is_some() {
            return Err(StepError::RepeatingMessage);
        }
        *slot = Some(
            round
                .verify_received(idx_from, message)
                .map_err(StepError::Receive)?,
        );
    }

    // Check that all the states are finished

    let mut result = Vec::new();

    for (round, accum) in init.into_iter().zip(accums.into_iter()) {
        let accum_final = accum.finalize().map_err(|_| StepError::AccumFinalize)?;
        let outcome = round
            .finalize(rng, accum_final)
            .map_err(StepError::Finalize)?;
        result.push(outcome);
    }

    Ok(result)
}
