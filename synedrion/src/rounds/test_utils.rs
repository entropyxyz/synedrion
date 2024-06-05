// TODO: Remove as soon as https://github.com/yaahc/displaydoc/pull/47
//lands and displaydoc releases a new version
#![allow(non_local_definitions)]
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use displaydoc::Display;
use itertools::izip;
use rand_core::CryptoRngCore;

use super::generic::{FinalizableToNextRound, FinalizableToResult, ProtocolResult, Round};
use super::{FinalizeError, PartyIdx};

#[derive(Debug, Display)]
pub(crate) enum StepError {
    /// Error when finalizing the round (missing messages).
    AccumFinalize,
    /// Error when verifying a received message.
    #[displaydoc("Error when verifying a received message ({0})")]
    Receive(String),
    /// A party attempted to send a message to itself.
    #[displaydoc("A party {0:?} attempted to send a message to itself")]
    MessageToItself(PartyIdx),
}

pub(crate) struct AssembledRound<R: Round> {
    round: R,
    payloads: BTreeMap<PartyIdx, <R as Round>::Payload>,
    artifacts: BTreeMap<PartyIdx, <R as Round>::Artifact>,
}

pub(crate) fn step_round<R>(
    rng: &mut impl CryptoRngCore,
    rounds: Vec<R>,
) -> Result<Vec<AssembledRound<R>>, StepError>
where
    R: Round,
    <R as Round>::BroadcastMessage: Clone,
{
    // Collect outgoing messages

    let mut artifact_accums = (0..rounds.len())
        .map(|_| BTreeMap::new())
        .collect::<Vec<_>>();

    // `to, from, message`
    let mut messages = Vec::<(
        PartyIdx,
        PartyIdx,
        (<R as Round>::BroadcastMessage, <R as Round>::DirectMessage),
    )>::new();

    for (idx_from, round) in rounds.iter().enumerate() {
        let idx_from = PartyIdx::from_usize(idx_from);

        let destinations = round.message_destinations();
        let broadcast = round.make_broadcast_message(rng);

        for idx_to in destinations {
            if idx_to == idx_from {
                return Err(StepError::MessageToItself(idx_from));
            }

            let (direct, artifact) = round.make_direct_message(rng, idx_to);
            // Can unwrap here since the destinations list is not empty
            messages.push((idx_to, idx_from, (broadcast.clone().unwrap(), direct)));
            assert!(artifact_accums[idx_from.as_usize()]
                .insert(idx_to, artifact)
                .is_none());
        }
    }

    // Deliver messages

    let mut payload_accums = (0..rounds.len())
        .map(|_| BTreeMap::new())
        .collect::<Vec<_>>();
    for (idx_to, idx_from, (broadcast, direct)) in messages.into_iter() {
        let round = &rounds[idx_to.as_usize()];
        let payload = round
            .verify_message(idx_from, broadcast, direct)
            .map_err(|err| StepError::Receive(format!("{:?}", err)))?;
        payload_accums[idx_to.as_usize()].insert(idx_from, payload);
    }

    // Assemble

    let mut assembled = Vec::new();
    for (round, payloads, artifacts) in izip!(rounds, payload_accums, artifact_accums) {
        if !round.can_finalize(payloads.keys(), artifacts.keys()) {
            return Err(StepError::AccumFinalize);
        };

        assembled.push(AssembledRound {
            round,
            payloads,
            artifacts,
        });
    }
    Ok(assembled)
}

pub(crate) fn step_next_round<R: FinalizableToNextRound>(
    rng: &mut impl CryptoRngCore,
    assembled_rounds: Vec<AssembledRound<R>>,
) -> Result<Vec<R::NextRound>, FinalizeError<R::Result>> {
    let mut results = Vec::new();
    for assembled_round in assembled_rounds.into_iter() {
        let next_round = assembled_round.round.finalize_to_next_round(
            rng,
            assembled_round.payloads,
            assembled_round.artifacts,
        )?;
        results.push(next_round);
    }
    Ok(results)
}

pub(crate) fn step_result<R: FinalizableToResult>(
    rng: &mut impl CryptoRngCore,
    assembled_rounds: Vec<AssembledRound<R>>,
) -> Result<Vec<<R::Result as ProtocolResult>::Success>, FinalizeError<R::Result>> {
    let mut results = Vec::new();
    for assembled_round in assembled_rounds.into_iter() {
        let result = assembled_round.round.finalize_to_result(
            rng,
            assembled_round.payloads,
            assembled_round.artifacts,
        )?;
        results.push(result);
    }
    Ok(results)
}
