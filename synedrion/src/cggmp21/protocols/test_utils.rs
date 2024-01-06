use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use itertools::izip;
use rand_core::CryptoRngCore;

use super::generic::{
    BroadcastRound, DirectRound, FinalizableToNextRound, FinalizableToResult, ProtocolResult, Round,
};
use super::{FinalizeError, PartyIdx};

#[derive(Debug)]
pub(crate) enum StepError {
    AccumFinalize,
    Receive(String),
}

pub(crate) struct AssembledRound<R: Round> {
    round: R,
    bc_payloads: BTreeMap<PartyIdx, <R as BroadcastRound>::Payload>,
    dm_payloads: BTreeMap<PartyIdx, <R as DirectRound>::Payload>,
    dm_artifacts: BTreeMap<PartyIdx, <R as DirectRound>::Artifact>,
}

pub(crate) fn step_round<R>(
    rng: &mut impl CryptoRngCore,
    rounds: Vec<R>,
) -> Result<Vec<AssembledRound<R>>, StepError>
where
    R: Round,
    <R as BroadcastRound>::Message: Clone,
{
    // Collect outgoing messages

    let mut dm_artifact_accums = (0..rounds.len())
        .map(|_| BTreeMap::new())
        .collect::<Vec<_>>();

    // `to, from, message`
    let mut direct_messages = Vec::<(PartyIdx, PartyIdx, <R as DirectRound>::Message)>::new();
    let mut broadcasts = Vec::<(PartyIdx, PartyIdx, <R as BroadcastRound>::Message)>::new();

    for (idx_from, round) in rounds.iter().enumerate() {
        let idx_from = PartyIdx::from_usize(idx_from);

        if let Some(destinations) = round.direct_message_destinations() {
            for idx_to in destinations {
                let (message, artifact) = round.make_direct_message(rng, idx_to).unwrap();
                direct_messages.push((idx_to, idx_from, message));
                assert!(dm_artifact_accums[idx_from.as_usize()]
                    .insert(idx_to, artifact)
                    .is_none());
            }
        }

        if let Some(destinations) = round.broadcast_destinations() {
            let message = round.make_broadcast(rng).unwrap();
            for idx_to in destinations {
                broadcasts.push((idx_to, idx_from, message.clone()));
            }
        }
    }

    // Deliver direct messages

    let mut dm_payload_accums = (0..rounds.len())
        .map(|_| BTreeMap::new())
        .collect::<Vec<_>>();
    for (idx_to, idx_from, message) in direct_messages.into_iter() {
        let round = &rounds[idx_to.as_usize()];
        let payload = round
            .verify_direct_message(idx_from, message)
            .map_err(|err| StepError::Receive(format!("{:?}", err)))?;
        dm_payload_accums[idx_to.as_usize()].insert(idx_from, payload);
    }

    // Deliver broadcasts

    let mut bc_payload_accums = (0..rounds.len())
        .map(|_| BTreeMap::new())
        .collect::<Vec<_>>();
    for (idx_to, idx_from, message) in broadcasts.into_iter() {
        let round = &rounds[idx_to.as_usize()];
        let payload = round
            .verify_broadcast(idx_from, message)
            .map_err(|err| StepError::Receive(format!("{:?}", err)))?;
        bc_payload_accums[idx_to.as_usize()].insert(idx_from, payload);
    }

    // Assemble

    let mut assembled = Vec::new();
    for (round, bc_payloads, dm_payloads, dm_artifacts) in izip!(
        rounds,
        bc_payload_accums,
        dm_payload_accums,
        dm_artifact_accums
    ) {
        if !round.can_finalize(bc_payloads.keys(), dm_payloads.keys(), dm_artifacts.keys()) {
            return Err(StepError::AccumFinalize);
        };

        assembled.push(AssembledRound {
            round,
            bc_payloads,
            dm_payloads,
            dm_artifacts,
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
            assembled_round.bc_payloads,
            assembled_round.dm_payloads,
            assembled_round.dm_artifacts,
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
            assembled_round.bc_payloads,
            assembled_round.dm_payloads,
            assembled_round.dm_artifacts,
        )?;
        results.push(result);
    }
    Ok(results)
}
