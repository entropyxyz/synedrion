use alloc::{collections::BTreeSet, format, vec::Vec};
use core::{fmt::Debug, marker::PhantomData};

use manul::{
    combinators::misbehave::{Behavior, Misbehaving, MisbehavingEntryPoint},
    dev::run_sync,
    dev::ExecutionResult,
    protocol::{
        Artifact, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EntryPoint, NormalBroadcast, PartyId,
        Protocol, ProtocolError, ProtocolMessagePart, Serializer,
    },
    session::{LocalError, SessionParameters},
    signature::Keypair,
};
use rand_core::CryptoRngCore;

/// Executes the sessions for the given entry points,
/// making one party (first in alphabetical order) the malicious one with the wrapper `M` and the given `behavior`.
#[allow(clippy::type_complexity)]
pub(crate) fn run_with_one_malicious_party<SP, M, B>(
    rng: &mut impl CryptoRngCore,
    entry_points: Vec<(SP::Signer, M::EntryPoint)>,
    behavior: &B,
) -> Result<ExecutionResult<<M::EntryPoint as EntryPoint<SP::Verifier>>::Protocol, SP>, LocalError>
where
    SP: SessionParameters,
    B: Behavior + Clone,
    M: Misbehaving<SP::Verifier, B>,
{
    let ids = entry_points
        .iter()
        .map(|(signer, _ep)| signer.verifying_key())
        .collect::<BTreeSet<_>>();
    let misbehaving_id = ids
        .first()
        .ok_or_else(|| LocalError::new("Entry points list cannot be empty"))?;
    let modified_entry_points = entry_points
        .into_iter()
        .map(|(signer, entry_point)| {
            let id = signer.verifying_key();
            let maybe_behavior = if &id == misbehaving_id {
                Some(behavior.clone())
            } else {
                None
            };
            let entry_point = MisbehavingEntryPoint::<SP::Verifier, B, M>::new(entry_point, maybe_behavior);
            (signer, entry_point)
        })
        .collect();

    run_sync::<_, SP>(rng, modified_entry_points)
}

/// Executes [`run_with_one_malicious_party`] and checks that the malicous party
/// does not generate any provable error reports, while all the others do.
///
/// Checks that these reports can be verified given `associated_data`,
/// and their description starts with `expected_description`, returning a `LocalError` otherwise.
#[allow(clippy::type_complexity)]
pub(crate) fn check_evidence_with_behavior<SP, M, B>(
    rng: &mut impl CryptoRngCore,
    entry_points: Vec<(SP::Signer, M::EntryPoint)>,
    behavior: &B,
    associated_data: &<<<M::EntryPoint as EntryPoint<SP::Verifier>>::Protocol as Protocol<SP::Verifier>>::ProtocolError as ProtocolError<SP::Verifier>>::AssociatedData,
    expected_description: &str,
) -> Result<(), LocalError>
where
    SP: SessionParameters,
    B: Behavior + Clone,
    M: Misbehaving<SP::Verifier, B>,
{
    let ids = entry_points
        .iter()
        .map(|(signer, _ep)| signer.verifying_key())
        .collect::<BTreeSet<_>>();
    let misbehaving_id = ids
        .first()
        .ok_or_else(|| LocalError::new("Entry points list cannot be empty"))?;

    let execution_result = run_with_one_malicious_party::<SP, M, B>(rng, entry_points, behavior)?;
    let mut reports = execution_result.reports;

    let misbehaving_party_report = reports
        .remove(misbehaving_id)
        .ok_or_else(|| LocalError::new("Misbehaving node ID is not present in the reports"))?;
    assert!(misbehaving_party_report.provable_errors.is_empty());

    for (id, report) in reports {
        if report.provable_errors.len() != 1 {
            return Err(LocalError::new(format!(
                "Node {id:?} reported more than one provable errors"
            )));
        }

        let description = report
            .provable_errors
            .get(misbehaving_id)
            .ok_or_else(|| LocalError::new("A lawful node did not generate a provable error report"))?
            .description();
        if !description.starts_with(expected_description) {
            return Err(LocalError::new(format!(
                "Got {description}, expected {expected_description}"
            )));
        }

        let verification_result = report.provable_errors[misbehaving_id].verify(associated_data);
        if verification_result.is_err() {
            return Err(LocalError::new(format!("Failed to verify: {verification_result:?}")));
        }
    }

    Ok(())
}

/// Indicates the error for which part of the protocol message needs to be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckPart {
    EchoBroadcast,
    NormalBroadcast,
    DirectMessage,
}

#[derive(Debug, Clone, Copy)]
struct ModifyPart {
    round: u8,
    part: CheckPart,
}

impl ModifyPart {
    fn new(round: u8, part: CheckPart) -> Self {
        Self { round, part }
    }
}

struct InvalidMessageOverride<EP>(PhantomData<EP>);

impl<Id: PartyId, EP> Misbehaving<Id, ModifyPart> for InvalidMessageOverride<EP>
where
    EP: 'static + Debug + EntryPoint<Id>,
{
    type EntryPoint = EP;

    fn modify_echo_broadcast(
        _rng: &mut impl CryptoRngCore,
        round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
        modify: &ModifyPart,
        serializer: &Serializer,
        _deserializer: &Deserializer,
        echo_broadcast: EchoBroadcast,
    ) -> Result<EchoBroadcast, LocalError> {
        if round.id() != modify.round || modify.part != CheckPart::EchoBroadcast {
            return Ok(echo_broadcast);
        }

        // This triggers an error both in the case where the part is not supposed to be present,
        // and in the case where it is (because the deserialization fails).
        EchoBroadcast::new::<[u8; 0]>(serializer, [])
    }

    fn modify_normal_broadcast(
        _rng: &mut impl CryptoRngCore,
        round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
        modify: &ModifyPart,
        serializer: &Serializer,
        _deserializer: &Deserializer,
        normal_broadcast: NormalBroadcast,
    ) -> Result<NormalBroadcast, LocalError> {
        if round.id() != modify.round || modify.part != CheckPart::NormalBroadcast {
            return Ok(normal_broadcast);
        }

        // This triggers an error both in the case where the part is not supposed to be present,
        // and in the case where it is (because the deserialization fails).
        NormalBroadcast::new::<[u8; 0]>(serializer, [])
    }

    fn modify_direct_message(
        _rng: &mut impl CryptoRngCore,
        round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
        modify: &ModifyPart,
        serializer: &Serializer,
        _deserializer: &Deserializer,
        _destination: &Id,
        direct_message: DirectMessage,
        artifact: Option<Artifact>,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        if round.id() != modify.round || modify.part != CheckPart::DirectMessage {
            return Ok((direct_message, artifact));
        }

        // This triggers an error both in the case where the part is not supposed to be present,
        // and in the case where it is (because the deserialization fails).
        let direct_message = DirectMessage::new::<[u8; 0]>(serializer, [])?;
        Ok((direct_message, artifact))
    }
}

/// Checks that generating and verifying evidence for an invalid message part works correctly.
///
/// Pass `expecting_a_message = true` if in the round `round_num` the part `part` is expected to exist,
/// `false` otherwise.
pub(crate) fn check_invalid_message_evidence<SP, EP>(
    rng: &mut impl CryptoRngCore,
    entry_points: Vec<(SP::Signer, EP)>,
    round_num: u8,
    part: CheckPart,
    associated_data: &<<EP::Protocol as Protocol<SP::Verifier>>::ProtocolError as ProtocolError<SP::Verifier>>::AssociatedData,
    expecting_a_message: bool,
) -> Result<(), LocalError>
where
    EP: 'static + Debug + EntryPoint<SP::Verifier>,
    SP: SessionParameters,
{
    let prefix = match part {
        CheckPart::EchoBroadcast => "Echo broadcast",
        CheckPart::NormalBroadcast => "Normal broadcast",
        CheckPart::DirectMessage => "Direct message",
    };
    let error = if expecting_a_message {
        "Deserialization error"
    } else {
        "The payload was expected to be `None`, but contains a message"
    };

    let expected_description = format!("{prefix} error: {error}");

    check_evidence_with_behavior::<SP, InvalidMessageOverride<EP>, _>(
        rng,
        entry_points,
        &ModifyPart::new(round_num, part),
        associated_data,
        &expected_description,
    )
}
