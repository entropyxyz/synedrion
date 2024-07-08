use alloc::collections::{BTreeMap, BTreeSet};
use core::marker::PhantomData;

use serde::Deserialize;
use signature::hazmat::PrehashVerifier;

use super::message_bundle::{MessageBundle, VerifiedMessageBundle};
use super::session::Messages;
use super::signed_message::SignedMessage;
use crate::rounds::{EvidenceRequiresMessages, ProtocolResult};

#[derive(Debug, Clone)]
pub struct Evidence<Res: ProtocolResult<Verifier>, Sig, Verifier> {
    party: Verifier,
    result: Res::ProvableError,
    message_bundle: MessageBundle,
    // Map round number -> message signed by the offending party
    bcs: BTreeMap<u8, SignedMessage>,
    dms: BTreeMap<u8, SignedMessage>,
    echos: BTreeMap<u8, SignedMessage>,
    phantom: PhantomData<Sig>,
}

impl<
        Res: ProtocolResult<Verifier>,
        Sig: Clone + for<'de> Deserialize<'de>,
        Verifier: Clone + Ord,
    > Evidence<Res, Sig, Verifier>
{
    pub(crate) fn new(
        party: &Verifier,
        result: Res::ProvableError,
        message_bundle: VerifiedMessageBundle,
        messages: &Messages<Verifier>,
    ) -> Self {
        let bcs = result
            .requires_bcs()
            .iter()
            .map(|round_num| (*round_num, messages.bcs[round_num][party].clone()))
            .collect();
        let dms = result
            .requires_dms()
            .iter()
            .map(|round_num| (*round_num, messages.dms[round_num][party].clone()))
            .collect();
        let echos = result
            .requires_echos()
            .iter()
            .map(|round_num| (*round_num, messages.echos[round_num][party].clone()))
            .collect();

        Self {
            party: party.clone(),
            result,
            message_bundle: message_bundle.into_unverified(),
            bcs,
            dms,
            echos,
            phantom: PhantomData,
        }
    }
}

impl<Res: ProtocolResult<Verifier>, Sig: Clone + for<'de> Deserialize<'de>, Verifier>
    Evidence<Res, Sig, Verifier>
where
    Verifier: Clone + PrehashVerifier<Sig>,
{
    pub fn verify_malicious(
        &self,
        verifier: &Verifier,
        shared_randomness: &[u8],
        other_ids: &BTreeSet<Verifier>,
        my_id: &Verifier,
    ) -> bool {
        let bcs = self
            .bcs
            .iter()
            .map(|(round, message)| {
                (
                    *round,
                    message
                        .clone()
                        .verify(verifier)
                        .unwrap()
                        .serialized_message()
                        .clone(),
                )
            })
            .collect();
        let dms = self
            .dms
            .iter()
            .map(|(round, message)| {
                (
                    *round,
                    message
                        .clone()
                        .verify(verifier)
                        .unwrap()
                        .serialized_message()
                        .clone(),
                )
            })
            .collect();
        let echos = self
            .echos
            .iter()
            .map(|(round, message)| {
                (
                    *round,
                    message
                        .clone()
                        .verify(verifier)
                        .unwrap()
                        .serialized_message()
                        .clone(),
                )
            })
            .collect();

        self.result
            .verify_malicious(shared_randomness, other_ids, my_id, &bcs, &dms, &echos)
    }
}
