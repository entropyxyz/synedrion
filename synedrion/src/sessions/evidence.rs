use alloc::collections::{BTreeMap, BTreeSet};
use core::marker::PhantomData;

use serde::Deserialize;
use signature::hazmat::PrehashVerifier;

use super::signed_message::SignedMessage;
use crate::rounds::{EvidenceRequiresMessages, ProtocolResult};

#[derive(Debug, Clone)]
pub struct Evidence<Res: ProtocolResult<Verifier>, Sig, Verifier> {
    party: Verifier,
    result: Res::ProvableError,
    // Map round number -> message signed by the offending party
    messages: BTreeMap<(u8, bool), SignedMessage>,
    phantom: PhantomData<Sig>,
}

impl<Res: ProtocolResult<Verifier>, Sig: Clone + for<'de> Deserialize<'de>, Verifier>
    Evidence<Res, Sig, Verifier>
where
    Verifier: Clone + PrehashVerifier<Sig>,
{
    fn new(
        party: &Verifier,
        result: Res::ProvableError,
        all_messages: &BTreeMap<(u8, bool), SignedMessage>,
    ) -> Self {
        let messages = result
            .requires_messages()
            .iter()
            .map(|(round_num, echo)| {
                (
                    (*round_num, *echo),
                    all_messages[&(*round_num, *echo)].clone(),
                )
            })
            .collect();
        Self {
            party: party.clone(),
            result,
            messages,
            phantom: PhantomData,
        }
    }

    fn verify_malicious(
        &self,
        verifier: &Verifier,
        shared_randomness: &[u8],
        other_ids: &BTreeSet<Verifier>,
        my_id: &Verifier,
    ) -> bool {
        let vmessages = self
            .messages
            .iter()
            .map(|((round, echo), message)| {
                let vmessage = message.clone().verify(verifier).unwrap();
                ((*round, *echo), vmessage.serialized_message().clone())
            })
            .collect::<BTreeMap<_, _>>();

        self.result
            .verify_malicious(shared_randomness, other_ids, my_id, &vmessages)
    }
}
