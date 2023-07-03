use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use signature::hazmat::PrehashVerifier;

use super::error::{Error, TheirFault};
use super::signed_message::{SignedMessage, VerifiedMessage};
use crate::protocols::type_erased::{deserialize_message, serialize_message, ToSendSerialized};
use crate::PartyIdx;

#[derive(Clone)]
pub(crate) struct BroadcastConsensus<Sig, Verifier> {
    verifiers: Vec<Verifier>,
    broadcasts: Vec<(PartyIdx, VerifiedMessage<Sig>)>,
    received_echo_from: BTreeSet<PartyIdx>,
}

#[derive(Serialize, Deserialize)]
struct Message<Sig> {
    broadcasts: Vec<(PartyIdx, SignedMessage<Sig>)>,
}

impl<Sig, Verifier> BroadcastConsensus<Sig, Verifier>
where
    Sig: Clone + Serialize + for<'de> Deserialize<'de> + PartialEq + Eq,
    Verifier: PrehashVerifier<Sig> + Clone,
{
    pub fn new(broadcasts: Vec<(PartyIdx, VerifiedMessage<Sig>)>, verifiers: &[Verifier]) -> Self {
        // TODO: don't have to clone `verifiers` here, can just keep a ref.
        Self {
            broadcasts,
            verifiers: verifiers.into(),
            received_echo_from: BTreeSet::new(),
        }
    }

    pub fn to_send(&self) -> ToSendSerialized {
        let message = Message {
            broadcasts: self
                .broadcasts
                .iter()
                .cloned()
                .map(|(idx, msg)| (idx, msg.into_unverified()))
                .collect(),
        };
        ToSendSerialized::Broadcast(serialize_message(&message).unwrap())
    }

    pub fn receive_message(
        &mut self,
        from: PartyIdx,
        verified_message: VerifiedMessage<Sig>,
    ) -> Result<(), Error> {
        // TODO: check that `from` is valid here?
        let message: Message<Sig> = deserialize_message(verified_message.payload()).unwrap();

        // TODO: check that there are no repeating indices?
        let bc_map = message.broadcasts.into_iter().collect::<BTreeMap<_, _>>();

        if bc_map.len() != self.broadcasts.len() {
            return Err(Error::TheirFault {
                party: from,
                error: TheirFault::VerificationFail(
                    "Unexpected number of broadcasts received".into(),
                ),
            });
        }

        // CHECK: should we save our own broadcast,
        // and check that the other nodes received it?
        // Or is this excessive since they are signed by us anyway?

        for (idx, broadcast) in self.broadcasts.iter() {
            // CHECK: the party `from` won't send us its own broadcast the second time.
            // It gives no additional assurance.
            if idx == &from {
                continue;
            }

            let echoed_bc = bc_map.get(idx).ok_or_else(|| Error::TheirFault {
                party: from,
                error: TheirFault::VerificationFail(format!(
                    "Missing broadcast from party {idx:?}"
                )),
            })?;

            let verified_bc = echoed_bc
                .clone()
                .verify(&self.verifiers[idx.as_usize()])
                .map_err(|error| Error::TheirFault { party: from, error })?;

            if broadcast != &verified_bc {
                return Err(Error::TheirFault {
                    party: *idx,
                    error: TheirFault::VerificationFail("Received conflicting broadcasts".into()),
                });
            }
        }

        self.received_echo_from.insert(from);

        Ok(())
    }

    pub fn can_finalize(&self) -> bool {
        for (idx, _) in self.broadcasts.iter() {
            if self.received_echo_from.get(idx).is_none() {
                return false;
            }
        }
        true
    }

    pub fn finalize(self) -> Result<(), Error> {
        if !self.can_finalize() {
            // TODO: report which nodes are missing
            return Err(Error::NotEnoughMessages);
        }
        Ok(())
    }
}
