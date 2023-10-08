use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use signature::hazmat::PrehashVerifier;

use super::error::{Error, TheirFault};
use super::signed_message::{SignedMessage, VerifiedMessage};
use super::type_erased::{deserialize_message, serialize_message};
use crate::tools::collections::HoleVecAccum;
use crate::PartyIdx;

#[derive(Clone)]
pub(crate) struct BroadcastConsensus<Sig, Verifier> {
    verifiers: Vec<Verifier>,
    broadcasts: Vec<(PartyIdx, VerifiedMessage<Sig>)>,
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
        }
    }

    pub fn make_broadcast(&self) -> Box<[u8]> {
        let message = Message {
            broadcasts: self
                .broadcasts
                .iter()
                .cloned()
                .map(|(idx, msg)| (idx, msg.into_unverified()))
                .collect(),
        };
        serialize_message(&message).unwrap()
    }

    pub fn verify_broadcast(
        &self,
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

        Ok(())
    }

    pub fn finalize(self) -> Result<(), Error> {
        Ok(())
    }
}

pub(crate) struct BcConsensusAccum {
    received_echo_from: HoleVecAccum<()>,
}

impl BcConsensusAccum {
    pub fn new(num_parties: usize, party_idx: PartyIdx) -> Self {
        Self {
            received_echo_from: HoleVecAccum::new(num_parties, party_idx.as_usize()),
        }
    }

    pub fn add_echo_received(&mut self, from: PartyIdx) -> Result<(), Error> {
        self.received_echo_from
            .insert(from.as_usize(), ())
            .ok_or(Error::TheirFault {
                party: from,
                error: TheirFault::DuplicateMessage,
            })
    }

    pub fn can_finalize(&self) -> bool {
        self.received_echo_from.can_finalize()
    }

    pub fn finalize(self) -> Result<(), Error> {
        if self.can_finalize() {
            Ok(())
        } else {
            Err(Error::NotEnoughMessages)
        }
    }
}
