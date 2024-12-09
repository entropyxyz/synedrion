//! Threshold key resharing protocol.
//!
//! Based on T. M. Wong, C. Wang, J. M. Wing "Verifiable Secret Redistribution for Archive Systems"
//! <https://www.cs.cmu.edu/~wing/publications/Wong-Winga02.pdf>
//! <https://doi.org/10.1109/SISW.2002.1183515>
//! (Specifically, REDIST protocol).

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use core::{fmt::Debug, marker::PhantomData};

use k256::ecdsa::VerifyingKey;
use manul::protocol::{
    Artifact, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EchoRoundParticipation, EntryPoint,
    FinalizeOutcome, LocalError, NormalBroadcast, PartyId, Payload, Protocol, ProtocolError, ProtocolMessagePart,
    ProtocolValidationError, ReceiveError, Round, RoundId, Serializer,
};
use rand_core::CryptoRngCore;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use super::ThresholdKeyShare;
use crate::{
    curve::{Point, Scalar},
    tools::{
        sss::{interpolation_coeff, shamir_join_points, shamir_join_scalars, Polynomial, PublicPolynomial, ShareId},
        DowncastMap, Without,
    },
    SchemeParams,
};

/// A protocol for modifying the set of owners of a shared secret key.
#[derive(Debug)]
pub struct KeyResharingProtocol<P: SchemeParams, I: Debug>(PhantomData<(P, I)>);

impl<P: SchemeParams, I: PartyId> Protocol for KeyResharingProtocol<P, I> {
    type Result = Option<ThresholdKeyShare<P, I>>;
    type ProtocolError = KeyResharingError;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum KeyResharingError {
    UnexpectedSender,
    SubshareMismatch,
}

impl ProtocolError for KeyResharingError {
    fn description(&self) -> String {
        unimplemented!()
    }

    fn required_direct_messages(&self) -> BTreeSet<RoundId> {
        unimplemented!()
    }

    fn required_echo_broadcasts(&self) -> BTreeSet<RoundId> {
        unimplemented!()
    }

    fn required_combined_echos(&self) -> BTreeSet<RoundId> {
        unimplemented!()
    }

    fn verify_messages_constitute_error(
        &self,
        _deserializer: &Deserializer,
        _echo_broadcast: &EchoBroadcast,
        _normal_broadcat: &NormalBroadcast,
        _direct_message: &DirectMessage,
        _echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
        _normal_broadcasts: &BTreeMap<RoundId, NormalBroadcast>,
        _direct_messages: &BTreeMap<RoundId, DirectMessage>,
        _combined_echos: &BTreeMap<RoundId, Vec<EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        unimplemented!()
    }
}

/// Old share data.
#[derive(Debug, Clone)]
pub struct OldHolder<P: SchemeParams, I: Ord> {
    /// The threshold key share.
    pub key_share: ThresholdKeyShare<P, I>,
}

/// New share data.
#[derive(Debug, Clone)]
pub struct NewHolder<I: Ord> {
    /// The verifying key the old shares add up to.
    pub verifying_key: VerifyingKey,
    /// The old threshold.
    pub old_threshold: usize,
    /// Some of the holders of the old shares (at least `old_threshold` of them).
    pub old_holders: BTreeSet<I>,
}

/// An entry point for the [`KeyResharingProtocol`].
#[derive(Debug, Clone)]
pub struct KeyResharing<P: SchemeParams, I: Ord> {
    /// Old share data if the node holds it, or `None`.
    old_holder: Option<OldHolder<P, I>>,
    /// New share data if the node is one of the new holders, or `None`.
    new_holder: Option<NewHolder<I>>,
    /// The new holders of the shares.
    new_holders: BTreeSet<I>,
    /// The new threshold.
    new_threshold: usize,
}

impl<P: SchemeParams, I: Ord> KeyResharing<P, I> {
    /// Creates a new entry point for the node with the given ID.
    pub fn new(
        old_holder: Option<OldHolder<P, I>>,
        new_holder: Option<NewHolder<I>>,
        new_holders: BTreeSet<I>,
        new_threshold: usize,
    ) -> Self {
        Self {
            old_holder,
            new_holder,
            new_holders,
            new_threshold,
        }
    }
}

impl<P: SchemeParams, I: PartyId> EntryPoint<I> for KeyResharing<P, I> {
    type Protocol = KeyResharingProtocol<P, I>;

    fn make_round(
        self,
        rng: &mut impl CryptoRngCore,
        _shared_randomness: &[u8],
        id: &I,
    ) -> Result<BoxedRound<I, Self::Protocol>, LocalError> {
        // Start new share indices from 1.
        let new_share_ids = self
            .new_holders
            .iter()
            .enumerate()
            .map(|(idx, id)| {
                let idx: u64 = idx.try_into().expect("no more than 2^64-1 shares needed");
                (id.clone(), ShareId::new(idx + 1))
            })
            .collect();

        if self.old_holder.is_none() && self.new_holder.is_none() {
            return Err(LocalError::new("Either old holder or new holder data must be provided"));
        };

        let message_destinations = if self.old_holder.is_some() {
            // It is possible that a party is both an old holder and a new holder.
            // This will be processed separately.
            self.new_holders.clone().without(id)
        } else {
            BTreeSet::new()
        };

        let expecting_messages_from = if let Some(new_holder) = self.new_holder.as_ref() {
            // TODO: we only need `old_threshold` of them, but it is not supported yet in `manul`.
            new_holder.old_holders.clone().without(id)
        } else {
            BTreeSet::new()
        };

        let echo_round_participation = if self.old_holder.is_some() && self.new_holder.is_none() {
            EchoRoundParticipation::Send
        } else if self.new_holder.is_some() && self.old_holder.is_none() {
            EchoRoundParticipation::Receive {
                echo_targets: self.new_holders.without(id),
            }
        } else {
            EchoRoundParticipation::Default
        };

        let old_holder = self
            .old_holder
            .map(|old_holder| {
                let polynomial = Polynomial::random(
                    rng,
                    old_holder.key_share.secret_share.expose_secret(),
                    self.new_threshold,
                );
                let public_polynomial = polynomial.public();

                Ok(OldHolderData {
                    polynomial,
                    share_id: *old_holder.key_share.share_id()?,
                    public_polynomial,
                })
            })
            .transpose()?;

        let new_holder = self.new_holder.map(|new_holder| NewHolderData { inputs: new_holder });

        Ok(BoxedRound::new_dynamic(Round1 {
            old_holder,
            new_holder,
            new_share_ids,
            new_threshold: self.new_threshold,
            my_id: id.clone(),
            message_destinations,
            expecting_messages_from,
            echo_round_participation,
            phantom: PhantomData,
        }))
    }
}

#[derive(Debug)]
struct OldHolderData {
    share_id: ShareId,
    polynomial: Polynomial,
    public_polynomial: PublicPolynomial,
}

#[derive(Debug)]
struct NewHolderData<I: Ord> {
    inputs: NewHolder<I>,
}

#[derive(Debug)]
struct Round1<P: SchemeParams, I: Ord> {
    old_holder: Option<OldHolderData>,
    new_holder: Option<NewHolderData<I>>,
    new_share_ids: BTreeMap<I, ShareId>,
    new_threshold: usize,
    my_id: I,
    message_destinations: BTreeSet<I>,
    expecting_messages_from: BTreeSet<I>,
    echo_round_participation: EchoRoundParticipation<I>,
    phantom: PhantomData<P>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Round1BroadcastMessage {
    public_polynomial: PublicPolynomial,
    old_share_id: ShareId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Round1DirectMessage {
    subshare: Scalar,
}

struct Round1Payload {
    subshare: Scalar,
    public_polynomial: PublicPolynomial,
    old_share_id: ShareId,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round1<P, I> {
    type Protocol = KeyResharingProtocol<P, I>;

    fn id(&self) -> RoundId {
        RoundId::new(1)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        BTreeSet::new()
    }

    fn message_destinations(&self) -> &BTreeSet<I> {
        &self.message_destinations
    }

    fn expecting_messages_from(&self) -> &BTreeSet<I> {
        &self.expecting_messages_from
    }

    fn echo_round_participation(&self) -> EchoRoundParticipation<I> {
        self.echo_round_participation.clone()
    }

    fn make_echo_broadcast(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
    ) -> Result<EchoBroadcast, LocalError> {
        if let Some(old_holder) = self.old_holder.as_ref() {
            EchoBroadcast::new(
                serializer,
                Round1BroadcastMessage {
                    public_polynomial: old_holder.public_polynomial.clone(),
                    old_share_id: old_holder.share_id,
                },
            )
        } else {
            Ok(EchoBroadcast::none())
        }
    }

    fn make_direct_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        serializer: &Serializer,
        destination: &I,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        if let Some(old_holder) = self.old_holder.as_ref() {
            let their_share_id = self.new_share_ids.get(destination).ok_or(LocalError::new(format!(
                "destination={:?} is missing from the new_share_ids",
                destination
            )))?;

            let subshare = old_holder.polynomial.evaluate(their_share_id);
            let dm = DirectMessage::new(serializer, Round1DirectMessage { subshare })?;
            Ok((dm, None))
        } else {
            Ok((DirectMessage::none(), None))
        }
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        from: &I,
        echo_broadcast: EchoBroadcast,
        normal_broadcast: NormalBroadcast,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        normal_broadcast.assert_is_none()?;
        let echo_broadcast = echo_broadcast.deserialize::<Round1BroadcastMessage>(deserializer)?;
        let direct_message = direct_message.deserialize::<Round1DirectMessage>(deserializer)?;

        if let Some(new_holder) = self.new_holder.as_ref() {
            if new_holder.inputs.old_holders.contains(from) {
                let my_share_id = self.new_share_ids.get(&self.my_id).ok_or(LocalError::new(format!(
                    "my_id={:?} is missing from the new_share_ids",
                    &self.my_id
                )))?;
                let public_subshare_from_poly = echo_broadcast.public_polynomial.evaluate(my_share_id);
                let public_subshare_from_private = direct_message.subshare.mul_by_generator();

                // Check that the public polynomial sent in the broadcast corresponds to the secret share
                // sent in the direct message.
                if public_subshare_from_poly != public_subshare_from_private {
                    return Err(ReceiveError::protocol(KeyResharingError::SubshareMismatch));
                }

                return Ok(Payload::new(Round1Payload {
                    subshare: direct_message.subshare,
                    public_polynomial: echo_broadcast.public_polynomial,
                    old_share_id: echo_broadcast.old_share_id,
                }));
            }
        }
        Err(ReceiveError::protocol(KeyResharingError::UnexpectedSender))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, Payload>,
        _artifacts: BTreeMap<I, Artifact>,
    ) -> Result<FinalizeOutcome<I, Self::Protocol>, LocalError> {
        // If this party is not a new holder, exit.
        let new_holder = match self.new_holder.as_ref() {
            Some(new_holder) => new_holder,
            None => return Ok(FinalizeOutcome::Result(None)),
        };

        let mut payloads = payloads.downcast_all::<Round1Payload>()?;

        let share_id = self
            .new_share_ids
            .get(&self.my_id)
            .ok_or_else(|| LocalError::new(format!("my_id={:?} is missing from new_share_ids", &self.my_id)))?;

        // If this node is both an old and a new holder,
        // add a simulated payload to the mapping, as if it sent a message to itself.
        if let Some(old_holder) = self.old_holder.as_ref() {
            if self.new_holder.as_ref().is_some() {
                let subshare = old_holder.polynomial.evaluate(share_id);
                let my_payload = Round1Payload {
                    subshare,
                    public_polynomial: old_holder.public_polynomial.clone(),
                    old_share_id: old_holder.share_id,
                };
                payloads.insert(self.my_id.clone(), my_payload);
            }
        }

        // Check that the 0-th coefficients of public polynomials (that is, the old shares)
        // add up to the expected verifying key.
        let old_share_ids = payloads
            .values()
            .map(|payload| payload.old_share_id)
            .collect::<BTreeSet<_>>();
        let vkey = payloads
            .values()
            .map(|payload| {
                payload
                    .public_polynomial
                    .coeff0()
                    .map(|coeff0| coeff0 * &interpolation_coeff(&old_share_ids, &payload.old_share_id))
            })
            .sum::<Result<_, _>>()?;
        if Point::from_verifying_key(&new_holder.inputs.verifying_key) != vkey {
            // TODO (#113): this is unattributable.
            // Should we add an enum variant to `FinalizeError`?
            // or take the public shares as an input (assuming the nodes published those previously)
            panic!("Invalid shares");
        }

        // Assemble the new share.
        let subshares = new_holder
            .inputs
            .old_holders
            .iter()
            .map(|id| {
                let payload = payloads
                    .get(id)
                    .ok_or(LocalError::new("id={id:?} is missing from the payloads"))?;
                Ok((payload.old_share_id, payload.subshare))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let secret_share = SecretBox::new(Box::new(shamir_join_scalars(&subshares)));

        // Generate the public shares of all the new holders.
        let public_shares = self
            .new_share_ids
            .iter()
            .map(|(id, share_id)| {
                let public_subshares = payloads
                    .values()
                    .map(|p| (p.old_share_id, p.public_polynomial.evaluate(share_id)))
                    .collect::<BTreeMap<_, _>>();
                let public_share = shamir_join_points(&public_subshares);
                (id.clone(), public_share)
            })
            .collect();

        Ok(FinalizeOutcome::Result(Some(ThresholdKeyShare {
            owner: self.my_id.clone(),
            threshold: self.new_threshold as u32,
            secret_share,
            share_ids: self.new_share_ids,
            public_shares,
            phantom: PhantomData,
        })))
    }
}

#[allow(clippy::indexing_slicing)]
#[cfg(test)]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};

    use manul::{
        dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
        session::signature::Keypair,
    };
    use rand_core::OsRng;
    use secrecy::ExposeSecret;

    use super::{KeyResharing, NewHolder, OldHolder, ThresholdKeyShare};
    use crate::TestParams;

    #[test]
    fn execute_key_reshare() {
        let signers = (0..4).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers.iter().map(|signer| signer.verifying_key()).collect::<Vec<_>>();

        let old_holders = BTreeSet::from([ids[0], ids[1], ids[2]]);
        let new_holders = BTreeSet::from([ids[1], ids[2], ids[3]]);

        let old_key_shares =
            ThresholdKeyShare::<TestParams, TestVerifier>::new_centralized(&mut OsRng, &old_holders, 2, None);
        let old_vkey = old_key_shares[&ids[0]].verifying_key();
        let new_threshold = 2;

        let party0 = KeyResharing::new(
            Some(OldHolder {
                key_share: old_key_shares[&ids[0]].clone(),
            }),
            None,
            new_holders.clone(),
            new_threshold,
        );

        let party1 = KeyResharing::new(
            Some(OldHolder {
                key_share: old_key_shares[&ids[1]].clone(),
            }),
            Some(NewHolder {
                verifying_key: old_vkey,
                old_threshold: 2,
                old_holders: old_holders.clone(),
            }),
            new_holders.clone(),
            new_threshold,
        );

        let party2 = KeyResharing::new(
            Some(OldHolder {
                key_share: old_key_shares[&ids[2]].clone(),
            }),
            Some(NewHolder {
                verifying_key: old_vkey,
                old_threshold: 2,
                old_holders: old_holders.clone(),
            }),
            new_holders.clone(),
            new_threshold,
        );

        let party3 = KeyResharing::new(
            None,
            Some(NewHolder {
                verifying_key: old_vkey,
                old_threshold: 2,
                old_holders: old_holders.clone(),
            }),
            new_holders.clone(),
            new_threshold,
        );

        let entry_points = signers
            .into_iter()
            .zip([party0, party1, party2, party3])
            .collect::<Vec<_>>();

        let shares = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
            .unwrap()
            .results()
            .unwrap();

        // Check that the party that is not among the new holders gets None as a result
        assert!(shares[&ids[0]].is_none());

        // Unwrap the results of the new holders
        let shares = shares
            .into_iter()
            .filter(|(id, _share)| id != &ids[0])
            .map(|(id, share)| (id, share.unwrap()))
            .collect::<BTreeMap<_, _>>();

        // Check that all public information is the same between the shares
        let public_sets = shares
            .iter()
            .map(|(id, share)| (*id, share.public_shares.clone()))
            .collect::<BTreeMap<_, _>>();
        assert!(public_sets.values().all(|pk| pk == &public_sets[&ids[1]]));

        // Check that the public keys correspond to the secret key shares
        for share in shares.values() {
            let public = share.secret_share.expose_secret().mul_by_generator();
            assert_eq!(public, share.public_shares[&share.owner]);
        }
    }
}
