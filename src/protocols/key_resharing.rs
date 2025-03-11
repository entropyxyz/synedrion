//! Threshold key resharing protocol.
//!
//! Based on T. M. Wong, C. Wang, J. M. Wing "Verifiable Secret Redistribution for Archive Systems"
//! <https://www.cs.cmu.edu/~wing/publications/Wong-Winga02.pdf>
//! <https://doi.org/10.1109/SISW.2002.1183515>
//! (Specifically, REDIST protocol).
//!
//! This is not a part of the CGGMP proper, but is requried to extend it to operating with threshold key shares,
//! since the CGGMP paper itself does not contain any threshold functionality.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
};
use core::{fmt::Debug, marker::PhantomData};

use ecdsa::VerifyingKey;
use manul::protocol::{
    Artifact, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EchoRoundParticipation, EntryPoint,
    FinalizeOutcome, LocalError, MessageValidationError, NormalBroadcast, PartyId, Payload, Protocol, ProtocolError,
    ProtocolMessage, ProtocolMessagePart, ProtocolValidationError, ReceiveError, RequiredMessages, Round, RoundId,
    Serializer,
};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::{
    curve::{Point, Scalar},
    entities::ThresholdKeyShare,
    params::SchemeParams,
    tools::{
        protocol_shortcuts::{DowncastMap, Without},
        sss::{interpolation_coeff, shamir_join_points, shamir_join_scalars, Polynomial, PublicPolynomial, ShareId},
        Secret,
    },
};

/// A protocol for modifying the set of owners of a shared secret key.
#[derive(Debug)]
pub struct KeyResharingProtocol<P: SchemeParams, I: Debug>(PhantomData<(P, I)>);

impl<P: SchemeParams, I: PartyId> Protocol<I> for KeyResharingProtocol<P, I> {
    type Result = Option<ThresholdKeyShare<P, I>>;
    type ProtocolError = KeyResharingError;

    fn verify_direct_message_is_invalid(
        _deserializer: &Deserializer,
        _round_id: &RoundId,
        _message: &DirectMessage,
    ) -> Result<(), MessageValidationError> {
        unimplemented!()
    }

    fn verify_echo_broadcast_is_invalid(
        _deserializer: &Deserializer,
        _round_id: &RoundId,
        _message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        unimplemented!()
    }

    fn verify_normal_broadcast_is_invalid(
        _deserializer: &Deserializer,
        _round_id: &RoundId,
        _message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError> {
        unimplemented!()
    }
}

/// Provable faults of KeyResharing
#[derive(displaydoc::Display, Debug, Clone, Copy, Serialize, Deserialize)]
pub enum KeyResharingError {
    /// Unexpected sender of a message (not one of the old holders)
    UnexpectedSender,
    /// Mismatch of the subshare
    SubshareMismatch,
}

impl<I> ProtocolError<I> for KeyResharingError {
    type AssociatedData = ();

    fn required_messages(&self) -> RequiredMessages {
        unimplemented!()
    }

    fn verify_messages_constitute_error(
        &self,
        _deserializer: &Deserializer,
        _guilty_party: &I,
        _shared_randomness: &[u8],
        _associated_data: &Self::AssociatedData,
        _message: ProtocolMessage,
        _previous_messages: BTreeMap<RoundId, ProtocolMessage>,
        _combined_echos: BTreeMap<RoundId, BTreeMap<I, EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        unimplemented!()
    }
}

/// Old share data.
#[derive(Debug, Clone)]
pub struct OldHolder<P: SchemeParams, I: Ord + for<'x> Deserialize<'x>> {
    /// The threshold key share.
    pub key_share: ThresholdKeyShare<P, I>,
}

/// New share data.
#[derive(Debug, Clone)]
pub struct NewHolder<P: SchemeParams, I: Ord> {
    /// The verifying key the old shares add up to.
    pub verifying_key: VerifyingKey<P::Curve>,
    /// The old threshold.
    pub old_threshold: usize,
    /// Some of the holders of the old shares (at least `old_threshold` of them).
    pub old_holders: BTreeSet<I>,
}

/// An entry point for the [`KeyResharingProtocol`].
#[derive(Debug, Clone)]
pub struct KeyResharing<P: SchemeParams, I: Ord + for<'x> Deserialize<'x>> {
    /// Old share data if the node holds it, or `None`.
    old_holder: Option<OldHolder<P, I>>,
    /// New share data if the node is one of the new holders, or `None`.
    new_holder: Option<NewHolder<P, I>>,
    /// The new holders of the shares.
    new_holders: BTreeSet<I>,
    /// The new threshold.
    new_threshold: usize,
}

impl<P, I> KeyResharing<P, I>
where
    P: SchemeParams,
    I: Ord + for<'x> Deserialize<'x>,
{
    /// Creates a new entry point for the node with the given ID.
    pub fn new(
        old_holder: Option<OldHolder<P, I>>,
        new_holder: Option<NewHolder<P, I>>,
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

impl<P, I> EntryPoint<I> for KeyResharing<P, I>
where
    P: SchemeParams,
    I: PartyId,
{
    type Protocol = KeyResharingProtocol<P, I>;

    fn entry_round_id() -> RoundId {
        1.into()
    }

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
                let polynomial = Polynomial::random(rng, old_holder.key_share.secret_share.clone(), self.new_threshold);
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
struct OldHolderData<P: SchemeParams> {
    share_id: ShareId<P>,
    polynomial: Polynomial<P>,
    public_polynomial: PublicPolynomial<P>,
}

#[derive(Debug)]
struct NewHolderData<P: SchemeParams, I: Ord> {
    inputs: NewHolder<P, I>,
}

#[derive(Debug)]
struct Round1<P: SchemeParams, I: Ord> {
    old_holder: Option<OldHolderData<P>>,
    new_holder: Option<NewHolderData<P, I>>,
    new_share_ids: BTreeMap<I, ShareId<P>>,
    new_threshold: usize,
    my_id: I,
    message_destinations: BTreeSet<I>,
    expecting_messages_from: BTreeSet<I>,
    echo_round_participation: EchoRoundParticipation<I>,
    phantom: PhantomData<P>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "
    for<'x> PublicPolynomial<P>: Deserialize<'x>,
    for<'x> ShareId<P>: Deserialize<'x>
"))]
struct Round1BroadcastMessage<P: SchemeParams> {
    public_polynomial: PublicPolynomial<P>,
    old_share_id: ShareId<P>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "Secret<Scalar<P>>: for<'x> Deserialize<'x>"))]
struct Round1DirectMessage<P: SchemeParams> {
    subshare: Secret<Scalar<P>>,
}
struct Round1Payload<P: SchemeParams> {
    subshare: Secret<Scalar<P>>,
    public_polynomial: PublicPolynomial<P>,
    old_share_id: ShareId<P>,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round1<P, I> {
    type Protocol = KeyResharingProtocol<P, I>;

    fn id(&self) -> RoundId {
        1.into()
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        [].into()
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

            let subshare: Secret<Scalar<P>> = old_holder.polynomial.evaluate(their_share_id);
            let dm = DirectMessage::new(serializer, Round1DirectMessage { subshare })?;
            Ok((dm, None))
        } else {
            Ok((DirectMessage::none(), None))
        }
    }

    fn receive_message(
        &self,
        deserializer: &Deserializer,
        from: &I,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<I, Self::Protocol>> {
        message.normal_broadcast.assert_is_none()?;
        let echo_broadcast = message
            .echo_broadcast
            .deserialize::<Round1BroadcastMessage<P>>(deserializer)?;
        let direct_message = message
            .direct_message
            .deserialize::<Round1DirectMessage<P>>(deserializer)?;

        if let Some(new_holder) = self.new_holder.as_ref() {
            if new_holder.inputs.old_holders.contains(from) {
                let my_share_id = self.new_share_ids.get(&self.my_id).ok_or(LocalError::new(format!(
                    "my_id={:?} is missing from the new_share_ids",
                    &self.my_id
                )))?;
                let public_subshare_from_poly = echo_broadcast.public_polynomial.evaluate(my_share_id);
                let public_subshare_from_private = Secret::mul_by_generator(&direct_message.subshare);

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

        let mut payloads = payloads.downcast_all::<Round1Payload<P>>()?;

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
                    .map(|coeff0| coeff0 * interpolation_coeff(&old_share_ids, &payload.old_share_id))
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
                    .ok_or_else(|| LocalError::new("id={id:?} is missing from the payloads"))?;
                Ok((payload.old_share_id, payload.subshare.clone()))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let secret_share = shamir_join_scalars(subshares);

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
        })))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};

    use manul::{
        dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
        signature::Keypair,
    };
    use rand_core::OsRng;

    use super::{KeyResharing, NewHolder, OldHolder, ThresholdKeyShare};
    use crate::dev::TestParams;

    #[test]
    fn execute_key_reshare() {
        let signers = (0..4).map(TestSigner::new).collect::<Vec<_>>();
        let ids = signers.iter().map(|signer| signer.verifying_key()).collect::<Vec<_>>();

        let old_holders = BTreeSet::from([ids[0], ids[1], ids[2]]);
        let new_holders = BTreeSet::from([ids[1], ids[2], ids[3]]);

        let old_key_shares =
            ThresholdKeyShare::<TestParams, TestVerifier>::new_centralized(&mut OsRng, &old_holders, 2, None).unwrap();
        let old_vkey = old_key_shares[&ids[0]].verifying_key().unwrap();
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
            let public = share.secret_share.mul_by_generator();
            assert_eq!(public, share.public_shares[&share.owner]);
        }
    }
}
