//! Threshold key resharing protocol.
//!
//! Based on T. M. Wong, C. Wang, J. M. Wing "Verifiable Secret Redistribution for Archive Systems"
//! <https://www.cs.cmu.edu/~wing/publications/Wong-Winga02.pdf>
//! <https://doi.org/10.1109/SISW.2002.1183515>
//! (Specifically, REDIST protocol).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::fmt::Debug;
use core::marker::PhantomData;

use k256::ecdsa::VerifyingKey;
use rand_core::CryptoRngCore;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};

use super::ThresholdKeyShare;
use crate::curve::{Point, Scalar};
use crate::rounds::{
    FinalizableToResult, FinalizationRequirement, FinalizeError, FirstRound, InitError,
    ProtocolResult, Round, ToResult,
};
use crate::tools::sss::{
    interpolation_coeff, shamir_join_points, shamir_join_scalars, Polynomial, PublicPolynomial,
    ShareId,
};
use crate::SchemeParams;

/// The outcomes of KeyResharing protocol.
#[derive(Debug)]
pub struct KeyResharingResult<P: SchemeParams, I: Debug>(PhantomData<P>, PhantomData<I>);

impl<P: SchemeParams, I: Ord + Debug> ProtocolResult for KeyResharingResult<P, I> {
    type Success = Option<ThresholdKeyShare<P, I>>;
    type ProvableError = KeyResharingError;
    type CorrectnessProof = ();
}

#[derive(Debug, Clone, Copy)]
pub enum KeyResharingError {
    UnexpectedSender,
    SubshareMismatch,
}

/// Old share data.
#[derive(Clone)]
pub struct OldHolder<P: SchemeParams, I: Ord> {
    /// The threshold key share.
    pub key_share: ThresholdKeyShare<P, I>,
}

/// New share data.
#[derive(Clone)]
pub struct NewHolder<I: Ord> {
    /// The verifying key the old shares add up to.
    pub verifying_key: VerifyingKey,
    /// The old threshold.
    pub old_threshold: usize,
    /// Some of the holders of the old shares (at least `old_threshold` of them).
    pub old_holders: BTreeSet<I>,
}

/// Inputs for the Key Resharing protocol.
#[derive(Clone)]
pub struct KeyResharingInputs<P: SchemeParams, I: Ord> {
    /// Old share data if the node holds it, or `None`.
    pub old_holder: Option<OldHolder<P, I>>,
    /// New share data if the node is one of the new holders, or `None`.
    pub new_holder: Option<NewHolder<I>>,
    /// The new holders of the shares.
    pub new_holders: BTreeSet<I>,
    /// The new threshold.
    pub new_threshold: usize,
}

struct OldHolderData {
    share_id: ShareId,
    polynomial: Polynomial,
    public_polynomial: PublicPolynomial,
}

struct NewHolderData<I: Ord> {
    inputs: NewHolder<I>,
}

pub struct Round1<P: SchemeParams, I: Ord> {
    old_holder: Option<OldHolderData>,
    new_holder: Option<NewHolderData<I>>,
    new_share_ids: BTreeMap<I, ShareId>,
    new_threshold: usize,
    other_ids: BTreeSet<I>,
    my_id: I,
    message_destinations: BTreeSet<I>,
    phantom: PhantomData<P>,
}

impl<P: SchemeParams, I: Clone + Ord + Debug> FirstRound<I> for Round1<P, I> {
    type Inputs = KeyResharingInputs<P, I>;
    fn new(
        rng: &mut impl CryptoRngCore,
        _shared_randomness: &[u8],
        other_ids: BTreeSet<I>,
        my_id: I,
        inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        // Start new share indices from 1.
        let new_share_ids = inputs
            .new_holders
            .iter()
            .enumerate()
            .map(|(idx, id)| (id.clone(), ShareId::new(idx + 1)))
            .collect();

        if inputs.old_holder.is_none() && inputs.new_holder.is_none() {
            return Err(InitError(
                "Either old holder or new holder data must be provided".into(),
            ));
        };

        let message_destinations = if inputs.old_holder.is_some() {
            // It is possible that a party is both an old holder and a new holder.
            // This will be processed separately.
            let mut new_holders_except_me = inputs.new_holders;
            new_holders_except_me.remove(&my_id);
            new_holders_except_me
        } else {
            BTreeSet::new()
        };

        let old_holder = inputs.old_holder.map(|old_holder| {
            let polynomial = Polynomial::random(
                rng,
                old_holder.key_share.secret_share.expose_secret(),
                inputs.new_threshold,
            );
            let public_polynomial = polynomial.public();

            OldHolderData {
                polynomial,
                share_id: old_holder.key_share.share_id(),
                public_polynomial,
            }
        });

        let new_holder = inputs
            .new_holder
            .map(|new_holder| NewHolderData { inputs: new_holder });

        Ok(Round1 {
            old_holder,
            new_holder,
            new_share_ids,
            new_threshold: inputs.new_threshold,
            other_ids,
            my_id,
            message_destinations,
            phantom: PhantomData,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1BroadcastMessage {
    public_polynomial: PublicPolynomial,
    old_share_id: ShareId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1DirectMessage {
    subshare: Scalar,
}

pub struct Round1Payload {
    subshare: Scalar,
    public_polynomial: PublicPolynomial,
    old_share_id: ShareId,
}

impl<P: SchemeParams, I: Clone + Ord + Debug> Round<I> for Round1<P, I> {
    type Type = ToResult;
    type Result = KeyResharingResult<P, I>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = None;

    fn other_ids(&self) -> &BTreeSet<I> {
        &self.other_ids
    }

    fn my_id(&self) -> &I {
        &self.my_id
    }

    const REQUIRES_ECHO: bool = true;
    type BroadcastMessage = Round1BroadcastMessage;
    type DirectMessage = Round1DirectMessage;
    type Payload = Round1Payload;
    type Artifact = ();

    fn message_destinations(&self) -> &BTreeSet<I> {
        &self.message_destinations
    }

    fn make_broadcast_message(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        self.old_holder
            .as_ref()
            .map(|old_holder| Round1BroadcastMessage {
                public_polynomial: old_holder.public_polynomial.clone(),
                old_share_id: old_holder.share_id,
            })
    }

    fn make_direct_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        destination: &I,
    ) -> (Self::DirectMessage, Self::Artifact) {
        if let Some(old_holder) = self.old_holder.as_ref() {
            let subshare = old_holder
                .polynomial
                .evaluate(&self.new_share_ids[destination]);
            (Round1DirectMessage { subshare }, ())
        } else {
            // TODO (#54): this should be prevented by type system
            panic!("This node does not send messages in this round");
        }
    }

    fn verify_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        from: &I,
        broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        if let Some(new_holder) = self.new_holder.as_ref() {
            if new_holder.inputs.old_holders.contains(from) {
                let public_subshare_from_poly = broadcast_msg
                    .public_polynomial
                    .evaluate(&self.new_share_ids[self.my_id()]);
                let public_subshare_from_private = direct_msg.subshare.mul_by_generator();

                // Check that the public polynomial sent in the broadcast corresponds to the secret share
                // sent in the direct message.
                if public_subshare_from_poly != public_subshare_from_private {
                    return Err(KeyResharingError::SubshareMismatch);
                }

                return Ok(Round1Payload {
                    subshare: direct_msg.subshare,
                    public_polynomial: broadcast_msg.public_polynomial,
                    old_share_id: broadcast_msg.old_share_id,
                });
            }
        }
        Err(KeyResharingError::UnexpectedSender)
    }

    fn finalization_requirement() -> FinalizationRequirement {
        FinalizationRequirement::Custom
    }

    fn can_finalize(&self, received: &BTreeSet<I>) -> bool {
        if let Some(new_holder) = self.new_holder.as_ref() {
            let threshold = if self.old_holder.is_some() && self.new_holder.is_some() {
                new_holder.inputs.old_threshold - 1
            } else {
                new_holder.inputs.old_threshold
            };
            received.len() >= threshold
        } else {
            true
        }
    }

    fn missing_messages(&self, received: &BTreeSet<I>) -> BTreeSet<I> {
        if let Some(new_holder) = self.new_holder.as_ref() {
            new_holder
                .inputs
                .old_holders
                .iter()
                .filter(|id| !received.contains(id) && id != &self.my_id())
                .cloned()
                .collect()
        } else {
            BTreeSet::new()
        }
    }
}

impl<P: SchemeParams, I: Ord + Clone + Debug> FinalizableToResult<I> for Round1<P, I> {
    fn finalize_to_result(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        _artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        // If this party is not a new holder, exit.
        let new_holder = match self.new_holder.as_ref() {
            Some(new_holder) => new_holder,
            None => return Ok(None),
        };

        let share_id = self.new_share_ids[self.my_id()];

        let mut payloads = payloads;

        // If this node is both an old and a new holder,
        // add a simulated payload to the mapping, as if it sent a message to itself.
        if let Some(old_holder) = self.old_holder.as_ref() {
            if self.new_holder.as_ref().is_some() {
                let subshare = old_holder.polynomial.evaluate(&share_id);
                let my_payload = Round1Payload {
                    subshare,
                    public_polynomial: old_holder.public_polynomial.clone(),
                    old_share_id: old_holder.share_id,
                };
                payloads.insert(self.my_id().clone(), my_payload);
            }
        }

        // Check that the 0-th coefficients of public polynomials (that is, the old shares)
        // add up to the expected verifying key.
        let old_share_ids = payloads
            .values()
            .map(|payload| payload.old_share_id)
            .collect::<Vec<_>>();
        let vkey = payloads
            .values()
            .map(|payload| {
                payload.public_polynomial.coeff0()
                    * interpolation_coeff(old_share_ids.iter(), &payload.old_share_id)
            })
            .sum();
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
            .map(|id| (payloads[id].old_share_id, payloads[id].subshare))
            .collect::<BTreeMap<_, _>>();
        let secret_share = SecretBox::new(Box::new(shamir_join_scalars(subshares.iter())));

        // Generate the public shares of all the new holders.
        let public_shares = self
            .new_share_ids
            .keys()
            .map(|id| {
                let share_id = self.new_share_ids[id];
                let public_subshares = payloads
                    .values()
                    .map(|p| (p.old_share_id, p.public_polynomial.evaluate(&share_id)))
                    .collect::<BTreeMap<_, _>>();
                let public_share = shamir_join_points(public_subshares.iter());
                (id.clone(), public_share)
            })
            .collect();

        Ok(Some(ThresholdKeyShare {
            owner: self.my_id().clone(),
            threshold: self.new_threshold as u32,
            secret_share,
            share_ids: self.new_share_ids,
            public_shares,
            phantom: PhantomData,
        }))
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};

    use rand_core::{OsRng, RngCore};
    use secrecy::ExposeSecret;

    use super::ThresholdKeyShare;
    use super::{KeyResharingInputs, NewHolder, OldHolder, Round1};
    use crate::rounds::{
        test_utils::{step_result, step_round, Id},
        FirstRound,
    };
    use crate::TestParams;

    #[test]
    fn execute_key_reshare() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let ids = [Id(0), Id(1), Id(2), Id(3)];

        let old_holders = BTreeSet::from([ids[0], ids[1], ids[2]]);
        let new_holders = BTreeSet::from([ids[1], ids[2], ids[3]]);

        let old_key_shares =
            ThresholdKeyShare::<TestParams, Id>::new_centralized(&mut OsRng, &old_holders, 2, None);
        let old_vkey = old_key_shares[&ids[0]].verifying_key();

        let party0 = Round1::new(
            &mut OsRng,
            &shared_randomness,
            BTreeSet::from([ids[1], ids[2], ids[3]]),
            ids[0],
            KeyResharingInputs {
                old_holder: Some(OldHolder {
                    key_share: old_key_shares[&ids[0]].clone(),
                }),
                new_holder: None,
                new_holders: new_holders.clone(),
                new_threshold: 2,
            },
        )
        .unwrap();

        let party1 = Round1::new(
            &mut OsRng,
            &shared_randomness,
            BTreeSet::from([ids[0], ids[2], ids[3]]),
            ids[1],
            KeyResharingInputs {
                old_holder: Some(OldHolder {
                    key_share: old_key_shares[&ids[1]].clone(),
                }),
                new_holder: Some(NewHolder {
                    verifying_key: old_vkey,
                    old_threshold: 2,
                    old_holders: old_holders.clone(),
                }),
                new_holders: new_holders.clone(),
                new_threshold: 2,
            },
        )
        .unwrap();

        let party2 = Round1::new(
            &mut OsRng,
            &shared_randomness,
            BTreeSet::from([ids[0], ids[1], ids[3]]),
            ids[2],
            KeyResharingInputs {
                old_holder: Some(OldHolder {
                    key_share: old_key_shares[&ids[2]].clone(),
                }),
                new_holder: Some(NewHolder {
                    verifying_key: old_vkey,
                    old_threshold: 2,
                    old_holders: old_holders.clone(),
                }),
                new_holders: new_holders.clone(),
                new_threshold: 2,
            },
        )
        .unwrap();

        let party3 = Round1::new(
            &mut OsRng,
            &shared_randomness,
            BTreeSet::from([ids[0], ids[1], ids[2]]),
            ids[3],
            KeyResharingInputs {
                old_holder: None,
                new_holder: Some(NewHolder {
                    verifying_key: old_vkey,
                    old_threshold: 2,
                    old_holders: old_holders.clone(),
                }),
                new_holders: new_holders.clone(),
                new_threshold: 2,
            },
        )
        .unwrap();

        let r1 = BTreeMap::from([
            (ids[0], party0),
            (ids[1], party1),
            (ids[2], party2),
            (ids[3], party3),
        ]);

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let shares = step_result(&mut OsRng, r1a).unwrap();

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
