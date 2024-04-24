//! Threshold key resharing protocol.
//!
//! Based on T. M. Wong, C. Wang, J. M. Wing "Verifiable Secret Redistribution for Archive Systems"
//! https://www.cs.cmu.edu/~wing/publications/Wong-Winga02.pdf
//! https://doi.org/10.1109/SISW.2002.1183515
//! (Specifically, REDIST protocol).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::cggmp21::SchemeParams;
use crate::curve::{Point, Scalar};
use crate::rounds::{
    FinalizableToResult, FinalizationRequirement, FinalizeError, FirstRound, InitError, PartyIdx,
    ProtocolResult, ReceiveError, Round, ToResult,
};
use crate::threshold::ThresholdKeyShareSeed;
use crate::tools::{
    bitvec::BitVec,
    sss::{
        interpolation_coeff, shamir_join_points, shamir_join_scalars, Polynomial, PublicPolynomial,
        ShareIdx,
    },
};

#[derive(Debug)]
pub struct KeyResharingResult<P: SchemeParams>(PhantomData<P>);

impl<P: SchemeParams> ProtocolResult for KeyResharingResult<P> {
    type Success = Option<ThresholdKeyShareSeed<P>>;
    type ProvableError = KeyResharingError;
    type CorrectnessProof = ();
}

#[derive(Debug, Clone)]
pub enum KeyResharingError {
    UnexpectedSender,
    SubshareMismatch,
}

pub struct OldHolder<P: SchemeParams> {
    key_share_seed: ThresholdKeyShareSeed<P>,
}

pub struct NewHolder {
    verifying_key: Point,
    init_id: BitVec,
    old_threshold: usize,
    old_holders: Vec<PartyIdx>,
}

pub struct KeyResharingContext<P: SchemeParams> {
    old_holder: Option<OldHolder<P>>,
    new_holder: Option<NewHolder>,
    new_holders: Vec<PartyIdx>,
    new_threshold: usize,
}

struct OldHolderData<P: SchemeParams> {
    inputs: OldHolder<P>,
    polynomial: Polynomial,
    public_polynomial: PublicPolynomial,
}

struct NewHolderData {
    inputs: NewHolder,
}

pub struct Round1<P: SchemeParams> {
    old_holder: Option<OldHolderData<P>>,
    new_holder: Option<NewHolderData>,
    new_share_idxs: BTreeMap<PartyIdx, ShareIdx>,
    new_threshold: usize,
    num_parties: usize,
    party_idx: PartyIdx,
    init_id: BitVec,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Inputs = KeyResharingContext<P>;
    fn new(
        rng: &mut impl CryptoRngCore,
        _shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        // Start new share indices from 1.
        let new_share_idxs = inputs
            .new_holders
            .iter()
            .enumerate()
            .map(|(idx, party_idx)| (*party_idx, ShareIdx::new(idx + 1)))
            .collect();

        let init_id = if let Some(old_holder) = inputs.old_holder.as_ref() {
            old_holder.key_share_seed.init_id.clone()
        } else if let Some(new_holder) = inputs.new_holder.as_ref() {
            new_holder.init_id.clone()
        } else {
            return Err(InitError(
                "Either old holder or new holder data must be provided".into(),
            ));
        };

        let old_holder = inputs.old_holder.map(|old_holder| {
            let polynomial = Polynomial::random(
                rng,
                &old_holder.key_share_seed.secret(),
                inputs.new_threshold,
            );
            let public_polynomial = polynomial.public();
            OldHolderData {
                polynomial,
                public_polynomial,
                inputs: old_holder,
            }
        });

        let new_holder = inputs
            .new_holder
            .map(|new_holder| NewHolderData { inputs: new_holder });

        Ok(Round1 {
            old_holder,
            new_holder,
            new_share_idxs,
            new_threshold: inputs.new_threshold,
            party_idx,
            num_parties,
            init_id,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1BroadcastMessage {
    public_polynomial: PublicPolynomial,
    old_share_idx: ShareIdx,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1DirectMessage {
    subshare: Scalar,
}

pub struct Round1Payload {
    subshare: Scalar,
    public_polynomial: PublicPolynomial,
    old_share_idx: ShareIdx,
}

impl<P: SchemeParams> Round for Round1<P> {
    type Type = ToResult;
    type Result = KeyResharingResult<P>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);

    fn num_parties(&self) -> usize {
        self.num_parties
    }

    fn party_idx(&self) -> PartyIdx {
        self.party_idx
    }

    const REQUIRES_ECHO: bool = true;
    type BroadcastMessage = Round1BroadcastMessage;
    type DirectMessage = Round1DirectMessage;
    type Payload = Round1Payload;
    type Artifact = ();

    fn message_destinations(&self) -> Vec<PartyIdx> {
        if self.old_holder.is_some() {
            self.new_share_idxs.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }

    fn make_broadcast_message(
        &self,
        _rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        self.old_holder
            .as_ref()
            .map(|old_holder| Round1BroadcastMessage {
                public_polynomial: old_holder.public_polynomial.clone(),
                old_share_idx: old_holder.inputs.key_share_seed.index(),
            })
    }

    fn make_direct_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> (Self::DirectMessage, Self::Artifact) {
        if let Some(old_holder) = self.old_holder.as_ref() {
            let subshare = old_holder
                .polynomial
                .evaluate(&self.new_share_idxs[&destination]);
            (Round1DirectMessage { subshare }, ())
        } else {
            // TODO: this should be prevented by type system
            panic!("This node does not send messages in this round");
        }
    }

    fn verify_message(
        &self,
        from: PartyIdx,
        broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        if let Some(new_holder) = self.new_holder.as_ref() {
            if new_holder
                .inputs
                .old_holders
                .iter()
                .any(|party_idx| party_idx == &from)
            {
                let public_subshare_from_poly = broadcast_msg
                    .public_polynomial
                    .evaluate(&self.new_share_idxs[&self.party_idx()]);
                let public_subshare_from_private = direct_msg.subshare.mul_by_generator();

                // Check that the public polynomial sent in the broadcast corresponds to the secret share
                // sent in the direct message.
                if public_subshare_from_poly != public_subshare_from_private {
                    return Err(ReceiveError::Provable(KeyResharingError::SubshareMismatch));
                }

                return Ok(Round1Payload {
                    subshare: direct_msg.subshare,
                    public_polynomial: broadcast_msg.public_polynomial,
                    old_share_idx: broadcast_msg.old_share_idx,
                });
            }
        }
        Err(ReceiveError::Provable(KeyResharingError::UnexpectedSender))
    }

    fn finalization_requirement() -> FinalizationRequirement {
        FinalizationRequirement::Custom
    }

    fn can_finalize<'a>(
        &self,
        payloads: impl Iterator<Item = &'a PartyIdx>,
        _artifacts: impl Iterator<Item = &'a PartyIdx>,
    ) -> bool {
        if let Some(new_holder) = self.new_holder.as_ref() {
            let set = payloads.cloned().collect::<BTreeSet<_>>();
            let threshold = new_holder.inputs.old_threshold;
            set.len() >= threshold
        } else {
            true
        }
    }

    fn missing_payloads<'a>(
        &self,
        payloads: impl Iterator<Item = &'a PartyIdx>,
        _artifacts: impl Iterator<Item = &'a PartyIdx>,
    ) -> BTreeSet<PartyIdx> {
        if let Some(new_holder) = self.new_holder.as_ref() {
            let set = payloads.cloned().collect::<BTreeSet<_>>();
            new_holder
                .inputs
                .old_holders
                .iter()
                .cloned()
                .filter(|idx| !set.contains(idx))
                .collect()
        } else {
            BTreeSet::new()
        }
    }
}

impl<P: SchemeParams> FinalizableToResult for Round1<P> {
    fn finalize_to_result(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        _artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        // If this party is not a new holder, exit.
        let new_holder = match self.new_holder.as_ref() {
            Some(new_holder) => new_holder,
            None => return Ok(None),
        };

        let share_idx = self.new_share_idxs[&self.party_idx()];

        // Check that the 0-th coefficients of public polynomials (that is, the old shares)
        // add up to the expected verifying key.
        let old_share_idxs = payloads
            .values()
            .map(|payload| payload.old_share_idx)
            .collect::<Vec<_>>();
        let vkey = payloads
            .values()
            .map(|payload| {
                payload.public_polynomial.coeff0()
                    * interpolation_coeff(&old_share_idxs, &payload.old_share_idx)
            })
            .sum();
        if new_holder.inputs.verifying_key != vkey {
            // TODO: this is unattributable.
            // Should we add an enum variant to `FinalizeError`?
            // or take the public shares as an input (assuming the nodes published those previously)
            panic!("Invalid shares");
        }

        // Assemble the new share.
        let subshares = new_holder
            .inputs
            .old_holders
            .iter()
            .map(|party_idx| {
                (
                    payloads[&party_idx].old_share_idx,
                    payloads[&party_idx].subshare,
                )
            })
            .collect::<BTreeMap<_, _>>();
        let secret_share = shamir_join_scalars(subshares.iter());

        // Generate the public shares of all the new holders.
        let public_shares = self
            .new_share_idxs
            .keys()
            .map(|party_idx| {
                let share_idx = self.new_share_idxs[&party_idx];
                let public_subshares = payloads
                    .values()
                    .map(|p| (p.old_share_idx, p.public_polynomial.evaluate(&share_idx)))
                    .collect::<BTreeMap<_, _>>();
                let public_share = shamir_join_points(public_subshares.iter());
                (share_idx, public_share)
            })
            .collect();

        Ok(Some(ThresholdKeyShareSeed {
            index: share_idx,
            threshold: self.new_threshold as u32,
            secret_share,
            public_shares,
            init_id: self.init_id,
            phantom: PhantomData,
        }))
    }
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, RngCore};

    use super::super::threshold::ThresholdKeyShareSeed;
    use super::{KeyResharingContext, NewHolder, OldHolder, Round1};
    use crate::cggmp21::TestParams;
    use crate::rounds::{
        test_utils::{step_result, step_round},
        FirstRound, PartyIdx,
    };

    #[test]
    fn execute_key_reshare() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let num_parties = 4;
        let old_key_shares =
            ThresholdKeyShareSeed::<TestParams>::new_centralized(&mut OsRng, 2, 3, None);
        let old_vkey = old_key_shares[0].verifying_key_as_point();

        let old_holders = vec![
            PartyIdx::from_usize(0),
            PartyIdx::from_usize(1),
            PartyIdx::from_usize(2),
        ];
        let new_holders = vec![
            PartyIdx::from_usize(1),
            PartyIdx::from_usize(2),
            PartyIdx::from_usize(3),
        ];

        let init_id = old_key_shares[0].init_id.clone();

        let party0 = Round1::new(
            &mut OsRng,
            &shared_randomness,
            num_parties,
            PartyIdx::from_usize(0),
            KeyResharingContext {
                old_holder: Some(OldHolder {
                    key_share_seed: old_key_shares[0].clone(),
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
            num_parties,
            PartyIdx::from_usize(1),
            KeyResharingContext {
                old_holder: Some(OldHolder {
                    key_share_seed: old_key_shares[1].clone(),
                }),
                new_holder: Some(NewHolder {
                    verifying_key: old_vkey,
                    init_id: init_id.clone(),
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
            num_parties,
            PartyIdx::from_usize(2),
            KeyResharingContext {
                old_holder: Some(OldHolder {
                    key_share_seed: old_key_shares[2].clone(),
                }),
                new_holder: Some(NewHolder {
                    verifying_key: old_vkey,
                    init_id: init_id.clone(),
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
            num_parties,
            PartyIdx::from_usize(3),
            KeyResharingContext {
                old_holder: None,
                new_holder: Some(NewHolder {
                    verifying_key: old_vkey,
                    init_id: init_id.clone(),
                    old_threshold: 2,
                    old_holders: old_holders.clone(),
                }),
                new_holders: new_holders.clone(),
                new_threshold: 2,
            },
        )
        .unwrap();

        let r1 = vec![party0, party1, party2, party3];

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let shares = step_result(&mut OsRng, r1a).unwrap();

        // Check that the party that is not among the new holders gets None as a result
        assert!(shares[0].is_none());

        // Unwrap the results of the new holders
        let shares: Vec<ThresholdKeyShareSeed<_>> = shares[1..4]
            .iter()
            .cloned()
            .map(|share| share.unwrap())
            .collect::<Vec<_>>();

        // Check that all public information is the same between the shares
        let public_sets = shares
            .iter()
            .map(|s| s.public_shares.clone())
            .collect::<Vec<_>>();
        assert!(public_sets[1..].iter().all(|pk| pk == &public_sets[0]));

        // Check that the public keys correspond to the secret key shares
        for share in shares {
            let public = share.secret_share.mul_by_generator();
            assert_eq!(public, share.public_shares[&share.index()]);
        }
    }
}
