//! Threshold key resharing protocol.
//!
//! Based on T. M. Wong, C. Wang, J. M. Wing "Verifiable Secret Redistribution for Archive Systems"
//! https://www.cs.cmu.edu/~wing/publications/Wong-Winga02.pdf
//! https://doi.org/10.1109/SISW.2002.1183515
//! (Specifically, REDIST protocol).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use crate::curve::{Point, Scalar};
use crate::rounds::{
    BaseRound, BroadcastRound, DirectRound, Finalizable, FinalizableToResult,
    FinalizationRequirement, FinalizeError, FirstRound, InitError, PartyIdx, ProtocolResult,
    ReceiveError, ToResult,
};
use crate::threshold::ThresholdKeyShareSeed;
use crate::tools::sss::{
    interpolation_coeff, shamir_join_points, shamir_join_scalars, Polynomial, PublicPolynomial,
    ShareIdx,
};

#[derive(Debug)]
pub struct KeyResharingResult;

impl ProtocolResult for KeyResharingResult {
    type Success = Option<ThresholdKeyShareSeed>;
    type ProvableError = KeyResharingError;
    type CorrectnessProof = ();
}

#[derive(Debug, Clone)]
pub enum KeyResharingError {
    UnexpectedSender,
    SubshareMismatch,
}

pub struct OldHolder {
    key_share_seed: ThresholdKeyShareSeed,
}

pub struct NewHolder {
    verifying_key: Point,
    old_threshold: usize,
    old_holders: Vec<PartyIdx>,
}

pub struct KeyResharingContext {
    old_holder: Option<OldHolder>,
    new_holder: Option<NewHolder>,
    new_holders: Vec<PartyIdx>,
    new_threshold: usize,
}

struct OldHolderData {
    context: OldHolder,
    polynomial: Polynomial,
    public_polynomial: PublicPolynomial,
}

struct NewHolderData {
    context: NewHolder,
}

pub struct Round1 {
    old_holder: Option<OldHolderData>,
    new_holder: Option<NewHolderData>,
    new_share_idxs: BTreeMap<PartyIdx, ShareIdx>,
    new_threshold: usize,
    num_parties: usize,
    party_idx: PartyIdx,
}

impl FirstRound for Round1 {
    type Context = KeyResharingContext;
    fn new(
        rng: &mut impl CryptoRngCore,
        _shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        context: Self::Context,
    ) -> Result<Self, InitError> {
        // Start new share indices from 1.
        let new_share_idxs = context
            .new_holders
            .iter()
            .enumerate()
            .map(|(idx, party_idx)| (*party_idx, ShareIdx::new(idx + 1)))
            .collect();

        let old_holder = context.old_holder.map(|old_holder| {
            let polynomial = Polynomial::random(
                rng,
                &old_holder.key_share_seed.secret(),
                context.new_threshold,
            );
            let public_polynomial = polynomial.public();
            OldHolderData {
                polynomial,
                public_polynomial,
                context: old_holder,
            }
        });

        let new_holder = context.new_holder.map(|new_holder| NewHolderData {
            context: new_holder,
        });

        Ok(Round1 {
            old_holder,
            new_holder,
            new_share_idxs,
            new_threshold: context.new_threshold,
            party_idx,
            num_parties,
        })
    }
}

impl BaseRound for Round1 {
    type Type = ToResult;
    type Result = KeyResharingResult;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);

    fn num_parties(&self) -> usize {
        self.num_parties
    }

    fn party_idx(&self) -> PartyIdx {
        self.party_idx
    }
}

pub struct Round1DirectPayload {
    subshare: Scalar,
    public_subshare: Point,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1Direct {
    subshare: Scalar,
}

impl DirectRound for Round1 {
    type Message = Round1Direct;
    type Payload = Round1DirectPayload;
    type Artifact = ();

    fn direct_message_destinations(&self) -> Option<Vec<PartyIdx>> {
        if self.old_holder.is_some() {
            Some(self.new_share_idxs.keys().cloned().collect())
        } else {
            None
        }
    }

    fn make_direct_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artifact), String> {
        if let Some(old_holder) = self.old_holder.as_ref() {
            let subshare = old_holder
                .polynomial
                .evaluate(&self.new_share_idxs[&destination]);
            Ok((Round1Direct { subshare }, ()))
        } else {
            Err("This node does not send direct messages in this round".into())
        }
    }

    fn verify_direct_message(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        if let Some(new_holder) = self.new_holder.as_ref() {
            if new_holder
                .context
                .old_holders
                .iter()
                .any(|party_idx| party_idx == &from)
            {
                return Ok(Round1DirectPayload {
                    subshare: msg.subshare,
                    public_subshare: msg.subshare.mul_by_generator(),
                });
            }
        }
        Err(ReceiveError::Provable(KeyResharingError::UnexpectedSender))
    }
}

pub struct Round1BcastPayload {
    public_polynomial: PublicPolynomial,
    public_subshare: Point,
    old_share_idx: ShareIdx,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Round1Bcast {
    public_polynomial: PublicPolynomial,
    old_share_idx: ShareIdx,
}

impl BroadcastRound for Round1 {
    const REQUIRES_CONSENSUS: bool = true;
    type Message = Round1Bcast;
    type Payload = Round1BcastPayload;

    fn broadcast_destinations(&self) -> Option<Vec<PartyIdx>> {
        if self.old_holder.is_some() {
            Some(self.new_share_idxs.keys().cloned().collect())
        } else {
            None
        }
    }

    fn make_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        if let Some(old_holder) = self.old_holder.as_ref() {
            Ok(Round1Bcast {
                public_polynomial: old_holder.public_polynomial.clone(),
                old_share_idx: old_holder.context.key_share_seed.index(),
            })
        } else {
            Err("This node does not send broadcast messages in this round".into())
        }
    }

    fn verify_broadcast(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        if let Some(new_holder) = self.new_holder.as_ref() {
            if new_holder
                .context
                .old_holders
                .iter()
                .any(|party_idx| party_idx == &from)
            {
                let public_subshare = msg
                    .public_polynomial
                    .evaluate(&self.new_share_idxs[&self.party_idx()]);
                return Ok(Round1BcastPayload {
                    public_polynomial: msg.public_polynomial,
                    public_subshare,
                    old_share_idx: msg.old_share_idx,
                });
            }
        }
        Err(ReceiveError::Provable(KeyResharingError::UnexpectedSender))
    }
}

impl Finalizable for Round1 {
    fn requirement() -> FinalizationRequirement {
        FinalizationRequirement::Custom
    }

    fn can_finalize<'a>(
        &self,
        bc_payloads: impl Iterator<Item = &'a PartyIdx>,
        dm_payloads: impl Iterator<Item = &'a PartyIdx>,
        _dm_artifacts: impl Iterator<Item = &'a PartyIdx>,
    ) -> bool {
        if let Some(new_holder) = self.new_holder.as_ref() {
            let bc_set = bc_payloads.cloned().collect::<BTreeSet<_>>();
            let dm_set = dm_payloads.cloned().collect::<BTreeSet<_>>();
            let threshold = new_holder.context.old_threshold;
            bc_set.len() >= threshold && dm_set.len() >= threshold
        } else {
            true
        }
    }

    fn missing_payloads<'a>(
        &self,
        bc_payloads: impl Iterator<Item = &'a PartyIdx>,
        dm_payloads: impl Iterator<Item = &'a PartyIdx>,
        _dm_artifacts: impl Iterator<Item = &'a PartyIdx>,
    ) -> BTreeSet<PartyIdx> {
        if let Some(new_holder) = self.new_holder.as_ref() {
            let bc_set = bc_payloads.cloned().collect::<BTreeSet<_>>();
            let dm_set = dm_payloads.cloned().collect::<BTreeSet<_>>();
            new_holder
                .context
                .old_holders
                .iter()
                .cloned()
                .filter(|idx| !bc_set.contains(idx) || !dm_set.contains(idx))
                .collect()
        } else {
            BTreeSet::new()
        }
    }
}

impl FinalizableToResult for Round1 {
    fn finalize_to_result(
        self,
        _rng: &mut impl CryptoRngCore,
        bc_payloads: BTreeMap<PartyIdx, <Self as BroadcastRound>::Payload>,
        dm_payloads: BTreeMap<PartyIdx, <Self as DirectRound>::Payload>,
        _dm_artifacts: BTreeMap<PartyIdx, <Self as DirectRound>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        // If this party is not a new holder, exit.
        let new_holder = match self.new_holder.as_ref() {
            Some(new_holder) => new_holder,
            None => return Ok(None),
        };

        let share_idx = self.new_share_idxs[&self.party_idx()];

        // Check that the public polynomial sent in the broadcast corresponds to the secret share
        // sent in the direct message.
        for party_idx in new_holder.context.old_holders.iter() {
            if dm_payloads[&party_idx].public_subshare != bc_payloads[&party_idx].public_subshare {
                return Err(FinalizeError::Provable {
                    party: *party_idx,
                    error: KeyResharingError::SubshareMismatch,
                });
            }
        }

        // Check that the 0-th coefficients of public polynomials (that is, the old shares)
        // add up to the expected verifying key.
        let old_share_idxs = bc_payloads
            .values()
            .map(|payload| payload.old_share_idx)
            .collect::<Vec<_>>();
        let vkey = bc_payloads
            .values()
            .map(|payload| {
                payload.public_polynomial.coeff0()
                    * interpolation_coeff(&old_share_idxs, &payload.old_share_idx)
            })
            .sum();
        if new_holder.context.verifying_key != vkey {
            // TODO: this is unattributable.
            // Should we add an enum variant to `FinalizeError`?
            // or take the public shares as an input (assuming the nodes published those previously)
            panic!("Invalid shares");
        }

        // Assemble the new share.
        let subshares = new_holder
            .context
            .old_holders
            .iter()
            .map(|party_idx| {
                (
                    bc_payloads[&party_idx].old_share_idx,
                    dm_payloads[&party_idx].subshare,
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
                let public_subshares = bc_payloads
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
        }))
    }
}

#[cfg(test)]
mod tests {
    use rand_core::{OsRng, RngCore};

    use super::super::threshold::ThresholdKeyShareSeed;
    use super::{KeyResharingContext, NewHolder, OldHolder, Round1};
    use crate::rounds::{
        test_utils::{step_result, step_round},
        FirstRound, PartyIdx,
    };

    #[test]
    fn execute_key_reshare() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let num_parties = 4;
        let old_key_shares = ThresholdKeyShareSeed::new_centralized(&mut OsRng, 2, 3, None);
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
        let shares: Vec<ThresholdKeyShareSeed> = shares[1..4]
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
