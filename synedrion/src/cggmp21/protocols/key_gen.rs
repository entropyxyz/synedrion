//! Merged KeyInit and KeyRefresh protocols, to generate a full key share in one go.
//! Since both take three rounds and are independent, we can execute them in parallel.

use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;

use super::super::{AuxInfo, KeyShare, SchemeParams};
use super::key_init::{self, KeyInitResult};
use super::key_refresh::{self, KeyRefreshResult};
use crate::rounds::{
    no_direct_messages, wrap_finalize_error, CorrectnessProofWrapper, EvidenceRequiresMessages,
    FinalizableToNextRound, FinalizableToResult, FinalizeError, FirstRound, InitError, PartyId,
    ProtocolResult, Round, ToNextRound, ToResult,
};

/// Possible results of the merged KeyGen and KeyRefresh protocols.
#[derive(Debug)]
pub struct KeyGenResult<P: SchemeParams, I>(PhantomData<P>, PhantomData<I>);

impl<P: SchemeParams, I: PartyId> ProtocolResult<I> for KeyGenResult<P, I> {
    type Success = (KeyShare<P, I>, AuxInfo<P, I>);
    type ProvableError = KeyGenError<P, I>;
    type CorrectnessProof = KeyGenProof<P, I>;
}

/// Possible verifiable errors of the merged KeyGen and KeyRefresh protocols.
#[derive(Debug, Clone)]
pub enum KeyGenError<P: SchemeParams, I: PartyId> {
    /// An error in the KeyGen part of the protocol.
    KeyInit(<KeyInitResult<P, I> as ProtocolResult<I>>::ProvableError),
    /// An error in the KeyRefresh part of the protocol.
    KeyRefresh(<KeyRefreshResult<P, I> as ProtocolResult<I>>::ProvableError),
}

impl<P: SchemeParams, I: PartyId> EvidenceRequiresMessages<I> for KeyGenError<P, I> {}

/// A proof of a node's correct behavior for the merged KeyGen and KeyRefresh protocols.
#[derive(Debug)]
pub enum KeyGenProof<P: SchemeParams, I: PartyId> {
    /// A proof for the KeyGen part of the protocol.
    KeyInit(<KeyInitResult<P, I> as ProtocolResult<I>>::CorrectnessProof),
    /// A proof for the KeyRefresh part of the protocol.
    KeyRefresh(<KeyRefreshResult<P, I> as ProtocolResult<I>>::CorrectnessProof),
}

impl<P: SchemeParams, I: PartyId> CorrectnessProofWrapper<I, KeyInitResult<P, I>>
    for KeyGenResult<P, I>
{
    fn wrap_proof(
        proof: <KeyInitResult<P, I> as ProtocolResult<I>>::CorrectnessProof,
    ) -> Self::CorrectnessProof {
        KeyGenProof::KeyInit(proof)
    }
}

impl<P: SchemeParams, I: PartyId> CorrectnessProofWrapper<I, KeyRefreshResult<P, I>>
    for KeyGenResult<P, I>
{
    fn wrap_proof(
        proof: <KeyRefreshResult<P, I> as ProtocolResult<I>>::CorrectnessProof,
    ) -> Self::CorrectnessProof {
        KeyGenProof::KeyRefresh(proof)
    }
}

pub(crate) struct Round1<P: SchemeParams, I> {
    key_init_round: key_init::Round1<P, I>,
    key_refresh_round: key_refresh::Round1<P, I>,
}

impl<P: SchemeParams, I: PartyId> FirstRound<I> for Round1<P, I> {
    type Inputs = ();
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        other_ids: BTreeSet<I>,
        my_id: I,
        _inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        let key_init_round =
            key_init::Round1::new(rng, shared_randomness, other_ids.clone(), my_id.clone(), ())?;
        let key_refresh_round =
            key_refresh::Round1::new(rng, shared_randomness, other_ids, my_id, ())?;
        Ok(Self {
            key_init_round,
            key_refresh_round,
        })
    }
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round1<P, I> {
    type Type = ToNextRound;
    type Result = KeyGenResult<P, I>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);

    fn other_ids(&self) -> &BTreeSet<I> {
        self.key_init_round.other_ids()
    }

    fn my_id(&self) -> &I {
        self.key_init_round.my_id()
    }

    const REQUIRES_ECHO: bool = <key_init::Round1<P, I> as Round<I>>::REQUIRES_ECHO
        || <key_refresh::Round1<P, I> as Round<I>>::REQUIRES_ECHO;
    type BroadcastMessage = (
        <key_init::Round1<P, I> as Round<I>>::BroadcastMessage,
        <key_refresh::Round1<P, I> as Round<I>>::BroadcastMessage,
    );
    type DirectMessage = ();
    type Payload = (
        <key_init::Round1<P, I> as Round<I>>::Payload,
        <key_refresh::Round1<P, I> as Round<I>>::Payload,
    );
    type Artifact = ();

    fn make_broadcast_message(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        // Can unwrap here since both protocols always send out broadcasts.
        let key_init_message = self.key_init_round.make_broadcast_message(rng).unwrap();
        let key_refresh_message = self.key_refresh_round.make_broadcast_message(rng).unwrap();

        Some((key_init_message, key_refresh_message))
    }

    no_direct_messages!(I);

    fn verify_message(
        &self,
        rng: &mut impl CryptoRngCore,
        from: &I,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult<I>>::ProvableError> {
        let (key_init_message, key_refresh_message) = broadcast_msg;
        let key_init_payload = self
            .key_init_round
            .verify_message(rng, from, key_init_message, ())
            .map_err(KeyGenError::KeyInit)?;
        let key_refresh_payload = self
            .key_refresh_round
            .verify_message(rng, from, key_refresh_message, ())
            .map_err(KeyGenError::KeyRefresh)?;
        Ok((key_init_payload, key_refresh_payload))
    }
}

impl<P: SchemeParams, I: PartyId> FinalizableToNextRound<I> for Round1<P, I> {
    type NextRound = Round2<P, I>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        _artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<I, Self::Result>> {
        let (key_init_payloads, key_refresh_payloads) = payloads
            .into_iter()
            .map(|(id, (init_payload, refresh_payload))| {
                ((id.clone(), init_payload), (id, refresh_payload))
            })
            .unzip();

        let key_init_round = self
            .key_init_round
            .finalize_to_next_round(rng, key_init_payloads, BTreeMap::new())
            .map_err(wrap_finalize_error)?;
        let key_refresh_round = self
            .key_refresh_round
            .finalize_to_next_round(rng, key_refresh_payloads, BTreeMap::new())
            .map_err(wrap_finalize_error)?;
        Ok(Round2 {
            key_init_round,
            key_refresh_round,
        })
    }
}

pub(crate) struct Round2<P: SchemeParams, I> {
    key_init_round: key_init::Round2<P, I>,
    key_refresh_round: key_refresh::Round2<P, I>,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round2<P, I> {
    type Type = ToNextRound;
    type Result = KeyGenResult<P, I>;
    const ROUND_NUM: u8 = 2;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);

    fn other_ids(&self) -> &BTreeSet<I> {
        self.key_init_round.other_ids()
    }

    fn my_id(&self) -> &I {
        self.key_init_round.my_id()
    }

    const REQUIRES_ECHO: bool = <key_init::Round1<P, I> as Round<I>>::REQUIRES_ECHO
        || <key_refresh::Round1<P, I> as Round<I>>::REQUIRES_ECHO;
    type BroadcastMessage = (
        <key_init::Round2<P, I> as Round<I>>::BroadcastMessage,
        <key_refresh::Round2<P, I> as Round<I>>::BroadcastMessage,
    );
    type DirectMessage = ();
    type Payload = (
        <key_init::Round2<P, I> as Round<I>>::Payload,
        <key_refresh::Round2<P, I> as Round<I>>::Payload,
    );
    type Artifact = ();

    fn make_broadcast_message(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        // Can unwrap here since both protocols always send out broadcasts.
        let key_init_message = self.key_init_round.make_broadcast_message(rng).unwrap();
        let key_refresh_message = self.key_refresh_round.make_broadcast_message(rng).unwrap();

        Some((key_init_message, key_refresh_message))
    }

    no_direct_messages!(I);

    fn verify_message(
        &self,
        rng: &mut impl CryptoRngCore,
        from: &I,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult<I>>::ProvableError> {
        let (key_init_message, key_refresh_message) = broadcast_msg;
        let key_init_payload = self
            .key_init_round
            .verify_message(rng, from, key_init_message, ())
            .map_err(KeyGenError::KeyInit)?;
        let key_refresh_payload = self
            .key_refresh_round
            .verify_message(rng, from, key_refresh_message, ())
            .map_err(KeyGenError::KeyRefresh)?;
        Ok((key_init_payload, key_refresh_payload))
    }
}

impl<P: SchemeParams, I: PartyId> FinalizableToNextRound<I> for Round2<P, I> {
    type NextRound = Round3<P, I>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        _artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<I, Self::Result>> {
        let (key_init_payloads, key_refresh_payloads) = payloads
            .into_iter()
            .map(|(id, (init_payload, refresh_payload))| {
                ((id.clone(), init_payload), (id, refresh_payload))
            })
            .unzip();

        let key_init_round = self
            .key_init_round
            .finalize_to_next_round(rng, key_init_payloads, BTreeMap::new())
            .map_err(wrap_finalize_error)?;
        let key_refresh_round = self
            .key_refresh_round
            .finalize_to_next_round(rng, key_refresh_payloads, BTreeMap::new())
            .map_err(wrap_finalize_error)?;
        Ok(Round3 {
            key_init_round,
            key_refresh_round,
        })
    }
}

pub(crate) struct Round3<P: SchemeParams, I> {
    key_init_round: key_init::Round3<P, I>,
    key_refresh_round: key_refresh::Round3<P, I>,
}

impl<P: SchemeParams, I: PartyId> Round<I> for Round3<P, I> {
    type Type = ToResult;
    type Result = KeyGenResult<P, I>;
    const ROUND_NUM: u8 = 3;
    const NEXT_ROUND_NUM: Option<u8> = None;

    fn other_ids(&self) -> &BTreeSet<I> {
        self.key_init_round.other_ids()
    }

    fn my_id(&self) -> &I {
        self.key_init_round.my_id()
    }

    const REQUIRES_ECHO: bool = <key_init::Round3<P, I> as Round<I>>::REQUIRES_ECHO
        || <key_refresh::Round3<P, I> as Round<I>>::REQUIRES_ECHO;
    type BroadcastMessage = <key_init::Round3<P, I> as Round<I>>::BroadcastMessage;
    type DirectMessage = <key_refresh::Round3<P, I> as Round<I>>::DirectMessage;
    type Payload = (
        <key_init::Round3<P, I> as Round<I>>::Payload,
        <key_refresh::Round3<P, I> as Round<I>>::Payload,
    );
    type Artifact = <key_refresh::Round3<P, I> as Round<I>>::Artifact;

    fn make_broadcast_message(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        self.key_init_round.make_broadcast_message(rng)
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &I,
    ) -> (Self::DirectMessage, Self::Artifact) {
        self.key_refresh_round.make_direct_message(rng, destination)
    }

    fn verify_message(
        &self,
        rng: &mut impl CryptoRngCore,
        from: &I,
        broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult<I>>::ProvableError> {
        #[allow(clippy::let_unit_value)]
        let key_init_payload = self
            .key_init_round
            .verify_message(rng, from, broadcast_msg, ())
            .map_err(KeyGenError::KeyInit)?;
        let key_refresh_payload = self
            .key_refresh_round
            .verify_message(rng, from, (), direct_msg)
            .map_err(KeyGenError::KeyRefresh)?;
        Ok((key_init_payload, key_refresh_payload))
    }
}

impl<P: SchemeParams, I: PartyId> FinalizableToResult<I> for Round3<P, I> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
        artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult<I>>::Success, FinalizeError<I, Self::Result>> {
        let (key_init_payloads, key_refresh_payloads) = payloads
            .into_iter()
            .map(|(id, (init_payload, refresh_payload))| {
                ((id.clone(), init_payload), (id, refresh_payload))
            })
            .unzip();

        let key_share = self
            .key_init_round
            .finalize_to_result(rng, key_init_payloads, BTreeMap::new())
            .map_err(wrap_finalize_error)?;
        let (key_share_change, aux_info) = self
            .key_refresh_round
            .finalize_to_result(rng, key_refresh_payloads, artifacts)
            .map_err(wrap_finalize_error)?;
        Ok((key_share.update(key_share_change), aux_info))
    }
}
