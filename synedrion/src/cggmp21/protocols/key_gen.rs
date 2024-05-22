//! Merged KeyInit and KeyRefresh protocols, to generate a full key share in one go.
//! Since both take three rounds and are independent, we can execute them in parallel.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;

use super::super::{AuxInfo, KeyShare, SchemeParams};
use super::key_init::{self, KeyInitResult};
use super::key_refresh::{self, KeyRefreshResult};
use crate::rounds::{
    no_direct_messages, wrap_finalize_error, CorrectnessProofWrapper, FinalizableToNextRound,
    FinalizableToResult, FinalizeError, FirstRound, InitError, PartyIdx, ProtocolResult, Round,
    ToNextRound, ToResult,
};

/// Possible results of the merged KeyGen and KeyRefresh protocols.
#[derive(Debug, Clone, Copy)]
pub struct KeyGenResult<P: SchemeParams>(PhantomData<P>);

impl<P: SchemeParams> ProtocolResult for KeyGenResult<P> {
    type Success = (KeyShare<P>, AuxInfo<P>);
    type ProvableError = KeyGenError<P>;
    type CorrectnessProof = KeyGenProof<P>;
}

/// Possible verifiable errors of the merged KeyGen and KeyRefresh protocols.
#[derive(Debug, Clone)]
pub enum KeyGenError<P: SchemeParams> {
    /// An error in the KeyGen part of the protocol.
    KeyInit(<KeyInitResult<P> as ProtocolResult>::ProvableError),
    /// An error in the KeyRefresh part of the protocol.
    KeyRefresh(<KeyRefreshResult<P> as ProtocolResult>::ProvableError),
}

/// A proof of a node's correct behavior for the merged KeyGen and KeyRefresh protocols.
#[derive(Debug, Clone)]
pub enum KeyGenProof<P: SchemeParams> {
    /// A proof for the KeyGen part of the protocol.
    KeyInit(<KeyInitResult<P> as ProtocolResult>::CorrectnessProof),
    /// A proof for the KeyRefresh part of the protocol.
    KeyRefresh(<KeyRefreshResult<P> as ProtocolResult>::CorrectnessProof),
}

impl<P: SchemeParams> CorrectnessProofWrapper<KeyInitResult<P>> for KeyGenResult<P> {
    fn wrap_proof(
        proof: <KeyInitResult<P> as ProtocolResult>::CorrectnessProof,
    ) -> Self::CorrectnessProof {
        KeyGenProof::KeyInit(proof)
    }
}

impl<P: SchemeParams> CorrectnessProofWrapper<KeyRefreshResult<P>> for KeyGenResult<P> {
    fn wrap_proof(
        proof: <KeyRefreshResult<P> as ProtocolResult>::CorrectnessProof,
    ) -> Self::CorrectnessProof {
        KeyGenProof::KeyRefresh(proof)
    }
}

pub(crate) struct Round1<P: SchemeParams> {
    key_init_round: key_init::Round1<P>,
    key_refresh_round: key_refresh::Round1<P>,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Inputs = ();
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        _inputs: Self::Inputs,
    ) -> Result<Self, InitError> {
        let key_init_round =
            key_init::Round1::new(rng, shared_randomness, num_parties, party_idx, ())?;
        let key_refresh_round =
            key_refresh::Round1::new(rng, shared_randomness, num_parties, party_idx, ())?;
        Ok(Self {
            key_init_round,
            key_refresh_round,
        })
    }
}

impl<P: SchemeParams> Round for Round1<P> {
    type Type = ToNextRound;
    type Result = KeyGenResult<P>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);

    fn num_parties(&self) -> usize {
        self.key_init_round.num_parties()
    }

    fn party_idx(&self) -> PartyIdx {
        self.key_init_round.party_idx()
    }

    const REQUIRES_ECHO: bool = <key_init::Round1<P> as Round>::REQUIRES_ECHO
        || <key_refresh::Round1<P> as Round>::REQUIRES_ECHO;
    type BroadcastMessage = (
        <key_init::Round1<P> as Round>::BroadcastMessage,
        <key_refresh::Round1<P> as Round>::BroadcastMessage,
    );
    type DirectMessage = ();
    type Payload = (
        <key_init::Round1<P> as Round>::Payload,
        <key_refresh::Round1<P> as Round>::Payload,
    );
    type Artifact = ();

    fn message_destinations(&self) -> Vec<PartyIdx> {
        let key_init_dest = self.key_init_round.message_destinations();
        let key_refresh_dest = self.key_refresh_round.message_destinations();
        assert!(key_init_dest == key_refresh_dest);
        key_init_dest
    }

    fn make_broadcast_message(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        // Can unwrap here since both protocols always send out broadcasts.
        let key_init_message = self.key_init_round.make_broadcast_message(rng).unwrap();
        let key_refresh_message = self.key_refresh_round.make_broadcast_message(rng).unwrap();

        Some((key_init_message, key_refresh_message))
    }

    no_direct_messages!();

    fn verify_message(
        &self,
        from: PartyIdx,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        let (key_init_message, key_refresh_message) = broadcast_msg;
        let key_init_payload = self
            .key_init_round
            .verify_message(from, key_init_message, ())
            .map_err(KeyGenError::KeyInit)?;
        let key_refresh_payload = self
            .key_refresh_round
            .verify_message(from, key_refresh_message, ())
            .map_err(KeyGenError::KeyRefresh)?;
        Ok((key_init_payload, key_refresh_payload))
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round1<P> {
    type NextRound = Round2<P>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        _artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let (key_init_payloads, key_refresh_payloads) = payloads
            .into_iter()
            .map(|(idx, (init_payload, refresh_payload))| {
                ((idx, init_payload), (idx, refresh_payload))
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

pub(crate) struct Round2<P: SchemeParams> {
    key_init_round: key_init::Round2<P>,
    key_refresh_round: key_refresh::Round2<P>,
}

impl<P: SchemeParams> Round for Round2<P> {
    type Type = ToNextRound;
    type Result = KeyGenResult<P>;
    const ROUND_NUM: u8 = 2;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);

    fn num_parties(&self) -> usize {
        self.key_init_round.num_parties()
    }

    fn party_idx(&self) -> PartyIdx {
        self.key_init_round.party_idx()
    }

    const REQUIRES_ECHO: bool = <key_init::Round1<P> as Round>::REQUIRES_ECHO
        || <key_refresh::Round1<P> as Round>::REQUIRES_ECHO;
    type BroadcastMessage = (
        <key_init::Round2<P> as Round>::BroadcastMessage,
        <key_refresh::Round2<P> as Round>::BroadcastMessage,
    );
    type DirectMessage = ();
    type Payload = (
        <key_init::Round2<P> as Round>::Payload,
        <key_refresh::Round2<P> as Round>::Payload,
    );
    type Artifact = ();

    fn message_destinations(&self) -> Vec<PartyIdx> {
        let key_init_dest = self.key_init_round.message_destinations();
        let key_refresh_dest = self.key_refresh_round.message_destinations();
        assert!(key_init_dest == key_refresh_dest);
        key_init_dest
    }

    fn make_broadcast_message(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        // Can unwrap here since both protocols always send out broadcasts.
        let key_init_message = self.key_init_round.make_broadcast_message(rng).unwrap();
        let key_refresh_message = self.key_refresh_round.make_broadcast_message(rng).unwrap();

        Some((key_init_message, key_refresh_message))
    }

    no_direct_messages!();

    fn verify_message(
        &self,
        from: PartyIdx,
        broadcast_msg: Self::BroadcastMessage,
        _direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        let (key_init_message, key_refresh_message) = broadcast_msg;
        let key_init_payload = self
            .key_init_round
            .verify_message(from, key_init_message, ())
            .map_err(KeyGenError::KeyInit)?;
        let key_refresh_payload = self
            .key_refresh_round
            .verify_message(from, key_refresh_message, ())
            .map_err(KeyGenError::KeyRefresh)?;
        Ok((key_init_payload, key_refresh_payload))
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round2<P> {
    type NextRound = Round3<P>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        _artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let (key_init_payloads, key_refresh_payloads) = payloads
            .into_iter()
            .map(|(idx, (init_payload, refresh_payload))| {
                ((idx, init_payload), (idx, refresh_payload))
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

pub(crate) struct Round3<P: SchemeParams> {
    key_init_round: key_init::Round3<P>,
    key_refresh_round: key_refresh::Round3<P>,
}

impl<P: SchemeParams> Round for Round3<P> {
    type Type = ToResult;
    type Result = KeyGenResult<P>;
    const ROUND_NUM: u8 = 3;
    const NEXT_ROUND_NUM: Option<u8> = None;

    fn num_parties(&self) -> usize {
        self.key_init_round.num_parties()
    }

    fn party_idx(&self) -> PartyIdx {
        self.key_init_round.party_idx()
    }

    const REQUIRES_ECHO: bool = <key_init::Round3<P> as Round>::REQUIRES_ECHO
        || <key_refresh::Round3<P> as Round>::REQUIRES_ECHO;
    type BroadcastMessage = <key_init::Round3<P> as Round>::BroadcastMessage;
    type DirectMessage = <key_refresh::Round3<P> as Round>::DirectMessage;
    type Payload = (
        <key_init::Round3<P> as Round>::Payload,
        <key_refresh::Round3<P> as Round>::Payload,
    );
    type Artifact = <key_refresh::Round3<P> as Round>::Artifact;

    fn message_destinations(&self) -> Vec<PartyIdx> {
        let key_init_dest = self.key_init_round.message_destinations();
        let key_refresh_dest = self.key_refresh_round.message_destinations();
        assert!(key_init_dest == key_refresh_dest);
        key_init_dest
    }

    fn make_broadcast_message(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Option<Self::BroadcastMessage> {
        self.key_init_round.make_broadcast_message(rng)
    }

    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> (Self::DirectMessage, Self::Artifact) {
        self.key_refresh_round.make_direct_message(rng, destination)
    }

    fn verify_message(
        &self,
        from: PartyIdx,
        broadcast_msg: Self::BroadcastMessage,
        direct_msg: Self::DirectMessage,
    ) -> Result<Self::Payload, <Self::Result as ProtocolResult>::ProvableError> {
        #[allow(clippy::let_unit_value)]
        let key_init_payload = self
            .key_init_round
            .verify_message(from, broadcast_msg, ())
            .map_err(KeyGenError::KeyInit)?;
        let key_refresh_payload = self
            .key_refresh_round
            .verify_message(from, (), direct_msg)
            .map_err(KeyGenError::KeyRefresh)?;
        Ok((key_init_payload, key_refresh_payload))
    }
}

impl<P: SchemeParams> FinalizableToResult for Round3<P> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<PartyIdx, <Self as Round>::Payload>,
        artifacts: BTreeMap<PartyIdx, <Self as Round>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let (key_init_payloads, key_refresh_payloads) = payloads
            .into_iter()
            .map(|(idx, (init_payload, refresh_payload))| {
                ((idx, init_payload), (idx, refresh_payload))
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
