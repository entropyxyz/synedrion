//! Merged KeyInit and KeyRefresh protocols, to generate a full key share in one go.
//! Since both take three rounds and are independent, we can execute them in parallel.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::key_init::{self, KeyInitResult};
use super::key_refresh::{self, KeyRefreshResult};
use crate::cggmp21::SchemeParams;
use crate::common::KeyShare;
use crate::rounds::{
    wrap_finalize_error, wrap_receive_error, BaseRound, BroadcastRound, DirectRound, Finalizable,
    FinalizableToNextRound, FinalizableToResult, FinalizationRequirement, FinalizeError,
    FirstRound, InitError, PartyIdx, ProtocolResult, ReceiveError, ResultWrapper, ToNextRound,
    ToResult,
};

/// Possible results of the merged KeyGen and KeyRefresh protocols.
#[derive(Debug, Clone, Copy)]
pub struct KeyGenResult<P: SchemeParams>(PhantomData<P>);

impl<P: SchemeParams> ProtocolResult for KeyGenResult<P> {
    type Success = KeyShare<P>;
    type ProvableError = KeyGenError<P>;
    type CorrectnessProof = KeyGenProof<P>;
}

/// Possible verifiable errors of the merged KeyGen and KeyRefresh protocols.
#[derive(Debug, Clone)]
pub enum KeyGenError<P: SchemeParams> {
    /// An error in the KeyGen part of the protocol.
    KeyInit(<KeyInitResult as ProtocolResult>::ProvableError),
    /// An error in the KeyRefresh part of the protocol.
    KeyRefresh(<KeyRefreshResult<P> as ProtocolResult>::ProvableError),
}

/// A proof of a node's correct behavior for the merged KeyGen and KeyRefresh protocols.
#[derive(Debug, Clone)]
pub enum KeyGenProof<P: SchemeParams> {
    /// A proof for the KeyGen part of the protocol.
    KeyInit(<KeyInitResult as ProtocolResult>::CorrectnessProof),
    /// A proof for the KeyRefresh part of the protocol.
    KeyRefresh(<KeyRefreshResult<P> as ProtocolResult>::CorrectnessProof),
}

impl<P: SchemeParams> ResultWrapper<KeyInitResult> for KeyGenResult<P> {
    fn wrap_error(error: <KeyInitResult as ProtocolResult>::ProvableError) -> Self::ProvableError {
        KeyGenError::KeyInit(error)
    }
    fn wrap_proof(
        proof: <KeyInitResult as ProtocolResult>::CorrectnessProof,
    ) -> Self::CorrectnessProof {
        KeyGenProof::KeyInit(proof)
    }
}

impl<P: SchemeParams> ResultWrapper<KeyRefreshResult<P>> for KeyGenResult<P> {
    fn wrap_error(
        error: <KeyRefreshResult<P> as ProtocolResult>::ProvableError,
    ) -> Self::ProvableError {
        KeyGenError::KeyRefresh(error)
    }
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "<key_init::Round1<P> as BroadcastRound>::Message: Serialize,
    <key_refresh::Round1<P> as BroadcastRound>::Message: Serialize"
))]
#[serde(bound(
    deserialize = "<key_init::Round1<P> as BroadcastRound>::Message: for<'x> Deserialize<'x>,
    <key_refresh::Round1<P> as BroadcastRound>::Message: for<'x> Deserialize<'x>"
))]
pub struct Round1Message<P: SchemeParams> {
    key_init_message: <key_init::Round1<P> as BroadcastRound>::Message,
    key_refresh_message: <key_refresh::Round1<P> as BroadcastRound>::Message,
}

impl<P: SchemeParams> BaseRound for Round1<P> {
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
}

impl<P: SchemeParams> BroadcastRound for Round1<P> {
    const REQUIRES_CONSENSUS: bool = <key_init::Round1<P> as BroadcastRound>::REQUIRES_CONSENSUS
        || <key_refresh::Round1<P> as BroadcastRound>::REQUIRES_CONSENSUS;
    type Message = Round1Message<P>;
    type Payload = (
        <key_init::Round1<P> as BroadcastRound>::Payload,
        <key_refresh::Round1<P> as BroadcastRound>::Payload,
    );
    fn broadcast_destinations(&self) -> Option<Vec<PartyIdx>> {
        let key_init_dest = self.key_init_round.broadcast_destinations();
        let key_refresh_dest = self.key_refresh_round.broadcast_destinations();
        assert!(key_init_dest == key_refresh_dest);
        key_init_dest
    }
    fn make_broadcast(&self, rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        let key_init_message = self.key_init_round.make_broadcast(rng)?;
        let key_refresh_message = self.key_refresh_round.make_broadcast(rng)?;
        Ok(Round1Message {
            key_init_message,
            key_refresh_message,
        })
    }
    fn verify_broadcast(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        let key_init_payload = self
            .key_init_round
            .verify_broadcast(from, msg.key_init_message)
            .map_err(wrap_receive_error)?;
        let key_refresh_payload = self
            .key_refresh_round
            .verify_broadcast(from, msg.key_refresh_message)
            .map_err(wrap_receive_error)?;
        Ok((key_init_payload, key_refresh_payload))
    }
}

impl<P: SchemeParams> DirectRound for Round1<P> {
    type Message = ();
    type Payload = ();
    type Artifact = ();
}

impl<P: SchemeParams> Finalizable for Round1<P> {
    fn requirement() -> FinalizationRequirement {
        FinalizationRequirement::AllBroadcasts
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round1<P> {
    type NextRound = Round2<P>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: BTreeMap<PartyIdx, <Self as BroadcastRound>::Payload>,
        _dm_payloads: BTreeMap<PartyIdx, <Self as DirectRound>::Payload>,
        _dm_artifacts: BTreeMap<PartyIdx, <Self as DirectRound>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let (key_init_bc_payloads, key_refresh_bc_payloads) = bc_payloads
            .into_iter()
            .map(|(idx, (init_payload, refresh_payload))| {
                ((idx, init_payload), (idx, refresh_payload))
            })
            .unzip();

        let key_init_round = self
            .key_init_round
            .finalize_to_next_round(rng, key_init_bc_payloads, BTreeMap::new(), BTreeMap::new())
            .map_err(wrap_finalize_error)?;
        let key_refresh_round = self
            .key_refresh_round
            .finalize_to_next_round(
                rng,
                key_refresh_bc_payloads,
                BTreeMap::new(),
                BTreeMap::new(),
            )
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "<key_init::Round2<P> as BroadcastRound>::Message: Serialize,
    <key_refresh::Round2<P> as BroadcastRound>::Message: Serialize"
))]
#[serde(bound(
    deserialize = "<key_init::Round2<P> as BroadcastRound>::Message: for<'x> Deserialize<'x>,
    <key_refresh::Round2<P> as BroadcastRound>::Message: for<'x> Deserialize<'x>"
))]
pub struct Round2Message<P: SchemeParams> {
    key_init_message: <key_init::Round2<P> as BroadcastRound>::Message,
    key_refresh_message: <key_refresh::Round2<P> as BroadcastRound>::Message,
}

impl<P: SchemeParams> BaseRound for Round2<P> {
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
}

impl<P: SchemeParams> BroadcastRound for Round2<P> {
    const REQUIRES_CONSENSUS: bool = <key_init::Round1<P> as BroadcastRound>::REQUIRES_CONSENSUS
        || <key_refresh::Round1<P> as BroadcastRound>::REQUIRES_CONSENSUS;
    type Message = Round2Message<P>;
    type Payload = (
        <key_init::Round2<P> as BroadcastRound>::Payload,
        <key_refresh::Round2<P> as BroadcastRound>::Payload,
    );

    fn broadcast_destinations(&self) -> Option<Vec<PartyIdx>> {
        let key_init_dest = self.key_init_round.broadcast_destinations();
        let key_refresh_dest = self.key_refresh_round.broadcast_destinations();
        assert!(key_init_dest == key_refresh_dest);
        key_init_dest
    }
    fn make_broadcast(&self, rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        let key_init_message = self.key_init_round.make_broadcast(rng)?;
        let key_refresh_message = self.key_refresh_round.make_broadcast(rng)?;
        Ok(Round2Message {
            key_init_message,
            key_refresh_message,
        })
    }

    fn verify_broadcast(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        let key_init_payload = self
            .key_init_round
            .verify_broadcast(from, msg.key_init_message)
            .map_err(wrap_receive_error)?;
        let key_refresh_payload = self
            .key_refresh_round
            .verify_broadcast(from, msg.key_refresh_message)
            .map_err(wrap_receive_error)?;
        Ok((key_init_payload, key_refresh_payload))
    }
}

impl<P: SchemeParams> DirectRound for Round2<P> {
    type Message = ();
    type Payload = ();
    type Artifact = ();
}

impl<P: SchemeParams> Finalizable for Round2<P> {
    fn requirement() -> FinalizationRequirement {
        FinalizationRequirement::AllBroadcasts
    }
}

impl<P: SchemeParams> FinalizableToNextRound for Round2<P> {
    type NextRound = Round3<P>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: BTreeMap<PartyIdx, <Self as BroadcastRound>::Payload>,
        _dm_payloads: BTreeMap<PartyIdx, <Self as DirectRound>::Payload>,
        _dm_artifacts: BTreeMap<PartyIdx, <Self as DirectRound>::Artifact>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        let (key_init_bc_payloads, key_refresh_bc_payloads) = bc_payloads
            .into_iter()
            .map(|(idx, (init_payload, refresh_payload))| {
                ((idx, init_payload), (idx, refresh_payload))
            })
            .unzip();

        let key_init_round = self
            .key_init_round
            .finalize_to_next_round(rng, key_init_bc_payloads, BTreeMap::new(), BTreeMap::new())
            .map_err(wrap_finalize_error)?;
        let key_refresh_round = self
            .key_refresh_round
            .finalize_to_next_round(
                rng,
                key_refresh_bc_payloads,
                BTreeMap::new(),
                BTreeMap::new(),
            )
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

impl<P: SchemeParams> BaseRound for Round3<P> {
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
}

impl<P: SchemeParams> BroadcastRound for Round3<P> {
    const REQUIRES_CONSENSUS: bool = key_init::Round3::<P>::REQUIRES_CONSENSUS;
    type Message = <key_init::Round3<P> as BroadcastRound>::Message;
    type Payload = <key_init::Round3<P> as BroadcastRound>::Payload;

    fn broadcast_destinations(&self) -> Option<Vec<PartyIdx>> {
        self.key_init_round.broadcast_destinations()
    }
    fn make_broadcast(&self, rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        self.key_init_round.make_broadcast(rng)
    }

    fn verify_broadcast(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        self.key_init_round
            .verify_broadcast(from, msg)
            .map_err(wrap_receive_error)
    }
}

impl<P: SchemeParams> DirectRound for Round3<P> {
    type Artifact = <key_refresh::Round3<P> as DirectRound>::Artifact;
    type Message = <key_refresh::Round3<P> as DirectRound>::Message;
    type Payload = <key_refresh::Round3<P> as DirectRound>::Payload;

    fn direct_message_destinations(&self) -> Option<Vec<PartyIdx>> {
        self.key_refresh_round.direct_message_destinations()
    }
    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artifact), String> {
        self.key_refresh_round.make_direct_message(rng, destination)
    }

    fn verify_direct_message(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        self.key_refresh_round
            .verify_direct_message(from, msg)
            .map_err(wrap_receive_error)
    }
}

impl<P: SchemeParams> Finalizable for Round3<P> {
    fn requirement() -> FinalizationRequirement {
        FinalizationRequirement::AllBroadcastsAndDms
    }
}

impl<P: SchemeParams> FinalizableToResult for Round3<P> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: BTreeMap<PartyIdx, <Self as BroadcastRound>::Payload>,
        dm_payloads: BTreeMap<PartyIdx, <Self as DirectRound>::Payload>,
        dm_artifacts: BTreeMap<PartyIdx, <Self as DirectRound>::Artifact>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let keyshare_seed = self
            .key_init_round
            .finalize_to_result(rng, bc_payloads, BTreeMap::new(), BTreeMap::new())
            .map_err(wrap_finalize_error)?;
        let keyshare_change = self
            .key_refresh_round
            .finalize_to_result(rng, BTreeMap::new(), dm_payloads, dm_artifacts)
            .map_err(wrap_finalize_error)?;
        Ok(KeyShare::new(keyshare_seed, keyshare_change))
    }
}
