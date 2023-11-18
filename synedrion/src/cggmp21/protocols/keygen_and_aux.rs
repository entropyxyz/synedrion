use alloc::string::String;
use core::marker::PhantomData;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::auxiliary::{self, KeyRefreshResult};
use super::common::{KeyShare, PartyIdx};
use super::generic::{
    BaseRound, BroadcastRound, DirectRound, FinalizableToNextRound, FinalizableToResult,
    FinalizeError, FirstRound, InitError, ProtocolResult, ReceiveError, ToNextRound, ToResult,
};
use super::keygen::{self, KeygenResult};
use super::wrappers::{wrap_finalize_error, wrap_receive_error, ResultWrapper};
use crate::cggmp21::SchemeParams;
use crate::tools::collections::{HoleRange, HoleVec};

/// Possible results of the merged KeyGen and KeyRefresh protocols.
#[derive(Debug, Clone, Copy)]
pub struct KeygenAndAuxResult<P: SchemeParams>(PhantomData<P>);

impl<P: SchemeParams> ProtocolResult for KeygenAndAuxResult<P> {
    type Success = KeyShare<P>;
    type ProvableError = KeygenAndAuxError<P>;
    type CorrectnessProof = KeygenAndAuxProof<P>;
}

/// Possible verifiable errors of the merged KeyGen and KeyRefresh protocols.
#[derive(Debug, Clone)]
pub enum KeygenAndAuxError<P: SchemeParams> {
    /// An error in the KeyGen part of the protocol.
    Keygen(<KeygenResult as ProtocolResult>::ProvableError),
    /// An error in the KeyRefresh part of the protocol.
    KeyRefresh(<KeyRefreshResult<P> as ProtocolResult>::ProvableError),
}

/// A proof of a node's correct behavior for the merged KeyGen and KeyRefresh protocols.
#[derive(Debug, Clone)]
pub enum KeygenAndAuxProof<P: SchemeParams> {
    /// A proof for the KeyGen part of the protocol.
    Keygen(<KeygenResult as ProtocolResult>::CorrectnessProof),
    /// A proof for the KeyRefresh part of the protocol.
    KeyRefresh(<KeyRefreshResult<P> as ProtocolResult>::CorrectnessProof),
}

impl<P: SchemeParams> ResultWrapper<KeygenResult> for KeygenAndAuxResult<P> {
    fn wrap_error(error: <KeygenResult as ProtocolResult>::ProvableError) -> Self::ProvableError {
        KeygenAndAuxError::Keygen(error)
    }
    fn wrap_proof(
        proof: <KeygenResult as ProtocolResult>::CorrectnessProof,
    ) -> Self::CorrectnessProof {
        KeygenAndAuxProof::Keygen(proof)
    }
}

impl<P: SchemeParams> ResultWrapper<KeyRefreshResult<P>> for KeygenAndAuxResult<P> {
    fn wrap_error(
        error: <KeyRefreshResult<P> as ProtocolResult>::ProvableError,
    ) -> Self::ProvableError {
        KeygenAndAuxError::KeyRefresh(error)
    }
    fn wrap_proof(
        proof: <KeyRefreshResult<P> as ProtocolResult>::CorrectnessProof,
    ) -> Self::CorrectnessProof {
        KeygenAndAuxProof::KeyRefresh(proof)
    }
}

pub(crate) struct Round1<P: SchemeParams> {
    keygen_round: keygen::Round1<P>,
    aux_round: auxiliary::Round1<P>,
}

impl<P: SchemeParams> FirstRound for Round1<P> {
    type Context = ();
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        _context: Self::Context,
    ) -> Result<Self, InitError> {
        let keygen_round = keygen::Round1::new(rng, shared_randomness, num_parties, party_idx, ())?;
        let aux_round = auxiliary::Round1::new(rng, shared_randomness, num_parties, party_idx, ())?;
        Ok(Self {
            keygen_round,
            aux_round,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "<keygen::Round1<P> as BroadcastRound>::Message: Serialize,
    <auxiliary::Round1<P> as BroadcastRound>::Message: Serialize"
))]
#[serde(bound(
    deserialize = "<keygen::Round1<P> as BroadcastRound>::Message: for<'x> Deserialize<'x>,
    <auxiliary::Round1<P> as BroadcastRound>::Message: for<'x> Deserialize<'x>"
))]
pub struct Round1Message<P: SchemeParams> {
    keygen_message: <keygen::Round1<P> as BroadcastRound>::Message,
    aux_message: <auxiliary::Round1<P> as BroadcastRound>::Message,
}

impl<P: SchemeParams> BaseRound for Round1<P> {
    type Type = ToNextRound;
    type Result = KeygenAndAuxResult<P>;
    const ROUND_NUM: u8 = 1;
    const NEXT_ROUND_NUM: Option<u8> = Some(2);
}

impl<P: SchemeParams> BroadcastRound for Round1<P> {
    const REQUIRES_CONSENSUS: bool = <keygen::Round1<P> as BroadcastRound>::REQUIRES_CONSENSUS
        || <auxiliary::Round1<P> as BroadcastRound>::REQUIRES_CONSENSUS;
    type Message = Round1Message<P>;
    type Payload = (
        <keygen::Round1<P> as BroadcastRound>::Payload,
        <auxiliary::Round1<P> as BroadcastRound>::Payload,
    );
    fn broadcast_destinations(&self) -> Option<HoleRange> {
        let keygen_dest = self.keygen_round.broadcast_destinations();
        let aux_dest = self.aux_round.broadcast_destinations();
        assert!(keygen_dest == aux_dest);
        keygen_dest
    }
    fn make_broadcast(&self, rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        let keygen_message = self.keygen_round.make_broadcast(rng)?;
        let aux_message = self.aux_round.make_broadcast(rng)?;
        Ok(Round1Message {
            keygen_message,
            aux_message,
        })
    }
    fn verify_broadcast(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        let keygen_payload = self
            .keygen_round
            .verify_broadcast(from, msg.keygen_message)
            .map_err(wrap_receive_error)?;
        let aux_payload = self
            .aux_round
            .verify_broadcast(from, msg.aux_message)
            .map_err(wrap_receive_error)?;
        Ok((keygen_payload, aux_payload))
    }
}

impl<P: SchemeParams> DirectRound for Round1<P> {
    type Message = ();
    type Payload = ();
    type Artefact = ();
}

impl<P: SchemeParams> FinalizableToNextRound for Round1<P> {
    type NextRound = Round2<P>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        dm_artefacts: Option<HoleVec<<Self as DirectRound>::Artefact>>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        assert!(dm_payloads.is_none());
        assert!(dm_artefacts.is_none());
        let (keygen_bc_payloads, aux_bc_payloads) = bc_payloads
            .map(|payloads| payloads.unzip())
            .map_or((None, None), |(x, y)| (Some(x), Some(y)));

        let keygen_round = self
            .keygen_round
            .finalize_to_next_round(rng, keygen_bc_payloads, None, None)
            .map_err(wrap_finalize_error)?;
        let aux_round = self
            .aux_round
            .finalize_to_next_round(rng, aux_bc_payloads, None, None)
            .map_err(wrap_finalize_error)?;
        Ok(Round2 {
            keygen_round,
            aux_round,
        })
    }
}

pub(crate) struct Round2<P: SchemeParams> {
    keygen_round: keygen::Round2<P>,
    aux_round: auxiliary::Round2<P>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "<keygen::Round2<P> as BroadcastRound>::Message: Serialize,
    <auxiliary::Round2<P> as BroadcastRound>::Message: Serialize"
))]
#[serde(bound(
    deserialize = "<keygen::Round2<P> as BroadcastRound>::Message: for<'x> Deserialize<'x>,
    <auxiliary::Round2<P> as BroadcastRound>::Message: for<'x> Deserialize<'x>"
))]
pub struct Round2Message<P: SchemeParams> {
    keygen_message: <keygen::Round2<P> as BroadcastRound>::Message,
    aux_message: <auxiliary::Round2<P> as BroadcastRound>::Message,
}

impl<P: SchemeParams> BaseRound for Round2<P> {
    type Type = ToNextRound;
    type Result = KeygenAndAuxResult<P>;
    const ROUND_NUM: u8 = 2;
    const NEXT_ROUND_NUM: Option<u8> = Some(3);
}

impl<P: SchemeParams> BroadcastRound for Round2<P> {
    const REQUIRES_CONSENSUS: bool = <keygen::Round1<P> as BroadcastRound>::REQUIRES_CONSENSUS
        || <auxiliary::Round1<P> as BroadcastRound>::REQUIRES_CONSENSUS;
    type Message = Round2Message<P>;
    type Payload = (
        <keygen::Round2<P> as BroadcastRound>::Payload,
        <auxiliary::Round2<P> as BroadcastRound>::Payload,
    );

    fn broadcast_destinations(&self) -> Option<HoleRange> {
        let keygen_dest = self.keygen_round.broadcast_destinations();
        let aux_dest = self.aux_round.broadcast_destinations();
        assert!(keygen_dest == aux_dest);
        keygen_dest
    }
    fn make_broadcast(&self, rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        let keygen_message = self.keygen_round.make_broadcast(rng)?;
        let aux_message = self.aux_round.make_broadcast(rng)?;
        Ok(Round2Message {
            keygen_message,
            aux_message,
        })
    }

    fn verify_broadcast(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        let keygen_payload = self
            .keygen_round
            .verify_broadcast(from, msg.keygen_message)
            .map_err(wrap_receive_error)?;
        let aux_payload = self
            .aux_round
            .verify_broadcast(from, msg.aux_message)
            .map_err(wrap_receive_error)?;
        Ok((keygen_payload, aux_payload))
    }
}

impl<P: SchemeParams> DirectRound for Round2<P> {
    type Message = ();
    type Payload = ();
    type Artefact = ();
}

impl<P: SchemeParams> FinalizableToNextRound for Round2<P> {
    type NextRound = Round3<P>;
    fn finalize_to_next_round(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        dm_artefacts: Option<HoleVec<<Self as DirectRound>::Artefact>>,
    ) -> Result<Self::NextRound, FinalizeError<Self::Result>> {
        assert!(dm_payloads.is_none());
        assert!(dm_artefacts.is_none());
        let (keygen_bc_payloads, aux_bc_payloads) = bc_payloads
            .map(|payloads| payloads.unzip())
            .map_or((None, None), |(x, y)| (Some(x), Some(y)));

        let keygen_round = self
            .keygen_round
            .finalize_to_next_round(rng, keygen_bc_payloads, None, None)
            .map_err(wrap_finalize_error)?;
        let aux_round = self
            .aux_round
            .finalize_to_next_round(rng, aux_bc_payloads, None, None)
            .map_err(wrap_finalize_error)?;
        Ok(Round3 {
            keygen_round,
            aux_round,
        })
    }
}

pub(crate) struct Round3<P: SchemeParams> {
    keygen_round: keygen::Round3<P>,
    aux_round: auxiliary::Round3<P>,
}

impl<P: SchemeParams> BaseRound for Round3<P> {
    type Type = ToResult;
    type Result = KeygenAndAuxResult<P>;
    const ROUND_NUM: u8 = 3;
    const NEXT_ROUND_NUM: Option<u8> = None;
}

impl<P: SchemeParams> BroadcastRound for Round3<P> {
    const REQUIRES_CONSENSUS: bool = keygen::Round3::<P>::REQUIRES_CONSENSUS;
    type Message = <keygen::Round3<P> as BroadcastRound>::Message;
    type Payload = <keygen::Round3<P> as BroadcastRound>::Payload;

    fn broadcast_destinations(&self) -> Option<HoleRange> {
        self.keygen_round.broadcast_destinations()
    }
    fn make_broadcast(&self, rng: &mut impl CryptoRngCore) -> Result<Self::Message, String> {
        self.keygen_round.make_broadcast(rng)
    }

    fn verify_broadcast(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        self.keygen_round
            .verify_broadcast(from, msg)
            .map_err(wrap_receive_error)
    }
}

impl<P: SchemeParams> DirectRound for Round3<P> {
    type Artefact = <auxiliary::Round3<P> as DirectRound>::Artefact;
    type Message = <auxiliary::Round3<P> as DirectRound>::Message;
    type Payload = <auxiliary::Round3<P> as DirectRound>::Payload;

    fn direct_message_destinations(&self) -> Option<HoleRange> {
        self.aux_round.direct_message_destinations()
    }
    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: PartyIdx,
    ) -> Result<(Self::Message, Self::Artefact), String> {
        self.aux_round.make_direct_message(rng, destination)
    }

    fn verify_direct_message(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError<Self::Result>> {
        self.aux_round
            .verify_direct_message(from, msg)
            .map_err(wrap_receive_error)
    }
}

impl<P: SchemeParams> FinalizableToResult for Round3<P> {
    fn finalize_to_result(
        self,
        rng: &mut impl CryptoRngCore,
        bc_payloads: Option<HoleVec<<Self as BroadcastRound>::Payload>>,
        dm_payloads: Option<HoleVec<<Self as DirectRound>::Payload>>,
        dm_artefacts: Option<HoleVec<<Self as DirectRound>::Artefact>>,
    ) -> Result<<Self::Result as ProtocolResult>::Success, FinalizeError<Self::Result>> {
        let keyshare_seed = self
            .keygen_round
            .finalize_to_result(rng, bc_payloads, None, None)
            .map_err(wrap_finalize_error)?;
        let keyshare_change = self
            .aux_round
            .finalize_to_result(rng, None, dm_payloads, dm_artefacts)
            .map_err(wrap_finalize_error)?;
        Ok(KeyShare::new(keyshare_seed, keyshare_change))
    }
}
