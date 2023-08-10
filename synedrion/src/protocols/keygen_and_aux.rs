use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::auxiliary;
use super::common::{KeyShare, PartyIdx, SchemeParams};
use super::generic::{
    BaseRound, FinalizeError, FinalizeSuccess, FirstRound, InitError, NonExistent, ReceiveError,
    Round, ToSendTyped,
};
use super::keygen;
use crate::tools::collections::HoleVec;

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
#[serde(
    bound(serialize = "<keygen::Round1<P> as BaseRound>::Message: Serialize,
    <auxiliary::Round1<P> as BaseRound>::Message: Serialize")
)]
#[serde(bound(
    deserialize = "<keygen::Round1<P> as BaseRound>::Message: for<'x> Deserialize<'x>,
    <auxiliary::Round1<P> as BaseRound>::Message: for<'x> Deserialize<'x>"
))]
pub struct Round1Message<P: SchemeParams> {
    keygen_message: <keygen::Round1<P> as BaseRound>::Message,
    aux_message: <auxiliary::Round1<P> as BaseRound>::Message,
}

pub struct Round1Payload<P: SchemeParams> {
    keygen_payload: <keygen::Round1<P> as BaseRound>::Payload,
    aux_payload: <auxiliary::Round1<P> as BaseRound>::Payload,
}

impl<P: SchemeParams> BaseRound for Round1<P> {
    type Message = Round1Message<P>;
    type Payload = Round1Payload<P>;

    const ROUND_NUM: u8 = 1;
    const REQUIRES_BROADCAST_CONSENSUS: bool =
        <keygen::Round1<P> as BaseRound>::REQUIRES_BROADCAST_CONSENSUS
            || <auxiliary::Round1<P> as BaseRound>::REQUIRES_BROADCAST_CONSENSUS;

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        // TODO: find a way to do it in a type-safe manner.
        // One way is to allow both broadcast and direct messages in the same round
        // (which we otherwise need for presigning)
        let keygen_message = match self.keygen_round.to_send(rng) {
            ToSendTyped::Broadcast(msg) => msg,
            _ => panic!("This round is not expected to produce direct messages"),
        };
        let aux_message = match self.aux_round.to_send(rng) {
            ToSendTyped::Broadcast(msg) => msg,
            _ => panic!("This round is not expected to produce direct messages"),
        };
        ToSendTyped::Broadcast(Round1Message {
            keygen_message,
            aux_message,
        })
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        let keygen_payload = self
            .keygen_round
            .verify_received(from, msg.keygen_message)?;
        let aux_payload = self.aux_round.verify_received(from, msg.aux_message)?;
        Ok(Round1Payload {
            keygen_payload,
            aux_payload,
        })
    }
}

impl<P: SchemeParams> Round for Round1<P> {
    type NextRound = Round2<P>;
    type Result = KeyShare<P>;
    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let (keygen_payloads, aux_payloads) = payloads
            .map(|payload| (payload.keygen_payload, payload.aux_payload))
            .unzip();
        let keygen_result = self.keygen_round.finalize(rng, keygen_payloads)?;
        let aux_result = self.aux_round.finalize(rng, aux_payloads)?;
        match (keygen_result, aux_result) {
            (
                FinalizeSuccess::AnotherRound(keygen_round),
                FinalizeSuccess::AnotherRound(aux_round),
            ) => Ok(FinalizeSuccess::AnotherRound(Round2::<P> {
                keygen_round,
                aux_round,
            })),
            _ => Err(FinalizeError::ProtocolMergeParallel(
                "Unexpected finalization results in round 1".into(),
            )),
        }
    }
    const NEXT_ROUND_NUM: Option<u8> = Some(2);
}

pub(crate) struct Round2<P: SchemeParams> {
    keygen_round: keygen::Round2<P>,
    aux_round: auxiliary::Round2<P>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(
    bound(serialize = "<keygen::Round2<P> as BaseRound>::Message: Serialize,
    <auxiliary::Round2<P> as BaseRound>::Message: Serialize")
)]
#[serde(bound(
    deserialize = "<keygen::Round2<P> as BaseRound>::Message: for<'x> Deserialize<'x>,
    <auxiliary::Round2<P> as BaseRound>::Message: for<'x> Deserialize<'x>"
))]
pub struct Round2Message<P: SchemeParams> {
    keygen_message: <keygen::Round2<P> as BaseRound>::Message,
    aux_message: <auxiliary::Round2<P> as BaseRound>::Message,
}

pub struct Round2Payload<P: SchemeParams> {
    keygen_payload: <keygen::Round2<P> as BaseRound>::Payload,
    aux_payload: <auxiliary::Round2<P> as BaseRound>::Payload,
}

impl<P: SchemeParams> BaseRound for Round2<P> {
    type Message = Round2Message<P>;
    type Payload = Round2Payload<P>;

    const ROUND_NUM: u8 = 2;
    const REQUIRES_BROADCAST_CONSENSUS: bool =
        <keygen::Round2<P> as BaseRound>::REQUIRES_BROADCAST_CONSENSUS
            || <auxiliary::Round2<P> as BaseRound>::REQUIRES_BROADCAST_CONSENSUS;

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        // TODO: find a way to do it in a type-safe manner.
        // One way is to allow both broadcast and direct messages in the same round
        // (which we otherwise need for presigning)
        let keygen_message = match self.keygen_round.to_send(rng) {
            ToSendTyped::Broadcast(msg) => msg,
            _ => panic!("This round is not expected to produce direct messages"),
        };
        let aux_message = match self.aux_round.to_send(rng) {
            ToSendTyped::Broadcast(msg) => msg,
            _ => panic!("This round is not expected to produce direct messages"),
        };
        ToSendTyped::Broadcast(Round2Message {
            keygen_message,
            aux_message,
        })
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        let keygen_payload = self
            .keygen_round
            .verify_received(from, msg.keygen_message)?;
        let aux_payload = self.aux_round.verify_received(from, msg.aux_message)?;
        Ok(Round2Payload {
            keygen_payload,
            aux_payload,
        })
    }
}

impl<P: SchemeParams> Round for Round2<P> {
    type NextRound = Round3<P>;
    type Result = KeyShare<P>;
    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let (keygen_payloads, aux_payloads) = payloads
            .map(|payload| (payload.keygen_payload, payload.aux_payload))
            .unzip();
        let keygen_result = self.keygen_round.finalize(rng, keygen_payloads)?;
        let aux_result = self.aux_round.finalize(rng, aux_payloads)?;
        match (keygen_result, aux_result) {
            (
                FinalizeSuccess::AnotherRound(keygen_round),
                FinalizeSuccess::AnotherRound(aux_round),
            ) => Ok(FinalizeSuccess::AnotherRound(Round3::<P> {
                keygen_round,
                aux_round,
            })),
            _ => Err(FinalizeError::ProtocolMergeParallel(
                "Unexpected finalization results in round 2".into(),
            )),
        }
    }
    const NEXT_ROUND_NUM: Option<u8> = Some(3);
}

pub(crate) struct Round3<P: SchemeParams> {
    keygen_round: keygen::Round3<P>,
    aux_round: auxiliary::Round3<P>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(
    bound(serialize = "<keygen::Round3<P> as BaseRound>::Message: Serialize,
    <auxiliary::Round3<P> as BaseRound>::Message: Serialize")
)]
#[serde(bound(
    deserialize = "<keygen::Round3<P> as BaseRound>::Message: for<'x> Deserialize<'x>,
    <auxiliary::Round3<P> as BaseRound>::Message: for<'x> Deserialize<'x>"
))]
pub struct Round3Message<P: SchemeParams> {
    keygen_message: <keygen::Round3<P> as BaseRound>::Message,
    aux_message: <auxiliary::Round3<P> as BaseRound>::Message,
}

pub struct Round3Payload<P: SchemeParams> {
    keygen_payload: <keygen::Round3<P> as BaseRound>::Payload,
    aux_payload: <auxiliary::Round3<P> as BaseRound>::Payload,
}

impl<P: SchemeParams> BaseRound for Round3<P> {
    type Message = Round3Message<P>;
    type Payload = Round3Payload<P>;

    const ROUND_NUM: u8 = 3;
    const REQUIRES_BROADCAST_CONSENSUS: bool = false;

    fn to_send(&self, rng: &mut impl CryptoRngCore) -> ToSendTyped<Self::Message> {
        // TODO: find a way to do it in a type-safe manner.
        // One way is to allow both broadcast and direct messages in the same round
        // (which we otherwise need for presigning)
        let keygen_message = match self.keygen_round.to_send(rng) {
            ToSendTyped::Broadcast(msg) => msg,
            _ => panic!("This round is not expected to produce direct messages"),
        };
        let aux_messages = match self.aux_round.to_send(rng) {
            ToSendTyped::Direct(msgs) => msgs,
            _ => panic!("This round is not expected to produce direct messages"),
        };

        let messages = aux_messages
            .into_iter()
            .map(|(to, aux_message)| {
                let message = Round3Message {
                    keygen_message: keygen_message.clone(),
                    aux_message,
                };
                (to, message)
            })
            .collect();

        ToSendTyped::Direct(messages)
    }

    fn verify_received(
        &self,
        from: PartyIdx,
        msg: Self::Message,
    ) -> Result<Self::Payload, ReceiveError> {
        let keygen_payload = self
            .keygen_round
            .verify_received(from, msg.keygen_message)?;
        let aux_payload = self.aux_round.verify_received(from, msg.aux_message)?;
        Ok(Round3Payload {
            keygen_payload,
            aux_payload,
        })
    }
}

impl<P: SchemeParams> Round for Round3<P> {
    type NextRound = NonExistent<Self::Result>;
    type Result = KeyShare<P>;
    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let (keygen_payloads, aux_payloads) = payloads
            .map(|payload| (payload.keygen_payload, payload.aux_payload))
            .unzip();
        let keygen_result = self.keygen_round.finalize(rng, keygen_payloads)?;
        let aux_result = self.aux_round.finalize(rng, aux_payloads)?;
        match (keygen_result, aux_result) {
            (FinalizeSuccess::Result(keyshare_seed), FinalizeSuccess::Result(keyshare_change)) => {
                Ok(FinalizeSuccess::Result(KeyShare::new(
                    keyshare_seed,
                    keyshare_change,
                )))
            }
            _ => Err(FinalizeError::ProtocolMergeParallel(
                "Unexpected finalization results in round 3".into(),
            )),
        }
    }
    const NEXT_ROUND_NUM: Option<u8> = None;
}
