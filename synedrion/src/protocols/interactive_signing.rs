use alloc::boxed::Box;

use rand_core::CryptoRngCore;

use super::common::{KeyShare, PartyIdx};
use super::generic::{FinalizeError, FinalizeSuccess, FirstRound, InitError, NonExistent, Round};
use super::merged::BaseRoundWrapper;
use super::presigning;
use super::signing;
use crate::curve::{RecoverableSignature, Scalar};
use crate::sigma::params::SchemeParams;
use crate::tools::collections::HoleVec;

struct RoundContext<P: SchemeParams> {
    shared_randomness: Box<[u8]>,
    key_share: KeyShare<P>,
    message: Scalar,
}

#[derive(Clone)]
pub(crate) struct Context<P: SchemeParams> {
    pub(crate) key_share: KeyShare<P>,
    pub(crate) message: Scalar,
}

pub(crate) struct Round1Part1<P: SchemeParams> {
    round: presigning::Round1Part1<P>,
    context: RoundContext<P>,
}

impl<P: SchemeParams> FirstRound for Round1Part1<P> {
    type Context = Context<P>;
    fn new(
        rng: &mut impl CryptoRngCore,
        shared_randomness: &[u8],
        num_parties: usize,
        party_idx: PartyIdx,
        context: Self::Context,
    ) -> Result<Self, InitError> {
        let round = presigning::Round1Part1::new(
            rng,
            shared_randomness,
            num_parties,
            party_idx,
            context.key_share.clone(),
        )?;
        let context = RoundContext {
            shared_randomness: shared_randomness.into(),
            key_share: context.key_share,
            message: context.message,
        };
        Ok(Self { context, round })
    }
}

impl<P: SchemeParams> BaseRoundWrapper for Round1Part1<P> {
    type InnerRound = presigning::Round1Part1<P>;
    const ROUND_NUM: u8 = 1;
    fn inner_round(&self) -> &Self::InnerRound {
        &self.round
    }
}

impl<P: SchemeParams> Round for Round1Part1<P> {
    type NextRound = Round1Part2<P>;
    type Result = RecoverableSignature;
    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let result = self.round.finalize(rng, payloads)?;
        match result {
            FinalizeSuccess::AnotherRound(round) => {
                Ok(FinalizeSuccess::AnotherRound(Round1Part2::<P> {
                    round,
                    context: self.context,
                }))
            }
            FinalizeSuccess::Result(_res) => unreachable!(),
        }
    }
    const NEXT_ROUND_NUM: Option<u8> = Some(2);
}

pub(crate) struct Round1Part2<P: SchemeParams> {
    round: presigning::Round1Part2<P>,
    context: RoundContext<P>,
}

impl<P: SchemeParams> BaseRoundWrapper for Round1Part2<P> {
    type InnerRound = presigning::Round1Part2<P>;
    const ROUND_NUM: u8 = 2;
    fn inner_round(&self) -> &Self::InnerRound {
        &self.round
    }
}

impl<P: SchemeParams> Round for Round1Part2<P> {
    type NextRound = Round2<P>;
    type Result = RecoverableSignature;
    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let result = self.round.finalize(rng, payloads)?;
        match result {
            FinalizeSuccess::AnotherRound(round) => {
                Ok(FinalizeSuccess::AnotherRound(Round2::<P> {
                    round,
                    context: self.context,
                }))
            }
            FinalizeSuccess::Result(_res) => unreachable!(),
        }
    }
    const NEXT_ROUND_NUM: Option<u8> = Some(3);
}

pub(crate) struct Round2<P: SchemeParams> {
    round: presigning::Round2<P>,
    context: RoundContext<P>,
}

impl<P: SchemeParams> BaseRoundWrapper for Round2<P> {
    type InnerRound = presigning::Round2<P>;
    const ROUND_NUM: u8 = 3;
    fn inner_round(&self) -> &Self::InnerRound {
        &self.round
    }
}

impl<P: SchemeParams> Round for Round2<P> {
    type NextRound = Round3<P>;
    type Result = RecoverableSignature;
    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let result = self.round.finalize(rng, payloads)?;
        match result {
            FinalizeSuccess::AnotherRound(round) => {
                Ok(FinalizeSuccess::AnotherRound(Round3::<P> {
                    round,
                    context: self.context,
                }))
            }
            FinalizeSuccess::Result(_res) => unreachable!(),
        }
    }
    const NEXT_ROUND_NUM: Option<u8> = Some(4);
}

pub(crate) struct Round3<P: SchemeParams> {
    round: presigning::Round3<P>,
    context: RoundContext<P>,
}

impl<P: SchemeParams> BaseRoundWrapper for Round3<P> {
    type InnerRound = presigning::Round3<P>;
    const ROUND_NUM: u8 = 4;
    fn inner_round(&self) -> &Self::InnerRound {
        &self.round
    }
}

impl<P: SchemeParams> Round for Round3<P> {
    type NextRound = SigningRound;
    type Result = RecoverableSignature;
    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        let num_parties = self.context.key_share.num_parties();
        let party_idx = self.context.key_share.party_index();
        let result = self.round.finalize(rng, payloads)?;
        match result {
            FinalizeSuccess::AnotherRound(_round) => unreachable!(),
            FinalizeSuccess::Result(result) => {
                let signing_context = signing::Context {
                    message: self.context.message,
                    presigning: result,
                    verifying_key: self.context.key_share.verifying_key_as_point(),
                };
                let signing_round = signing::Round1::new(
                    rng,
                    &self.context.shared_randomness,
                    num_parties,
                    party_idx,
                    signing_context,
                )
                .map_err(FinalizeError::ProtocolMergeSequential)?;
                Ok(FinalizeSuccess::AnotherRound(SigningRound {
                    round: signing_round,
                }))
            }
        }
    }
    const NEXT_ROUND_NUM: Option<u8> = Some(5);
}

pub(crate) struct SigningRound {
    round: signing::Round1,
}

impl BaseRoundWrapper for SigningRound {
    type InnerRound = signing::Round1;
    const ROUND_NUM: u8 = 5;
    fn inner_round(&self) -> &Self::InnerRound {
        &self.round
    }
}

impl Round for SigningRound {
    type NextRound = NonExistent<Self::Result>;
    type Result = RecoverableSignature;
    fn finalize(
        self,
        rng: &mut impl CryptoRngCore,
        payloads: HoleVec<Self::Payload>,
    ) -> Result<FinalizeSuccess<Self>, FinalizeError> {
        self.round
            .finalize(rng, payloads)
            .map(|success| match success {
                FinalizeSuccess::Result(res) => FinalizeSuccess::Result(res),
                FinalizeSuccess::AnotherRound(_round) => unreachable!(),
            })
    }
    const NEXT_ROUND_NUM: Option<u8> = None;
}
