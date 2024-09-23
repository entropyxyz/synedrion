use rand_core::CryptoRngCore;


use crate::{PartyId, rounds::Round};

pub trait MaliciousRoundWrapper<I: PartyId> {
    type InnerRound: Round<I>;
    fn inner_round(&self) -> &Self::InnerRound;
}

pub trait MaliciousRound<I: PartyId>: MaliciousRoundWrapper<I> {
    fn make_direct_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &I,
    ) -> (
        <Self::InnerRound as Round<I>>::DirectMessage,
        <Self::InnerRound as Round<I>>::Artifact,
    ) {
        self.inner_round().make_direct_message(rng, destination)
    }

    fn make_broadcast_message(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Option<<Self::InnerRound as Round<I>>::BroadcastMessage> {
        self.inner_round().make_broadcast_message(rng)
    }
}

macro_rules! malicious_round {
    ($round: ident, $inner_round: ident) => {

        impl<P: SchemeParams, I: PartyId> MaliciousRoundWrapper<I> for $round<P, I> {
            type InnerRound = $inner_round<P, I>;
            fn inner_round(&self) -> &Self::InnerRound { &self.0 }
        }

        impl<P: SchemeParams, I: PartyId> Round<I> for $round<P, I> {
            type Type = <<Self as MaliciousRoundWrapper<I>>::InnerRound as Round<I>>::Type;
            type Result = <<Self as MaliciousRoundWrapper<I>>::InnerRound as Round<I>>::Result;
            const ROUND_NUM: u8 = <<Self as MaliciousRoundWrapper<I>>::InnerRound as Round<I>>::ROUND_NUM;
            const NEXT_ROUND_NUM: Option<u8> = <<Self as MaliciousRoundWrapper<I>>::InnerRound as Round<I>>::NEXT_ROUND_NUM;

            fn other_ids(&self) -> &BTreeSet<I> {
                self.inner_round().other_ids()
            }

            fn my_id(&self) -> &I {
                self.inner_round().my_id()
            }

            const REQUIRES_ECHO: bool = <<Self as MaliciousRoundWrapper<I>>::InnerRound as Round<I>>::REQUIRES_ECHO;
            type BroadcastMessage = <<Self as MaliciousRoundWrapper<I>>::InnerRound as Round<I>>::BroadcastMessage;
            type DirectMessage = <<Self as MaliciousRoundWrapper<I>>::InnerRound as Round<I>>::DirectMessage;
            type Payload = <<Self as MaliciousRoundWrapper<I>>::InnerRound as Round<I>>::Payload;
            type Artifact = <<Self as MaliciousRoundWrapper<I>>::InnerRound as Round<I>>::Artifact;

            fn message_destinations(&self) -> &BTreeSet<I> {
                self.inner_round().message_destinations()
            }

            fn make_broadcast_message(
                &self,
                rng: &mut impl CryptoRngCore,
            ) -> Option<Self::BroadcastMessage> {
                MaliciousRound::make_broadcast_message(self, rng)
            }

            fn make_direct_message(
                &self,
                rng: &mut impl CryptoRngCore,
                destination: &I,
            ) -> (Self::DirectMessage, Self::Artifact) {
                MaliciousRound::make_direct_message(self, rng, destination)
            }

            fn verify_message(
                &self,
                rng: &mut impl CryptoRngCore,
                from: &I,
                broadcast_msg: Self::BroadcastMessage,
                direct_msg: Self::DirectMessage,
            ) -> Result<Self::Payload, <Self::Result as crate::ProtocolResult<I>>::ProvableError> {
                self.inner_round()
                    .verify_message(rng, from, broadcast_msg, direct_msg)
            }

            fn finalization_requirement() -> crate::rounds::FinalizationRequirement {
                <<Self as MaliciousRoundWrapper<I>>::InnerRound as Round<I>>::finalization_requirement()
            }
        }
    };
}

pub(crate) use malicious_round;

macro_rules! malicious_to_next_round {
    ($round: ident, $next_round: ident) => {
        impl<P: SchemeParams, I: PartyId> crate::rounds::FinalizableToNextRound<I> for $round<P, I> {
            type NextRound = $next_round<P, I>;
            fn finalize_to_next_round(
                self,
                rng: &mut impl CryptoRngCore,
                payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
                artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
            ) -> Result<Self::NextRound, crate::rounds::FinalizeError<I, Self::Result>> {
                let next_round = self.0
                    .finalize_to_next_round(rng, payloads, artifacts)?;
                Ok($next_round(next_round, self.1))
            }
        }
    };
}

pub(crate) use malicious_to_next_round;

macro_rules! malicious_to_result {
    ($round: ident) => {
        impl<P: SchemeParams, I: PartyId> crate::rounds::FinalizableToResult<I> for $round<P, I> {
            fn finalize_to_result(
                self,
                rng: &mut impl CryptoRngCore,
                payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
                artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
            ) -> Result<
                <Self::Result as crate::ProtocolResult<I>>::Success,
                crate::rounds::FinalizeError<I, Self::Result>,
            > {
                self.0.finalize_to_result(rng, payloads, artifacts)
            }
        }
    };
}

pub(crate) use malicious_to_result;
