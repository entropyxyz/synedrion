#[cfg(test)]
mod tests {
    use alloc::collections::{BTreeMap, BTreeSet};
    use rand_core::CryptoRngCore;

    use rand_core::{OsRng, RngCore};
    use secrecy::ExposeSecret;

    use super::super::key_init::{Round1, Round2, Round3};
    use crate::cggmp21::TestParams;
    use crate::rounds::{
        test_utils::{step_next_round, step_result, step_round, Id, Without},
        FinalizableToNextRound, FinalizableToResult, FinalizationRequirement, FinalizeError,
        FirstRound, Round,
    };
    use crate::tools::bitvec::BitVec;
    use crate::{PartyId, ProtocolResult, SchemeParams};

    trait MaliciousRoundWrapper<I: PartyId> {
        type InnerRound: Round<I>;
        fn inner_round(&self) -> &Self::InnerRound;
    }

    trait MaliciousRound<I: PartyId>: MaliciousRoundWrapper<I> {
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
                ) -> Result<Self::Payload, <Self::Result as ProtocolResult<I>>::ProvableError> {
                    self.inner_round()
                        .verify_message(rng, from, broadcast_msg, direct_msg)
                }

                fn finalization_requirement() -> FinalizationRequirement {
                    <<Self as MaliciousRoundWrapper<I>>::InnerRound as Round<I>>::finalization_requirement()
                }
            }
        };
    }

    macro_rules! malicious_to_next_round {
        ($round: ident, $next_round: ident) => {
            impl<P: SchemeParams, I: PartyId> FinalizableToNextRound<I> for $round<P, I> {
                type NextRound = $next_round<P, I>;
                fn finalize_to_next_round(
                    self,
                    rng: &mut impl CryptoRngCore,
                    payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
                    artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
                ) -> Result<Self::NextRound, FinalizeError<I, Self::Result>> {
                    self.0
                        .finalize_to_next_round(rng, payloads, artifacts)
                        .map($next_round)
                }
            }
        };
    }

    macro_rules! malicious_to_result {
        ($round: ident) => {
            impl<P: SchemeParams, I: PartyId> FinalizableToResult<I> for $round<P, I> {
                fn finalize_to_result(
                    self,
                    rng: &mut impl CryptoRngCore,
                    payloads: BTreeMap<I, <Self as Round<I>>::Payload>,
                    artifacts: BTreeMap<I, <Self as Round<I>>::Artifact>,
                ) -> Result<
                    <Self::Result as ProtocolResult<I>>::Success,
                    FinalizeError<I, Self::Result>,
                > {
                    self.0.finalize_to_result(rng, payloads, artifacts)
                }
            }
        };
    }

    struct MRound1<P: SchemeParams, I>(Round1<P, I>);
    struct MRound2<P: SchemeParams, I>(Round2<P, I>);
    struct MRound3<P: SchemeParams, I>(Round3<P, I>);

    impl<P: SchemeParams, I: PartyId> MaliciousRound<I> for MRound1<P, I> {
        // Here we do bad stuff
    }

    impl<P: SchemeParams, I: PartyId> MaliciousRound<I> for MRound2<P, I> {
        fn make_broadcast_message(
            &self,
            rng: &mut impl CryptoRngCore,
        ) -> Option<<Round2<P, I> as Round<I>>::BroadcastMessage> {
            let mut message = self.0.make_broadcast_message(rng)?;

            // Garbage `u`
            message.data.u = BitVec::random(rng, message.data.u.len());

            Some(message)
        }
    }

    impl<P: SchemeParams, I: PartyId> MaliciousRound<I> for MRound3<P, I> {
        // Here we do bad stuff
    }

    malicious_round!(MRound1, Round1);
    malicious_round!(MRound2, Round2);
    malicious_round!(MRound3, Round3);

    malicious_to_next_round!(MRound1, MRound2);
    malicious_to_next_round!(MRound2, MRound3);
    malicious_to_result!(MRound3);

    #[test]
    fn execute_keygen() {
        let mut shared_randomness = [0u8; 32];
        OsRng.fill_bytes(&mut shared_randomness);

        let ids = BTreeSet::from([Id(0), Id(1), Id(2)]);

        let r1 = ids
            .iter()
            .map(|id| {
                let round = MRound1(
                    Round1::<TestParams, Id>::new(
                        &mut OsRng,
                        &shared_randomness,
                        ids.clone().without(id),
                        *id,
                        (),
                    )
                    .unwrap(),
                );
                (*id, round)
            })
            .collect();

        let r1a = step_round(&mut OsRng, r1).unwrap();
        let r2 = step_next_round(&mut OsRng, r1a).unwrap();
        let r2a = step_round(&mut OsRng, r2).unwrap();
        let r3 = step_next_round(&mut OsRng, r2a).unwrap();
        let r3a = step_round(&mut OsRng, r3).unwrap();
        let shares = step_result(&mut OsRng, r3a).unwrap();

        // Check that the sets of public keys are the same at each node

        let public_sets = shares
            .iter()
            .map(|(id, share)| (*id, share.public_shares.clone()))
            .collect::<BTreeMap<_, _>>();

        assert!(public_sets.values().all(|pk| pk == &public_sets[&Id(0)]));

        // Check that the public keys correspond to the secret key shares
        let public_set = &public_sets[&Id(0)];

        let public_from_secret = shares
            .into_iter()
            .map(|(id, share)| (id, share.secret_share.expose_secret().mul_by_generator()))
            .collect();

        assert!(public_set == &public_from_secret);
    }
}
