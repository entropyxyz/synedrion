#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;
    use alloc::collections::{BTreeMap, BTreeSet};
    use rand_core::CryptoRngCore;

    use rand_core::{OsRng, RngCore};

    use super::super::key_init::{Round1, Round2, Round3};
    use crate::cggmp21::TestParams;
    use crate::rounds::{
        test_utils::{step_next_round, step_result, step_round, Id, Without},
        FirstRound, Round,
    };
    use crate::tools::bitvec::BitVec;
    use crate::{PartyId, SchemeParams};
    use crate::rounds::malicious::{malicious_round, malicious_to_next_round, malicious_to_result, MaliciousRoundWrapper, MaliciousRound};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum MaliciousAction {
        RandomU,
    }

    struct MRound1<P: SchemeParams, I>(Round1<P, I>, MaliciousAction);
    struct MRound2<P: SchemeParams, I>(Round2<P, I>, MaliciousAction);
    struct MRound3<P: SchemeParams, I>(Round3<P, I>, MaliciousAction);

    impl<P: SchemeParams, I: PartyId> MaliciousRound<I> for MRound1<P, I> {
        // Here we do bad stuff
    }

    impl<P: SchemeParams, I: PartyId> MaliciousRound<I> for MRound2<P, I> {
        fn make_broadcast_message(
            &self,
            rng: &mut impl CryptoRngCore,
        ) -> Option<<Round2<P, I> as Round<I>>::BroadcastMessage> {
            let mut message = self.0.make_broadcast_message(rng)?;

            if self.1 == MaliciousAction::RandomU {
                message.data.u = BitVec::random(rng, message.data.u.len());
            }

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
                    MaliciousAction::RandomU,
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
