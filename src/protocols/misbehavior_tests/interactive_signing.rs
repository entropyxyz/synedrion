use alloc::collections::{BTreeMap, BTreeSet};

use elliptic_curve::FieldBytes;
use manul::{
    combinators::misbehave::{FinalizeOverride, Misbehaving},
    dev::{BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
    protocol::{
        Artifact, BoxedFormat, BoxedRound, DirectMessage, EchoBroadcast, EntryPoint, FinalizeOutcome, LocalError,
        NormalBroadcast, Payload, ProtocolMessagePart,
    },
    signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng, RngCore};

use super::super::interactive_signing::{
    InteractiveSigning, InteractiveSigningAssociatedData, InteractiveSigningProtocol, Round1EchoBroadcast, Round2,
    Round2EchoBroadcast, Round2NormalBroadcast, Round3, Round3EchoBroadcast, Round3NormalBroadcast, Round3Payload,
    Round4NormalBroadcast, Round5, Round6,
};
use crate::{
    curve::{Point, RecoverableSignature, Scalar},
    dev::TestParams,
    entities::{AuxInfo, KeyShare},
    params::SchemeParams,
    tools::{
        protocol_shortcuts::{DowncastMap, MapValues},
        protocol_shortcuts_dev::{check_evidence_with_behavior, check_invalid_message_evidence, CheckPart},
    },
    zk::{ElogProof, ElogPublicInputs, ElogSecretInputs},
};

type Id = TestVerifier;
type P = TestParams;
type SP = TestSessionParams<BinaryFormat>;
type Curve = <TestParams as SchemeParams>::Curve;

#[allow(clippy::type_complexity)]
fn make_entry_points() -> (
    InteractiveSigningAssociatedData<P, Id>,
    Vec<(TestSigner, InteractiveSigning<P, Id>)>,
) {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers.iter().map(TestSigner::verifying_key).collect::<BTreeSet<_>>();

    let key_shares = KeyShare::<TestParams, TestVerifier>::new_centralized(&mut OsRng, &all_ids, None);
    let aux_infos = AuxInfo::new_centralized(&mut OsRng, &all_ids);

    let mut message = FieldBytes::<Curve>::default();
    OsRng.fill_bytes(&mut message);

    let entry_points = signers
        .into_iter()
        .map(|signer| {
            let id = signer.verifying_key();
            let entry_point =
                InteractiveSigning::new(message, key_shares[&id].clone(), aux_infos[&id].clone()).unwrap();
            (signer, entry_point)
        })
        .collect();

    let id = all_ids.first().unwrap();
    let associated_data = InteractiveSigningAssociatedData {
        shares: key_shares[id].public().clone(),
        aux: aux_infos[id].public().clone(),
        message,
    };

    (associated_data, entry_points)
}

fn check_evidence<M>(expected_description: &str) -> Result<(), LocalError>
where
    M: Misbehaving<Id, (), EntryPoint = InteractiveSigning<P, Id>>,
{
    let (associated_data, entry_points) = make_entry_points();
    check_evidence_with_behavior::<SP, M, _>(&mut OsRng, entry_points, &(), &associated_data, expected_description)
}

mod invalid_messages {
    use super::*;

    #[test]
    fn echo() {
        // Note that this test checks the happy path only. The error rounds need to be triggered explicitly,
        // so they are checked in a separate test.

        let (associated_data, entry_points) = make_entry_points();

        for (round_id, expecting_messages) in [(1, true), (2, true), (3, true), (4, false)] {
            check_invalid_message_evidence::<SP, _>(
                &mut OsRng,
                entry_points.clone(),
                round_id,
                CheckPart::EchoBroadcast,
                &associated_data,
                expecting_messages,
            )
            .unwrap();
        }
    }

    #[test]
    fn normal() {
        // Note that this test checks the happy path only. The error rounds need to be triggered explicitly,
        // so they are checked in a separate test.

        let (associated_data, entry_points) = make_entry_points();

        for (round_id, expecting_messages) in [(1, false), (2, true), (3, true), (4, true)] {
            check_invalid_message_evidence::<SP, _>(
                &mut OsRng,
                entry_points.clone(),
                round_id,
                CheckPart::NormalBroadcast,
                &associated_data,
                expecting_messages,
            )
            .unwrap();
        }
    }

    #[test]
    fn direct_message() {
        // Note that this test checks the happy path only. The error rounds need to be triggered explicitly,
        // so they are checked in a separate test.

        let (associated_data, entry_points) = make_entry_points();

        for (round_id, expecting_messages) in [(1, true), (2, false), (3, false), (4, false)] {
            check_invalid_message_evidence::<SP, _>(
                &mut OsRng,
                entry_points.clone(),
                round_id,
                CheckPart::DirectMessage,
                &associated_data,
                expecting_messages,
            )
            .unwrap();
        }
    }
}

#[test]
fn r1_enc_elg_0_failed() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_echo_broadcast(
            rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,
            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            if round.id() == 1 {
                let mut message = echo_broadcast.deserialize::<Round1EchoBroadcast<P>>(format).unwrap();
                message.cap_a1 = Scalar::random(rng).mul_by_generator();
                return EchoBroadcast::new(format, message);
            }

            Ok(echo_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 1: failed to verify `\\psi^0` (`П^{enc-elg}` proof).").unwrap();
}

#[test]
fn r1_enc_elg_1_failed() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_echo_broadcast(
            rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,
            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            if round.id() == 1 {
                let mut message = echo_broadcast.deserialize::<Round1EchoBroadcast<P>>(format).unwrap();
                message.cap_b1 = Scalar::random(rng).mul_by_generator();
                return EchoBroadcast::new(format, message);
            }

            Ok(echo_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 1: failed to verify `\\psi^1` (`П^{enc-elg}` proof).").unwrap();
}

#[test]
fn r2_wrong_ids_d() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_normal_broadcast(
            _rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,
            normal_broadcast: NormalBroadcast,
        ) -> Result<NormalBroadcast, LocalError> {
            if round.id() == 2 {
                let mut message = normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(format)
                    .unwrap();
                message.cap_ds.pop_first();
                return NormalBroadcast::new(format, message);
            }

            Ok(normal_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 2: wrong IDs in `D` map.").unwrap();
}

#[test]
fn r2_wrong_ids_f() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_echo_broadcast(
            _rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,
            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            if round.id() == 2 {
                let mut message = echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(format)
                    .unwrap();
                message.cap_fs.pop_first();
                return EchoBroadcast::new(format, message);
            }

            Ok(echo_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 2: wrong IDs in `F` map.").unwrap();
}

#[test]
fn r2_wrong_ids_psi() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_normal_broadcast(
            _rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,
            normal_broadcast: NormalBroadcast,
        ) -> Result<NormalBroadcast, LocalError> {
            if round.id() == 2 {
                let mut message = normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(format)
                    .unwrap();
                message.psis.pop_first();
                return NormalBroadcast::new(format, message);
            }

            Ok(normal_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 2: wrong IDs in `\\psi` map (`П^{aff-g}` proofs for `D`).")
        .unwrap();
}

#[test]
fn r2_aff_g_psi_failed() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_echo_broadcast(
            rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,
            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            if round.id() == 2 {
                let mut message = echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P, Id>>(format)
                    .unwrap();
                message.cap_gamma = Scalar::random(rng).mul_by_generator();
                return EchoBroadcast::new(format, message);
            }

            Ok(echo_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 2: failed to verify `\\psi` (`П^{aff-g}` proof for `D`).")
        .unwrap();
}

#[test]
fn r2_aff_g_hat_psi_failed() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_normal_broadcast(
            _rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,
            normal_broadcast: NormalBroadcast,
        ) -> Result<NormalBroadcast, LocalError> {
            if round.id() == 2 {
                let mut message = normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(format)
                    .unwrap();
                message.hat_cap_ds = message.cap_ds.clone();
                return NormalBroadcast::new(format, message);
            }

            Ok(normal_broadcast)
        }
    }

    check_evidence::<Override>(
        "Protocol error: Round 2: failed to verify `\\hat{psi}` (`П^{aff-g}` proof for `\\hat{D}`).",
    )
    .unwrap();
}

#[test]
fn r2_elog_failed() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_normal_broadcast(
            rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,

            normal_broadcast: NormalBroadcast,
        ) -> Result<NormalBroadcast, LocalError> {
            if round.id() == 2 {
                let round2 = round.downcast_ref::<Round2<P, Id>>()?;
                let aux = (&round2.context.epid, &round2.context.my_id);

                // An invalid `y`
                let y = Scalar::random(rng);
                let cap_y = y.mul_by_generator();
                let cap_b1 = round2.context.b.mul_by_generator();
                let cap_b2 = cap_y * &round2.context.b + round2.context.gamma.mul_by_generator();

                let mut message = normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P, Id>>(format)
                    .unwrap();

                // We can't replace any dependent values in the messages because
                // it will trigger errors in earlier proofs.
                // So we're replacing the elog proof itself, with one incorrect value (`y`).

                message.psi_elog = ElogProof::new(
                    rng,
                    ElogSecretInputs {
                        y: &round2.context.gamma,
                        lambda: &round2.context.b,
                    },
                    // Note that the parameter order in the protocol description
                    // and in the ZK proof description do not match.
                    ElogPublicInputs {
                        cap_l: &cap_b1,
                        cap_m: &cap_b2,
                        cap_x: &cap_y,
                        cap_y: &round2.cap_gamma,
                        h: &Point::generator(),
                    },
                    &aux,
                );
                return NormalBroadcast::new(format, message);
            }

            Ok(normal_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 2: failed to verify `П^{elog}` proof.").unwrap();
}

#[test]
fn r3_elog_failed() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_normal_broadcast(
            rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,

            normal_broadcast: NormalBroadcast,
        ) -> Result<NormalBroadcast, LocalError> {
            if round.id() == 3 {
                let mut message = normal_broadcast
                    .deserialize::<Round3NormalBroadcast<P>>(format)
                    .unwrap();
                message.cap_delta = Scalar::random(rng).mul_by_generator();
                return NormalBroadcast::new(format, message);
            }

            Ok(normal_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 3: failed to verify `П^{elog}` proof.").unwrap();
}

#[test]
fn r4_invalid_signature_share() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_normal_broadcast(
            rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,

            normal_broadcast: NormalBroadcast,
        ) -> Result<NormalBroadcast, LocalError> {
            if round.id() == 4 {
                let mut message = normal_broadcast
                    .deserialize::<Round4NormalBroadcast<P>>(format)
                    .unwrap();
                message.sigma = Scalar::random(rng);
                return NormalBroadcast::new(format, message);
            }

            Ok(normal_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 4: signature share verification failed.").unwrap();
}

fn force_round5_on_malicious_node(
    rng: &mut dyn CryptoRngCore,
    round: BoxedRound<Id, InteractiveSigningProtocol<P, Id>>,
    payloads: BTreeMap<Id, Payload>,
    artifacts: BTreeMap<Id, Artifact>,
) -> Result<FinalizeOverride<Id, InteractiveSigningProtocol<P, Id>>, LocalError> {
    if round.id() == 3 {
        // Manually start the error round in the malicious node

        let round3 = round.downcast::<Round3<P, Id>>()?;
        let payloads = payloads.downcast_all::<Round3Payload<P>>()?;

        let mut deltas = payloads.map_values(|payload| payload.delta);
        deltas.insert(round3.context.my_id, round3.r3_echo_broadcast.delta);

        let mut cap_ks = round3.r1_payloads.map_values_ref(|payload| payload.cap_k.clone());
        cap_ks.insert(round3.context.my_id, round3.cap_k);

        let outcome = FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round5 {
            context: round3.context,
            deltas,
            betas: round3.betas,
            ss: round3.ss,
            rs: round3.rs,
            cap_gammas: round3.cap_gammas,
            cap_ks,
            cap_ds: round3.cap_ds,
            cap_fs: round3.cap_fs,
        }));

        return Ok(FinalizeOverride::Override(outcome));
    }

    if round.id() == 5 {
        // Return a bogus signature in the malicious node,
        // so that it finishes successfully.
        // Since it's the only malicious node, all the messages it receives will contain
        // valid correctness proofs, which will normally lead to a finalization error.
        return Ok(FinalizeOverride::Override(FinalizeOutcome::Result(
            RecoverableSignature::random(rng).ok_or_else(|| LocalError::new("Failed to create signature"))?,
        )));
    }

    Ok(FinalizeOverride::UseDefault {
        round,
        payloads,
        artifacts,
    })
}

#[test]
fn r5_dec_failed() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_echo_broadcast(
            rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,

            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            if round.id() == 3 {
                // Trigger the error round in lawful nodes
                let mut message = echo_broadcast.deserialize::<Round3EchoBroadcast<P>>(format).unwrap();
                message.delta = Scalar::random(rng);
                return EchoBroadcast::new(format, message);
            }

            Ok(echo_broadcast)
        }

        fn override_finalize(
            rng: &mut dyn CryptoRngCore,
            round: BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            payloads: BTreeMap<Id, Payload>,
            artifacts: BTreeMap<Id, Artifact>,
        ) -> Result<FinalizeOverride<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>, LocalError> {
            force_round5_on_malicious_node(rng, round, payloads, artifacts)
        }
    }

    check_evidence::<Override>("Protocol error: Round 5: `П^{dec}` proof verification failed.").unwrap();
}

mod invalid_r5_messages {
    use super::*;
    struct Override;

    impl Misbehaving<Id, CheckPart> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_echo_broadcast(
            rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            behavior: &CheckPart,
            format: &BoxedFormat,

            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            if round.id() == 3 {
                // Trigger the error round in lawful nodes
                let mut message = echo_broadcast.deserialize::<Round3EchoBroadcast<P>>(format).unwrap();
                message.delta = Scalar::random(rng);
                return EchoBroadcast::new(format, message);
            }

            // Actual test: supply an invalid message on the malicious node
            if round.id() == 5 && behavior == &CheckPart::EchoBroadcast {
                return EchoBroadcast::new::<[u8; 0]>(format, []);
            }

            Ok(echo_broadcast)
        }

        fn modify_normal_broadcast(
            _rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            behavior: &CheckPart,
            format: &BoxedFormat,
            normal_broadcast: NormalBroadcast,
        ) -> Result<NormalBroadcast, LocalError> {
            // Actual test: supply an invalid message on the malicious node
            if round.id() == 5 && behavior == &CheckPart::NormalBroadcast {
                return NormalBroadcast::new::<[u8; 0]>(format, []);
            }

            Ok(normal_broadcast)
        }

        fn modify_direct_message(
            _rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            behavior: &CheckPart,
            format: &BoxedFormat,
            _destination: &Id,
            direct_message: DirectMessage,
            artifact: Option<Artifact>,
        ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
            // Actual test: supply an invalid message on the malicious node
            if round.id() == 5 && behavior == &CheckPart::DirectMessage {
                let dm = DirectMessage::new::<[u8; 0]>(format, [])?;
                return Ok((dm, artifact));
            }

            Ok((direct_message, artifact))
        }

        fn override_finalize(
            rng: &mut dyn CryptoRngCore,
            round: BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &CheckPart,
            payloads: BTreeMap<Id, Payload>,
            artifacts: BTreeMap<Id, Artifact>,
        ) -> Result<FinalizeOverride<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>, LocalError> {
            force_round5_on_malicious_node(rng, round, payloads, artifacts)
        }
    }

    #[test]
    fn echo() {
        let (associated_data, entry_points) = make_entry_points();

        check_evidence_with_behavior::<SP, Override, _>(
            &mut OsRng,
            entry_points.clone(),
            &CheckPart::EchoBroadcast,
            &associated_data,
            "Echo broadcast error: Deserialization error",
        )
        .unwrap();
    }

    #[test]
    fn normal() {
        let (associated_data, entry_points) = make_entry_points();

        check_evidence_with_behavior::<SP, Override, _>(
            &mut OsRng,
            entry_points.clone(),
            &CheckPart::NormalBroadcast,
            &associated_data,
            "Normal broadcast error: The payload was expected to be `None`, but contains a message",
        )
        .unwrap();
    }

    #[test]
    fn direct_message() {
        let (associated_data, entry_points) = make_entry_points();

        check_evidence_with_behavior::<SP, Override, _>(
            &mut OsRng,
            entry_points.clone(),
            &CheckPart::DirectMessage,
            &associated_data,
            "Direct message error: The payload was expected to be `None`, but contains a message",
        )
        .unwrap();
    }
}

fn force_round6_on_malicious_node(
    rng: &mut dyn CryptoRngCore,
    round: BoxedRound<Id, InteractiveSigningProtocol<P, Id>>,
    payloads: BTreeMap<Id, Payload>,
    artifacts: BTreeMap<Id, Artifact>,
) -> Result<FinalizeOverride<Id, InteractiveSigningProtocol<P, Id>>, LocalError> {
    if round.id() == 3 {
        // Manually start the error round in the malicious node

        let round3 = round.downcast::<Round3<P, Id>>()?;
        let payloads = payloads.downcast_all::<Round3Payload<P>>()?;

        let mut cap_ks = round3.r1_payloads.map_values_ref(|payload| payload.cap_k.clone());
        cap_ks.insert(round3.context.my_id, round3.cap_k);

        let mut cap_ss = payloads.map_values_ref(|payload| payload.cap_s);
        cap_ss.insert(round3.context.my_id, round3.r3_normal_broadcast.cap_s);

        let outcome = FinalizeOutcome::AnotherRound(BoxedRound::new_dynamic(Round6 {
            context: round3.context,
            cap_gamma_combined: round3.cap_gamma_combined,
            hat_betas: round3.hat_betas,
            hat_ss: round3.hat_ss,
            hat_rs: round3.hat_rs,
            cap_ks,
            cap_ss,
            hat_cap_ds: round3.hat_cap_ds,
            hat_cap_fs: round3.hat_cap_fs,
        }));

        return Ok(FinalizeOverride::Override(outcome));
    }

    if round.id() == 6 {
        // Return a bogus signature in the malicious node,
        // so that it finishes successfully.
        // Since it's the only malicious node, all the messages it receives will contain
        // valid correctness proofs, which will normally lead to a finalization error.
        return Ok(FinalizeOverride::Override(FinalizeOutcome::Result(
            RecoverableSignature::random(rng).ok_or_else(|| LocalError::new("Failed to create signature"))?,
        )));
    }

    Ok(FinalizeOverride::UseDefault {
        round,
        payloads,
        artifacts,
    })
}

#[test]
fn r6_dec_failed() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_normal_broadcast(
            rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,

            normal_broadcast: NormalBroadcast,
        ) -> Result<NormalBroadcast, LocalError> {
            // Actual test: supply an invalid message on the malicious node
            if round.id() == 3 {
                // Trigger the error round in lawful nodes
                let mut message = normal_broadcast
                    .deserialize::<Round3NormalBroadcast<P>>(format)
                    .unwrap();
                message.cap_s = Scalar::random(rng).mul_by_generator();
                return NormalBroadcast::new(format, message);
            }

            Ok(normal_broadcast)
        }

        fn override_finalize(
            rng: &mut dyn CryptoRngCore,
            round: BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            payloads: BTreeMap<Id, Payload>,
            artifacts: BTreeMap<Id, Artifact>,
        ) -> Result<FinalizeOverride<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>, LocalError> {
            force_round6_on_malicious_node(rng, round, payloads, artifacts)
        }
    }

    check_evidence::<Override>("Protocol error: Round 6: `П^{dec}` proof verification failed.").unwrap();
}

mod invalid_r6_messages {
    use super::*;
    struct Override;

    impl Misbehaving<Id, CheckPart> for Override {
        type EntryPoint = InteractiveSigning<P, Id>;

        fn modify_echo_broadcast(
            _rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            behavior: &CheckPart,
            format: &BoxedFormat,
            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            // Actual test: supply an invalid message on the malicious node
            if round.id() == 6 && behavior == &CheckPart::EchoBroadcast {
                return EchoBroadcast::new::<[u8; 0]>(format, []);
            }

            Ok(echo_broadcast)
        }

        fn modify_normal_broadcast(
            rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            behavior: &CheckPart,
            format: &BoxedFormat,

            normal_broadcast: NormalBroadcast,
        ) -> Result<NormalBroadcast, LocalError> {
            if round.id() == 3 {
                // Trigger the error round in lawful nodes
                let mut message = normal_broadcast
                    .deserialize::<Round3NormalBroadcast<P>>(format)
                    .unwrap();
                message.cap_s = Scalar::random(rng).mul_by_generator();
                return NormalBroadcast::new(format, message);
            }

            // Actual test: supply an invalid message on the malicious node
            if round.id() == 6 && behavior == &CheckPart::NormalBroadcast {
                return NormalBroadcast::new::<[u8; 0]>(format, []);
            }

            Ok(normal_broadcast)
        }

        fn modify_direct_message(
            _rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            behavior: &CheckPart,
            format: &BoxedFormat,
            _destination: &Id,
            direct_message: DirectMessage,
            artifact: Option<Artifact>,
        ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
            // Actual test: supply an invalid message on the malicious node
            if round.id() == 6 && behavior == &CheckPart::DirectMessage {
                let dm = DirectMessage::new::<[u8; 0]>(format, [])?;
                return Ok((dm, artifact));
            }

            Ok((direct_message, artifact))
        }

        fn override_finalize(
            rng: &mut dyn CryptoRngCore,
            round: BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &CheckPart,
            payloads: BTreeMap<Id, Payload>,
            artifacts: BTreeMap<Id, Artifact>,
        ) -> Result<FinalizeOverride<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>, LocalError> {
            force_round6_on_malicious_node(rng, round, payloads, artifacts)
        }
    }

    #[test]
    fn echo() {
        let (associated_data, entry_points) = make_entry_points();

        check_evidence_with_behavior::<SP, Override, _>(
            &mut OsRng,
            entry_points.clone(),
            &CheckPart::EchoBroadcast,
            &associated_data,
            "Echo broadcast error: Deserialization error",
        )
        .unwrap();
    }

    #[test]
    fn normal() {
        let (associated_data, entry_points) = make_entry_points();

        check_evidence_with_behavior::<SP, Override, _>(
            &mut OsRng,
            entry_points.clone(),
            &CheckPart::NormalBroadcast,
            &associated_data,
            "Normal broadcast error: The payload was expected to be `None`, but contains a message",
        )
        .unwrap();
    }

    #[test]
    fn direct_message() {
        let (associated_data, entry_points) = make_entry_points();

        check_evidence_with_behavior::<SP, Override, _>(
            &mut OsRng,
            entry_points.clone(),
            &CheckPart::DirectMessage,
            &associated_data,
            "Direct message error: The payload was expected to be `None`, but contains a message",
        )
        .unwrap();
    }
}
