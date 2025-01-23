use alloc::collections::BTreeSet;

use manul::{
    combinators::misbehave::Misbehaving,
    dev::{BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
    protocol::{
        BoxedRound, Deserializer, EchoBroadcast, EntryPoint, LocalError, NormalBroadcast, ProtocolMessagePart,
        Serializer,
    },
    signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng};

use super::{
    key_init::{KeyInit, Round2EchoBroadcast, Round3, Round3Broadcast},
    params::TestParams,
    sigma::SchProof,
};
use crate::{
    curve::Scalar,
    tools::{
        bitvec::BitVec,
        protocol_shortcuts_dev::{check_evidence_with_behavior, check_invalid_message_evidence, CheckPart},
        Secret,
    },
};

type Id = TestVerifier;
type P = TestParams;
type SP = TestSessionParams<BinaryFormat>;

fn make_entry_points() -> Vec<(TestSigner, KeyInit<P, Id>)> {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    signers
        .into_iter()
        .map(|signer| (signer, KeyInit::new(all_ids.clone()).unwrap()))
        .collect()
}

fn check_evidence<M>(expected_description: &str) -> Result<(), LocalError>
where
    M: Misbehaving<Id, (), EntryPoint = KeyInit<P, Id>>,
{
    check_evidence_with_behavior::<SP, M, _>(&mut OsRng, make_entry_points().clone(), &(), &(), expected_description)
}

#[test]
fn invalid_messages() {
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        make_entry_points().clone(),
        1,
        CheckPart::EchoBroadcast,
        &(),
        true,
    )
    .unwrap();
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        make_entry_points().clone(),
        2,
        CheckPart::EchoBroadcast,
        &(),
        true,
    )
    .unwrap();
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        make_entry_points().clone(),
        3,
        CheckPart::EchoBroadcast,
        &(),
        false,
    )
    .unwrap();

    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        make_entry_points().clone(),
        1,
        CheckPart::NormalBroadcast,
        &(),
        false,
    )
    .unwrap();
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        make_entry_points().clone(),
        2,
        CheckPart::NormalBroadcast,
        &(),
        false,
    )
    .unwrap();
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        make_entry_points().clone(),
        3,
        CheckPart::NormalBroadcast,
        &(),
        true,
    )
    .unwrap();

    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        make_entry_points().clone(),
        1,
        CheckPart::DirectMessage,
        &(),
        false,
    )
    .unwrap();
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        make_entry_points().clone(),
        2,
        CheckPart::DirectMessage,
        &(),
        false,
    )
    .unwrap();
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        make_entry_points().clone(),
        3,
        CheckPart::DirectMessage,
        &(),
        false,
    )
    .unwrap();
}

#[test]
fn r2_hash_mismatch() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = KeyInit<P, Id>;

        fn modify_echo_broadcast(
            rng: &mut impl CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            serializer: &Serializer,
            deserializer: &Deserializer,
            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            if round.id() == 2 {
                let orig_message = echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P>>(deserializer)
                    .unwrap();
                let mut data = orig_message.data;

                // Replace `u` with something other than we committed to when hashing it in Round 1.
                data.u = BitVec::random(rng, data.u.bits().len());

                let message = Round2EchoBroadcast { data };
                return EchoBroadcast::new(serializer, message);
            }

            Ok(echo_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: A hash mismatch in Round 2").unwrap();
}

#[test]
fn r3_invalid_sch_proof() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = KeyInit<P, Id>;

        fn modify_normal_broadcast(
            rng: &mut impl CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            serializer: &Serializer,
            _deserializer: &Deserializer,
            normal_broadcast: NormalBroadcast,
        ) -> Result<NormalBroadcast, LocalError> {
            if round.id() == 3 {
                let round3 = round.downcast_ref::<Round3<P, Id>>()?;
                let context = &round3.context;
                let aux = (&context.sid_hash, &context.my_id, &round3.rho);

                // Make a proof for a random secret. This won't pass verification.
                let x = Secret::init_with(|| Scalar::random(rng));
                let psi = SchProof::new(
                    &context.tau,
                    &x,
                    &context.public_data.cap_a,
                    &x.mul_by_generator(),
                    &aux,
                );

                let message = Round3Broadcast { psi };
                return NormalBroadcast::new(serializer, message);
            }

            Ok(normal_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Failed to verify `П^sch` in Round 3").unwrap();
}
