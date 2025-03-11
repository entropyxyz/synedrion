use alloc::collections::BTreeSet;

use manul::{
    combinators::misbehave::Misbehaving,
    dev::{BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
    protocol::{BoxedRound, Deserializer, EntryPoint, LocalError, NormalBroadcast, ProtocolMessagePart, Serializer},
    signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng};

use super::key_init::{KeyInit, KeyInitAssociatedData, Round2NormalBroadcast, Round3, Round3NormalBroadcast};
use crate::{
    curve::Scalar,
    dev::TestParams,
    tools::{
        bitvec::BitVec,
        protocol_shortcuts_dev::{check_evidence_with_behavior, check_invalid_message_evidence, CheckPart},
        Secret,
    },
    zk::SchProof,
};

type Id = TestVerifier;
type P = TestParams;
type SP = TestSessionParams<BinaryFormat>;

#[allow(clippy::type_complexity)]
fn make_entry_points() -> (KeyInitAssociatedData<Id>, Vec<(TestSigner, KeyInit<P, Id>)>) {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points = signers
        .into_iter()
        .map(|signer| (signer, KeyInit::new(all_ids.clone()).unwrap()))
        .collect();

    (KeyInitAssociatedData { ids: all_ids }, entry_points)
}

fn check_evidence<M>(expected_description: &str) -> Result<(), LocalError>
where
    M: Misbehaving<Id, (), EntryPoint = KeyInit<P, Id>>,
{
    let (associated_data, entry_points) = make_entry_points();
    check_evidence_with_behavior::<SP, M, _>(
        &mut OsRng,
        entry_points.clone(),
        &(),
        &associated_data,
        expected_description,
    )
}

#[test]
fn invalid_messages() {
    let (associated_data, entry_points) = make_entry_points();

    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        entry_points.clone(),
        1,
        CheckPart::EchoBroadcast,
        &associated_data,
        true,
    )
    .unwrap();
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        entry_points.clone(),
        2,
        CheckPart::EchoBroadcast,
        &associated_data,
        true,
    )
    .unwrap();
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        entry_points.clone(),
        3,
        CheckPart::EchoBroadcast,
        &associated_data,
        false,
    )
    .unwrap();

    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        entry_points.clone(),
        1,
        CheckPart::NormalBroadcast,
        &associated_data,
        false,
    )
    .unwrap();
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        entry_points.clone(),
        2,
        CheckPart::NormalBroadcast,
        &associated_data,
        true,
    )
    .unwrap();
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        entry_points.clone(),
        3,
        CheckPart::NormalBroadcast,
        &associated_data,
        true,
    )
    .unwrap();

    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        entry_points.clone(),
        1,
        CheckPart::DirectMessage,
        &associated_data,
        false,
    )
    .unwrap();
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        entry_points.clone(),
        2,
        CheckPart::DirectMessage,
        &associated_data,
        false,
    )
    .unwrap();
    check_invalid_message_evidence::<SP, _>(
        &mut OsRng,
        entry_points.clone(),
        3,
        CheckPart::DirectMessage,
        &associated_data,
        false,
    )
    .unwrap();
}

#[test]
fn r2_hash_mismatch() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = KeyInit<P, Id>;

        fn modify_normal_broadcast(
            rng: &mut impl CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            serializer: &Serializer,
            deserializer: &Deserializer,
            normal_broadcast: NormalBroadcast,
        ) -> Result<NormalBroadcast, LocalError> {
            if round.id() == 2 {
                let mut message = normal_broadcast
                    .deserialize::<Round2NormalBroadcast<P>>(deserializer)
                    .unwrap();

                // Replace `u` with something other than we committed to when hashing it in Round 1.
                message.u = BitVec::random(rng, message.u.bits().len());

                return NormalBroadcast::new(serializer, message);
            }

            Ok(normal_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 2: the previously sent hash does not match the public data.")
        .unwrap();
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
                let aux = (&context.sid, &context.my_id, &round3.rho_combined);

                // Make a proof for a random secret. This won't pass verification.
                let x = Secret::init_with(|| Scalar::random(rng));
                let psi = SchProof::new(
                    &context.tau,
                    &x,
                    &context.public_data.cap_a,
                    &x.mul_by_generator(),
                    &aux,
                );

                let message = Round3NormalBroadcast { psi };
                return NormalBroadcast::new(serializer, message);
            }

            Ok(normal_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 3: failed to verify `П^{sch}`").unwrap();
}
