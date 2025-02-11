use alloc::collections::BTreeSet;

use manul::{
    combinators::misbehave::Misbehaving,
    dev::{BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
    protocol::{
        Artifact, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EntryPoint, LocalError, NormalBroadcast,
        ProtocolMessagePart, Serializer,
    },
    signature::Keypair,
};
use rand_chacha::ChaCha8Rng;
use rand_core::{CryptoRngCore, OsRng, SeedableRng};

use super::{
    aux_gen::{
        AuxGen, AuxGenAssociatedData, Round1, Round1EchoBroadcast, Round2EchoBroadcast, Round2NormalBroadcast,
        Round3DirectMessage, Round3NormalBroadcast,
    },
    params::{SchemeParams, TestParams},
    sigma::{FacProof, ModProof, PrmProof},
};
use crate::{
    paillier::{PaillierParams, PublicKeyPaillierWire, RPParams, RPParamsWire, RPSecret, SecretKeyPaillierWire},
    tools::{
        hashing::FofHasher,
        protocol_shortcuts_dev::{check_evidence_with_behavior, check_invalid_message_evidence, CheckPart},
    },
};

type Id = TestVerifier;
type P = TestParams;
type SP = TestSessionParams<BinaryFormat>;

#[allow(clippy::type_complexity)]
fn make_entry_points() -> (AuxGenAssociatedData<Id>, Vec<(TestSigner, AuxGen<P, Id>)>) {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers.iter().map(TestSigner::verifying_key).collect::<BTreeSet<_>>();

    let entry_points = signers
        .into_iter()
        .map(|signer| (signer, AuxGen::new(all_ids.clone()).unwrap()))
        .collect();
    (AuxGenAssociatedData { ids: all_ids }, entry_points)
}

fn check_evidence<M>(expected_description: &str) -> Result<(), LocalError>
where
    M: Misbehaving<Id, (), EntryPoint = AuxGen<P, Id>>,
{
    let (associated_data, entry_points) = make_entry_points().clone();
    check_evidence_with_behavior::<SP, M, _>(&mut OsRng, entry_points, &(), &associated_data, expected_description)
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
        true,
    )
    .unwrap();
}

#[test]
fn r2_hash_mismatch() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = AuxGen<P, Id>;

        fn modify_echo_broadcast(
            _rng: &mut impl CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            serializer: &Serializer,
            _deserializer: &Deserializer,
            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            if round.id() == 1 {
                // Send a wrong hash in the Round 1 message
                let message = Round1EchoBroadcast {
                    cap_v: FofHasher::new_with_dst(b"bad hash").finalize(),
                };
                let echo_broadcast = EchoBroadcast::new(serializer, message)?;
                return Ok(echo_broadcast);
            }

            Ok(echo_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 2: the previously sent hash does not match the public data.")
        .unwrap();
}

#[test]
fn r2_paillier_modulus_too_small() {
    fn make_small_modulus_pk<P: PaillierParams>() -> PublicKeyPaillierWire<P> {
        let mut rng = ChaCha8Rng::seed_from_u64(123);
        let paillier_sk = SecretKeyPaillierWire::<P>::random_small(&mut rng);
        paillier_sk.public_key()
    }

    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = AuxGen<P, Id>;

        fn modify_normal_broadcast(
            _rng: &mut impl CryptoRngCore,
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
                message.paillier_pk = make_small_modulus_pk::<<P as SchemeParams>::Paillier>();
                let normal_broadcast = NormalBroadcast::new(serializer, message)?;
                return Ok(normal_broadcast);
            }

            Ok(normal_broadcast)
        }

        fn modify_echo_broadcast(
            _rng: &mut impl CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            serializer: &Serializer,
            _deserializer: &Deserializer,
            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            if round.id() == 1 {
                let round1 = round.downcast_ref::<Round1<P, Id>>()?;
                let mut data = round1.public_data.clone();
                data.paillier_pk = make_small_modulus_pk::<<P as SchemeParams>::Paillier>().into_precomputed();
                let message = Round1EchoBroadcast {
                    cap_v: data.hash(&round1.context.sid, &round1.context.my_id),
                };
                let echo_broadcast = EchoBroadcast::new(serializer, message)?;
                return Ok(echo_broadcast);
            }

            Ok(echo_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 2: Paillier modulus is too small.").unwrap();
}

#[test]
fn r2_rp_modulus_too_small() {
    fn make_small_modulus_rp_params<P: PaillierParams>() -> RPParamsWire<P> {
        let mut rng = ChaCha8Rng::seed_from_u64(123);
        RPParams::random_small(&mut rng).to_wire()
    }

    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = AuxGen<P, Id>;

        fn modify_echo_broadcast(
            _rng: &mut impl CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            serializer: &Serializer,
            deserializer: &Deserializer,
            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            if round.id() == 1 {
                // Technically we only need to modify `X`, but we need to substitute the hash in Round 1 too,
                // so that in Round 2 the hash check could pass and the execution reaches the IDs check.
                let round1 = round.downcast_ref::<Round1<P, Id>>()?;

                let mut data = round1.public_data.clone();
                data.rp_params = make_small_modulus_rp_params::<<P as SchemeParams>::Paillier>().to_precomputed();

                let message = Round1EchoBroadcast {
                    cap_v: data.hash(&round1.context.sid, &round1.context.my_id),
                };
                let echo_broadcast = EchoBroadcast::new(serializer, message)?;
                return Ok(echo_broadcast);
            }

            if round.id() == 2 {
                let mut message = echo_broadcast
                    .deserialize::<Round2EchoBroadcast<P>>(deserializer)
                    .unwrap();
                message.rp_params = make_small_modulus_rp_params::<<P as SchemeParams>::Paillier>();
                let echo_broadcast = EchoBroadcast::new(serializer, message)?;
                return Ok(echo_broadcast);
            }

            Ok(echo_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 2: ring-Pedersent modulus is too small.").unwrap();
}

#[test]
fn r2_prm_failed() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = AuxGen<P, Id>;

        fn modify_echo_broadcast(
            _rng: &mut impl CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            serializer: &Serializer,
            _deserializer: &Deserializer,
            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            if round.id() == 1 {
                let round1 = round.downcast_ref::<Round1<P, Id>>()?;
                let mut data = round1.public_data.clone();

                let mut rng = ChaCha8Rng::seed_from_u64(123);
                let secret = RPSecret::random(&mut rng);
                let rp_params = RPParams::random_with_secret(&mut rng, &secret);
                data.psi = PrmProof::new(&mut rng, &secret, &rp_params, &1u8);

                let message = Round1EchoBroadcast {
                    cap_v: data.hash(&round1.context.sid, &round1.context.my_id),
                };
                let echo_broadcast = EchoBroadcast::new(serializer, message)?;
                return Ok(echo_broadcast);
            }

            Ok(echo_broadcast)
        }

        fn modify_normal_broadcast(
            _rng: &mut impl CryptoRngCore,
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

                let mut rng = ChaCha8Rng::seed_from_u64(123);
                let secret = RPSecret::random(&mut rng);
                let rp_params = RPParams::random_with_secret(&mut rng, &secret);
                message.psi = PrmProof::new(&mut rng, &secret, &rp_params, &1u8);

                let normal_broadcast = NormalBroadcast::new(serializer, message)?;
                return Ok(normal_broadcast);
            }

            Ok(normal_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 2: `П^{prm}` verification failed.").unwrap();
}

#[test]
fn r3_mod_failed() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = AuxGen<P, Id>;

        fn modify_normal_broadcast(
            rng: &mut impl CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            serializer: &Serializer,
            deserializer: &Deserializer,
            normal_broadcast: NormalBroadcast,
        ) -> Result<NormalBroadcast, LocalError> {
            if round.id() == 3 {
                let mut message = normal_broadcast
                    .deserialize::<Round3NormalBroadcast<P>>(deserializer)
                    .unwrap();

                let sk = SecretKeyPaillierWire::random(rng).into_precomputed();
                message.psi_prime = ModProof::new(rng, &sk, &1u8);

                let normal_broadcast = NormalBroadcast::new(serializer, message)?;
                return Ok(normal_broadcast);
            }

            Ok(normal_broadcast)
        }
    }

    check_evidence::<Override>("Protocol error: Round 3: `П^{mod}` verification failed.").unwrap();
}

#[test]
fn r3_fac_failed() {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = AuxGen<P, Id>;

        fn modify_direct_message(
            rng: &mut impl CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            serializer: &Serializer,
            deserializer: &Deserializer,
            _destination: &Id,
            direct_message: DirectMessage,
            artifact: Option<Artifact>,
        ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
            if round.id() == 3 {
                let mut message = direct_message
                    .deserialize::<Round3DirectMessage<P>>(deserializer)
                    .unwrap();
                let sk = SecretKeyPaillierWire::random(&mut OsRng).into_precomputed();
                let rp_params = RPParams::random(rng);
                message.psi = FacProof::new(rng, &sk, &rp_params, &1u8);
                let direct_message = DirectMessage::new(serializer, message)?;
                return Ok((direct_message, artifact));
            }

            Ok((direct_message, artifact))
        }
    }

    check_evidence::<Override>("Protocol error: Round 3: `П^{fac}` verification failed.").unwrap();
}
