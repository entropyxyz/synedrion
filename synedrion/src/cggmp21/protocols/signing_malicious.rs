use alloc::collections::BTreeSet;
use core::marker::PhantomData;

use manul::{
    combinators::misbehave::{Misbehaving, MisbehavingEntryPoint},
    dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
    protocol::{
        BoxedRound, Deserializer, EntryPoint, LocalError, NormalBroadcast, PartyId, ProtocolMessagePart, RoundId,
        Serializer,
    },
    session::signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng, RngCore};

use super::{
    super::SchemeParams,
    interactive_signing::{InteractiveSigning, Round4Message},
};
use crate::{
    cggmp21::{AuxInfo, KeyShare, TestParams},
    curve::Scalar,
};

#[derive(Debug, Clone, Copy)]
enum Behavior {
    InvalidSigma,
}

struct MaliciousSigningOverride<P>(PhantomData<P>);

impl<P: SchemeParams, Id: PartyId> Misbehaving<Id, Behavior> for MaliciousSigningOverride<P> {
    type EntryPoint = InteractiveSigning<P, Id>;

    fn modify_normal_broadcast(
        rng: &mut impl CryptoRngCore,
        round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
        behavior: &Behavior,
        serializer: &Serializer,
        _deserializer: &Deserializer,
        normal_broadcast: NormalBroadcast,
    ) -> Result<NormalBroadcast, LocalError> {
        let bc = if round.id() == RoundId::new(4) {
            match behavior {
                Behavior::InvalidSigma => {
                    let message = Round4Message {
                        sigma: Scalar::random(rng),
                    };
                    NormalBroadcast::new(serializer, message)?
                }
            }
        } else {
            normal_broadcast
        };
        Ok(bc)
    }
}

type MaliciousSigning<P, Id> = MisbehavingEntryPoint<Id, Behavior, MaliciousSigningOverride<P>>;

#[test]
fn execute_signing() {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let ids = signers.iter().map(|signer| signer.verifying_key()).collect::<Vec<_>>();
    let ids_set = BTreeSet::from_iter(ids.clone());

    let key_shares = KeyShare::<TestParams, TestVerifier>::new_centralized(&mut OsRng, &ids_set, None);
    let aux_infos = AuxInfo::new_centralized(&mut OsRng, &ids_set);

    let mut message = [0u8; 32];
    OsRng.fill_bytes(&mut message);

    let entry_points = signers
        .into_iter()
        .map(|signer| {
            let id = signer.verifying_key();
            let signing = InteractiveSigning::new(message, key_shares[&id].clone(), aux_infos[&id].clone());
            let behavior = if id == ids[0] {
                Some(Behavior::InvalidSigma)
            } else {
                None
            };
            let entry_points = MaliciousSigning::new(signing, behavior);
            (signer, entry_points)
        })
        .collect();

    let mut reports = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
        .unwrap()
        .reports;

    let _report0 = reports.remove(&ids[0]).unwrap();
    let report1 = reports.remove(&ids[1]).unwrap();
    let report2 = reports.remove(&ids[2]).unwrap();

    assert!(!report1.provable_errors.is_empty());
    assert!(!report2.provable_errors.is_empty());
}
