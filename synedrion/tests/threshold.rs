use std::collections::{BTreeMap, BTreeSet};

use digest::typenum::Unsigned;
use ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
use manul::{
    dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
    signature::Keypair,
};
use primeorder::{elliptic_curve::Curve, FieldBytes};
use rand_core::OsRng;
use synedrion::{
    AuxGen, DeriveChildKey, InteractiveSigning, KeyInit, KeyResharing, NewHolder, OldHolder, SchemeParams,
    ThresholdKeyShare,
};
use tracing::info;

fn make_signers(num_parties: usize) -> (Vec<TestSigner>, Vec<TestVerifier>) {
    let signers = (0..num_parties)
        .map(|idx| TestSigner::new(idx as u8))
        .collect::<Vec<_>>();
    let verifiers = signers.iter().map(|signer| signer.verifying_key()).collect::<Vec<_>>();
    (signers, verifiers)
}

#[test_log::test]
fn full_sequence() {
    // type Params = synedrion::ProductionParams112;
    type Params = synedrion::TestParams;
    type C = <Params as SchemeParams>::Curve;
    let now = std::time::Instant::now();
    let t = 3;
    let n = 5;
    let (signers, verifiers) = make_signers(n);

    let all_verifiers = BTreeSet::from_iter(verifiers.iter().cloned());
    let old_holders = BTreeSet::from_iter(verifiers.iter().cloned().take(t));

    // Use first `t` nodes for the initial t-of-t key generation
    let entry_points = signers[..t]
        .iter()
        .map(|signer| {
            let entry_point = KeyInit::<Params, TestVerifier>::new(old_holders.clone()).unwrap();
            (*signer, entry_point)
        })
        .collect();
    info!("Setup took {:?}", now.elapsed());
    let now = std::time::Instant::now();
    info!("\nRunning KeyInit\n");
    let key_shares = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
        .unwrap()
        .results()
        .unwrap();

    // Convert to t-of-t threshold keyshares
    let t_key_shares = key_shares
        .into_iter()
        .map(|(verifier, key_share)| (verifier, ThresholdKeyShare::from_key_share(&key_share)))
        .collect::<BTreeMap<_, _>>();

    // Derive child shares
    let path = "m/0/2/1/4/2".parse().unwrap();
    let child_key_shares = t_key_shares
        .iter()
        .map(|(verifier, key_share)| (verifier, key_share.derive_bip32(&path).unwrap()))
        .collect::<BTreeMap<_, _>>();

    // The full verifying key can be obtained both from the original key shares and child key shares
    let child_vkey = t_key_shares[&verifiers[0]].derive_verifying_key_bip32(&path).unwrap();
    assert_eq!(child_vkey, child_key_shares[&verifiers[0]].verifying_key().unwrap());

    // Reshare to `n` nodes

    // This will need to be published so that new holders can see it and verify the received data
    let new_holder = NewHolder::<Params, _> {
        verifying_key: t_key_shares[&verifiers[0]].verifying_key().unwrap(),
        old_threshold: t_key_shares[&verifiers[0]].threshold(),
        old_holders,
    };

    // Old holders' sessions (which will also hold the newly reshared parts)
    let mut entry_points = (0..t)
        .map(|idx| {
            let entry_point = KeyResharing::<Params, TestVerifier>::new(
                Some(OldHolder {
                    key_share: t_key_shares[&verifiers[idx]].clone(),
                }),
                Some(new_holder.clone()),
                all_verifiers.clone(),
                t,
            );
            (signers[idx], entry_point)
        })
        .collect::<Vec<_>>();

    // New holders' sessions
    let new_holder_entry_points = (t..n)
        .map(|idx| {
            let entry_point =
                KeyResharing::<Params, TestVerifier>::new(None, Some(new_holder.clone()), all_verifiers.clone(), t);
            (signers[idx], entry_point)
        })
        .collect::<Vec<_>>();

    entry_points.extend(new_holder_entry_points);
    info!("KeyInit took {:?}", now.elapsed());
    let now = std::time::Instant::now();
    info!("\nRunning KeyReshare\n");
    let new_t_key_shares = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
        .unwrap()
        .results()
        .unwrap();

    // All the nodes are holders now, we can unwrap the Options.
    let new_t_key_shares = new_t_key_shares
        .into_iter()
        .map(|(verifier, key_share)| (verifier, key_share.unwrap()))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        new_t_key_shares[&verifiers[0]].verifying_key().unwrap(),
        t_key_shares[&verifiers[0]].verifying_key().unwrap()
    );

    // Check that resharing did not change the derived child key
    let child_vkey_after_resharing = new_t_key_shares[&verifiers[0]]
        .derive_verifying_key_bip32(&path)
        .unwrap();
    assert_eq!(child_vkey, child_vkey_after_resharing);

    // Generate auxiliary data

    let entry_points = (0..n)
        .map(|idx| {
            let entry_point = AuxGen::<Params, TestVerifier>::new(all_verifiers.clone()).unwrap();
            (signers[idx], entry_point)
        })
        .collect::<Vec<_>>();

    info!("KeyReshare took {:?}", now.elapsed());
    let now = std::time::Instant::now();
    let runsync_t = std::time::Instant::now();
    let aux_infos = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
        .unwrap()
        .results()
        .unwrap();
    info!("run_sync AuxInfo took {:?}", runsync_t.elapsed());

    // For signing, we select `t` parties and these parties:
    // - derive child key shares
    // - convert their threshold key shares into regular key shares.

    let selected_signers = [signers[0], signers[2], signers[4]];
    let selected_parties = BTreeSet::from([verifiers[0], verifiers[2], verifiers[4]]);
    let selected_key_shares = [
        new_t_key_shares[&verifiers[0]]
            .derive_bip32(&path)
            .unwrap()
            .to_key_share(&selected_parties)
            .unwrap(),
        new_t_key_shares[&verifiers[2]]
            .derive_bip32(&path)
            .unwrap()
            .to_key_share(&selected_parties)
            .unwrap(),
        new_t_key_shares[&verifiers[4]]
            .derive_bip32(&path)
            .unwrap()
            .to_key_share(&selected_parties)
            .unwrap(),
    ];
    let selected_aux_infos = [
        aux_infos[&verifiers[0]].clone().subset(&selected_parties).unwrap(),
        aux_infos[&verifiers[2]].clone().subset(&selected_parties).unwrap(),
        aux_infos[&verifiers[4]].clone().subset(&selected_parties).unwrap(),
    ];

    // Perform signing with the key shares

    let message =
        FieldBytes::<C>::from_slice(&b"abcdefghijklmnopqrstuvwxyz123456"[..<C as Curve>::FieldBytesSize::USIZE]);

    let entry_points = (0..3)
        .map(|idx| {
            let entry_point = InteractiveSigning::new(
                *message,
                selected_key_shares[idx].clone(),
                selected_aux_infos[idx].clone(),
            )
            .unwrap();
            (selected_signers[idx], entry_point)
        })
        .collect();

    info!("AuxGen took {:?}", now.elapsed()); // ~42 sec
    let now = std::time::Instant::now();
    info!("\nRunning InteractiveSigning\n"); // ~3 sec
    let signatures = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points)
        .unwrap()
        .results()
        .unwrap();

    for (_verifier, signature) in signatures {
        let (sig, rec_id) = signature.to_backend();

        // TODO(dp): bip32 dependent
        // Check that the signature can be verified
        child_vkey.verify_prehash(message, &sig).unwrap();

        // Check that the key can be recovered
        let recovered_key = VerifyingKey::recover_from_prehash(message, &sig, rec_id).unwrap();
        // TODO(dp): bip32 dependent
        assert_eq!(recovered_key, child_vkey);
    }
    info!("Done. Interactive signing took {:?}", now.elapsed());
}
