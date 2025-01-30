use std::collections::BTreeSet;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use manul::{
    dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
    signature::Keypair,
};
use rand_core::OsRng;
use synedrion::{AuxGen, AuxInfo, InteractiveSigning, KeyInit, KeyShare, TestParams};

fn bench_happy_paths(c: &mut Criterion) {
    let mut group = c.benchmark_group("happy path");

    type SessionParams = TestSessionParams<BinaryFormat>;

    let signers = (0..2).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    group.bench_function("KeyInit, 2 parties", |b| {
        b.iter_batched(
            || {
                signers
                    .iter()
                    .map(|signer| {
                        let entry_point = KeyInit::<TestParams, TestVerifier>::new(all_ids.clone()).unwrap();
                        (*signer, entry_point)
                    })
                    .collect::<Vec<_>>()
            },
            |entry_points| run_sync::<_, SessionParams>(&mut OsRng, entry_points).unwrap(),
            BatchSize::SmallInput,
        )
    });

    let key_shares = KeyShare::new_centralized(&mut OsRng, &all_ids, None);
    let aux_infos = AuxInfo::new_centralized(&mut OsRng, &all_ids);
    let message = [1u8; 32];

    group.sample_size(10);
    group.bench_function("InteractiveSigning, 2 parties", |b| {
        b.iter_batched(
            || {
                signers
                    .iter()
                    .map(|signer| {
                        let id = signer.verifying_key();
                        let entry_point = InteractiveSigning::<TestParams, TestVerifier>::new(
                            message,
                            key_shares[&id].clone(),
                            aux_infos[&id].clone(),
                        );
                        (*signer, entry_point)
                    })
                    .collect::<Vec<_>>()
            },
            |entry_points| run_sync::<_, SessionParams>(&mut OsRng, entry_points).unwrap(),
            BatchSize::LargeInput,
        )
    });

    group.sample_size(20);
    group.bench_function("AuxGen, 2 parties", |b| {
        b.iter_batched(
            || {
                signers
                    .iter()
                    .map(|signer| {
                        let entry_point = AuxGen::<TestParams, TestVerifier>::new(all_ids.clone()).unwrap();
                        (*signer, entry_point)
                    })
                    .collect::<Vec<_>>()
            },
            |entry_points| run_sync::<_, SessionParams>(&mut OsRng, entry_points).unwrap(),
            BatchSize::SmallInput,
        )
    });

    group.finish()
}

criterion_group!(benches, bench_happy_paths);

criterion_main!(benches);
