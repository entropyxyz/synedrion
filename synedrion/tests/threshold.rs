use std::collections::BTreeMap;

use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand::Rng;
use rand_core::OsRng;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use synedrion::{
    make_key_init_session, make_key_refresh_session, make_key_resharing_session, CombinedMessage,
    FinalizeOutcome, KeyResharingInputs, MappedResult, NewHolder, OldHolder, Session, TestParams,
    ThresholdKeyShare,
};

type MessageOut = (VerifyingKey, VerifyingKey, CombinedMessage<Signature>);
type MessageIn = (VerifyingKey, CombinedMessage<Signature>);

fn key_to_str(key: &VerifyingKey) -> String {
    hex::encode(&key.to_encoded_point(true).as_bytes()[1..5])
}

async fn run_session<Res: MappedResult<VerifyingKey>>(
    tx: mpsc::Sender<MessageOut>,
    rx: mpsc::Receiver<MessageIn>,
    session: Session<Res, Signature, SigningKey, VerifyingKey>,
) -> Res::MappedSuccess {
    let mut rx = rx;

    let mut session = session;
    let mut cached_messages = Vec::new();

    let key = session.verifier();
    let key_str = key_to_str(&key);

    loop {
        println!(
            "{key_str}: *** starting round {:?} ***",
            session.current_round()
        );

        // This is kept in the main task since it's mutable,
        // and we don't want to bother with synchronization.
        let mut accum = session.make_accumulator();

        // Note: generating/sending messages and verifying newly received messages
        // can be done in parallel, with the results being assembled into `accum`
        // sequentially in the host task.

        let destinations = session.message_destinations();
        for destination in destinations.iter() {
            // In production usage, this will happen in a spawned task
            // (since it can take some time to create a message),
            // and the artifact will be sent back to the host task
            // to be added to the accumulator.
            let (message, artifact) = session.make_message(&mut OsRng, destination).unwrap();
            println!(
                "{key_str}: sending a message to {}",
                key_to_str(destination)
            );
            tx.send((key, *destination, message)).await.unwrap();

            // This will happen in a host task
            accum.add_artifact(artifact).unwrap();
        }

        for preprocessed in cached_messages {
            // In production usage, this will happen in a spawned task.
            println!("{key_str}: applying a cached message");
            let result = session.process_message(preprocessed).unwrap();

            // This will happen in a host task.
            accum.add_processed_message(result).unwrap().unwrap();
        }

        while !session.can_finalize(&accum).unwrap() {
            // This can be checked if a timeout expired, to see which nodes have not responded yet.
            let unresponsive_parties = session.missing_messages(&accum).unwrap();
            assert!(!unresponsive_parties.is_empty());

            println!("{key_str}: waiting for a message");
            let (from, message) = rx.recv().await.unwrap();

            // Perform quick checks before proceeding with the verification.
            let preprocessed = session
                .preprocess_message(&mut accum, &from, message)
                .unwrap();

            if let Some(preprocessed) = preprocessed {
                // In production usage, this will happen in a spawned task.
                println!("{key_str}: applying a message from {}", key_to_str(&from));
                let result = session.process_message(preprocessed).unwrap();

                // This will happen in a host task.
                accum.add_processed_message(result).unwrap().unwrap();
            }
        }

        println!("{key_str}: finalizing the round");

        match session.finalize_round(&mut OsRng, accum).unwrap() {
            FinalizeOutcome::Success(res) => break res,
            FinalizeOutcome::AnotherRound {
                session: new_session,
                cached_messages: new_cached_messages,
            } => {
                session = new_session;
                cached_messages = new_cached_messages;
            }
        }
    }
}

async fn message_dispatcher(
    txs: BTreeMap<VerifyingKey, mpsc::Sender<MessageIn>>,
    rx: mpsc::Receiver<MessageOut>,
) {
    let mut rx = rx;
    let mut messages = Vec::<MessageOut>::new();
    loop {
        let msg = match rx.recv().await {
            Some(msg) => msg,
            None => break,
        };
        messages.push(msg);

        while let Ok(msg) = rx.try_recv() {
            messages.push(msg)
        }

        while !messages.is_empty() {
            // Pull a random message from the list,
            // to increase the chances that they are delivered out of order.
            let message_idx = rand::thread_rng().gen_range(0..messages.len());
            let (id_from, id_to, message) = messages.swap_remove(message_idx);

            txs[&id_to].send((id_from, message)).await.unwrap();

            // Give up execution so that the tasks could process messages.
            sleep(Duration::from_millis(0)).await;

            if let Ok(msg) = rx.try_recv() {
                messages.push(msg);
            };
        }
    }
}

fn make_signers(num_parties: usize) -> (Vec<SigningKey>, Vec<VerifyingKey>) {
    let signers = (0..num_parties)
        .map(|_| SigningKey::random(&mut OsRng))
        .collect::<Vec<_>>();
    let verifiers = signers
        .iter()
        .map(|signer| *signer.verifying_key())
        .collect::<Vec<_>>();
    (signers, verifiers)
}

async fn run_nodes<Res>(
    sessions: Vec<Session<Res, Signature, SigningKey, VerifyingKey>>,
) -> Vec<Res::MappedSuccess>
where
    Res: MappedResult<VerifyingKey> + Send + 'static,
    Res::MappedSuccess: Send + 'static,
{
    let num_parties = sessions.len();

    let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<MessageOut>(100);

    let channels = (0..num_parties).map(|_| mpsc::channel::<MessageIn>(100));
    let (txs, rxs): (Vec<mpsc::Sender<MessageIn>>, Vec<mpsc::Receiver<MessageIn>>) =
        channels.unzip();
    let tx_map = sessions
        .iter()
        .map(|session| session.verifier())
        .zip(txs.into_iter())
        .collect();

    let dispatcher_task = message_dispatcher(tx_map, dispatcher_rx);
    let dispatcher = tokio::spawn(dispatcher_task);

    let handles: Vec<tokio::task::JoinHandle<Res::MappedSuccess>> = rxs
        .into_iter()
        .zip(sessions.into_iter())
        .map(|(rx, session)| {
            let node_task = run_session(dispatcher_tx.clone(), rx, session);
            tokio::spawn(node_task)
        })
        .collect();

    // Drop the last copy of the dispatcher's incoming channel so that it could finish.
    drop(dispatcher_tx);

    let mut results = Vec::with_capacity(num_parties);
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    dispatcher.await.unwrap();

    results
}

#[tokio::test]
async fn full_sequence() {
    let t = 3;
    let n = 5;
    let (signers, verifiers) = make_signers(n);

    let shared_randomness = b"1234567890";

    // Use first `t` nodes for the initial t-of-t key generation
    let sessions = signers[..t]
        .iter()
        .map(|signer| {
            make_key_init_session::<TestParams, Signature, SigningKey, VerifyingKey>(
                &mut OsRng,
                shared_randomness,
                signer.clone(),
                &verifiers[..t],
            )
            .unwrap()
        })
        .collect();

    println!("\nRunning KeyInit\n");
    let key_share_seeds = run_nodes(sessions).await;

    // Convert to t-of-t threshold keyshares
    let t_key_share_seeds = key_share_seeds
        .iter()
        .map(|key_share_seed| key_share_seed.to_threshold_key_share_seed())
        .collect::<Vec<_>>();

    // Reshare the keyshare seeds to `n` nodes

    // This will need to be published so that new holders could see it and verify the received data
    let new_holder = NewHolder {
        verifying_key: t_key_share_seeds[0].verifying_key(),
        old_threshold: t_key_share_seeds[0].threshold(),
        old_holders: verifiers[..t].to_vec(),
    };

    // Old holders' sessions (which will also hold the newly reshared parts)
    let mut sessions = (0..t)
        .map(|idx| {
            let inputs = KeyResharingInputs {
                old_holder: Some(OldHolder {
                    key_share_seed: t_key_share_seeds[idx].clone(),
                }),
                new_holder: Some(new_holder.clone()),
                new_holders: verifiers.clone(),
                new_threshold: t,
            };
            make_key_resharing_session::<TestParams, Signature, SigningKey, VerifyingKey>(
                &mut OsRng,
                shared_randomness,
                signers[idx].clone(),
                &verifiers,
                &inputs,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    // New holders' sessions
    let new_holder_sessions = (t..n)
        .map(|idx| {
            let inputs = KeyResharingInputs {
                old_holder: None,
                new_holder: Some(new_holder.clone()),
                new_holders: verifiers.clone(),
                new_threshold: t,
            };
            make_key_resharing_session::<TestParams, Signature, SigningKey, VerifyingKey>(
                &mut OsRng,
                shared_randomness,
                signers[idx].clone(),
                &verifiers,
                &inputs,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    sessions.extend(new_holder_sessions.into_iter());

    println!("\nRunning KeyReshare\n");
    let new_t_key_share_seeds = run_nodes(sessions).await;

    let new_t_key_share_seeds = new_t_key_share_seeds
        .into_iter()
        .map(|seed| seed.unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        new_t_key_share_seeds[0].verifying_key(),
        t_key_share_seeds[0].verifying_key()
    );

    // Generate auxiliary data
    let sessions = (0..n)
        .map(|idx| {
            make_key_refresh_session::<TestParams, Signature, SigningKey, VerifyingKey>(
                &mut OsRng,
                shared_randomness,
                signers[idx].clone(),
                &verifiers,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    println!("\nRunning KeyRefresh\n");
    let key_share_changes = run_nodes(sessions).await;

    let t_key_shares = new_t_key_share_seeds
        .into_iter()
        .zip(key_share_changes.into_iter())
        .map(|(seed, change)| ThresholdKeyShare::new(seed, change))
        .collect::<Vec<_>>();
}
