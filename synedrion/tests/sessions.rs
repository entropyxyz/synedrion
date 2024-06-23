use std::collections::{BTreeMap, BTreeSet};

use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, SigningKey, VerifyingKey};
use rand::Rng;
use rand_core::OsRng;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use synedrion::{
    make_interactive_signing_session, make_key_gen_session, AuxInfo, MessageBundle,
    FinalizeOutcome, KeyShare, ProtocolResult, Session, TestParams,
};

type MessageOut = (VerifyingKey, VerifyingKey, MessageBundle<Signature>);
type MessageIn = (VerifyingKey, MessageBundle<Signature>);

fn key_to_str(key: &VerifyingKey) -> String {
    hex::encode(&key.to_encoded_point(true).as_bytes()[1..5])
}

async fn run_session<Res: ProtocolResult>(
    tx: mpsc::Sender<MessageOut>,
    rx: mpsc::Receiver<MessageIn>,
    session: Session<Res, Signature, SigningKey, VerifyingKey>,
) -> Res::Success {
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
) -> Vec<Res::Success>
where
    Res: ProtocolResult + Send + 'static,
    Res::Success: Send,
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

    let handles: Vec<tokio::task::JoinHandle<Res::Success>> = rxs
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
async fn keygen_and_aux() {
    let num_parties = 3;
    let (signers, verifiers) = make_signers(num_parties);
    let verifiers_set = BTreeSet::from_iter(verifiers.iter().cloned());

    let shared_randomness = b"1234567890";

    let sessions = signers
        .into_iter()
        .map(|signer| {
            make_key_gen_session::<TestParams, Signature, _, _>(
                &mut OsRng,
                shared_randomness,
                signer,
                &verifiers_set,
            )
            .unwrap()
        })
        .collect();

    let (key_shares, _aux_infos): (Vec<_>, Vec<_>) = run_nodes(sessions).await.into_iter().unzip();

    for (idx, key_share) in key_shares.iter().enumerate() {
        assert_eq!(key_share.owner(), &verifiers[idx]);
        assert_eq!(key_share.all_parties(), verifiers_set);
        assert_eq!(key_share.verifying_key(), key_shares[0].verifying_key());
    }
}

#[tokio::test]
async fn interactive_signing() {
    let num_parties = 3;
    let (signers, verifiers) = make_signers(num_parties);
    let verifiers_set = BTreeSet::from_iter(verifiers.iter().cloned());

    let key_shares =
        KeyShare::<TestParams, VerifyingKey>::new_centralized(&mut OsRng, &verifiers_set, None);
    let aux_infos =
        AuxInfo::<TestParams, VerifyingKey>::new_centralized(&mut OsRng, &verifiers_set);

    let shared_randomness = b"1234567890";
    let message = b"abcdefghijklmnopqrstuvwxyz123456";

    let sessions = (0..num_parties)
        .map(|idx| {
            make_interactive_signing_session::<_, Signature, _, _>(
                &mut OsRng,
                shared_randomness,
                signers[idx].clone(),
                &verifiers_set,
                &key_shares[&verifiers[idx]],
                &aux_infos[&verifiers[idx]],
                message,
            )
            .unwrap()
        })
        .collect();

    let signatures = run_nodes(sessions).await;

    for signature in signatures {
        let (sig, rec_id) = signature.to_backend();
        let vkey = key_shares[&verifiers[0]].verifying_key();

        // Check that the signature can be verified
        vkey.verify_prehash(message, &sig).unwrap();

        // Check that the key can be recovered
        let recovered_key = VerifyingKey::recover_from_prehash(message, &sig, rec_id).unwrap();
        assert_eq!(recovered_key, vkey);
    }
}
