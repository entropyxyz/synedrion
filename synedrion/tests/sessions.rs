use std::collections::BTreeMap;

use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, SigningKey, VerifyingKey};
use rand::seq::SliceRandom;
use rand_core::OsRng;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use synedrion::{
    sessions::{
        make_interactive_signing_session, make_keygen_and_aux_session, FinalizeOutcome, Session,
        SignedMessage,
    },
    KeyShare, PartyIdx, ProtocolResult, TestParams,
};

type MessageOut = (PartyIdx, PartyIdx, SignedMessage<Signature>);
type MessageIn = (PartyIdx, SignedMessage<Signature>);

async fn run_session<Res: ProtocolResult>(
    tx: mpsc::Sender<MessageOut>,
    rx: mpsc::Receiver<MessageIn>,
    session: Session<Res, Signature, SigningKey, VerifyingKey>,
    party_idx: PartyIdx,
) -> <Res as ProtocolResult>::Success {
    let mut rx = rx;

    let mut session = session;
    let mut cached_messages = Vec::new();

    loop {
        println!(
            "*** {:?}: starting round {:?}",
            party_idx,
            session.current_round()
        );

        // This is kept in the main task since it's mutable,
        // and we don't want to bother with synchronization.
        let mut accum = session.make_accumulator();

        // Note: generating/sending messages, verifying cached messages,
        // and verifying newly received messages can be done in parallel,
        // with the results being assembled into `accum` sequentially in the host task.

        let destinations = session.broadcast_destinations();
        if let Some(destinations) = destinations {
            // In production usage, this will happen in a spawned task
            let message = session.make_broadcast(&mut OsRng).unwrap();
            for idx_to in destinations.iter() {
                println!("{party_idx:?}: sending a broadcast to {idx_to:?}");
                tx.send((party_idx, *idx_to, message.clone()))
                    .await
                    .unwrap();
            }
        }

        let destinations = session.direct_message_destinations();
        if let Some(destinations) = destinations {
            for idx_to in destinations.iter() {
                // In production usage, this will happen in a spawned task
                // (since it can take some time to create a message),
                // and the artefact will be sent back to the host task
                // to be added to the accumulator.
                let (message, artefact) = session.make_direct_message(&mut OsRng, idx_to).unwrap();
                println!("{party_idx:?}: sending a direct message to {idx_to:?}");
                tx.send((party_idx, *idx_to, message)).await.unwrap();

                // This will happen in a host task
                accum.add_artefact(artefact).unwrap();
            }
        }

        for (idx_from, message) in cached_messages {
            // In production usage, this will happen in a spawned task.
            println!("{party_idx:?}: applying a cached message from {idx_from:?}");
            let result = session.verify_message(idx_from, message).unwrap();

            // This will happen in a host task.
            accum.add_processed_message(result).unwrap();
        }

        while !session.can_finalize(&accum) {
            println!("{party_idx:?}: waiting for a message");
            let (idx_from, message) = rx.recv().await.unwrap();

            // TODO: check here that the message from this origin hasn't been already processed
            // if accum.already_processed(message) { ... }

            // In production usage, this will happen in a spawned task.
            println!("{party_idx:?}: applying a message from {idx_from:?}");
            let result = session.verify_message(idx_from, message).unwrap();

            // This will happen in a host task.
            accum.add_processed_message(result).unwrap();
        }

        println!("{party_idx:?}: finalizing the round");

        match session.finalize_round(&mut OsRng, accum).unwrap() {
            FinalizeOutcome::Success(res) => break res,
            FinalizeOutcome::AnotherRound(new_session, new_cached_messages) => {
                session = new_session;
                cached_messages = new_cached_messages;
            }
        }
    }
}

async fn message_dispatcher(
    txs: BTreeMap<PartyIdx, mpsc::Sender<MessageIn>>,
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
        messages.shuffle(&mut rand::thread_rng());

        while let Some((id_from, id_to, message)) = messages.pop() {
            txs[&id_to].send((id_from, message)).await.unwrap();

            // Give up execution so that the tasks could process messages.
            sleep(Duration::from_millis(0)).await;

            if let Ok(msg) = rx.try_recv() {
                messages.push(msg);
                // TODO: we can just pull a random message instead of reshuffling
                messages.shuffle(&mut rand::thread_rng());
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
) -> Vec<<Res as ProtocolResult>::Success>
where
    Res: ProtocolResult + Send + 'static,
    <Res as ProtocolResult>::Success: Send + 'static,
{
    let num_parties = sessions.len();
    let parties = (0..num_parties)
        .map(PartyIdx::from_usize)
        .collect::<Vec<_>>();

    let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<MessageOut>(100);

    let channels = (0..num_parties).map(|_| mpsc::channel::<MessageIn>(100));
    let (txs, rxs): (Vec<mpsc::Sender<MessageIn>>, Vec<mpsc::Receiver<MessageIn>>) =
        channels.unzip();
    let tx_map = parties.iter().cloned().zip(txs.into_iter()).collect();
    let rx_map = parties.iter().cloned().zip(rxs.into_iter());

    let dispatcher_task = message_dispatcher(tx_map, dispatcher_rx);
    let dispatcher = tokio::spawn(dispatcher_task);

    let handles: Vec<tokio::task::JoinHandle<<Res as ProtocolResult>::Success>> = rx_map
        .zip(sessions.into_iter())
        .map(|((party_idx, rx), session)| {
            let node_task = run_session(dispatcher_tx.clone(), rx, session, party_idx);
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

    let shared_randomness = b"1234567890";

    let sessions = signers
        .into_iter()
        .enumerate()
        .map(|(idx, signer)| {
            make_keygen_and_aux_session::<TestParams, Signature, _, _>(
                &mut OsRng,
                shared_randomness,
                signer,
                &verifiers,
                PartyIdx::from_usize(idx),
            )
            .unwrap()
        })
        .collect();

    let key_shares = run_nodes(sessions).await;

    for (idx, key_share) in key_shares.iter().enumerate() {
        assert_eq!(key_share.party_index(), PartyIdx::from_usize(idx));
        assert_eq!(key_share.num_parties(), num_parties);
        assert_eq!(key_share.verifying_key(), key_shares[0].verifying_key());
    }
}

#[tokio::test]
async fn interactive_signing() {
    let num_parties = 3;
    let (signers, verifiers) = make_signers(num_parties);

    let key_shares = KeyShare::<TestParams>::new_centralized(&mut OsRng, num_parties, None);
    let shared_randomness = b"1234567890";
    let message = b"abcdefghijklmnopqrstuvwxyz123456";

    let sessions = key_shares
        .iter()
        .zip(signers.into_iter())
        .map(|(key_share, signer)| {
            make_interactive_signing_session::<_, Signature, _, _>(
                &mut OsRng,
                shared_randomness,
                signer,
                &verifiers,
                key_share,
                message,
            )
            .unwrap()
        })
        .collect();

    let signatures = run_nodes(sessions).await;

    for signature in signatures {
        let (sig, rec_id) = signature.to_backend();
        let vkey = key_shares[0].verifying_key();

        // Check that the signature can be verified
        vkey.verify_prehash(message, &sig).unwrap();

        // Check that the key can be recovered
        let recovered_key = VerifyingKey::recover_from_prehash(message, &sig, rec_id).unwrap();
        assert_eq!(recovered_key, vkey);
    }
}
