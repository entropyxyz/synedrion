use std::collections::BTreeMap;

use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, SigningKey, VerifyingKey};
use rand::seq::SliceRandom;
use rand_core::OsRng;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use synedrion::{
    make_key_shares,
    sessions::{make_interactive_signing_session, FinalizeOutcome, SignedMessage, ToSend},
    KeyShare, PartyIdx, RecoverableSignature, TestSchemeParams,
};

type MessageOut = (PartyIdx, PartyIdx, SignedMessage<Signature>);
type MessageIn = (PartyIdx, SignedMessage<Signature>);

async fn node_session(
    tx: mpsc::Sender<MessageOut>,
    rx: mpsc::Receiver<MessageIn>,
    signer: SigningKey,
    verifiers: Vec<VerifyingKey>,
    shared_randomness: &[u8],
    key_share: KeyShare<TestSchemeParams>,
    message: &[u8; 32],
) -> RecoverableSignature {
    let mut rx = rx;

    let party_idx = key_share.party_index();

    let other_ids = (0..key_share.num_parties())
        .map(PartyIdx::from_usize)
        .filter(|idx| idx != &party_idx)
        .collect::<Vec<_>>();

    let mut sending = make_interactive_signing_session::<_, Signature, _, _>(
        &mut OsRng,
        shared_randomness,
        signer,
        &verifiers,
        &key_share,
        message,
    )
    .unwrap();

    loop {
        println!("*** {:?}: starting round", party_idx);

        let (mut receiving, to_send) = sending.start_receiving(&mut OsRng).unwrap();

        match to_send {
            ToSend::Broadcast(message) => {
                for id_to in other_ids.iter() {
                    tx.send((party_idx, *id_to, message.clone())).await.unwrap();
                }
            }
            ToSend::Direct(msgs) => {
                for (id_to, message) in msgs.into_iter() {
                    tx.send((party_idx, id_to, message)).await.unwrap();
                }
            }
        };

        println!("{party_idx:?}: applying cached messages");

        while receiving.has_cached_messages() {
            receiving.receive_cached_message().unwrap();
        }

        while !receiving.can_finalize() {
            println!("{party_idx:?}: waiting for a message");
            let (id_from, message) = rx.recv().await.unwrap();
            println!("{party_idx:?}: applying the message from {id_from:?}");
            receiving.receive(id_from, message).unwrap();
        }

        println!("{party_idx:?}: finalizing the round");

        match receiving.finalize(&mut OsRng).unwrap() {
            FinalizeOutcome::Result(res) => break res,
            FinalizeOutcome::AnotherRound(new_sending) => sending = new_sending,
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

        while !messages.is_empty() {
            let (id_from, id_to, message) = messages.pop().unwrap();
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

#[tokio::test]
async fn interactive_signing() {
    let num_parties = 3;
    let parties = (0..num_parties)
        .map(PartyIdx::from_usize)
        .collect::<Vec<_>>();

    let signers = (0..num_parties)
        .map(|_| SigningKey::random(&mut OsRng))
        .collect::<Vec<_>>();
    let verifiers = signers
        .iter()
        .map(|signer| *signer.verifying_key())
        .collect::<Vec<_>>();
    let key_shares = make_key_shares::<TestSchemeParams>(&mut OsRng, num_parties, None);

    let shared_randomness = b"1234567890";
    let message = b"abcdefghijklmnopqrstuvwxyz123456";

    let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<MessageOut>(100);

    let channels = (0..num_parties).map(|_| mpsc::channel::<MessageIn>(100));
    let (txs, rxs): (Vec<mpsc::Sender<MessageIn>>, Vec<mpsc::Receiver<MessageIn>>) =
        channels.unzip();
    let tx_map = parties.iter().cloned().zip(txs.into_iter()).collect();
    let rx_map = parties.iter().cloned().zip(rxs.into_iter());

    let dispatcher_task = message_dispatcher(tx_map, dispatcher_rx);
    let dispatcher = tokio::spawn(dispatcher_task);

    let handles: Vec<tokio::task::JoinHandle<RecoverableSignature>> = rx_map
        .map(|(party_idx, rx)| {
            let node_task = node_session(
                dispatcher_tx.clone(),
                rx,
                signers[party_idx.as_usize()].clone(),
                verifiers.clone(),
                shared_randomness,
                key_shares[party_idx.as_usize()].clone(),
                message,
            );
            tokio::spawn(node_task)
        })
        .collect();

    // Drop the last copy of the dispatcher's incoming channel so that it could finish.
    drop(dispatcher_tx);

    for handle in handles {
        let signature = handle.await.unwrap();
        let (sig, rec_id) = signature.to_backend();
        let vkey = key_shares[0].verifying_key();

        // Check that the signature can be verified
        vkey.verify_prehash(message, &sig).unwrap();

        // Check that the key can be recovered
        let recovered_key = VerifyingKey::recover_from_prehash(message, &sig, rec_id).unwrap();
        assert_eq!(recovered_key, vkey);
    }

    dispatcher.await.unwrap();
}
