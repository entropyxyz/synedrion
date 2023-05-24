use std::collections::BTreeMap;

use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
use rand::seq::SliceRandom;
use rand_core::OsRng;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};

use synedrion::{
    make_key_shares,
    sessions::{make_interactive_signing_session, ToSend},
    KeyShare, PartyIdx, Signature, TestSchemeParams,
};

type MessageOut = (PartyIdx, PartyIdx, Box<[u8]>);
type MessageIn = (PartyIdx, Box<[u8]>);

async fn node_session(
    tx: mpsc::Sender<MessageOut>,
    rx: mpsc::Receiver<MessageIn>,
    key_share: KeyShare<TestSchemeParams>,
    message: &[u8; 32],
) -> Signature {
    let mut rx = rx;

    let party_idx = key_share.party_index();

    let other_ids = (0..key_share.num_parties())
        .map(PartyIdx::from_usize)
        .filter(|idx| idx != &party_idx)
        .collect::<Vec<_>>();

    let mut session = make_interactive_signing_session(&mut OsRng, &key_share, message).unwrap();

    while !session.is_final_stage() {
        println!(
            "*** {:?}: starting stage {}",
            party_idx,
            session.current_stage_num()
        );

        let to_send = session.get_messages(&mut OsRng).unwrap();

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

        while session.has_cached_messages() {
            session.receive_cached_message().unwrap();
        }

        while !session.is_finished_receiving().unwrap() {
            println!("{party_idx:?}: waiting for a message");
            let (id_from, message_bytes) = rx.recv().await.unwrap();
            println!("{party_idx:?}: applying the message from {id_from:?}");
            session.receive(id_from, &message_bytes).unwrap();
        }

        println!("{party_idx:?}: finalizing the stage");
        session.finalize_stage(&mut OsRng).unwrap();
    }

    session.result().unwrap()
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
            let (id_from, id_to, message_bytes) = messages.pop().unwrap();
            txs[&id_to].send((id_from, message_bytes)).await.unwrap();

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
    let shares = make_key_shares::<TestSchemeParams>(&mut OsRng, num_parties, None);
    let key_shares = parties
        .iter()
        .zip(shares.into_vec().into_iter())
        .collect::<BTreeMap<_, _>>();
    let message = b"abcdefghijklmnopqrstuvwxyz123456";

    let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<MessageOut>(100);

    let channels = (0..num_parties).map(|_| mpsc::channel::<MessageIn>(100));
    let (txs, rxs): (Vec<mpsc::Sender<MessageIn>>, Vec<mpsc::Receiver<MessageIn>>) =
        channels.unzip();
    let tx_map = parties.iter().cloned().zip(txs.into_iter()).collect();
    let rx_map = parties.iter().cloned().zip(rxs.into_iter());

    let dispatcher_task = message_dispatcher(tx_map, dispatcher_rx);
    let dispatcher = tokio::spawn(dispatcher_task);

    let handles: Vec<tokio::task::JoinHandle<Signature>> = rx_map
        .map(|(party_idx, rx)| {
            let node_task = node_session(
                dispatcher_tx.clone(),
                rx,
                key_shares.get(&party_idx).unwrap().clone(),
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
        let vkey = key_shares[&parties[0]].verifying_key();

        // Check that the signature can be verified
        vkey.verify_prehash(message, &sig).unwrap();

        // Check that the key can be recovered
        let recovered_key = VerifyingKey::recover_from_prehash(message, &sig, rec_id).unwrap();
        assert_eq!(recovered_key, vkey);
    }

    dispatcher.await.unwrap();
}