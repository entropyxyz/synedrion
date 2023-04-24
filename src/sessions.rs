mod auxiliary;
mod generic;
mod interactive_signing;
mod keygen;
mod presigning;
mod signing;

pub use auxiliary::AuxiliaryState;
pub use generic::{PartyId, Session, ToSend};
pub use interactive_signing::InteractiveSigningState;
pub use keygen::KeygenState;
pub use presigning::PresigningState;
pub use signing::SigningState;

use alloc::string::String;

use rand_core::{CryptoRng, RngCore};

use crate::protocols::common::SessionId;
use crate::tools::group::Scalar;
use crate::{KeyShare, SchemeParams};

pub fn make_interactive_signing_session<P: SchemeParams, Id: PartyId>(
    rng: &mut (impl CryptoRng + RngCore),
    all_parties: &[Id],
    my_id: &Id,
    key_share: &KeyShare<P>,
    prehashed_message: &[u8],
) -> Result<Session<InteractiveSigningState<P>, Id>, String> {
    let scalar_message = Scalar::try_from_reduced_bytes(prehashed_message)?;

    let session_id = SessionId::random();
    let context = (all_parties.len(), key_share.clone(), scalar_message);

    Ok(Session::<InteractiveSigningState<P>, Id>::new(
        rng,
        &session_id,
        &all_parties,
        &my_id,
        &context,
    ))
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::vec;

    use k256::ecdsa::{signature::hazmat::PrehashVerifier, VerifyingKey};
    use rand::seq::SliceRandom;
    use rand_core::OsRng;
    use tokio::sync::mpsc;
    use tokio::time::{sleep, Duration};

    use crate::sessions::{make_interactive_signing_session, PartyId, ToSend};
    use crate::{make_key_shares, KeyShare, Signature, TestSchemeParams};

    #[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
    struct Id(u32);

    impl PartyId for Id {}

    type MessageOut = (Id, Id, Box<[u8]>);
    type MessageIn = (Id, Box<[u8]>);

    async fn node_session(
        tx: mpsc::Sender<MessageOut>,
        rx: mpsc::Receiver<MessageIn>,
        all_parties: Vec<Id>,
        my_id: Id,
        key_share: KeyShare<TestSchemeParams>,
        message: &[u8],
    ) -> Signature {
        let mut rx = rx;

        let mut session = make_interactive_signing_session(
            &mut OsRng,
            &all_parties,
            &my_id,
            &key_share,
            &message,
        )
        .unwrap();

        while !session.is_final_stage() {
            println!(
                "*** {:?}: starting stage {}",
                my_id,
                session.current_stage_num()
            );

            let to_send = session.get_messages(&mut OsRng);

            match to_send {
                ToSend::Broadcast { message, ids, .. } => {
                    for id_to in ids {
                        tx.send((my_id, id_to, message.clone())).await.unwrap();
                    }
                }
                ToSend::Direct(msgs) => {
                    for (id_to, message) in msgs.into_iter() {
                        tx.send((my_id, id_to, message)).await.unwrap();
                    }
                }
            };

            println!("{my_id:?}: applying cached messages");

            while session.has_cached_messages() {
                session.receive_cached_message();
            }

            while !session.is_finished_receiving() {
                println!("{my_id:?}: waiting for a message");
                let (id_from, message_bytes) = rx.recv().await.unwrap();
                println!("{my_id:?}: applying the message");
                session.receive(&id_from, &message_bytes);
            }

            println!("{my_id:?}: finalizing the stage");
            session.finalize_stage(&mut OsRng);
        }

        session.result()
    }

    async fn message_dispatcher(
        txs: BTreeMap<Id, mpsc::Sender<MessageIn>>,
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
    async fn signing() {
        let parties = vec![Id(111), Id(222), Id(333)];
        let shares = make_key_shares::<TestSchemeParams>(&mut OsRng, 3);
        let key_shares = parties
            .iter()
            .zip(shares.into_vec().into_iter())
            .collect::<BTreeMap<_, KeyShare<TestSchemeParams>>>();
        let message = b"abcdefghijklmnopqrstuvwxyz123456";

        let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<MessageOut>(100);

        let channels = parties.iter().map(|_id| mpsc::channel::<MessageIn>(100));
        let (txs, rxs): (Vec<mpsc::Sender<MessageIn>>, Vec<mpsc::Receiver<MessageIn>>) =
            channels.unzip();
        let tx_map = parties.iter().cloned().zip(txs.into_iter()).collect();
        let rx_map = parties.iter().cloned().zip(rxs.into_iter());

        let dispatcher_task = message_dispatcher(tx_map, dispatcher_rx);
        let dispatcher = tokio::spawn(dispatcher_task);

        let handles: Vec<tokio::task::JoinHandle<Signature>> = rx_map
            .map(|(id, rx)| {
                let node_task = node_session(
                    dispatcher_tx.clone(),
                    rx,
                    parties.clone(),
                    id,
                    key_shares.get(&id).unwrap().clone(),
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
            let vkey = key_shares[&parties[0]].verifying_key().unwrap();

            // Check that the signature can be verified
            vkey.verify_prehash(message, &sig).unwrap();

            // Check that the key can be recovered
            let recovered_key = VerifyingKey::recover_from_prehash(message, &sig, rec_id).unwrap();
            assert_eq!(recovered_key, vkey);
        }

        dispatcher.await.unwrap();
    }
}
