mod generic;
mod keygen;

pub use generic::{Session, ToSend};
pub use keygen::KeygenState;

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use rand::seq::SliceRandom;
    use tokio::sync::mpsc;
    use tokio::time::{sleep, Duration};

    use super::{KeygenState, Session, ToSend};
    use crate::protocols::keygen::{PartyId, SessionInfo};
    use crate::KeyShare;

    type Id = PartyId;
    type Message = (PartyId, Box<[u8]>);

    async fn node_session(
        tx: mpsc::Sender<(Id, Id, Box<[u8]>)>,
        rx: mpsc::Receiver<Message>,
        my_id: Id,
        session_info: SessionInfo,
    ) -> KeyShare {
        let mut rx = rx;
        let mut session = Session::new(KeygenState::new(&session_info, &my_id));

        while !session.is_final_stage() {
            println!(
                "*** {:?}: starting stage {}",
                my_id,
                session.current_stage_num()
            );

            let to_send = session.get_messages();

            match to_send {
                ToSend::Broadcast { message, ids, .. } => {
                    for id_to in ids {
                        tx.send((my_id.clone(), id_to.clone(), message.clone()))
                            .await
                            .unwrap();
                    }
                }
                ToSend::Direct(msgs) => {
                    for (id_to, message) in msgs.into_iter() {
                        tx.send((my_id.clone(), id_to.clone(), message))
                            .await
                            .unwrap();
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
                session.receive(id_from, &message_bytes);
            }

            println!("{my_id:?}: finalizing the stage");
            session.finalize_stage();
        }

        session.result()
    }

    async fn message_dispatcher(
        txs: BTreeMap<Id, mpsc::Sender<Message>>,
        rx: mpsc::Receiver<(Id, Id, Box<[u8]>)>,
    ) {
        let mut rx = rx;
        let mut messages = Vec::<(Id, Id, Box<[u8]>)>::new();
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
    async fn keygen() {
        let parties = [PartyId(111), PartyId(222), PartyId(333)];

        let session_info = SessionInfo {
            parties: parties.to_vec(),
            kappa: 256,
        };

        let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<(Id, Id, Box<[u8]>)>(100);

        let channels = parties
            .iter()
            .map(|_id| mpsc::channel::<Message>(100))
            .collect::<Vec<_>>();
        let (txs, rxs): (Vec<mpsc::Sender<Message>>, Vec<mpsc::Receiver<Message>>) =
            channels.into_iter().unzip();
        let tx_map = parties
            .iter()
            .cloned()
            .zip(txs.into_iter())
            .collect::<BTreeMap<_, _>>();
        let rx_map = parties
            .iter()
            .cloned()
            .zip(rxs.into_iter())
            .collect::<BTreeMap<_, _>>();

        let dispatcher_task = message_dispatcher(tx_map, dispatcher_rx);
        let dispatcher = tokio::spawn(async move { dispatcher_task.await });

        let handles: Vec<tokio::task::JoinHandle<KeyShare>> = rx_map
            .into_iter()
            .map(|(id, rx)| {
                let node_task = node_session(dispatcher_tx.clone(), rx, id, session_info.clone());
                tokio::spawn(async move { node_task.await })
            })
            .collect::<Vec<_>>();

        // Drop the last copy of the dispatcher's incoming channel so that it could finish.
        drop(dispatcher_tx);

        for handle in handles {
            let result = handle.await.unwrap();
            println!("Got result");
        }

        dispatcher.await.unwrap();
    }
}
