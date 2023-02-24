#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use rand::seq::SliceRandom;
    use serde::{Deserialize, Serialize};
    use tokio::sync::mpsc;
    use tokio::time::{sleep, Duration};

    use crate::protocols::keygen::{PartyId, Round1, Round2, Round3, SessionInfo};
    use crate::protocols::rounds::{OnFinalize, OnReceive, Round, ToSend};
    use crate::tools::collections::HoleMap;

    type Id = PartyId;
    type Message = (PartyId, Box<[u8]>);

    fn serialize_message(message: &impl Serialize) -> Box<[u8]> {
        rmp_serde::encode::to_vec(message)
            .unwrap()
            .into_boxed_slice()
    }

    fn deserialize_message<M: for<'de> Deserialize<'de>>(message_bytes: &[u8]) -> M {
        rmp_serde::decode::from_slice(message_bytes).unwrap()
    }

    fn serialize_with_round(round: u8, subround: u8, message: &[u8]) -> Box<[u8]> {
        rmp_serde::encode::to_vec(&(round, subround, message))
            .unwrap()
            .into_boxed_slice()
    }

    fn deserialize_with_round(message_bytes: &[u8]) -> (u8, u8, Box<[u8]>) {
        rmp_serde::decode::from_slice(message_bytes).unwrap()
    }

    async fn node(
        tx: mpsc::Sender<(Id, Id, Box<[u8]>)>,
        rx: mpsc::Receiver<Message>,
        my_id: Id,
        session_info: SessionInfo,
    ) -> Round3 {
        let mut rx = rx;

        println!("\n*** {my_id:?}: Starting Round 1 ***\n");

        let round1 = Round1::new(&session_info, &my_id);
        let (mut accum1, to_send) = round1.get_messages();

        match to_send {
            ToSend::Broadcast { message, ids, .. } => {
                let message_bytes = serialize_message(&message);
                for id_to in ids {
                    println!("{my_id:?}: sending broadcast to {id_to:?}");
                    tx.send((
                        my_id.clone(),
                        id_to.clone(),
                        serialize_with_round(1, 0, &message_bytes),
                    ))
                    .await
                    .unwrap();
                }
            }
            ToSend::Direct(msgs) => {
                for (id_to, message) in msgs.into_iter() {
                    println!("{my_id:?}: sending direct to {id_to:?}");
                    let message_bytes = serialize_message(&message);
                    tx.send((
                        my_id.clone(),
                        id_to.clone(),
                        serialize_with_round(1, 0, &message_bytes),
                    ))
                    .await
                    .unwrap();
                }
            }
        };

        let mut next_messages = Vec::<(PartyId, Box<[u8]>)>::new();
        let mut broadcasts = HoleMap::<Id, <Round1 as Round>::Message>::new(accum1.keys().cloned());

        let round2 = loop {
            let (id_from, message_bytes) = rx.recv().await.unwrap();

            let (round, subround, message_bytes2) = deserialize_with_round(&message_bytes);
            println!("{my_id:?}: received a message from {id_from:?} for round {round}-{subround}");

            if round == 1 && subround == 0 {
                let message: <Round1 as Round>::Message = deserialize_message(&message_bytes2);
                match round1.receive(&mut accum1, &id_from, message.clone()) {
                    OnReceive::Ok => {}
                    OnReceive::InvalidId => panic!("Invalid ID"),
                    OnReceive::AlreadyReceived => panic!("Already received from this ID"),
                    OnReceive::Fatal(err) => panic!("Error validating message: {err}"),
                };

                let bc = broadcasts.get_mut(&id_from).unwrap();
                assert!(bc.is_none());
                *bc = Some(message);
            } else if round == 1 && subround == 1 {
                println!("{my_id:?}: pushing 1-1 message");
                next_messages.push((id_from, message_bytes2));
            } else {
                panic!("{my_id:?}: unexpected message from round {round}-{subround}");
            }

            if Round1::can_finalize(&accum1) {
                match round1.clone().try_finalize(accum1.clone()) {
                    OnFinalize::NotFinished(_) => panic!("Could not finalize"),
                    OnFinalize::Finished(s) => break s,
                };
            }
        };

        let broadcasts = match broadcasts.try_finalize() {
            Err(_) => panic!("Could not finalize"),
            Ok(s) => s,
        };

        println!("\n*** {my_id:?}: Starting Round 1 consensus ***\n");

        // Re-broadcast
        let bc_list = broadcasts.iter().collect::<Vec<_>>();
        let message = serialize_message(&bc_list);
        let message_bytes = serialize_with_round(1, 1, &message);
        println!("{my_id:?}: sending 1-1 message");

        for id_to in broadcasts.keys() {
            tx.send((my_id.clone(), id_to.clone(), message_bytes.clone()))
                .await
                .unwrap();
        }

        let mut bc_accum = HoleMap::<Id, ()>::new(broadcasts.keys().cloned());

        for (id_from, message_bytes) in next_messages.drain(0..) {
            println!("{my_id:?}: applying a cached 1-1 message from {id_from:?}");
            let message: Vec<(Id, <Round1 as Round>::Message)> =
                deserialize_message(&message_bytes);
            // TODO: check that id is among node ids, check that all ids are present
            for (id, msg) in message {
                // TODO: should we save our own broadcast,
                // and check that the other nodes received them?
                // Or is this excessive since they are signed by us anyway?
                if id != my_id && broadcasts[&id] != msg {
                    panic!("{my_id:?}: {id_from:?} received a different broadcast from {id:?}");
                }
            }

            let acc = bc_accum.get_mut(&id_from).unwrap();
            assert!(acc.is_none());
            *acc = Some(());
        }

        loop {
            if bc_accum.can_finalize() {
                match round1.clone().try_finalize(accum1.clone()) {
                    OnFinalize::NotFinished(_) => panic!("Could not finalize"),
                    OnFinalize::Finished(_) => break,
                };
            }

            let (id_from, message_bytes) = rx.recv().await.unwrap();

            let (round, subround, message_bytes2) = deserialize_with_round(&message_bytes);
            println!("{my_id:?}: received a message from {id_from:?} for round {round}-{subround}");

            if round == 1 && subround == 1 {
                let message: Vec<(Id, <Round1 as Round>::Message)> =
                    deserialize_message(&message_bytes2);

                // TODO: check that id is among node ids, check that all ids are present
                for (id, msg) in message {
                    if id != my_id && broadcasts[&id] != msg {
                        panic!("{my_id:?}: {id_from:?} received a different broadcast from {id:?}");
                    }
                }

                let acc = bc_accum.get_mut(&id_from).unwrap();
                assert!(acc.is_none());
                *acc = Some(());
            } else if round == 2 && subround == 0 {
                next_messages.push((id_from, message_bytes2));
            } else {
                panic!("{my_id:?}: unexpected message from round {round}-{subround}");
            }
        }

        println!("\n*** {my_id:?}: Finished Round 1 ***\n");

        println!("\n*** {my_id:?}: Starting Round 2 ***\n");

        let (mut accum2, to_send) = round2.get_messages();

        for (id_from, message_bytes) in next_messages {
            println!("{my_id:?}: applying a cached message from {id_from:?}");

            let message: <Round2 as Round>::Message = deserialize_message(&message_bytes);
            match round2.receive(&mut accum2, &id_from, message) {
                OnReceive::Ok => {}
                OnReceive::InvalidId => panic!("Invalid ID"),
                OnReceive::AlreadyReceived => panic!("Already received from this ID"),
                OnReceive::Fatal(err) => panic!("Error validating message: {err}"),
            };
        }

        match to_send {
            ToSend::Broadcast { message, ids, .. } => {
                for id_to in ids {
                    println!("{my_id:?}: sending broadcast to {id_to:?}");
                    let message_bytes = serialize_message(&message);
                    tx.send((
                        my_id.clone(),
                        id_to.clone(),
                        serialize_with_round(2, 0, &message_bytes),
                    ))
                    .await
                    .unwrap();
                }
            }
            ToSend::Direct(msgs) => {
                for (id_to, message) in msgs.into_iter() {
                    println!("{my_id:?}: sending direct to {id_to:?}");
                    let message_bytes = serialize_message(&message);
                    tx.send((
                        my_id.clone(),
                        id_to.clone(),
                        serialize_with_round(2, 0, &message_bytes),
                    ))
                    .await
                    .unwrap();
                }
            }
        };

        let round3 = loop {
            if Round2::can_finalize(&accum2) {
                match round2.clone().try_finalize(accum2.clone()) {
                    OnFinalize::NotFinished(_) => panic!("Could not finalize"),
                    OnFinalize::Finished(s) => break s,
                };
            }

            let (id_from, message_bytes) = rx.recv().await.unwrap();

            let (round, subround, message_bytes) = deserialize_with_round(&message_bytes);
            println!("{my_id:?}: received a message from {id_from:?} for round {round}");

            if round == 2 && subround == 0 {
                let message: <Round2 as Round>::Message = deserialize_message(&message_bytes);
                match round2.receive(&mut accum2, &id_from, message) {
                    OnReceive::Ok => {}
                    OnReceive::InvalidId => panic!("Invalid ID"),
                    OnReceive::AlreadyReceived => panic!("Already received from this ID"),
                    OnReceive::Fatal(err) => panic!("Error validating message: {err}"),
                };
            } else {
                panic!("{my_id:?}: unexpected message from round {round}");
            }
        };

        println!("\n*** {my_id:?}: Finished Round 2 ***\n");

        round3
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

            loop {
                match rx.try_recv() {
                    Ok(msg) => messages.push(msg),
                    Err(_) => break,
                };
            }
            messages.shuffle(&mut rand::thread_rng());

            while messages.len() > 0 {
                let (id_from, id_to, message_bytes) = messages.pop().unwrap();
                txs[&id_to].send((id_from, message_bytes)).await.unwrap();

                // Give up execution so that the tasks could process messages.
                sleep(Duration::from_millis(0)).await;

                match rx.try_recv() {
                    Ok(msg) => {
                        messages.push(msg);
                        // TODO: we can just pull a random message instead of reshuffling
                        messages.shuffle(&mut rand::thread_rng());
                    }
                    Err(_) => {}
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

        let handles: Vec<tokio::task::JoinHandle<Round3>> = rx_map
            .into_iter()
            .map(|(id, rx)| {
                let node_task = node(dispatcher_tx.clone(), rx, id, session_info.clone());
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
