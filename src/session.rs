#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use rand::seq::SliceRandom;
    use serde::{Deserialize, Serialize};
    use tokio::sync::mpsc;
    use tokio::time::{sleep, Duration};

    use crate::protocols::keygen::{PartyId, Round1, Round2, Round3, SessionInfo};
    use crate::protocols::rounds::{
        ConsensusRound, ConsensusWrapper, OnFinalize, OnReceive, Round, ToSend,
    };
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

    fn serialize_with_round(round: u8, message: &[u8]) -> Box<[u8]> {
        rmp_serde::encode::to_vec(&(round, message))
            .unwrap()
            .into_boxed_slice()
    }

    fn deserialize_with_round(message_bytes: &[u8]) -> (u8, Box<[u8]>) {
        rmp_serde::decode::from_slice(message_bytes).unwrap()
    }

    enum Stage {
        Round1(ConsensusWrapper<Round1>),
        Round1R {
            round: ConsensusWrapper<Round1>,
            accum: HoleMap<PartyId, <ConsensusWrapper<Round1> as Round>::Payload>,
        },
        Round1Consensus {
            next_round: Round2,
            round: ConsensusRound<Round1>,
        },
        Round1ConsensusR {
            next_round: Round2,
            round: ConsensusRound<Round1>,
            accum: HoleMap<PartyId, <ConsensusRound<Round1> as Round>::Payload>,
        },
        Round2(Round2),
        Round2R {
            round: Round2,
            accum: HoleMap<PartyId, <Round2 as Round>::Payload>,
        },
        Result(Round3),
    }

    struct Session {
        id: PartyId,
        next_stage_messages: Vec<(PartyId, Box<[u8]>)>,
        stage: Stage,
    }

    fn get_messages<R: Round<Id = PartyId>>(
        round: &R,
        stage_num: u8,
    ) -> (HoleMap<Id, R::Payload>, ToSend<Id, Box<[u8]>>)
    where
        R::Message: Serialize,
    {
        let (accum, to_send) = round.get_messages();
        let to_send = match to_send {
            ToSend::Broadcast { message, ids, .. } => {
                let message_bytes = serialize_message(&message);
                let full_message_bytes = serialize_with_round(stage_num, &message_bytes);
                ToSend::Broadcast {
                    message: full_message_bytes,
                    ids,
                    needs_consensus: false,
                }
            }
            ToSend::Direct(msgs) => ToSend::Direct(
                msgs.into_iter()
                    .map(|(id, message)| {
                        let message_bytes = serialize_message(&message);
                        let full_message_bytes = serialize_with_round(stage_num, &message_bytes);
                        (id, full_message_bytes)
                    })
                    .collect(),
            ),
        };
        (accum, to_send)
    }

    fn receive<R: Round<Id = PartyId>>(
        round: &R,
        accum: &mut HoleMap<Id, R::Payload>,
        from: &Id,
        message_bytes: &[u8],
    ) where
        for<'de> R::Message: Deserialize<'de>,
    {
        let message: R::Message = deserialize_message(&message_bytes);
        match round.receive(accum, from, message) {
            OnReceive::Ok => {}
            OnReceive::InvalidId => panic!("Invalid ID"),
            OnReceive::AlreadyReceived => panic!("Already received from this ID"),
            OnReceive::Fatal(_err) => panic!("Error validating message"),
        };
    }

    fn finalize<R: Round<Id = PartyId>>(round: R, accum: HoleMap<Id, R::Payload>) -> R::NextRound {
        if R::can_finalize(&accum) {
            match round.try_finalize(accum) {
                OnFinalize::NotFinished(_) => panic!("Could not finalize"),
                OnFinalize::Finished(next_round) => next_round,
            }
        } else {
            panic!();
        }
    }

    impl Session {
        fn new(session_info: &SessionInfo, my_id: &Id) -> Self {
            let round1 = Round1::new(session_info, my_id);
            Self {
                id: my_id.clone(),
                next_stage_messages: Vec::new(),
                stage: Stage::Round1(ConsensusWrapper(round1)),
            }
        }

        fn get_messages(&mut self) -> ToSend<Id, Box<[u8]>> {
            let stage_num = self.current_stage_num();
            let (new_stage, to_send) = match &self.stage {
                Stage::Round1(r) => {
                    let (accum, to_send) = get_messages(r, stage_num);
                    // TODO: may be possible to avoid cloning here
                    let new_stage = Stage::Round1R {
                        round: r.clone(),
                        accum,
                    };
                    (new_stage, to_send)
                }
                Stage::Round1Consensus { round, next_round } => {
                    let (accum, to_send) = get_messages(round, stage_num);
                    // TODO: may be possible to avoid cloning here
                    let new_stage = Stage::Round1ConsensusR {
                        next_round: next_round.clone(),
                        round: round.clone(),
                        accum,
                    };
                    (new_stage, to_send)
                }
                Stage::Round2(r) => {
                    let (accum, to_send) = get_messages(r, stage_num);
                    // TODO: may be possible to avoid cloning here
                    let new_stage = Stage::Round2R {
                        round: r.clone(),
                        accum,
                    };
                    (new_stage, to_send)
                }
                _ => panic!(),
            };
            self.stage = new_stage;
            to_send
        }

        fn receive_current_stage(&mut self, from: Id, message_bytes: &[u8]) {
            match &mut self.stage {
                Stage::Round1R { round, accum } => receive(round, accum, &from, &message_bytes),
                Stage::Round1ConsensusR { round, accum, .. } => {
                    receive(round, accum, &from, &message_bytes)
                }
                Stage::Round2R { round, accum } => receive(round, accum, &from, &message_bytes),
                _ => panic!(),
            }
        }

        fn receive(&mut self, from: Id, message_bytes: &[u8]) {
            let stage_num = self.current_stage_num();
            let max_stages = self.stages_num();
            let (stage, message_bytes) = deserialize_with_round(&message_bytes);

            if stage == stage_num + 1 && stage <= max_stages {
                self.next_stage_messages.push((from, message_bytes));
            } else if stage == stage_num {
                self.receive_current_stage(from, &message_bytes);
            } else {
                panic!(
                    "{:?}: unexpected message from round {stage} (current stage: {})",
                    self.id, stage_num
                );
            }
        }

        fn receive_cached_message(&mut self) {
            let (from, message_bytes) = self.next_stage_messages.pop().unwrap();
            self.receive_current_stage(from, &message_bytes);
        }

        fn is_finished_receiving(&self) -> bool {
            match &self.stage {
                Stage::Round1R { accum, .. } => ConsensusWrapper::<Round1>::can_finalize(&accum),
                Stage::Round1ConsensusR { accum, .. } => {
                    ConsensusRound::<Round1>::can_finalize(&accum)
                }
                Stage::Round2R { accum, .. } => Round2::can_finalize(&accum),
                _ => panic!(),
            }
        }

        fn finalize_stage(&mut self) {
            let new_stage = match &self.stage {
                Stage::Round1R { round, accum } => {
                    let (new_round, broadcasts) = finalize(round.clone(), accum.clone());
                    Stage::Round1Consensus {
                        next_round: new_round,
                        round: ConsensusRound::<Round1> {
                            id: self.id.clone(),
                            broadcasts,
                        },
                    }
                }
                Stage::Round1ConsensusR {
                    next_round,
                    round,
                    accum,
                } => {
                    finalize(round.clone(), accum.clone());
                    Stage::Round2(next_round.clone())
                }
                Stage::Round2R { round, accum } => {
                    let next_round = finalize(round.clone(), accum.clone());
                    Stage::Result(next_round)
                }
                _ => panic!(),
            };

            self.stage = new_stage;
        }

        fn result(&self) -> Round3 {
            match &self.stage {
                Stage::Result(r) => r.clone(),
                _ => panic!(),
            }
        }

        fn is_final_stage(&self) -> bool {
            match self.stage {
                Stage::Result(_) => true,
                _ => false,
            }
        }

        fn current_stage_num(&self) -> u8 {
            match self.stage {
                Stage::Round1(_) => 1,
                Stage::Round1R { .. } => 1,
                Stage::Round1Consensus { .. } => 2,
                Stage::Round1ConsensusR { .. } => 2,
                Stage::Round2(_) => 3,
                Stage::Round2R { .. } => 3,
                _ => panic!(),
            }
        }

        fn stages_num(&self) -> u8 {
            3
        }

        fn has_cached_messages(&self) -> bool {
            self.next_stage_messages.len() > 0
        }
    }

    async fn node_session(
        tx: mpsc::Sender<(Id, Id, Box<[u8]>)>,
        rx: mpsc::Receiver<Message>,
        my_id: Id,
        session_info: SessionInfo,
    ) -> Round3 {
        let mut rx = rx;
        let mut session = Session::new(&session_info, &my_id);

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

            println!("{:?}: applying cached messages", my_id);

            while session.has_cached_messages() {
                session.receive_cached_message();
            }

            while !session.is_finished_receiving() {
                println!("{:?}: waiting for a message", my_id);
                let (id_from, message_bytes) = rx.recv().await.unwrap();
                println!("{:?}: applying the message", my_id);
                session.receive(id_from, &message_bytes);
            }

            println!("{:?}: finalizing the stage", my_id);
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
