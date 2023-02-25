#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use rand::seq::SliceRandom;
    use serde::{Deserialize, Serialize};
    use tokio::sync::mpsc;
    use tokio::time::{sleep, Duration};

    use crate::protocols::keygen::{KeyShare, PartyId, Round1, Round2, Round3, SessionInfo};
    use crate::protocols::rounds::{
        BroadcastRound, ConsensusBroadcastRound, ConsensusRound, ConsensusWrapper, OnFinalize,
        OnReceive, Round, ToSend,
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

    #[derive(Clone)]
    struct PreConsensusSubstage<R: ConsensusBroadcastRound<Id = PartyId>>
    where
        for<'de> <R as Round>::Message: Deserialize<'de>,
    {
        round: ConsensusWrapper<R>,
        accum: Option<HoleMap<R::Id, <ConsensusWrapper<R> as Round>::Payload>>,
    }

    impl<R: ConsensusBroadcastRound<Id = PartyId>> PreConsensusSubstage<R>
    where
        for<'de> <R as Round>::Message: Deserialize<'de>,
    {
        fn new(round: R) -> Self {
            Self {
                round: ConsensusWrapper(round),
                accum: None,
            }
        }

        fn get_messages(&mut self, stage_num: u8) -> ToSend<R::Id, Box<[u8]>> {
            if self.accum.is_some() {
                panic!();
            }

            let (accum, to_send) = get_messages(&self.round, stage_num);
            self.accum = Some(accum);
            to_send
        }

        fn receive(&mut self, from: R::Id, message_bytes: &[u8]) {
            match self.accum.as_mut() {
                Some(accum) => receive(&self.round, accum, &from, message_bytes),
                None => panic!(),
            }
        }

        fn is_finished_receiving(&self) -> bool {
            match &self.accum {
                Some(accum) => ConsensusWrapper::<R>::can_finalize(accum),
                None => panic!(),
            }
        }

        fn finalize(self) -> (R::Id, <ConsensusWrapper<R> as Round>::NextRound) {
            // TODO: make it so that finalize() result could be immediately passed
            // to the new() of the next round withour restructuring
            (self.round.id(), finalize(self.round, self.accum.unwrap()))
        }
    }

    #[derive(Clone)]
    struct ConsensusSubstage<R: ConsensusBroadcastRound<Id = PartyId>>
    where
        R::Message: PartialEq,
        for<'de> <R as Round>::Message: Deserialize<'de>,
    {
        round: ConsensusRound<R>,
        next_round: R::NextRound,
        accum: Option<HoleMap<R::Id, <ConsensusRound<R> as Round>::Payload>>,
    }

    impl<R: ConsensusBroadcastRound<Id = PartyId>> ConsensusSubstage<R>
    where
        R::Message: PartialEq,
        for<'de> <R as Round>::Message: Deserialize<'de>,
    {
        fn new(
            id: R::Id,
            next_round: R::NextRound,
            broadcasts: BTreeMap<R::Id, R::Message>,
        ) -> Self {
            Self {
                next_round,
                round: ConsensusRound { broadcasts, id },
                accum: None,
            }
        }

        fn get_messages(&mut self, stage_num: u8) -> ToSend<R::Id, Box<[u8]>> {
            if self.accum.is_some() {
                panic!();
            }

            let (accum, to_send) = get_messages(&self.round, stage_num);
            self.accum = Some(accum);
            to_send
        }

        fn receive(&mut self, from: R::Id, message_bytes: &[u8]) {
            match self.accum.as_mut() {
                Some(accum) => receive(&self.round, accum, &from, message_bytes),
                None => panic!(),
            }
        }

        fn is_finished_receiving(&self) -> bool {
            match &self.accum {
                Some(accum) => ConsensusRound::<R>::can_finalize(accum),
                None => panic!(),
            }
        }

        fn finalize(self) -> R::NextRound {
            finalize(self.round, self.accum.unwrap());
            self.next_round
        }
    }

    #[derive(Clone)]
    struct NormalSubstage<R: Round<Id = PartyId>>
    where
        for<'de> <R as Round>::Message: Deserialize<'de>,
    {
        round: R,
        accum: Option<HoleMap<R::Id, R::Payload>>,
    }

    impl<R: Round<Id = PartyId>> NormalSubstage<R>
    where
        for<'de> <R as Round>::Message: Deserialize<'de>,
    {
        fn new(round: R) -> Self {
            Self { round, accum: None }
        }

        fn get_messages(&mut self, stage_num: u8) -> ToSend<R::Id, Box<[u8]>> {
            if self.accum.is_some() {
                panic!();
            }

            let (accum, to_send) = get_messages(&self.round, stage_num);
            self.accum = Some(accum);
            to_send
        }

        fn receive(&mut self, from: R::Id, message_bytes: &[u8]) {
            match self.accum.as_mut() {
                Some(accum) => receive(&self.round, accum, &from, message_bytes),
                None => panic!(),
            }
        }

        fn is_finished_receiving(&self) -> bool {
            match &self.accum {
                Some(accum) => R::can_finalize(accum),
                None => panic!(),
            }
        }

        fn finalize(self) -> R::NextRound {
            finalize(self.round, self.accum.unwrap())
        }
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

    // TODO: may be able to get rid of the clone requirement - perhaps with `take_mut`.
    trait SessionStages: Clone {
        fn get_messages(&mut self) -> ToSend<Id, Box<[u8]>>;
        fn receive_current_stage(&mut self, from: Id, message_bytes: &[u8]);
        fn is_finished_receiving(&self) -> bool;
        fn finalize_stage(self) -> Self;
        fn is_final_stage(&self) -> bool;
        fn current_stage_num(&self) -> u8;
        fn stages_num(&self) -> u8;
        fn result(&self) -> Self::Result;
        type Result;
    }

    #[derive(Clone)]
    enum KeygenStage {
        Round1(PreConsensusSubstage<Round1>),
        Round1Consensus(ConsensusSubstage<Round1>),
        Round2(NormalSubstage<Round2>),
        Round3(NormalSubstage<Round3>),
        Result(KeyShare),
    }

    impl KeygenStage {
        fn new(session_info: &SessionInfo, my_id: &Id) -> Self {
            let round1 = Round1::new(session_info, my_id);
            Self::Round1(PreConsensusSubstage::new(round1))
        }
    }

    impl SessionStages for KeygenStage {
        type Result = KeyShare;

        fn get_messages(&mut self) -> ToSend<Id, Box<[u8]>> {
            let stage_num = self.current_stage_num();
            match self {
                // TODO: attach the stage number a level higher
                Self::Round1(r) => r.get_messages(stage_num),
                Self::Round1Consensus(r) => r.get_messages(stage_num),
                Self::Round2(r) => r.get_messages(stage_num),
                Self::Round3(r) => r.get_messages(stage_num),
                _ => panic!(),
            }
        }

        fn receive_current_stage(&mut self, from: Id, message_bytes: &[u8]) {
            match self {
                Self::Round1(r) => r.receive(from, &message_bytes),
                Self::Round1Consensus(r) => r.receive(from, &message_bytes),
                Self::Round2(r) => r.receive(from, &message_bytes),
                Self::Round3(r) => r.receive(from, &message_bytes),
                _ => panic!(),
            }
        }

        fn is_finished_receiving(&self) -> bool {
            match &self {
                Self::Round1(r) => r.is_finished_receiving(),
                Self::Round1Consensus(r) => r.is_finished_receiving(),
                Self::Round2(r) => r.is_finished_receiving(),
                Self::Round3(r) => r.is_finished_receiving(),
                _ => panic!(),
            }
        }

        fn finalize_stage(self) -> Self {
            match self {
                Self::Round1(r) => {
                    let (id, (new_round, broadcasts)) = r.finalize();
                    Self::Round1Consensus(ConsensusSubstage::new(id, new_round, broadcasts))
                }
                Self::Round1Consensus(r) => Self::Round2(NormalSubstage::new(r.finalize())),
                Self::Round2(r) => Self::Round3(NormalSubstage::new(r.finalize())),
                Self::Round3(r) => Self::Result(r.finalize()),
                _ => panic!(),
            }
        }

        fn result(&self) -> KeyShare {
            match self {
                Self::Result(r) => r.clone(),
                _ => panic!(),
            }
        }

        fn is_final_stage(&self) -> bool {
            match self {
                Self::Result(_) => true,
                _ => false,
            }
        }

        fn current_stage_num(&self) -> u8 {
            match self {
                Self::Round1(_) => 1,
                Self::Round1Consensus(_) => 2,
                Self::Round2(_) => 3,
                Self::Round3(_) => 4,
                _ => panic!(),
            }
        }

        fn stages_num(&self) -> u8 {
            4
        }
    }

    struct Session<S: SessionStages> {
        next_stage_messages: Vec<(PartyId, Box<[u8]>)>,
        stage: S,
    }

    impl<S: SessionStages> Session<S> {
        fn new(stage: S) -> Self {
            Self {
                next_stage_messages: Vec::new(),
                stage,
            }
        }

        fn get_messages(&mut self) -> ToSend<Id, Box<[u8]>> {
            self.stage.get_messages()
        }

        fn receive(&mut self, from: Id, message_bytes: &[u8]) {
            let stage_num = self.stage.current_stage_num();
            let max_stages = self.stage.stages_num();
            let (stage, message_bytes) = deserialize_with_round(&message_bytes);

            if stage == stage_num + 1 && stage <= max_stages {
                self.next_stage_messages.push((from, message_bytes));
            } else if stage == stage_num {
                self.stage.receive_current_stage(from, &message_bytes);
            } else {
                panic!("Unexpected message from round {stage} (current stage: {stage_num})");
            }
        }

        fn receive_cached_message(&mut self) {
            let (from, message_bytes) = self.next_stage_messages.pop().unwrap();
            self.stage.receive_current_stage(from, &message_bytes);
        }

        fn is_finished_receiving(&self) -> bool {
            self.stage.is_finished_receiving()
        }

        fn finalize_stage(&mut self) {
            // TODO: check that there are no cached messages left
            self.stage = self.stage.clone().finalize_stage();
        }

        fn result(&self) -> S::Result {
            self.stage.result()
        }

        fn is_final_stage(&self) -> bool {
            self.stage.is_final_stage()
        }

        fn current_stage_num(&self) -> u8 {
            self.stage.current_stage_num()
        }

        fn stages_num(&self) -> u8 {
            self.stage.stages_num()
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
    ) -> KeyShare {
        let mut rx = rx;
        let mut session = Session::new(KeygenStage::new(&session_info, &my_id));

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
