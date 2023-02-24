use alloc::collections::BTreeMap;

use crate::tools::collections::HoleMap;

pub enum ToSend<Id, Message> {
    Broadcast {
        ids: Vec<Id>,
        message: Message,
        needs_consensus: bool,
    },
    // TODO: return an iterator instead, since preparing one message can take some time
    Direct(Vec<(Id, Message)>),
}

pub(crate) trait Round: Sized {
    type Id: Sized + Eq + Ord + Clone;
    type Error: Sized;
    type Message: Sized;
    type Payload: Sized + Clone;
    type NextRound: Sized;

    fn to_send(&self) -> ToSend<Self::Id, Self::Message>;
    fn verify_received(
        &self,
        from: &Self::Id,
        msg: Self::Message,
    ) -> Result<Self::Payload, Self::Error>;
    fn finalize(self, payloads: BTreeMap<Self::Id, Self::Payload>) -> Self::NextRound;

    fn get_messages(
        &self,
    ) -> (
        HoleMap<Self::Id, Self::Payload>,
        ToSend<Self::Id, Self::Message>,
    ) {
        let to_send = self.to_send();

        let accum = match &to_send {
            ToSend::Broadcast { ids, .. } => HoleMap::new(ids.iter().cloned()),
            ToSend::Direct(messages) => HoleMap::new(messages.iter().map(|(id, _msg)| id.clone())),
        };

        (accum, to_send)
    }

    fn receive(
        &self,
        accum: &mut HoleMap<Self::Id, Self::Payload>,
        from: &Self::Id,
        msg: Self::Message,
    ) -> OnReceive<Self::Error> {
        let val_ref = match accum.get_mut(from) {
            None => return OnReceive::InvalidId,
            Some(val) => match val {
                Some(_) => return OnReceive::AlreadyReceived,
                None => val,
            },
        };

        match self.verify_received(from, msg) {
            Ok(payload) => {
                *val_ref = Some(payload);
                OnReceive::Ok
            }
            Err(err) => OnReceive::Fatal(err),
        }
    }

    // TODO: move to accum when it is its own type?
    fn can_finalize(accum: &HoleMap<Self::Id, Self::Payload>) -> bool {
        accum.can_finalize()
    }

    fn try_finalize(
        self,
        accum: HoleMap<Self::Id, Self::Payload>,
    ) -> OnFinalize<(Self, HoleMap<Self::Id, Self::Payload>), Self::NextRound> {
        let accum_final = match accum.try_finalize() {
            Ok(accum_final) => accum_final,
            Err(accum) => return OnFinalize::NotFinished((self, accum)),
        };

        OnFinalize::Finished(self.finalize(accum_final))
    }
}

pub(crate) enum OnFinalize<ThisState, NextState> {
    Finished(NextState),
    NotFinished(ThisState),
}

// TODO: Is it even possible to have a fatal error on reception of a message?
pub(crate) enum OnReceive<Error> {
    Ok,
    InvalidId,
    AlreadyReceived,
    Fatal(Error),
}

#[cfg(test)]
pub(crate) mod tests {

    use crate::tools::collections::HoleMap;

    use super::*;

    #[cfg(test)]
    use alloc::collections::BTreeMap;

    #[derive(Debug)]
    pub(crate) enum StepError<Error> {
        Transition(Error),
        Logic(String),
    }

    impl<Error> From<Error> for StepError<Error> {
        fn from(err: Error) -> Self {
            Self::Transition(err)
        }
    }

    pub(crate) fn step<R: Round>(
        init: BTreeMap<R::Id, R>,
    ) -> Result<BTreeMap<R::Id, R::NextRound>, StepError<R::Error>>
    where
        R::Id: Eq + Ord + Clone,
        R::Message: Clone,
    {
        // Collect outgoing messages

        let mut accums = BTreeMap::<R::Id, HoleMap<R::Id, R::Payload>>::new();
        // `to, from, message`
        let mut messages = Vec::<(R::Id, R::Id, R::Message)>::new();

        for (id_from, state) in init.iter() {
            let (accum, to_send) = state.get_messages();

            match to_send {
                ToSend::Broadcast { message, ids, .. } => {
                    for id_to in ids {
                        messages.push((id_to.clone(), id_from.clone(), message.clone()));
                    }
                }
                ToSend::Direct(msgs) => {
                    for (id_to, message) in msgs.into_iter() {
                        messages.push((id_to.clone(), id_from.clone(), message.clone()));
                    }
                }
            }

            accums.insert(id_from.clone(), accum);
        }

        // Send out messages

        for (id_to, id_from, message) in messages.into_iter() {
            let round = &init[&id_to];
            let accum = accums.get_mut(&id_to).unwrap();
            match round.receive(accum, &id_from, message) {
                OnReceive::Ok => {}
                OnReceive::InvalidId => return Err(StepError::Logic("Invalid ID".into())),
                OnReceive::AlreadyReceived => {
                    return Err(StepError::Logic("Already received from this ID".into()))
                }
                OnReceive::Fatal(err) => return Err(StepError::Transition(err)),
            };
        }

        // Check that all the states are finished

        let mut result = BTreeMap::<R::Id, R::NextRound>::new();
        for (id, round) in init.into_iter() {
            let accum = accums[&id].clone();
            let maybe_next_state = round.try_finalize(accum);

            let next_state = match maybe_next_state {
                OnFinalize::NotFinished(_) => {
                    return Err(StepError::Logic(
                        "State not finished after all messages are sent".to_string(),
                    ))
                }
                OnFinalize::Finished(s) => s,
            };
            result.insert(id, next_state);
        }

        Ok(result)
    }
}
