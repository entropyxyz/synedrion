pub(crate) trait RoundStart: Sized {
    type Id: Sized;
    type Error: Sized;
    type DirectMessage: Sized;
    type BroadcastMessage: Sized;
    type ReceivingState: RoundReceiving<
        Id = Self::Id,
        Error = Self::Error,
        DirectMessage = Self::DirectMessage,
        BroadcastMessage = Self::BroadcastMessage,
        Round = Self,
    >;
    fn execute(
        &self,
    ) -> Result<
        (
            Self::ReceivingState,
            Vec<(Self::Id, Self::DirectMessage)>,
            Self::BroadcastMessage,
        ),
        Self::Error,
    >;
}

pub(crate) enum OnFinalize<ThisState, NextState> {
    Finished(NextState),
    NotFinished(ThisState),
}

// TODO: Is it even possible to have a fatal error on reception of a message?
pub(crate) enum OnReceive<Error> {
    Ok,
    NonFatal(Error),
    Fatal(Error),
}

pub(crate) trait RoundReceiving: Sized {
    type Id: Sized;
    type Error: Sized;
    type DirectMessage: Sized;
    type BroadcastMessage: Sized;
    type Round: Sized;
    type NextState: Sized;

    const BCAST_REQUIRES_CONSENSUS: bool = false;

    fn receive_direct(
        &mut self,
        _round: &Self::Round,
        _from: &Self::Id,
        _msg: &Self::DirectMessage,
    ) -> OnReceive<Self::Error> {
        OnReceive::Ok
    }

    fn receive_bcast(
        &mut self,
        _round: &Self::Round,
        _from: &Self::Id,
        _msg: &Self::BroadcastMessage,
    ) -> OnReceive<Self::Error> {
        OnReceive::Ok
    }

    fn try_finalize(
        self,
        round: Self::Round,
    ) -> Result<OnFinalize<Self, Self::NextState>, Self::Error>;
}

#[cfg(test)]
pub(crate) mod tests {

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

    pub(crate) fn step<R: RoundStart>(
        init: BTreeMap<R::Id, R>,
    ) -> Result<
        BTreeMap<R::Id, <R::ReceivingState as RoundReceiving>::NextState>,
        StepError<R::Error>,
    >
    where
        R::Id: Eq + Ord + Clone,
    {
        // Collect outgoing messages

        let mut bcasts = BTreeMap::<R::Id, R::BroadcastMessage>::new();
        let mut dms = BTreeMap::<R::Id, Vec<(R::Id, R::DirectMessage)>>::new();
        let mut rstates = BTreeMap::<R::Id, (R, R::ReceivingState)>::new();

        for (id, state) in init.into_iter() {
            let (rstate, dm, bcast) = state.execute()?;

            for (to, msg) in dm.into_iter() {
                dms.entry(to).or_default().push((id.clone(), msg));
            }

            bcasts.insert(id.clone(), bcast);

            rstates.insert(id, (state, rstate));
        }

        // Send out broadcasts

        for (id, (state, rstate)) in rstates.iter_mut() {
            for (from, msg) in bcasts.iter() {
                // Don't send the broadcast to the actor it came from
                if from == id {
                    continue;
                }
                match rstate.receive_bcast(state, from, msg) {
                    OnReceive::Ok => {}
                    OnReceive::NonFatal(_err) => { /* TODO: or print the error? */ }
                    OnReceive::Fatal(err) => return Err(StepError::Transition(err)),
                };
            }
        }

        // Send out direct messages

        // TODO: check that IDs in the direct messages map are a subset of all IDs

        for (id, (state, rstate)) in rstates.iter_mut() {
            if let Some(dm) = dms.get(&id) {
                for (from, msg) in dm.iter() {
                    match rstate.receive_direct(state, from, msg) {
                        OnReceive::Ok => {}
                        OnReceive::NonFatal(_err) => { /* TODO: or print the error? */ }
                        OnReceive::Fatal(err) => return Err(StepError::Transition(err)),
                    };
                }
            };
        }

        // Check that all the states are finished

        let mut result = BTreeMap::<R::Id, <R::ReceivingState as RoundReceiving>::NextState>::new();
        for (id, (state, rstate)) in rstates.into_iter() {
            let maybe_next_state = rstate.try_finalize(state)?;

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
